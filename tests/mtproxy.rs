//! The proxy end to end: a Telegram client reaches the datacenter it names,
//! and everyone else is counted and closed.

mod common;

use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::mtproxy as client;
use common::mtproxy::{DOMAIN, KEY};
use ctr::cipher::StreamCipher;
use svpn::mtproxy::{Secret, Stats};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

const RELAXED: Ordering = Ordering::Relaxed;

/// A running proxy and a listener that stands in for every datacenter.
struct Stand {
    proxy: SocketAddr,
    datacenters: TcpListener,
    stats: Arc<Stats>,
    serve: JoinHandle<()>,
}

impl Drop for Stand {
    fn drop(&mut self) {
        self.serve.abort();
    }
}

async fn stand() -> Arc<Stand> {
    let datacenters = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secret = Arc::new(Secret::parse(&client::secret_hex(KEY, DOMAIN)).unwrap());
    let stats = Arc::new(Stats::default());
    let proxy = listener.local_addr().unwrap();
    // Every datacenter there is, is the one listener.
    let anywhere = datacenters.local_addr().unwrap();
    let serve = tokio::spawn(svpn::mtproxy::serve(
        listener,
        secret,
        Arc::new(move |dc| {
            if known(dc) {
                vec![anywhere]
            } else {
                Vec::new()
            }
        }),
        stats.clone(),
    ));
    Arc::new(Stand {
        proxy,
        datacenters,
        stats,
        serve,
    })
}

/// A datacenter with an address in the proxy's table.
fn known(dc: i16) -> bool {
    !svpn::mtproxy::addresses(dc).is_empty()
}

/// Echo whatever the first client sends through the proxy, until it goes
/// away; then the datacenter it asked for and all it sent.
async fn echo(stand: &Stand) -> Option<(i16, Vec<u8>)> {
    let (mut stream, _) = stand.datacenters.accept().await.ok()?;
    let mut frame = [0u8; client::FRAME];
    stream.read_exact(&mut frame).await.ok()?;
    let (dc, mut from_proxy, mut to_proxy) = client::datacenter(frame);
    let mut all = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await.ok()?;
        if read == 0 {
            break;
        }
        from_proxy.apply_keystream(&mut buffer[..read]);
        all.extend_from_slice(&buffer[..read]);
        to_proxy.apply_keystream(&mut buffer[..read]);
        stream.write_all(&buffer[..read]).await.ok()?;
    }
    Some((dc, all))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Say `message` in the client's stream and read back the next record.
async fn say(stream: &mut TcpStream, obfuscated: &mut client::Client, message: &[u8]) -> Vec<u8> {
    let mut bytes = message.to_vec();
    obfuscated.send.apply_keystream(&mut bytes);
    client::send(stream, false, &bytes).await.unwrap();
    let mut reply = client::receive(stream).await.unwrap().unwrap();
    obfuscated.recv.apply_keystream(&mut reply);
    reply
}

/// A client past the Fake TLS with its frame for `dc` sent.
async fn connected(stand: &Stand, key: &[u8; 16], dc: i16) -> (TcpStream, client::Client) {
    let mut stream = TcpStream::connect(stand.proxy).await.unwrap();
    let hello = client::hello(key, DOMAIN, now());
    stream.write_all(&hello).await.unwrap();
    let random: [u8; 32] = hello[11..43].try_into().unwrap();
    client::read_flight(&mut stream, key, random).await.unwrap();
    let (frame, obfuscated) = client::frame(key, dc);
    client::send(&mut stream, true, &frame).await.unwrap();
    (stream, obfuscated)
}

/// The counters reached these values.
async fn counters(stats: &Stats, accepted: u64, rejected: u64) -> bool {
    let reached = async {
        while stats.accepted.load(RELAXED) != accepted || stats.rejected.load(RELAXED) != rejected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let in_time = timeout(Duration::from_secs(5), reached).await.is_ok();
    assert!(
        in_time,
        "accepted {} rejected {}",
        stats.accepted.load(RELAXED),
        stats.rejected.load(RELAXED)
    );
    in_time
}

/// No client is held any more.
async fn idle(stats: &Stats) -> bool {
    let released = async {
        while stats.active.load(RELAXED) != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    timeout(Duration::from_secs(5), released).await.is_ok()
}

/// No datacenter heard from the proxy.
async fn nothing_came(stand: &Stand) -> bool {
    timeout(Duration::from_millis(300), stand.datacenters.accept())
        .await
        .is_err()
}

/// The proxy closed the stream without a word.
async fn closed(stream: &mut TcpStream) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        timeout(Duration::from_secs(5), stream.read(&mut byte)).await,
        Ok(Ok(0))
    )
}

/// The echo task of a stand.
fn echoist(stand: &Arc<Stand>) -> JoinHandle<Option<(i16, Vec<u8>)>> {
    let stand = stand.clone();
    tokio::spawn(async move { echo(&stand).await })
}

// ── a client ──

#[tokio::test]
async fn a_client_reaches_the_datacenter_it_names() {
    let stand = stand().await;
    let datacenter = echoist(&stand);
    let (mut stream, mut obfuscated) = connected(&stand, &KEY, 2).await;
    assert_eq!(say(&mut stream, &mut obfuscated, b"ping").await, b"ping");
    // The stream goes on under the same keys.
    assert_eq!(
        say(&mut stream, &mut obfuscated, b"and again").await,
        b"and again"
    );
    drop(stream);
    assert_eq!(
        datacenter.await.unwrap(),
        Some((2, b"pingand again".to_vec()))
    );
    assert!(counters(&stand.stats, 1, 0).await, "one client accepted");
    assert!(idle(&stand.stats).await);
}

#[tokio::test]
async fn a_media_datacenter_keeps_its_sign() {
    let stand = stand().await;
    let datacenter = echoist(&stand);
    let (mut stream, mut obfuscated) = connected(&stand, &KEY, -5).await;
    assert_eq!(say(&mut stream, &mut obfuscated, b"video").await, b"video");
    drop(stream);
    assert_eq!(datacenter.await.unwrap(), Some((-5, b"video".to_vec())));
}

// ── everyone else ──

#[tokio::test]
async fn a_client_of_another_secret_is_closed_before_the_datacenter() {
    let stand = stand().await;
    let mut stream = TcpStream::connect(stand.proxy).await.unwrap();
    let hello = client::hello(&[0xcd; 16], DOMAIN, now());
    stream.write_all(&hello).await.unwrap();
    assert!(closed(&mut stream).await);
    assert!(counters(&stand.stats, 0, 1).await, "one client rejected");
    assert!(nothing_came(&stand).await);
    assert!(idle(&stand.stats).await);
}

#[tokio::test]
async fn a_replayed_hello_is_refused() {
    let stand = stand().await;
    let datacenter = echoist(&stand);
    let hello = client::hello(&KEY, DOMAIN, now());
    let random: [u8; 32] = hello[11..43].try_into().unwrap();
    let mut first = TcpStream::connect(stand.proxy).await.unwrap();
    first.write_all(&hello).await.unwrap();
    client::read_flight(&mut first, &KEY, random).await.unwrap();
    let (frame, mut obfuscated) = client::frame(&KEY, 2);
    client::send(&mut first, true, &frame).await.unwrap();
    assert_eq!(say(&mut first, &mut obfuscated, b"first").await, b"first");
    drop(first);
    // The same hello again: recorded, refused.
    let mut again = TcpStream::connect(stand.proxy).await.unwrap();
    again.write_all(&hello).await.unwrap();
    assert!(closed(&mut again).await);
    assert!(counters(&stand.stats, 1, 1).await);
    assert_eq!(datacenter.await.unwrap(), Some((2, b"first".to_vec())));
}

#[tokio::test]
async fn anything_but_a_client_is_closed() {
    let stand = stand().await;
    let openings: [&[u8]; 4] = [
        b"GET / HTTP/1.1",
        b"not tls",
        &[0; 8],
        // A TLS record that is no ClientHello.
        &[0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4],
    ];
    for opening in openings {
        let mut stream = TcpStream::connect(stand.proxy).await.unwrap();
        stream.write_all(opening).await.unwrap();
        assert!(closed(&mut stream).await, "{opening:?}");
    }
    assert!(counters(&stand.stats, 0, 4).await, "four rejected");
    assert!(nothing_came(&stand).await);
    assert!(idle(&stand.stats).await);
}

#[tokio::test]
async fn a_client_of_an_unknown_datacenter_is_closed() {
    let stand = stand().await;
    let (mut stream, _) = connected(&stand, &KEY, 9).await;
    assert!(closed(&mut stream).await);
    assert!(counters(&stand.stats, 0, 1).await);
    assert!(nothing_came(&stand).await);
}

// ── the secret ──

/// `ee`, the key 01 .. 10, and `www.example.com`.
const SECRET: &str = "ee0102030405060708090a0b0c0d0e0f107777772e6578616d706c652e636f6d";

#[test]
fn a_secret_is_the_key_and_the_domain_of_a_link() {
    let secret = Secret::parse(&format!("  {SECRET}\n")).unwrap();
    assert_eq!(
        secret.key(),
        &[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    );
    assert_eq!(secret.domain(), "www.example.com");
    // Uppercase hex and an uppercase `ee` are the same secret.
    assert_eq!(Secret::parse(&SECRET.to_uppercase()).unwrap(), secret);
}

#[test]
fn a_malformed_secret_is_refused_without_being_repeated() {
    let key = "0102030405060708090a0b0c0d0e0f10";
    let domain = "7777772e6578616d706c652e636f6d";
    let bad = [
        format!("dd{key}{domain}"),   // another mode
        format!("{key}{domain}"),     // no mode
        format!("ee{key}"),           // no domain
        format!("ee{key}{domain}0"),  // odd length
        format!("ee{key}{domain}g0"), // not hex
        format!("ee{key}80{domain}"), // a domain that is not text
        String::new(),
    ];
    for text in bad {
        let error = Secret::parse(&text).unwrap_err().to_string();
        assert!(error.starts_with("telegram_proxy:"), "{error}");
        // The refusal says what is wrong, not what was sent.
        assert!(!error.contains(key), "{error}");
    }
}

#[test]
fn the_key_stays_out_of_debug_output() {
    let secret = Secret::parse(SECRET).unwrap();
    let shown = format!("{secret:?}");
    assert!(shown.contains("www.example.com"));
    assert!(!shown.contains("0102030405060708090a0b0c0d0e0f10"));
}
