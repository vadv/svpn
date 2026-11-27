//! The Fake TLS of the proxy: the hello it accepts, the flight it answers
//! with, and the record stream that follows.

mod common;

use common::mtproxy as client;
use common::mtproxy::{DOMAIN, KEY};
use svpn::mtproxy::faketls::{self, Reader, Reject};
use tokio::{
    io::{AsyncWriteExt, duplex},
    join,
};

const NOW: u64 = 1_800_000_000;

/// The proxy's verdict on a hello.
async fn checked(
    hello: &[u8],
    key: &[u8; 16],
    domain: &str,
    now: u64,
) -> Result<faketls::ClientHello, Reject> {
    let (mut proxy, mut telegram) = duplex(64 * 1024);
    let sending = async { telegram.write_all(hello).await };
    let mut reader = Reader::new(&mut proxy);
    let (verdict, sent) = join!(reader.hello(key, domain, now), sending);
    sent.unwrap();
    verdict
}

/// The hello as records of the given handshake sizes.
fn fragmented(hello: &[u8], sizes: &[usize]) -> Vec<u8> {
    let mut wire = Vec::new();
    let mut rest = &hello[5..];
    for size in sizes {
        let (piece, tail) = rest.split_at(*size);
        rest = tail;
        wire.extend_from_slice(&[0x16, 0x03, 0x01]);
        wire.extend_from_slice(&(piece.len() as u16).to_be_bytes());
        wire.extend_from_slice(piece);
    }
    wire.extend_from_slice(&[0x16, 0x03, 0x01]);
    wire.extend_from_slice(&(rest.len() as u16).to_be_bytes());
    wire.extend_from_slice(rest);
    wire
}

// ── the hello ──

#[tokio::test]
async fn a_signed_hello_is_accepted() {
    let hello = client::hello(&KEY, DOMAIN, NOW);
    let accepted = checked(&hello, &KEY, DOMAIN, NOW).await.unwrap();
    assert_eq!(accepted.random, hello[11..43]);
    assert_eq!(accepted.session_id, hello[44..76]);
    // GREASE is skipped for the first real cipher suite.
    assert_eq!(accepted.cipher, 0x1301);
}

#[tokio::test]
async fn a_hello_of_another_secret_or_domain_is_foreign() {
    let hello = client::hello(&KEY, DOMAIN, NOW);
    let other = [0xcd; 16];
    assert_eq!(
        checked(&hello, &other, DOMAIN, NOW).await,
        Err(Reject::Foreign)
    );
    assert_eq!(
        checked(&hello, &KEY, "www.other.com", NOW).await,
        Err(Reject::Foreign)
    );
    // The domain is the one in the link, byte for byte.
    assert_eq!(
        checked(&hello, &KEY, "WWW.EXAMPLE.COM", NOW).await,
        Err(Reject::Foreign)
    );
    // A hello the client signed for another domain.
    let other = client::hello(&KEY, "www.other.com", NOW);
    assert_eq!(
        checked(&other, &KEY, DOMAIN, NOW).await,
        Err(Reject::Foreign)
    );
}

#[tokio::test]
async fn a_tampered_hello_is_foreign() {
    let mut hello = client::hello(&KEY, DOMAIN, NOW);
    hello[300] ^= 1;
    assert_eq!(
        checked(&hello, &KEY, DOMAIN, NOW).await,
        Err(Reject::Foreign)
    );
    let mut hello = client::hello(&KEY, DOMAIN, NOW);
    hello[12] ^= 1;
    assert_eq!(
        checked(&hello, &KEY, DOMAIN, NOW).await,
        Err(Reject::Foreign)
    );
}

#[tokio::test]
async fn a_hello_from_another_time_is_stale() {
    let edge = faketls::MAX_SKEW;
    assert_eq!(
        checked(
            &client::hello(&KEY, DOMAIN, NOW - edge - 1),
            &KEY,
            DOMAIN,
            NOW
        )
        .await,
        Err(Reject::Stale)
    );
    assert_eq!(
        checked(
            &client::hello(&KEY, DOMAIN, NOW + edge + 1),
            &KEY,
            DOMAIN,
            NOW
        )
        .await,
        Err(Reject::Stale)
    );
    // The edge itself is inside the window, on both sides.
    for created in [NOW - edge, NOW + edge] {
        assert!(
            checked(&client::hello(&KEY, DOMAIN, created), &KEY, DOMAIN, NOW)
                .await
                .is_ok()
        );
    }
}

#[tokio::test]
async fn anything_but_a_client_hello_is_refused() {
    let cases: Vec<Vec<u8>> = vec![
        b"GET / HTTP/1.1".to_vec(),
        vec![
            0x17, 0x03, 0x03, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        vec![0x16, 0x03, 0x03, 0x00, 0x01, 0x0b],
        vec![
            0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0xff, 0xff, 0xff, 0, 0, 0, 0,
        ],
        vec![
            0x16, 0x05, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 3, 3, 0, 0,
        ],
    ];
    // More fragments than a ClientHello needs.
    let many = vec![vec![0x16, 0x03, 0x01, 0x00, 0x00]; 11].concat();
    for wire in cases.into_iter().chain([many]) {
        let (mut proxy, mut telegram) = duplex(64 * 1024);
        let sending = async { telegram.write_all(&wire).await };
        let mut reader = Reader::new(&mut proxy);
        let (verdict, sent) = join!(reader.hello(&KEY, DOMAIN, NOW), sending);
        sent.unwrap();
        assert_eq!(verdict, Err(Reject::Format), "{wire:x?}");
    }
    // A record longer than TLS allows.
    let long = vec![0x16, 0x03, 0x01, 0x40, 0x01, 1];
    assert_eq!(checked(&long, &KEY, DOMAIN, NOW).await, Err(Reject::Format));
}

#[tokio::test]
async fn a_closed_client_is_closed() {
    let (mut proxy, telegram) = duplex(64 * 1024);
    drop(telegram);
    assert_eq!(
        Reader::new(&mut proxy).hello(&KEY, DOMAIN, NOW).await,
        Err(Reject::Closed)
    );
    let (mut proxy, mut telegram) = duplex(64 * 1024);
    let mut reader = Reader::new(&mut proxy);
    telegram
        .write_all(&client::hello(&KEY, DOMAIN, NOW)[..100])
        .await
        .unwrap();
    drop(telegram);
    assert_eq!(reader.hello(&KEY, DOMAIN, NOW).await, Err(Reject::Closed));
}

#[tokio::test]
async fn a_hello_split_over_records_is_one_hello() {
    let hello = client::hello(&KEY, DOMAIN, NOW);
    for sizes in [
        vec![3usize],
        vec![1, 1, 1, 50, 200],
        vec![0],
        vec![4],
        vec![508],
    ] {
        let wire = fragmented(&hello, &sizes);
        let accepted = checked(&wire, &KEY, DOMAIN, NOW).await.unwrap();
        assert_eq!(accepted.session_id, hello[44..76], "{sizes:?}");
    }
}

#[tokio::test]
async fn what_follows_the_hello_in_the_same_records_is_kept_for_the_stream() {
    let hello = client::hello(&KEY, DOMAIN, NOW);
    // The client's ChangeCipherSpec and its first record right after the
    // hello, in the same write.
    let mut wire = hello.clone();
    wire.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    wire.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4]);
    let (mut proxy, mut telegram) = duplex(64 * 1024);
    let mut reader = Reader::new(&mut proxy);
    telegram.write_all(&wire).await.unwrap();
    let accepted = reader.hello(&KEY, DOMAIN, NOW).await.unwrap();
    assert_eq!(accepted.session_id, hello[44..76]);
    let mut out = [0u8; 16];
    assert_eq!(reader.read(&mut out).await.unwrap(), 4);
    assert_eq!(&out[..4], &[1, 2, 3, 4]);
}

// ── the flight ──

#[tokio::test]
async fn the_client_checks_the_flight() {
    let hello = client::hello(&KEY, DOMAIN, NOW);
    let (mut proxy, mut telegram) = duplex(256 * 1024);
    let mut reader = Reader::new(&mut proxy);
    telegram.write_all(&hello).await.unwrap();
    let accepted = reader.hello(&KEY, DOMAIN, NOW).await.unwrap();
    drop(reader);
    let noise = vec![0u8; faketls::noise_len([0, 0])];
    let flight = faketls::server_flight(&KEY, &accepted, [7; 32], &noise);
    proxy.write_all(&flight).await.unwrap();
    let random: [u8; 32] = hello[11..43].try_into().unwrap();
    client::read_flight(&mut telegram, &KEY, random)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_client_refuses_a_flight_signed_with_another_key() {
    let hello = client::hello(&KEY, DOMAIN, NOW);
    let (mut proxy, mut telegram) = duplex(256 * 1024);
    let mut reader = Reader::new(&mut proxy);
    telegram.write_all(&hello).await.unwrap();
    let accepted = reader.hello(&KEY, DOMAIN, NOW).await.unwrap();
    drop(reader);
    let noise = vec![0u8; faketls::noise_len([0, 0])];
    let flight = faketls::server_flight(&[0xcd; 16], &accepted, [7; 32], &noise);
    proxy.write_all(&flight).await.unwrap();
    let random: [u8; 32] = hello[11..43].try_into().unwrap();
    assert_eq!(
        client::read_flight(&mut telegram, &KEY, random)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Other
    );
}

// ── the record stream ──

fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut record = vec![kind, 0x03, 0x03];
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

#[tokio::test]
async fn records_skip_other_types_and_hand_out_payloads() {
    let mut wire = record(0x14, &[1]);
    wire.extend_from_slice(&record(0x17, &[10, 11]));
    wire.extend_from_slice(&record(0x15, &[1, 0]));
    wire.extend_from_slice(&record(0x17, &[20, 21, 22]));
    wire.extend_from_slice(&record(0x17, &[]));
    let (mut proxy, mut telegram) = duplex(1024);
    telegram.write_all(&wire).await.unwrap();
    drop(telegram);
    let mut reader = Reader::new(&mut proxy);
    let mut out = [0u8; 16];
    assert_eq!(reader.read(&mut out).await.unwrap(), 2);
    assert_eq!(&out[..2], &[10, 11]);
    // A record bigger than the buffer is handed out in pieces.
    let mut small = [0u8; 2];
    assert_eq!(reader.read(&mut small).await.unwrap(), 2);
    assert_eq!(small, [20, 21]);
    let mut one = [0u8; 1];
    assert_eq!(reader.read(&mut one).await.unwrap(), 1);
    assert_eq!(one, [22]);
    // The end between records is not an error.
    assert_eq!(reader.read(&mut out).await.unwrap(), 0);
}

#[tokio::test]
async fn a_record_cut_short_is_an_error() {
    let (mut proxy, mut telegram) = duplex(1024);
    telegram
        .write_all(&record(0x17, &[1, 2, 3])[..5])
        .await
        .unwrap();
    drop(telegram);
    let mut reader = Reader::new(&mut proxy);
    let mut out = [0u8; 8];
    assert_eq!(
        reader.read(&mut out).await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    let (mut proxy, mut telegram) = duplex(1024);
    telegram.write_all(b"not tls at all").await.unwrap();
    drop(telegram);
    let mut reader = Reader::new(&mut proxy);
    assert_eq!(
        reader.read(&mut out).await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn payloads_are_written_in_records_of_at_most_8192_bytes() {
    let (mut proxy, mut telegram) = duplex(64 * 1024);
    let payload: Vec<u8> = (0..20_000u32).map(|n| n as u8).collect();
    let writing = faketls::write(&mut proxy, &payload);
    let (written, sizes) = join!(writing, async {
        let mut sizes = Vec::new();
        while sizes.iter().sum::<usize>() < payload.len() {
            match client::receive(&mut telegram).await.unwrap() {
                Some(received) => {
                    assert!(received.len() <= 8192);
                    assert_eq!(
                        received,
                        payload[sizes.iter().sum::<usize>()..][..received.len()]
                    );
                    sizes.push(received.len());
                }
                None => break,
            }
        }
        sizes
    });
    written.unwrap();
    assert_eq!(sizes, [8192, 8192, 3616]);
}

#[tokio::test]
async fn noise_len_stays_inside_the_flight() {
    assert_eq!(faketls::noise_len([0, 0]), 2500);
    let top = faketls::noise_len([0xff, 0xff]);
    assert_eq!(top, 2500 + 65535 % 2200);
    assert!(top < 2500 + 2200);
}
