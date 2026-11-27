//! MTProto proxy for Telegram clients with Fake TLS, served by the hub.
//! A client that holds the secret connects to `listen`; the proxy answers
//! as a TLS server and relays the obfuscated stream to the Telegram
//! datacenter the client names. The datacenter is reached through the
//! routing table: on the hub's host the TUN carries it to an exit like any
//! other traffic of the host.
//!
//! Layout: `faketls` is the record layer and the hello, `obfuscation` the
//! stream under it, this file the settings, the listener and the relay.

pub mod faketls;
pub mod obfuscation;

use std::{
    collections::{HashMap, VecDeque},
    fmt, io,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail, ensure};
use ctr::cipher::StreamCipher;
use faketls::Reader;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};

/// Time for the whole hello: the Fake TLS one and the obfuscated one under
/// it.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Clients served at once; a connection beyond that is closed unread.
pub const MAX_CLIENTS: usize = 256;
/// How many hellos are kept to tell a replay from a new hello.
const REPLAYED: usize = 4096;
const TAG: &str = "telegram_proxy";

/// The secret of the clients' links: 16 bytes and the domain of the Fake
/// TLS, written as `ee`, the key and the domain in hex.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    key: [u8; 16],
    domain: String,
}

impl Secret {
    /// `ee`, 32 hex digits of the key and the domain in hex: the `secret`
    /// of a `tg://proxy` link.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let text = text.trim();
        ensure!(
            text.get(..2)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("ee")),
            "{TAG}: secret must start with ee"
        );
        let hex = match text.get(2..) {
            Some(hex) if hex.len() >= 34 && hex.len() % 2 == 0 => hex,
            _ => bail!("{TAG}: secret must be ee, 32 hex digits and a domain in hex"),
        };
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for pair in hex.as_bytes().as_chunks::<2>().0 {
            bytes.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
        }
        let (key, domain) = bytes.split_at(16);
        let domain = String::from_utf8(domain.to_vec())
            .with_context(|| format!("{TAG}: secret domain must be ASCII"))?;
        ensure!(
            !domain.is_empty() && domain.bytes().all(|byte| byte.is_ascii_graphic()),
            "{TAG}: secret must be ee, 32 hex digits and a domain in hex"
        );
        Ok(Self {
            key: key.try_into().expect("split_at(16) gives 16 bytes"),
            domain,
        })
    }

    /// The secret from the file that keeps it: one line.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("{TAG}: read {}", path.display()))?;
        Self::parse(&text)
    }

    /// The domain the clients send in their Fake TLS hello.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn key(&self) -> &[u8; 16] {
        &self.key
    }
}

// The key never reaches a log or a debug dump.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

/// One hex digit.
fn nibble(digit: u8) -> anyhow::Result<u8> {
    match digit {
        b'0'..=b'9' => Ok(digit & 0x0f),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => bail!("{TAG}: secret must be ee, 32 hex digits and a domain in hex"),
    }
}

/// The `telegram_proxy` block of the config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Where the clients connect.
    pub listen: SocketAddr,
    /// The secret the clients' links carry.
    pub secret: Secret,
}

/// Counters of the stats report.
#[derive(Debug, Default)]
pub struct Stats {
    /// Hellos that went on to a datacenter.
    pub accepted: AtomicU64,
    /// Connections closed before a datacenter was reached.
    pub rejected: AtomicU64,
    /// Connections open right now.
    pub active: AtomicU64,
}

/// Telegram datacenters as Telegram Desktop ships them.
const DATACENTERS: [(i16, Ipv4Addr); 6] = [
    (1, Ipv4Addr::new(149, 154, 175, 50)),
    (2, Ipv4Addr::new(149, 154, 167, 51)),
    (2, Ipv4Addr::new(95, 161, 76, 100)),
    (3, Ipv4Addr::new(149, 154, 175, 100)),
    (4, Ipv4Addr::new(149, 154, 167, 91)),
    (5, Ipv4Addr::new(149, 154, 171, 5)),
];

/// Addresses of a datacenter on port 443. The number is the client's with
/// its sign dropped: the media datacenter has the same addresses.
pub fn addresses(dc: i16) -> Vec<SocketAddr> {
    DATACENTERS
        .iter()
        .filter(|(known, _)| known.unsigned_abs() == dc.unsigned_abs())
        .map(|(_, ip)| SocketAddr::new((*ip).into(), 443))
        .collect()
}

/// Where the datacenters are, as the proxy dials them.
pub type Addresses = Arc<dyn Fn(i16) -> Vec<SocketAddr> + Send + Sync>;

/// Accept clients until the task is dropped; dropping it closes every
/// client. A failed accept is logged and the listener goes on.
pub async fn serve(
    listener: TcpListener,
    secret: Arc<Secret>,
    addresses: Addresses,
    stats: Arc<Stats>,
) {
    let replay = Arc::new(Mutex::new(Replay::default()));
    let mut clients: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        crate::warn!("telegram proxy: accept: {error}");
                        continue;
                    }
                };
                if clients.len() < MAX_CLIENTS {
                    let (replay, secret, addresses, stats) =
                        (replay.clone(), secret.clone(), addresses.clone(), stats.clone());
                    clients.spawn(client(stream, secret, addresses, stats, replay));
                }
            }
            _ = clients.join_next(), if !clients.is_empty() => {}
        }
    }
}

/// A client being served: `new` counts it, `drop` uncounts it.
struct Held(Arc<Stats>);

impl Held {
    fn new(stats: Arc<Stats>) -> Self {
        stats.active.fetch_add(1, Ordering::Relaxed);
        Self(stats)
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Session ids of accepted hellos, oldest first.
#[derive(Default)]
struct Replay {
    seen: HashMap<[u8; 32], u64>,
    order: VecDeque<[u8; 32]>,
}

impl Replay {
    /// Records the hello; `true` when it was recorded before.
    fn check(&mut self, id: [u8; 32], now: u64) -> bool {
        // Old entries are dropped first: a hello that old is refused by its
        // timestamp.
        while self.seen.len() >= REPLAYED
            || self
                .order
                .front()
                .is_some_and(|id| now.saturating_sub(self.seen[id]) > faketls::MAX_SKEW)
        {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.seen.remove(&oldest);
        }
        if self.seen.contains_key(&id) {
            return true;
        }
        self.seen.insert(id, now);
        self.order.push_back(id);
        false
    }
}

fn random(bytes: &mut [u8]) -> io::Result<()> {
    getrandom::fill(bytes).map_err(|_| io::Error::other("OS randomness unavailable"))
}

/// One client: the hello, then the relay until either side is done.
async fn client(
    stream: TcpStream,
    secret: Arc<Secret>,
    addresses: Addresses,
    stats: Arc<Stats>,
    replay: Arc<Mutex<Replay>>,
) {
    let _held = Held::new(stats.clone());
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = Reader::new(read);
    let started = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        start(&mut reader, &mut write, &secret, &addresses, &replay),
    )
    .await
    .context("handshake timed out")
    .and_then(|started| started);
    let session = match started {
        Ok(session) => {
            stats.accepted.fetch_add(1, Ordering::Relaxed);
            session
        }
        Err(error) => {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            crate::debug!("telegram proxy: {error:#}");
            return;
        }
    };
    if let Err(error) = relay(&mut reader, &mut write, session).await {
        crate::debug!("telegram proxy: {error}");
    }
}

/// Both ends of one session, past their handshakes.
struct Session {
    /// The client's stream under its records.
    client: obfuscation::Streams,
    /// The datacenter's stream.
    upstream: TcpStream,
    upstream_streams: obfuscation::Streams,
}

/// The hello of the client, then the datacenter's side of the stream.
async fn start<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut Reader<R>,
    write: &mut W,
    secret: &Secret,
    addresses: &Addresses,
    replay: &Mutex<Replay>,
) -> anyhow::Result<Session> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |passed| passed.as_secs());
    let hello = reader.hello(secret.key(), secret.domain(), now).await?;
    ensure!(
        !replay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .check(hello.session_id, now),
        "replayed hello"
    );
    let mut noise = vec![0u8; faketls::noise_len(crate::crypto::random::<2>()?)];
    random(&mut noise)?;
    let flight =
        faketls::server_flight(secret.key(), &hello, crate::crypto::random::<32>()?, &noise);
    write.write_all(&flight).await?;
    let mut frame = [0u8; obfuscation::FRAME];
    fill(reader, &mut frame).await?;
    let (dc, client) = obfuscation::received(frame, secret.key())?;
    let address = addresses(dc)
        .first()
        .copied()
        .with_context(|| format!("datacenter {dc} is unknown"))?;
    let upstream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await {
        Ok(connected) => connected.with_context(|| format!("connect {address}"))?,
        Err(_) => bail!("telegram proxy: connect {address} timed out"),
    };
    let frame = obfuscation::frame(dc, &mut random)?;
    let (wire, upstream_streams) = obfuscation::sent(&frame);
    let mut upstream = upstream;
    upstream.set_nodelay(true)?;
    upstream.write_all(&wire).await?;
    Ok(Session {
        client,
        upstream,
        upstream_streams,
    })
}

/// Fill `out` with payload from the records of `reader`.
async fn fill<R: AsyncRead + Unpin>(reader: &mut Reader<R>, out: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < out.len() {
        let read = reader.read(&mut out[filled..]).await?;
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        filled += read;
    }
    Ok(())
}

/// Both directions at once; the session is over when either one is.
async fn relay<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut Reader<R>,
    write: &mut W,
    session: Session,
) -> io::Result<()> {
    let Session {
        client,
        mut upstream,
        upstream_streams,
    } = session;
    let (mut upstream_read, mut upstream_write) = upstream.split();
    let up = up(
        reader,
        client.recv,
        upstream_streams.send,
        &mut upstream_write,
    );
    let down = down(
        &mut upstream_read,
        upstream_streams.recv,
        client.send,
        write,
    );
    tokio::select! {
        result = up => result,
        result = down => result,
    }
}

/// Client to datacenter: records in, an obfuscated stream out.
async fn up<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut Reader<R>,
    mut decrypt: obfuscation::Cipher,
    mut encrypt: obfuscation::Cipher,
    out: &mut W,
) -> io::Result<()> {
    let mut buffer = vec![0u8; faketls::MAX_RECORD];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        let bytes = &mut buffer[..read];
        decrypt.apply_keystream(bytes);
        encrypt.apply_keystream(bytes);
        out.write_all(bytes).await?;
    }
}

/// Datacenter to client: an obfuscated stream in, records out.
async fn down<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    input: &mut R,
    mut decrypt: obfuscation::Cipher,
    mut encrypt: obfuscation::Cipher,
    out: &mut W,
) -> io::Result<()> {
    let mut buffer = vec![0u8; faketls::MAX_RECORD];
    loop {
        let read = input.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        let bytes = &mut buffer[..read];
        decrypt.apply_keystream(bytes);
        encrypt.apply_keystream(bytes);
        faketls::write(out, bytes).await?;
    }
}
