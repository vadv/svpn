//! Fake TLS of an MTProto proxy. The client's ClientHello carries an HMAC
//! under the proxy secret and a timestamp; the answer repeats a TLS 1.3
//! server flight. After that the stream runs in `application_data` records
//! with no integrity of their own: the obfuscated layer underneath has it.

use std::io;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type HmacSha256 = Hmac<Sha256>;

/// Record types that appear on the wire.
pub const HANDSHAKE: u8 = 0x16;
pub const CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const APPLICATION_DATA: u8 = 0x17;

/// A record header: type, version, length.
pub const HEADER: usize = 5;
/// The largest payload a record may carry.
pub const MAX_RECORD: usize = 1 << 14;
/// The most records a ClientHello may be split over.
const MAX_RECORDS: usize = 10;
const MAX_HELLO: usize = MAX_RECORDS * MAX_RECORD;
/// `random` follows the record header, the handshake header and the version.
const RANDOM: usize = 11;
const RANDOM_LEN: usize = 32;
/// The last 4 bytes of `random` carry the creation time.
const TIMESTAMP: usize = 4;
/// How far from now a hello may have been created.
pub const MAX_SKEW: u64 = 24 * 60 * 60;
/// Size range of the record that takes the place of the encrypted server
/// flight.
const NOISE_MIN: usize = 2500;
const NOISE_SPAN: usize = 2200;
/// Payload of one record written to the client at most.
const WRITE_RECORD: usize = 8192;

/// The length of the noise record for two random bytes.
pub fn noise_len(draw: [u8; 2]) -> usize {
    NOISE_MIN + u16::from_be_bytes(draw) as usize % NOISE_SPAN
}

/// What the proxy keeps from a ClientHello to echo back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientHello {
    /// The bytes that carry the HMAC and the timestamp.
    pub random: [u8; RANDOM_LEN],
    /// Tells a replayed hello from a new one.
    pub session_id: [u8; RANDOM_LEN],
    /// The first cipher suite that is not GREASE.
    pub cipher: u16,
}

/// Why a ClientHello is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Not a ClientHello the proxy can read.
    Format,
    /// Signed for another secret or sent for another domain.
    Foreign,
    /// Created too far from now.
    Stale,
    /// The client closed before the whole hello arrived.
    Closed,
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Format => "not a ClientHello",
            Self::Foreign => "signed for another secret or domain",
            Self::Stale => "created too far from now",
            Self::Closed => "closed before the hello",
        })
    }
}

impl std::error::Error for Reject {}

/// A stream that ended early means the client left. Any other read error
/// means the stream is not TLS.
fn closed(error: std::io::Error) -> Reject {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        Reject::Closed
    } else {
        Reject::Format
    }
}

fn mac(key: &[u8; 16]) -> HmacSha256 {
    // HMAC takes a key of any length.
    HmacSha256::new_from_slice(key).expect("HMAC takes a key of any length")
}

/// The flight for an accepted hello: ServerHello, ChangeCipherSpec and one
/// `application_data` record. The client checks the HMAC over all three.
/// `share` is the key share of the ServerHello and `noise` the payload of
/// the record, as many bytes as `noise_len` asks for.
pub fn server_flight(
    key: &[u8; 16],
    hello: &ClientHello,
    share: [u8; 32],
    noise: &[u8],
) -> Vec<u8> {
    // ServerHello: 122 bytes of handshake with a TLS 1.3 version and an
    // X25519 key share; the 32 random bytes stay zero until the digest.
    let mut flight = Vec::with_capacity(HEADER + 0x7a + 6 + noise.len());
    flight.extend_from_slice(&[HANDSHAKE, 3, 3, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76, 3, 3]);
    flight.resize(flight.len() + RANDOM_LEN, 0);
    flight.push(RANDOM_LEN as u8);
    flight.extend_from_slice(&hello.session_id);
    flight.extend_from_slice(&hello.cipher.to_be_bytes());
    flight.extend_from_slice(&[
        0x00, // no compression
        0x00, 0x2e, // 46 bytes of extensions
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported versions: TLS 1.3
        0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, // key share: X25519
    ]);
    flight.extend_from_slice(&share);
    flight.extend_from_slice(&[CHANGE_CIPHER_SPEC, 3, 3, 0x00, 0x01, 0x01]);

    flight.extend_from_slice(&[APPLICATION_DATA, 3, 3]);
    flight.extend_from_slice(&(noise.len() as u16).to_be_bytes());
    flight.extend_from_slice(noise);

    // The digest is HMAC over the client random and the flight with a zero
    // random.
    let mut mac = mac(key);
    mac.update(&hello.random);
    mac.update(&flight[..RANDOM]);
    mac.update(&[0; RANDOM_LEN]);
    mac.update(&flight[RANDOM + RANDOM_LEN..]);
    let digest: [u8; RANDOM_LEN] = mac.finalize().into_bytes().into();
    flight[RANDOM..RANDOM + RANDOM_LEN].copy_from_slice(&digest);
    flight
}

/// The hello as one record: what the client signed, however it was split.
fn signed(mut handshake: Vec<u8>) -> Vec<u8> {
    let mut hello = vec![HANDSHAKE, 3, 1, 0, 0];
    hello[3..HEADER].copy_from_slice(&(handshake.len() as u16).to_be_bytes());
    hello.append(&mut handshake);
    hello
}

fn handshake_len(handshake: &[u8]) -> usize {
    4 + usize::from(handshake[1]) * 0x10000
        + usize::from(handshake[2]) * 0x100
        + usize::from(handshake[3])
}

/// Take `n` bytes off the front of `rest`.
fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], Reject> {
    let (head, tail) = rest.split_at_checked(n).ok_or(Reject::Format)?;
    *rest = tail;
    Ok(head)
}

/// Take a field preceded by its `width`-byte big-endian length.
fn chunk<'a>(rest: &mut &'a [u8], width: usize) -> Result<&'a [u8], Reject> {
    let len = take(rest, width)?
        .iter()
        .fold(0usize, |acc, &byte| acc << 8 | usize::from(byte));
    take(rest, len)
}

/// Split a contiguous hello into its parts and its server names.
fn parse(hello: &[u8]) -> Result<(ClientHello, Vec<Vec<u8>>), Reject> {
    let mut rest = hello.get(HEADER..).ok_or(Reject::Format)?;
    // A ClientHello that speaks TLS 1.2 on the wire.
    if rest.first() != Some(&0x01) || rest.get(4..6) != Some(&[3, 3]) {
        return Err(Reject::Format);
    }
    rest = &rest[6..];
    let random = take(&mut rest, RANDOM_LEN)?
        .try_into()
        .map_err(|_| Reject::Format)?;
    // A Telegram client always sends a 32-byte session id.
    let session_id = chunk(&mut rest, 1)?
        .try_into()
        .map_err(|_| Reject::Format)?;
    let cipher = chunk(&mut rest, 2)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&suite| u16::from_be_bytes(suite))
        .find(|suite| {
            let [high, low] = suite.to_be_bytes();
            !(high == low && high & 0x0f == 0x0a)
        })
        .ok_or(Reject::Format)?;
    let _compression = chunk(&mut rest, 1)?;
    let mut extensions = chunk(&mut rest, 2)?;
    if !rest.is_empty() {
        return Err(Reject::Format);
    }
    // server_name is the one extension the proxy reads.
    let mut names = Vec::new();
    while !extensions.is_empty() {
        let kind: [u8; 2] = take(&mut extensions, 2)?
            .try_into()
            .map_err(|_| Reject::Format)?;
        let data = chunk(&mut extensions, 2)?;
        if kind != [0, 0] {
            continue;
        }
        let mut list = data;
        let mut entries = chunk(&mut list, 2)?;
        if !list.is_empty() {
            return Err(Reject::Format);
        }
        while !entries.is_empty() {
            if take(&mut entries, 1)? != [0] {
                return Err(Reject::Format);
            }
            names.push(chunk(&mut entries, 2)?.to_vec());
        }
    }
    Ok((
        ClientHello {
            random,
            session_id,
            cipher,
        },
        names,
    ))
}

/// Check a contiguous hello against the secret and the domain.
pub fn check(hello: &[u8], key: &[u8; 16], domain: &str, now: u64) -> Result<ClientHello, Reject> {
    let (parsed, names) = parse(hello)?;
    if !names.iter().any(|name| name == domain.as_bytes()) {
        return Err(Reject::Foreign);
    }
    let random = hello
        .get(RANDOM..RANDOM + RANDOM_LEN)
        .ok_or(Reject::Format)?;
    let mut mac = mac(key);
    mac.update(&hello[..RANDOM]);
    mac.update(&[0; RANDOM_LEN]);
    mac.update(&hello[RANDOM + RANDOM_LEN..]);
    // random is the digest with its last 4 bytes XOR the creation time.
    let mut difference: [u8; RANDOM_LEN] = mac.finalize().into_bytes().into();
    for (byte, random) in difference.iter_mut().zip(random) {
        *byte ^= *random;
    }
    let (signed, timestamp) = difference.split_at(RANDOM_LEN - TIMESTAMP);
    if signed.iter().fold(0u8, |acc, &byte| acc | byte) != 0 {
        return Err(Reject::Foreign);
    }
    let created = timestamp
        .iter()
        .rev()
        .fold(0u64, |acc, &byte| acc << 8 | u64::from(byte));
    if created.abs_diff(now) > MAX_SKEW {
        return Err(Reject::Stale);
    }
    Ok(parsed)
}

/// The client's side of the record stream: the hello first, then
/// `application_data` records. Records of any other type are skipped.
pub struct Reader<T> {
    stream: T,
    /// Read from the stream and not consumed yet.
    buffered: Vec<u8>,
    /// Where the unconsumed part of `buffered` starts.
    start: usize,
    /// Payload of the current record that is still to be handed out.
    payload_left: usize,
}

impl<T: AsyncRead + Unpin> Reader<T> {
    pub fn new(stream: T) -> Self {
        Self {
            stream,
            buffered: Vec::new(),
            start: 0,
            payload_left: 0,
        }
    }

    fn ready(&self) -> usize {
        self.buffered.len() - self.start
    }

    fn consume(&mut self, n: usize) {
        self.start += n;
        if self.start == self.buffered.len() {
            self.buffered.clear();
            self.start = 0;
        }
    }

    /// Read until `n` bytes are ready.
    async fn need(&mut self, n: usize) -> io::Result<()> {
        let mut chunk = [0u8; 4096];
        while self.ready() < n {
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.buffered.extend_from_slice(&chunk[..read]);
        }
        Ok(())
    }

    /// A record header: type and length; `InvalidData` for anything but TLS.
    async fn header(&mut self) -> io::Result<(u8, usize)> {
        self.need(HEADER).await?;
        let header = &self.buffered[self.start..self.start + HEADER];
        if header[1] != 3 || u16::from_be_bytes([header[3], header[4]]) as usize > MAX_RECORD {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        Ok((
            header[0],
            u16::from_be_bytes([header[3], header[4]]) as usize,
        ))
    }

    /// Read one ClientHello and check it against the secret.
    pub async fn hello(
        &mut self,
        key: &[u8; 16],
        domain: &str,
        now: u64,
    ) -> Result<ClientHello, Reject> {
        let mut handshake: Vec<u8> = Vec::new();
        for _ in 0..MAX_RECORDS {
            let (kind, length) = self.header().await.map_err(closed)?;
            // The first record is a handshake one, and a ClientHello.
            if kind != HANDSHAKE || self.buffered[self.start + 2] != 1 {
                return Err(Reject::Format);
            }
            if length == 0 {
                self.consume(HEADER);
                continue;
            }
            // A record may carry less than the 4-byte handshake header.
            let head = 4usize.saturating_sub(handshake.len()).min(length);
            self.need(HEADER + head).await.map_err(|_| Reject::Closed)?;
            let head_at = self.start + HEADER;
            handshake.extend_from_slice(&self.buffered[head_at..head_at + head]);
            self.consume(HEADER + head);
            if handshake.len() < 4 {
                self.need(length - head).await.map_err(|_| Reject::Closed)?;
                self.consume(length - head);
                continue;
            }
            let total = handshake_len(&handshake);
            if total > MAX_HELLO {
                return Err(Reject::Format);
            }
            let wanted = (total - handshake.len()).min(length - head);
            self.need(wanted).await.map_err(|_| Reject::Closed)?;
            let wanted_at = self.start;
            handshake.extend_from_slice(&self.buffered[wanted_at..wanted_at + wanted]);
            self.consume(wanted);
            // Bytes after the hello in the same record stay for `read`.
            if handshake.len() == total {
                return check(&signed(handshake), key, domain, now);
            }
        }
        Err(Reject::Format)
    }

    /// The next `application_data` payload, at most `out.len()` bytes.
    /// `Ok(0)` is the end of the stream between two records.
    pub async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.payload_left > 0 {
                let take = self.payload_left.min(out.len());
                if self.ready() > 0 {
                    let take = take.min(self.ready());
                    let end = self.start + take;
                    out[..take].copy_from_slice(&self.buffered[self.start..end]);
                    self.consume(take);
                } else {
                    self.stream.read_exact(&mut out[..take]).await?;
                }
                self.payload_left -= take;
                return Ok(take);
            }
            let (kind, length) = match self.header().await {
                Ok(header) => header,
                // A closed stream is the end unless a record is half-read.
                Err(error) if self.ready() == 0 && error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(0);
                }
                Err(error) => return Err(error),
            };
            self.need(HEADER + length).await?;
            self.consume(HEADER);
            if kind == APPLICATION_DATA {
                self.payload_left = length;
            } else {
                self.consume(length);
            }
        }
    }
}

/// Write a payload as `application_data` records.
pub async fn write<T: AsyncWrite + Unpin>(stream: &mut T, payload: &[u8]) -> io::Result<()> {
    for record in payload.chunks(WRITE_RECORD) {
        let mut bytes = Vec::with_capacity(HEADER + record.len());
        bytes.extend_from_slice(&[APPLICATION_DATA, 3, 3]);
        bytes.extend_from_slice(&(record.len() as u16).to_be_bytes());
        bytes.extend_from_slice(record);
        stream.write_all(&bytes).await?;
    }
    Ok(())
}
