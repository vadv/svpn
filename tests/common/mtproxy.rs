//! A Telegram client as the proxy sees it, and the datacenter's end of the
//! stream. Both are written from the other side of the protocol, the way
//! Telegram Desktop writes them, so the proxy is checked against an
//! independent reading of the protocol.

// Some of the including test targets use part of the fixture.
#![allow(dead_code)]

use std::io;

use aes::Aes256;
use ctr::{
    Ctr128BE,
    cipher::{KeyIvInit, StreamCipher},
};
use hmac::{Hmac, KeyInit as _, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The secret of the clients' links.
pub const KEY: [u8; 16] = [0xab; 16];
pub const DOMAIN: &str = "www.example.com";
pub const FRAME: usize = 64;
/// The padded intermediate tag of a frame.
pub const TAG: [u8; 4] = [0xdd; 4];

type Cipher = Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// The secret of a link in hex: `ee`, the key and the domain.
pub fn secret_hex(key: [u8; 16], domain: &str) -> String {
    let bytes: Vec<u8> = std::iter::once(0xee)
        .chain(key)
        .chain(domain.bytes())
        .collect();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn random(bytes: &mut [u8]) {
    getrandom::fill(bytes).expect("OS randomness");
}

/// The first bytes of a frame must not read as anything but a frame.
pub fn good_start(frame: &[u8; FRAME]) -> bool {
    let word =
        |at: usize| u32::from_le_bytes([frame[at], frame[at + 1], frame[at + 2], frame[at + 3]]);
    const RESERVED: [u32; 6] = [
        u32::from_le_bytes(*b"HEAD"),
        u32::from_le_bytes(*b"POST"),
        u32::from_le_bytes(*b"GET "),
        0xeeeeeeee,
        0xdddddddd,
        0x02010316,
    ];
    frame[0] != 0xef && !RESERVED.contains(&word(0)) && word(4) != 0
}

/// The ClientHello a client sends: 517 bytes signed for the key, created
/// at `now`.
pub fn hello(key: &[u8; 16], domain: &str, now: u64) -> Vec<u8> {
    // record header, handshake header, version, random, session id length
    let mut hello = vec![
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03,
    ];
    hello.resize(hello.len() + 32, 0);
    hello.push(0x20);
    let mut session_id = [0u8; 32];
    random(&mut session_id);
    hello.extend_from_slice(&session_id);
    // 16 cipher suites after a GREASE one, 34 bytes in all.
    hello.extend_from_slice(&[0x00, 0x22, 0x0a, 0x0a]);
    hello.extend_from_slice(&[
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc,
        0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,
        0x01, 0x00,
    ]);
    hello.extend_from_slice(&[0x01, 0x00]); // one compression method: none
    let name = domain.as_bytes();
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x00]); // server_name
    let list = 3 + name.len();
    let before_extensions = hello.len();
    // The extension carries the list and its own length.
    extensions.extend_from_slice(&((list + 2) as u16).to_be_bytes());
    extensions.extend_from_slice(&(list as u16).to_be_bytes());
    extensions.push(0x00); // a host name
    extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
    extensions.extend_from_slice(name);
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // TLS 1.3
    // Padding brings the hello to 517 bytes: the extension list, its
    // length and the padding extension are all that is still added.
    let padding = 517 - before_extensions - extensions.len() - 6;
    assert!(padding > 0, "the domain is too long for a 517-byte hello");
    extensions.extend_from_slice(&[0x00, 0x15]);
    extensions.extend_from_slice(&(padding as u16).to_be_bytes());
    extensions.resize(extensions.len() + padding, 0);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);
    assert_eq!(hello.len(), 517);

    // random = HMAC(key, hello without random), the last 4 bytes XOR now.
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(&hello[..11]);
    mac.update(&[0; 32]);
    mac.update(&hello[43..]);
    let digest: [u8; 32] = mac.finalize().into_bytes().into();
    hello[11..43].copy_from_slice(&digest);
    for (byte, time) in hello[39..43].iter_mut().zip(now.to_le_bytes()) {
        *byte ^= time;
    }
    hello
}

/// Read the proxy's flight and check it the way the client does: the
/// ServerHello digest is the HMAC over the client random and the whole
/// flight with a zero digest.
pub async fn read_flight(
    stream: &mut (impl AsyncRead + Unpin),
    key: &[u8; 16],
    client_random: [u8; 32],
) -> io::Result<()> {
    let mut record = [0u8; 5];
    stream.read_exact(&mut record).await?;
    let mut flight = client_random.to_vec();
    flight.extend_from_slice(&record);
    let mut body = vec![0u8; u16::from_be_bytes([record[3], record[4]]) as usize];
    stream.read_exact(&mut body).await?;
    flight.extend_from_slice(&body);
    let mut rest = vec![0u8; 6 + 5];
    stream.read_exact(&mut rest).await?;
    let len = u16::from_be_bytes([rest[9], rest[10]]) as usize;
    let mut noise = vec![0u8; len];
    stream.read_exact(&mut noise).await?;
    flight.extend_from_slice(&rest);
    flight.extend_from_slice(&noise);
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(&flight[..43]);
    mac.update(&[0; 32]);
    mac.update(&flight[75..]);
    let digest: [u8; 32] = mac.finalize().into_bytes().into();
    if flight[43..75] != digest {
        return Err(io::Error::other(
            "the client refuses a flight it cannot check",
        ));
    }
    Ok(())
}

/// Write a payload in `application_data` records; `first` sends the
/// client's ChangeCipherSpec before them.
pub async fn send(
    stream: &mut (impl AsyncWrite + Unpin),
    first: bool,
    payload: &[u8],
) -> io::Result<()> {
    if first {
        stream
            .write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
            .await?;
    }
    for part in payload.chunks(2878) {
        let mut record = vec![0x17, 0x03, 0x03];
        record.extend_from_slice(&(part.len() as u16).to_be_bytes());
        record.extend_from_slice(part);
        stream.write_all(&record).await?;
    }
    Ok(())
}

/// One `application_data` record of the proxy; records of other types are
/// skipped. `None` at the end of the stream.
pub async fn receive(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 5];
    loop {
        if stream.read(&mut header[..1]).await? == 0 {
            return Ok(None);
        }
        stream.read_exact(&mut header[1..]).await?;
        assert_eq!(&header[1..3], &[3, 3], "a TLS record");
        let mut payload = vec![0u8; u16::from_be_bytes([header[3], header[4]]) as usize];
        stream.read_exact(&mut payload).await?;
        if header[0] == 0x17 {
            return Ok(Some(payload));
        }
    }
}

/// The client's side of the obfuscated stream.
pub struct Client {
    pub send: Cipher,
    pub recv: Cipher,
}

/// The keys of a frame's sender mixed with the secret.
fn mixed(bytes: &[u8], key: &[u8; 16]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(bytes);
    hash.update(key);
    hash.finalize().into()
}

/// `N` bytes of a slice from `at`, as an array.
fn at<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    bytes[at..at + N].try_into().unwrap()
}

fn cipher(key: [u8; 32], iv: [u8; 16]) -> Cipher {
    Cipher::new((&key).into(), (&iv).into())
}

/// The frame a client sends for a datacenter, and the stream under it: the
/// client encrypts with the frame's key and IV, the proxy answers with the
/// same 48 bytes reversed, both mixed with the secret.
pub fn frame(key: &[u8; 16], dc: i16) -> (Vec<u8>, Client) {
    let mut nonce = [0u8; FRAME];
    while !good_start(&nonce) {
        random(&mut nonce);
    }
    let mut reversed: Vec<u8> = nonce[8..56].to_vec();
    reversed.reverse();
    let mut send = cipher(mixed(&nonce[8..40], key), at(&nonce, 40));
    let recv = cipher(mixed(&reversed[..32], key), at(&reversed, 32));
    // Everything but the key and the IV goes encrypted.
    let mut wire = nonce;
    wire[56..60].copy_from_slice(&TAG);
    wire[60..62].copy_from_slice(&dc.to_le_bytes());
    send.apply_keystream(&mut wire);
    wire[8..56].copy_from_slice(&nonce[8..56]);
    (wire.to_vec(), Client { send, recv })
}

/// The datacenter's end of the proxy's frame: the datacenter asked for,
/// then the cipher of what comes from the proxy and the cipher of what goes
/// back to it. No secret is mixed in on this side.
pub fn datacenter(wire: [u8; FRAME]) -> (i16, Cipher, Cipher) {
    let mut reversed = wire[8..56].to_vec();
    reversed.reverse();
    let mut from_proxy = cipher(at(&wire, 8), at(&wire, 40));
    let to_proxy = cipher(at(&reversed, 0), at(&reversed, 32));
    // The tag and the datacenter travel encrypted, like everything but the
    // key and the IV.
    let mut plain = wire;
    from_proxy.apply_keystream(&mut plain);
    assert_eq!(plain[56..60], TAG, "the datacenter sees the transport tag");
    let dc = i16::from_le_bytes([plain[60], plain[61]]);
    (dc, from_proxy, to_proxy)
}
