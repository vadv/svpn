//! The obfuscated stream between a Telegram client and its datacenter, as
//! the proxy sees it. Each side that opens a stream starts with a 64-byte
//! random frame that names the datacenter and carries the AES-CTR key and
//! IV of the other direction. The keys of a client's frame are mixed with
//! the proxy secret, so only a holder of the secret can talk to the proxy.

use aes::Aes256;
use ctr::{
    Ctr128BE,
    cipher::{KeyIvInit, StreamCipher},
};
use sha2::{Digest, Sha256};

/// AES-256-CTR with a 128-bit big-endian counter: the Telegram stream cipher.
pub type Cipher = Ctr128BE<Aes256>;

/// Length of the frame a side sends first.
pub const FRAME: usize = 64;
/// The padded intermediate transport, the only one the proxy serves.
pub const TAG: [u8; 4] = [0xdd; 4];
/// The datacenter a client asks for with zero.
pub const DEFAULT_DC: i16 = 2;

const KEY: usize = 32;
const IV: usize = 16;
const OFFSET_KEY: usize = 8;
const OFFSET_TAG: usize = 56;
const OFFSET_DC: usize = 60;

/// Both directions of one obfuscated stream.
pub struct Streams {
    /// Encrypts what the proxy sends to the other side.
    pub send: Cipher,
    /// Decrypts what the proxy receives from the other side.
    pub recv: Cipher,
}

/// The frame is not signed for this proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Foreign;

impl std::fmt::Display for Foreign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a frame of this proxy")
    }
}

impl std::error::Error for Foreign {}

/// `COUNT` bytes of a frame from `at`, in order or reversed.
fn part<const COUNT: usize>(frame: &[u8; FRAME], at: usize, reversed: bool) -> [u8; COUNT] {
    std::array::from_fn(|i| frame[at + if reversed { COUNT - 1 - i } else { i }])
}

/// The keys of a client's frame are the SHA-256 of the key and the secret.
fn mixed(key: [u8; KEY], secret: &[u8; 16]) -> [u8; KEY] {
    let mut hash = Sha256::new();
    hash.update(key);
    hash.update(secret);
    hash.finalize().into()
}

/// A frame must not start as an HTTP method, another transport or zeros:
/// the datacenter would take it for something else.
fn good_start(frame: &[u8; FRAME]) -> bool {
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

/// A new frame for a datacenter. A negative number asks for its media
/// counterpart. `random` fills the bytes that must be random.
pub fn frame(
    dc: i16,
    random: &mut impl FnMut(&mut [u8]) -> std::io::Result<()>,
) -> std::io::Result<[u8; FRAME]> {
    let mut frame = [0u8; FRAME];
    while !good_start(&frame) {
        random(&mut frame)?;
    }
    frame[OFFSET_TAG..OFFSET_TAG + TAG.len()].copy_from_slice(&TAG);
    frame[OFFSET_DC..OFFSET_DC + 2].copy_from_slice(&dc.to_le_bytes());
    Ok(frame)
}

/// The two ciphers a frame lays out with no regard to who holds them: the
/// one from the frame's own key and IV, and the one from the same 48 bytes
/// reversed. Whoever sent the frame encrypted with the first; whoever
/// received it answers with the second. `secret` is mixed into the keys
/// when there is one.
fn laid_out(frame: &[u8; FRAME], secret: Option<&[u8; 16]>) -> (Cipher, Cipher) {
    let key = part::<KEY>(frame, OFFSET_KEY, false);
    let iv = part::<IV>(frame, OFFSET_KEY + KEY, false);
    // Reversed, the 48 bytes split 16 bytes earlier: the IV comes first.
    let (reversed_key, reversed_iv) = (
        part::<KEY>(frame, OFFSET_KEY + KEY - IV, true),
        part::<IV>(frame, OFFSET_KEY, true),
    );
    let mix = |key: [u8; KEY]| match secret {
        Some(secret) => mixed(key, secret),
        None => key,
    };
    (
        Cipher::new((&mix(key)).into(), (&iv).into()),
        Cipher::new((&mix(reversed_key)).into(), (&reversed_iv).into()),
    )
}

/// Put a frame on the wire: encrypted, except the key and the IV the
/// receiver derives its ciphers from. The returned stream is the sender's,
/// already past the frame.
pub fn sent(frame: &[u8; FRAME]) -> ([u8; FRAME], Streams) {
    let (mut own, reversed) = laid_out(frame, None);
    let mut wire = *frame;
    own.apply_keystream(&mut wire);
    wire[OFFSET_KEY..OFFSET_TAG].copy_from_slice(&frame[OFFSET_KEY..OFFSET_TAG]);
    (
        wire,
        Streams {
            send: own,
            recv: reversed,
        },
    )
}

/// Read a client's frame: the datacenter it asks for and the receiver's
/// stream, already past the frame.
pub fn received(mut wire: [u8; FRAME], secret: &[u8; 16]) -> Result<(i16, Streams), Foreign> {
    let (mut own, reversed) = laid_out(&wire, Some(secret));
    own.apply_keystream(&mut wire);
    if part::<{ TAG.len() }>(&wire, OFFSET_TAG, false) != TAG {
        return Err(Foreign);
    }
    let dc = i16::from_le_bytes(part(&wire, OFFSET_DC, false));
    Ok((
        if dc == 0 { DEFAULT_DC } else { dc },
        Streams {
            recv: own,
            send: reversed,
        },
    ))
}
