//! TCP-mode framing: layers L0/L1 (`[u32 BE len][payload]`, optional banner)
//! and L2 `Ssh` — the appearance of a plausible SSH session (EPIC-003 T06).
//! The payload is a UDP-mode cipher packet (`crypto::Cipher::seal`);
//! the binding frame carries the token before the first packet.

use std::collections::VecDeque;

use anyhow::{Context, Result, ensure};
use clap::ValueEnum;

use crate::crypto::Cipher;

/// Maximum frame payload: token 16 + seq 8 + packet ≤1401 + tag 16.
pub const MAX_PAYLOAD: usize = 16 + 8 + crate::crypto::MAX_PLAINTEXT + 16;
pub const TOKEN_BYTES: usize = 16;
/// Banner for layers L1/L2: a current OpenSSH version, family pattern (T02).
const BANNER: &[u8] = b"SSH-2.0-OpenSSH_9.9p2\r\n";
const MAX_BANNER: usize = 255 + 2;

// ==== L2: Camouflage::Ssh (EPIC-003 T06; requirements — the "Research T02" section) ====
// Appearance for the observer, not compatibility: a real SSH peer will not
// accept our kex. Before NEWKEYS the frames are plaintext BPP (RFC 4253),
// after — opaque blocks with no visible lengths, like OpenSSH AEAD ciphers
// (T02 §4). Each side's flow:
//   server: banner, KEXINIT | kex-reply(31), NEWKEYS, auth frames, data
//   client: banner, KEXINIT | binding(30),   NEWKEYS, auth frames, data

/// KEXINIT algorithm lists shared by both sides: the negotiation stays non-empty (T02 §2).
pub const KEX_LISTS: [&str; 10] = [
    "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256",
    "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-256",
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-256",
    "none",
    "none",
    "",
    "",
];
/// KEXINIT cookies of the sides: real SSH uses random ones, here they are deterministic.
pub const CLIENT_COOKIE_SEED: u8 = 0x31;
pub const SERVER_COOKIE_SEED: u8 = 0x77;
/// AEAD data frame header: `Cipher::seal` over the u32 length (seq 8 + ct 4 + tag 16).
const SSH_HEADER: usize = 8 + 4 + 16;
/// Binding BPP frame size limit: payload ≤ 16 + 1425 plus header and padding.
const SSH_BINDING_MAX: usize = 2048;

/// Camouflage level of the TCP flow.
#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum Camouflage {
    /// Binary flow with length frames.
    None,
    /// SSH banner exchange before the first frame.
    Banner,
    /// Plausible SSH session: banner, KEXINIT/kex/NEWKEYS, AEAD-appearance frames.
    Ssh,
}

/// L2 decoder step: a constant hello block of the other side, a binding frame, or data.
enum Step {
    Const(Vec<u8>),
    Binding,
    Data,
}

/// Incremental flow decoder: `push` feeds bytes, `next` yields ready
/// payloads. L2 data needs the flow cipher (it opens the frame header);
/// handshake and binding are parsed without it. Format errors are protocol errors.
pub struct Decoder {
    expect_banner: bool,
    ssh: Option<VecDeque<Step>>,
    /// L2 frame length with the header already opened: the cipher seq is spent once
    /// while the rest of the frame arrives into the buffer.
    pub pending_len: Option<usize>,
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new(camouflage: Camouflage) -> Self {
        Self {
            expect_banner: camouflage == Camouflage::Banner,
            ssh: None,
            pending_len: None,
            buf: Vec::new(),
        }
    }

    /// L2 decoder. `peer_is_client` — expect the client hello (banner, KEXINIT,
    /// binding, NEWKEYS, auth frames); otherwise the whole server hello is one constant block.
    pub fn new_ssh(peer_is_client: bool) -> Self {
        let steps = if peer_is_client {
            vec![
                Step::Const(kexinit(CLIENT_COOKIE_SEED)),
                Step::Binding,
                Step::Const(ssh_client_tail()),
                Step::Data,
            ]
        } else {
            let mut hello = kexinit(SERVER_COOKIE_SEED);
            hello.extend(ssh_server_tail());
            vec![Step::Const(hello), Step::Data]
        };
        Self {
            expect_banner: true,
            ssh: Some(steps.into()),
            pending_len: None,
            buf: Vec::new(),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// EOF is clean only between complete frames, after the handshake.
    pub fn finish(&self) -> Result<()> {
        ensure!(
            !self.expect_banner
                && self.buf.is_empty()
                && self.pending_len.is_none()
                && self.ssh.as_ref().is_none_or(|steps| {
                    steps.len() == 1 && matches!(steps.front(), Some(Step::Data))
                }),
            "TCP stream ended inside a frame or handshake"
        );
        Ok(())
    }

    /// The next ready payload, or `None` when more bytes are needed.
    pub fn next(&mut self, cipher: Option<&mut Cipher>) -> Result<Option<Vec<u8>>> {
        if self.expect_banner && !self.take_banner()? {
            return Ok(None);
        }
        loop {
            let Some(step) = self.ssh.as_ref().and_then(|steps| steps.front()) else {
                return self.take_frame();
            };
            match step {
                Step::Const(expected) => {
                    if !Self::take_const(expected, &mut self.buf)? {
                        return Ok(None);
                    }
                    self.advance();
                }
                Step::Binding => {
                    // The step lives until the frame is fully collected: TCP may split
                    // the binding across segments, and Ok(None) means "too few bytes", not an error.
                    let Some(payload) = self.take_binding()? else {
                        return Ok(None);
                    };
                    self.advance();
                    return Ok(Some(payload));
                }
                // Terminal step: all further frames are AEAD-appearance data.
                Step::Data => {
                    let cipher = cipher.context("SSH data frame requires the flow key")?;
                    return self.take_data(cipher);
                }
            }
        }
    }

    fn advance(&mut self) {
        if let Some(steps) = &mut self.ssh {
            steps.pop_front();
        }
    }

    /// L0/L1 length frame.
    fn take_frame(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes(self.buf[..4].try_into()?) as usize;
        ensure!(len <= MAX_PAYLOAD, "TCP frame too large");
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let payload = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        Ok(Some(payload))
    }

    /// Consumes the constant hello block; `false` — not enough bytes yet.
    pub fn take_const(expected: &[u8], buf: &mut Vec<u8>) -> Result<bool> {
        if buf.len() < expected.len() {
            ensure!(expected.starts_with(&buf[..]), "malformed SSH handshake");
            return Ok(false);
        }
        ensure!(buf.starts_with(expected), "malformed SSH handshake");
        buf.drain(..expected.len());
        Ok(true)
    }

    /// L2 binding frame: BPP msg 30 with the token and cipher packet inside.
    fn take_binding(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < 6 {
            return Ok(None);
        }
        let packet_length = u32::from_be_bytes(self.buf[..4].try_into()?) as usize;
        let padding = self.buf[4] as usize;
        ensure!(packet_length <= SSH_BINDING_MAX, "TCP frame too large");
        ensure!(
            padding >= 4 && packet_length > padding + TOKEN_BYTES + 6 && self.buf[5] == 30,
            "malformed TCP binding frame"
        );
        if self.buf.len() < 4 + packet_length {
            return Ok(None);
        }
        let payload_end = 4 + packet_length - padding;
        let payload = self.buf[6..payload_end].to_vec();
        self.buf.drain(..4 + packet_length);
        Ok(Some(payload))
    }

    /// L2 data frame: the header is opened with the cipher once, the length is cached
    /// until the block is fully loaded; then the sealed packet block is handed over whole.
    fn take_data(&mut self, cipher: &mut Cipher) -> Result<Option<Vec<u8>>> {
        let len = match self.pending_len {
            Some(len) => len,
            None => {
                if self.buf.len() < SSH_HEADER {
                    return Ok(None);
                }
                let length = cipher
                    .open(&self.buf[..SSH_HEADER])
                    .context("SSH frame header authentication failed")?;
                let len = u32::from_be_bytes(length.as_slice().try_into()?) as usize;
                ensure!(len <= MAX_PAYLOAD, "TCP frame too large");
                self.pending_len = Some(len);
                len
            }
        };
        if self.buf.len() < SSH_HEADER + len {
            return Ok(None);
        }
        let payload = self.buf[SSH_HEADER..SSH_HEADER + len].to_vec();
        self.buf.drain(..SSH_HEADER + len);
        self.pending_len = None;
        Ok(Some(payload))
    }

    /// Consumes the banner line; `false` — not enough bytes yet.
    fn take_banner(&mut self) -> Result<bool> {
        let Some(end) = self.buf.iter().position(|&b| b == b'\n') else {
            ensure!(self.buf.len() <= MAX_BANNER, "TCP banner too long");
            return Ok(false);
        };
        let line = self.buf[..=end].to_vec();
        self.buf.drain(..=end);
        ensure!(line.ends_with(b"\r\n"), "malformed TCP banner");
        let text = &line[..line.len() - 2];
        ensure!(text.starts_with(b"SSH-"), "TCP banner is not SSH");
        ensure!(text.is_ascii(), "TCP banner is not ASCII");
        self.expect_banner = false;
        Ok(true)
    }
}

/// Banner our side sends to the other side under `Camouflage::Banner`.
pub fn banner() -> &'static [u8] {
    BANNER
}

/// Frame with a payload (data or binding).
pub fn frame(payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(payload.len() <= MAX_PAYLOAD, "TCP frame payload too large");
    let mut bytes = Vec::with_capacity(4 + payload.len());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Binding frame payload: token + first cipher packet.
pub fn binding_payload(token: &[u8; TOKEN_BYTES], packet: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(TOKEN_BYTES + packet.len());
    payload.extend_from_slice(token);
    payload.extend_from_slice(packet);
    payload
}

/// Split the first connection frame's payload into token and cipher packet.
pub fn split_binding(payload: &[u8]) -> Result<(&[u8], &[u8])> {
    ensure!(payload.len() > TOKEN_BYTES, "empty TCP binding frame");
    Ok(payload.split_at(TOKEN_BYTES))
}

/// RFC 4253 BPP frame: [u32 packet_length][u8 padding_length][payload][padding];
/// packet_length excludes itself, padding ≥ 4, frame length is a multiple of 8 and ≥ 16.
/// `payload` starts with the msg byte of an SSH message.
pub fn bpp(payload: &[u8]) -> Vec<u8> {
    let mut padding = 4;
    while !(5 + payload.len() + padding).is_multiple_of(8) {
        padding += 1;
    }
    let mut frame = Vec::with_capacity(5 + payload.len() + padding);
    frame.extend_from_slice(&((1 + payload.len() + padding) as u32).to_be_bytes());
    frame.push(padding as u8);
    frame.extend_from_slice(payload);
    frame.extend(noise(padding, payload[0]));
    frame
}

/// KEXINIT (msg 20): cookie, 10 name-list, first_kex_packet_follows=0, reserved=0.
pub fn kexinit(cookie_seed: u8) -> Vec<u8> {
    let mut payload = vec![20];
    payload.extend(noise(16, cookie_seed));
    for list in KEX_LISTS {
        payload.extend_from_slice(&(list.len() as u32).to_be_bytes());
        payload.extend_from_slice(list.as_bytes());
    }
    payload.push(0);
    payload.extend_from_slice(&0u32.to_be_bytes());
    bpp(&payload)
}

/// Kex-reply (msg 31) of plausible size: Q_S 32 B + signature 64 B (T02 §3).
pub fn kex_reply() -> Vec<u8> {
    let mut payload = vec![31, 0, 0, 0, 32];
    payload.extend(noise(32, 41));
    payload.extend_from_slice(&64u32.to_be_bytes());
    payload.extend(noise(64, 43));
    bpp(&payload)
}

pub fn newkeys() -> Vec<u8> {
    bpp(&[21])
}

/// Small opaque frames after NEWKEYS — the auth exchange appearance (T02 §5):
/// the server's lengths 60 and 44 preserve the relation `len + 16 == service_accept_size`
/// by which Zeek detects USERAUTH_SUCCESS; the blocks cannot be parsed.
pub fn auth_frames(large_seed: u8, small_seed: u8, large: usize) -> Vec<u8> {
    let mut bytes = noise(large, large_seed);
    bytes.extend(noise(large - 16, small_seed));
    bytes
}

/// Server flow on accept: banner + KEXINIT (T02 §1–2).
pub fn ssh_server_hello() -> Vec<u8> {
    let mut bytes = BANNER.to_vec();
    bytes.extend(kexinit(SERVER_COOKIE_SEED));
    bytes
}

/// Server flow after binding: kex-reply, NEWKEYS, auth frames — "kex complete".
pub fn ssh_server_tail() -> Vec<u8> {
    let mut bytes = kex_reply();
    bytes.extend(newkeys());
    bytes.extend(auth_frames(0x61, 0x62, 60));
    bytes
}

/// Client flow on connect: banner + KEXINIT.
pub fn ssh_client_hello() -> Vec<u8> {
    let mut bytes = BANNER.to_vec();
    bytes.extend(kexinit(CLIENT_COOKIE_SEED));
    bytes
}

/// Client flow after the binding frame: NEWKEYS + auth frames.
pub fn ssh_client_tail() -> Vec<u8> {
    let mut bytes = newkeys();
    bytes.extend(auth_frames(0x71, 0x72, 52));
    bytes
}

/// L2 binding frame: BPP frame msg 30 (kex packet appearance) with the token and packet inside.
pub fn ssh_binding_frame(token: &[u8; TOKEN_BYTES], sealed: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        sealed.len() <= 8 + crate::crypto::MAX_PLAINTEXT + 16,
        "TCP frame payload too large"
    );
    let mut payload = vec![30];
    payload.extend_from_slice(token);
    payload.extend_from_slice(sealed);
    Ok(bpp(&payload))
}

/// L2 data frame — AEAD appearance (T02 §4): [seal(u32 block length)][sealed
/// packet]. Fixed-size header; the receiver opens it with the same flow
/// cipher; no new crypto primitives.
pub fn ssh_frame(cipher: &mut Cipher, payload: &[u8]) -> Result<Vec<u8>> {
    let sealed_len = (payload.len() + 8 + 16) as u32;
    let mut frame = cipher.seal(&sealed_len.to_be_bytes())?;
    frame.extend_from_slice(&cipher.seal(payload)?);
    Ok(frame)
}

/// Deterministic pseudonoise: cookie, padding, and kex/auth appearance bytes.
/// shortcut: appearance bytes repeat from session to session — an observer with
/// session history will notice the match; randomize if the T07 field check catches it.
fn noise(len: usize, seed: u8) -> Vec<u8> {
    let mut state = u16::from(seed);
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(251).wrapping_add(13);
            (state >> 8) as u8
        })
        .collect()
}
