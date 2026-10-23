use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit};
use anyhow::{Result, anyhow, ensure};
use zeroize::Zeroize;

pub const MAX_PLAINTEXT: usize = 1401;
const TAG_BYTES: usize = 16;
pub const MAX_PACKETS: u64 = 1 << 32;
// The AAD/nonce block margin is conservative; the OCB limit of 2^48 blocks is never reached.
pub const MAX_BLOCKS: u64 = 1 << 32;
const DIRECTION: u64 = 1 << 63;
/// A 4096-record window: the shared v2 channel tolerates more reordering
/// than the per-flow window of 128 from the first version.
pub const WINDOW: u64 = 4096;

#[derive(Debug)]
pub struct InvalidPacket(&'static str);

pub struct Cipher {
    cipher: Aes128Gcm,
    aad: [u8; 16],
    outgoing_direction: u64,
    pub next: u64,
    pub sent_blocks: u64,
    pub received_blocks: u64,
    replay: ReplayWindow,
}

#[derive(Debug)]
pub struct ReplayWindow {
    pub highest: Option<u64>,
    /// Age bitmap: bit 0 of word 0 is the freshest counter.
    pub seen: [u64; (WINDOW / 64) as usize],
}

impl std::fmt::Display for InvalidPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InvalidPacket {}

impl Cipher {
    pub fn new(key: [u8; 16], flow_id: u64, client: bool) -> Self {
        let mut aad = *b"SVPN0001\0\0\0\0\0\0\0\0";
        aad[8..].copy_from_slice(&flow_id.to_be_bytes());
        Self::with_aad(key, aad, client)
    }

    /// UDP v2: one key per channel epoch, the AAD binds records to the channel.
    pub fn new_channel(key: [u8; 16], channel_id: u64, client: bool) -> Self {
        let mut aad = *b"SVPNUDP2\0\0\0\0\0\0\0\0";
        aad[8..].copy_from_slice(&channel_id.to_be_bytes());
        Self::with_aad(key, aad, client)
    }

    fn with_aad(mut key: [u8; 16], aad: [u8; 16], client: bool) -> Self {
        let cipher = Aes128Gcm::new(key.as_ref().into());
        key.zeroize();
        Self {
            cipher,
            aad,
            outgoing_direction: if client { 0 } else { DIRECTION },
            next: 0,
            sent_blocks: 0,
            received_blocks: 0,
            replay: ReplayWindow::default(),
        }
    }

    pub fn seal(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        ensure!(plain.len() <= MAX_PLAINTEXT, "UDP plaintext too large");
        ensure!(self.next < MAX_PACKETS, "UDP key packet budget exhausted");
        let blocks = block_cost(plain.len());
        ensure!(
            self.sent_blocks + blocks <= MAX_BLOCKS,
            "UDP key block budget exhausted"
        );
        let sequence = self.outgoing_direction | self.next;
        // The nonce is consumed both on an encryption failure and on a failed UDP send.
        self.next += 1;
        self.sent_blocks += blocks;
        let mut packet = Vec::with_capacity(8 + plain.len() + TAG_BYTES);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(plain);
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce(sequence).into(), &self.aad, &mut packet[8..])
            .map_err(|_| anyhow!("UDP encryption failed"))?;
        packet.extend_from_slice(&tag);
        Ok(packet)
    }

    pub fn open(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            (8 + TAG_BYTES..=8 + MAX_PLAINTEXT + TAG_BYTES).contains(&packet.len()),
            InvalidPacket("invalid UDP length")
        );
        let sequence = u64::from_be_bytes(packet[..8].try_into()?);
        ensure!(
            sequence & DIRECTION != self.outgoing_direction,
            InvalidPacket("wrong UDP direction")
        );
        let counter = sequence & !DIRECTION;
        ensure!(
            counter < MAX_PACKETS && self.replay.allows(counter),
            InvalidPacket("replayed or expired UDP packet")
        );
        let end = packet.len() - TAG_BYTES;
        let blocks = block_cost(end - 8);
        ensure!(
            self.received_blocks + blocks <= MAX_BLOCKS,
            "UDP key block budget exhausted"
        );
        let (body, tag) = packet.split_at(end);
        let mut plain = body[8..].to_vec();
        self.cipher
            .decrypt_in_place_detached(
                &nonce(sequence).into(),
                &self.aad,
                &mut plain,
                // The length of `tag` is guaranteed by the packet.len() check above.
                tag.into(),
            )
            .map_err(|_| InvalidPacket("invalid UDP authentication"))?;
        self.replay.commit(counter);
        self.received_blocks += blocks;
        Ok(plain)
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            seen: [0; (WINDOW / 64) as usize],
        }
    }
}

impl ReplayWindow {
    pub fn allows(&self, counter: u64) -> bool {
        match self.highest {
            None => true,
            Some(highest) if counter > highest => true,
            Some(highest) => {
                let age = highest - counter;
                age < WINDOW && self.seen[(age / 64) as usize] & (1 << (age % 64)) == 0
            }
        }
    }

    pub fn commit(&mut self, counter: u64) {
        match self.highest {
            None => self.seen[0] = 1,
            Some(highest) if counter > highest => {
                let advance = counter - highest;
                if advance >= WINDOW {
                    self.seen = [0; (WINDOW / 64) as usize];
                    self.seen[0] = 1;
                } else {
                    Self::shift(&mut self.seen, advance as usize);
                    self.seen[0] |= 1;
                }
            }
            Some(highest) => {
                let age = (highest - counter) as usize;
                self.seen[age / 64] |= 1 << (age % 64);
            }
        }
        self.highest = Some(self.highest.map_or(counter, |highest| highest.max(counter)));
    }

    /// Shifts the bitmap `advance` positions toward higher ages.
    fn shift(seen: &mut [u64; 64], advance: usize) {
        let words = advance / 64;
        let bits = advance % 64;
        for index in (0..seen.len()).rev() {
            seen[index] = match index.checked_sub(words) {
                None => 0,
                Some(source) if bits == 0 => seen[source],
                Some(source) => {
                    let low = if source == 0 {
                        0
                    } else {
                        seen[source - 1] >> (64 - bits)
                    };
                    (seen[source] << bits) | low
                }
            };
        }
    }
}

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| anyhow!("OS randomness unavailable"))?;
    Ok(bytes)
}

fn nonce(sequence: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn block_cost(length: usize) -> u64 {
    length.div_ceil(16) as u64 + 2
}
