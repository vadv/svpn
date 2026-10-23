//! Shared datagram records, authenticated channels and bounded reassembly.

use std::{
    collections::{HashMap, hash_map::Entry},
    net::SocketAddr,
    time::{Duration, Instant},
};

use anyhow::{Result, bail, ensure};

use crate::crypto::{self, Cipher, MAX_PLAINTEXT};

pub const KIND_DATA: u8 = 0x01;
pub const KIND_PROBE_A: u8 = 0x02;
pub const KIND_PROBE_AB: u8 = 0x03;
pub const KIND_PROBE_B: u8 = 0x04;
pub const KIND_FLOW_PROBE: u8 = 0x05;
pub const KIND_FLOW_ECHO: u8 = 0x06;
pub const KIND_KEEPALIVE: u8 = 0x07;
pub const KIND_SIZE_PROBE: u8 = 0x08;

/// Bounds of a complete inner IPv4 packet: the minimum is header + ICMP,
/// the maximum is the channel limit.
pub const MIN_PACKET: usize = 28;
pub const MAX_PACKET: usize = 1400;
pub const DATA_HEADER: usize = 29;
pub const MAX_FRAGMENT: usize = MAX_PLAINTEXT - DATA_HEADER;
/// Per-channel reassembly limits: incomplete packets, bytes and TTL.
pub const MAX_PENDING_PACKETS: usize = 64;
pub const MAX_PENDING_BYTES: usize = 1024 * 1024;
pub const PENDING_TTL: Duration = Duration::from_secs(1);

const CHALLENGE: usize = 16;

/// Plaintext record. Channel-wide kinds use `flow_id = 0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Data {
        flow_id: u64,
        generation: u64,
        packet_id: u64,
        offset: u16,
        total_len: u16,
        fragment: Vec<u8>,
    },
    ProbeA {
        challenge: [u8; CHALLENGE],
    },
    ProbeAb {
        echo: [u8; CHALLENGE],
        challenge: [u8; CHALLENGE],
    },
    ProbeB {
        echo: [u8; CHALLENGE],
    },
    FlowProbe {
        flow_id: u64,
        generation: u64,
        challenge: [u8; CHALLENGE],
    },
    FlowEcho {
        flow_id: u64,
        generation: u64,
        echo: [u8; CHALLENGE],
    },
    Keepalive,
    SizeProbe {
        padding: Vec<u8>,
    },
}

impl Record {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut plain = Vec::with_capacity(MAX_PLAINTEXT);
        match self {
            Record::Data {
                flow_id,
                generation,
                packet_id,
                offset,
                total_len,
                fragment,
            } => {
                ensure!(!fragment.is_empty(), "empty fragment");
                ensure!(fragment.len() <= MAX_FRAGMENT, "fragment too large");
                ensure!(
                    *offset as usize + fragment.len() <= *total_len as usize,
                    "fragment exceeds total_len"
                );
                ensure!(
                    (1..=MAX_PACKET).contains(&(*total_len as usize)),
                    "total_len out of range"
                );
                ensure!(*generation != 0, "zero binding generation");
                plain.push(KIND_DATA);
                plain.extend_from_slice(&flow_id.to_be_bytes());
                plain.extend_from_slice(&generation.to_be_bytes());
                plain.extend_from_slice(&packet_id.to_be_bytes());
                plain.extend_from_slice(&offset.to_be_bytes());
                plain.extend_from_slice(&total_len.to_be_bytes());
                plain.extend_from_slice(fragment);
            }
            Record::ProbeA { challenge } => {
                plain.push(KIND_PROBE_A);
                plain.extend_from_slice(&[0; 8]);
                plain.extend_from_slice(challenge);
            }
            Record::ProbeAb { echo, challenge } => {
                plain.push(KIND_PROBE_AB);
                plain.extend_from_slice(&[0; 8]);
                plain.extend_from_slice(echo);
                plain.extend_from_slice(challenge);
            }
            Record::ProbeB { echo } => {
                plain.push(KIND_PROBE_B);
                plain.extend_from_slice(&[0; 8]);
                plain.extend_from_slice(echo);
            }
            Record::FlowProbe {
                flow_id,
                generation,
                challenge,
            } => {
                ensure!(*generation != 0, "zero binding generation");
                plain.push(KIND_FLOW_PROBE);
                plain.extend_from_slice(&flow_id.to_be_bytes());
                plain.extend_from_slice(&generation.to_be_bytes());
                plain.extend_from_slice(challenge);
            }
            Record::FlowEcho {
                flow_id,
                generation,
                echo,
            } => {
                ensure!(*generation != 0, "zero binding generation");
                plain.push(KIND_FLOW_ECHO);
                plain.extend_from_slice(&flow_id.to_be_bytes());
                plain.extend_from_slice(&generation.to_be_bytes());
                plain.extend_from_slice(echo);
            }
            Record::Keepalive => {
                plain.push(KIND_KEEPALIVE);
                plain.extend_from_slice(&[0; 8]);
            }
            Record::SizeProbe { padding } => {
                ensure!(padding.len() <= MAX_PLAINTEXT - 9, "size probe too large");
                plain.push(KIND_SIZE_PROBE);
                plain.extend_from_slice(&[0; 8]);
                plain.extend_from_slice(padding);
            }
        }
        ensure!(plain.len() <= MAX_PLAINTEXT, "record exceeds MAX_PLAINTEXT");
        ensure!(
            !matches!(
                self,
                Record::Data { flow_id: 0, .. }
                    | Record::FlowProbe { flow_id: 0, .. }
                    | Record::FlowEcho { flow_id: 0, .. }
            ),
            "flow_id 0 is reserved for channel records"
        );
        Ok(plain)
    }

    pub fn decode(plain: &[u8]) -> Result<Self> {
        let (&kind, rest) = plain
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("short record"))?;
        ensure!(rest.len() >= 8, "short record");
        let (flow_id, body) = rest.split_at(8);
        let flow_id = u64::from_be_bytes(flow_id.try_into()?);
        ensure!(
            flow_id == 0 || kind == KIND_DATA || kind == KIND_FLOW_PROBE || kind == KIND_FLOW_ECHO,
            "channel record must use flow_id 0"
        );
        ensure!(
            flow_id != 0 || kind != KIND_DATA && kind != KIND_FLOW_PROBE && kind != KIND_FLOW_ECHO,
            "flow record must use nonzero flow_id"
        );
        let (generation, body) = if matches!(kind, KIND_DATA | KIND_FLOW_PROBE | KIND_FLOW_ECHO) {
            ensure!(body.len() >= 8, "short binding generation");
            let (generation, body) = body.split_at(8);
            let generation = u64::from_be_bytes(generation.try_into()?);
            ensure!(generation != 0, "zero binding generation");
            (generation, body)
        } else {
            (0, body)
        };
        let record = match kind {
            KIND_DATA => {
                ensure!(body.len() >= 13, "short DATA record");
                let (packet_id, tail) = body.split_at(8);
                let (offset, tail) = tail.split_at(2);
                let (total_len, fragment) = tail.split_at(2);
                let record = Record::Data {
                    flow_id,
                    generation,
                    packet_id: u64::from_be_bytes(packet_id.try_into()?),
                    offset: u16::from_be_bytes(offset.try_into()?),
                    total_len: u16::from_be_bytes(total_len.try_into()?),
                    fragment: fragment.to_vec(),
                };
                // Repeat the structural checks so decode validates itself.
                record.encode()?;
                record
            }
            KIND_PROBE_A => Record::ProbeA {
                challenge: body.try_into()?,
            },
            KIND_PROBE_AB => {
                ensure!(body.len() == 2 * CHALLENGE, "short PROBE_AB record");
                let (echo, challenge) = body.split_at(CHALLENGE);
                Record::ProbeAb {
                    echo: echo.try_into()?,
                    challenge: challenge.try_into()?,
                }
            }
            KIND_PROBE_B => Record::ProbeB {
                echo: body.try_into()?,
            },
            KIND_FLOW_PROBE => Record::FlowProbe {
                flow_id,
                generation,
                challenge: body.try_into()?,
            },
            KIND_FLOW_ECHO => Record::FlowEcho {
                flow_id,
                generation,
                echo: body.try_into()?,
            },
            KIND_KEEPALIVE if body.is_empty() => Record::Keepalive,
            KIND_SIZE_PROBE => Record::SizeProbe {
                padding: body.to_vec(),
            },
            other => bail!("unknown record kind {other:#x}"),
        };
        Ok(record)
    }
}

/// Fragments from different bindings must never assemble into the same packet.
#[derive(Default)]
pub struct Reassembly {
    packets: HashMap<(u64, u64, u64), Partial>,
    bytes: usize,
}

struct Partial {
    total_len: u16,
    parts: Vec<(u16, Vec<u8>)>,
    have: usize,
    since: Instant,
}

impl Reassembly {
    /// Inserts a fragment; `Some(packet)` means the packet is fully reassembled.
    /// A duplicate of identical bytes is ignored; conflicting data
    /// or exceeding the limits drops the whole packet of this `packet_id`
    /// without affecting the others.
    pub fn insert(&mut self, record: &Record, now: Instant) -> Result<Option<Vec<u8>>> {
        let Record::Data {
            flow_id,
            generation,
            packet_id,
            offset,
            total_len,
            fragment,
        } = record
        else {
            bail!("reassembly accepts only DATA records");
        };
        let key = (*flow_id, *generation, *packet_id);
        let at_limit = self.packets.len() >= MAX_PENDING_PACKETS || self.bytes >= MAX_PENDING_BYTES;
        let packet = match self.packets.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                if at_limit {
                    // Limit exhausted: the new packet is lost, the channel stays alive.
                    return Ok(None);
                }
                self.bytes += 9;
                entry.insert(Partial {
                    total_len: *total_len,
                    parts: Vec::with_capacity(4),
                    have: 0,
                    since: now,
                })
            }
        };
        let start = *offset as usize;
        let end = start + fragment.len();
        // Conflicting data drops the whole packet but does not take down the channel:
        // a hostile fragment must not break reassembly of neighboring flows.
        if packet.total_len != *total_len || end > packet.total_len as usize {
            self.discard(key);
            return Ok(None);
        }
        let position = packet.parts.partition_point(|(at, _)| *at < *offset);
        if let Some((at, bytes)) = packet.parts.get(position) {
            let at = *at as usize;
            if at == start {
                if *bytes == *fragment {
                    return Ok(None); // exact duplicate
                }
                self.discard(key);
                return Ok(None); // offset conflict
            }
            if at < end {
                self.discard(key);
                return Ok(None); // forward overlap
            }
        }
        if position > 0 {
            let (at, prev) = &packet.parts[position - 1];
            if *at as usize + prev.len() > start {
                self.discard(key);
                return Ok(None); // backward overlap
            }
        }
        packet.have += fragment.len();
        self.bytes += fragment.len();
        packet.parts.insert(position, (*offset, fragment.clone()));
        packet.since = now;
        let total_len = packet.total_len;
        if packet.have < usize::from(total_len) {
            if self.bytes > MAX_PENDING_BYTES {
                self.discard(key);
            }
            return Ok(None);
        }
        // Full coverage: the parts are sorted and non-overlapping.
        let mut assembled = Vec::with_capacity(usize::from(total_len));
        for (at, bytes) in &packet.parts {
            assembled.extend_from_slice(bytes);
            debug_assert_eq!(*at as usize, assembled.len() - bytes.len());
        }
        self.bytes -= 9 + packet.have;
        self.packets.remove(&key);
        ensure!(assembled.len() == total_len as usize, "coverage gap");
        Ok(Some(assembled))
    }

    fn discard(&mut self, key: (u64, u64, u64)) {
        if let Some(packet) = self.packets.remove(&key) {
            self.bytes -= 9 + packet.have;
        }
    }

    /// Removes expired incomplete packets; called while processing records.
    pub fn expire(&mut self, now: Instant) {
        let before = self.bytes;
        self.packets.retain(|_, packet| {
            if now.duration_since(packet.since) > PENDING_TTL {
                self.bytes -= 9 + packet.have;
                false
            } else {
                true
            }
        });
        debug_assert!(self.bytes <= before);
    }

    pub fn pending(&self) -> usize {
        self.packets.len()
    }
}

/// One channel endpoint: record encryption and incoming fragment reassembly.
/// A single `Cipher` covers both directions (the sequence direction bit).
pub struct Channel {
    cipher: Cipher,
    reassembly: Reassembly,
}

impl Channel {
    pub fn new(key: [u8; 16], channel_id: u64, client: bool) -> Self {
        Self {
            cipher: Cipher::new_channel(key, channel_id, client),
            reassembly: Reassembly::default(),
        }
    }

    pub fn seal(&mut self, record: &Record) -> Result<Vec<u8>> {
        let plain = record.encode()?;
        self.cipher.seal(&plain)
    }

    pub fn open(&mut self, wire: &[u8], now: Instant) -> Result<Option<Record>> {
        let plain = match self.cipher.open(wire) {
            Ok(plain) => plain,
            Err(error) if error.is::<crypto::InvalidPacket>() => return Ok(None),
            Err(error) => return Err(error),
        };
        self.reassembly.expire(now);
        Ok(Some(Record::decode(&plain)?))
    }

    /// Runs a DATA record through reassembly; `Some` is a complete inner packet.
    pub fn assemble(&mut self, record: &Record, now: Instant) -> Result<Option<Vec<u8>>> {
        self.reassembly.insert(record, now)
    }

    pub fn reassembly(&self) -> &Reassembly {
        &self.reassembly
    }
}

/// Splits an inner IP packet into DATA records with the fragment size cap `chunk_cap`.
pub fn fragment_packet(
    flow_id: u64,
    generation: u64,
    packet_id: u64,
    packet: &[u8],
    chunk_cap: usize,
) -> Result<Vec<Record>> {
    ensure!(
        (MIN_PACKET..=MAX_PACKET).contains(&packet.len()),
        "inner packet out of range"
    );
    ensure!(chunk_cap >= 512, "chunk cap too small for MTU profile");
    let cap = chunk_cap.min(MAX_FRAGMENT);
    let mut records = Vec::with_capacity(3);
    for (index, chunk) in packet.chunks(cap).enumerate() {
        records.push(Record::Data {
            flow_id,
            generation,
            packet_id,
            offset: (index * cap) as u16,
            total_len: packet.len() as u16,
            fragment: chunk.to_vec(),
        });
    }
    Ok(records)
}

/// A fresh 128-bit challenge for channel/flow probes.
pub fn challenge() -> Result<[u8; CHALLENGE]> {
    crypto::random()
}

/// Sends a record to the channel socket; the destination address is the single peer.
pub async fn send_record(
    socket: &tokio::net::UdpSocket,
    peer: SocketAddr,
    channel: &mut Channel,
    record: &Record,
) -> Result<()> {
    let wire = channel.seal(record)?;
    socket.send_to(&wire, peer).await?;
    Ok(())
}

/// Reads one record from the socket; returns the sender and the record.
pub async fn recv_record(
    socket: &tokio::net::UdpSocket,
    channel: &mut Channel,
    now: Instant,
) -> Result<(SocketAddr, Record)> {
    let mut buffer = vec![0u8; MAX_PLAINTEXT + 24];
    loop {
        let (size, peer) = socket.recv_from(&mut buffer).await?;
        if let Some(record) = channel.open(&buffer[..size], now)? {
            return Ok((peer, record));
        }
    }
}
