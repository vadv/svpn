use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowKey {
    pub protocol: u8,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
}

impl FlowKey {
    pub fn valid_for(self, client_ip: Ipv4Addr) -> bool {
        self.source == client_ip
            && unicast(self.destination)
            && match self.protocol {
                6 | 17 => self.source_port != 0 && self.destination_port != 0,
                1 => self.destination_port == 0,
                _ => false,
            }
    }
}

pub struct Packet {
    pub flow: FlowKey,
    pub can_open: bool,
    /// RST flag of a complete TCP segment, never inferred from an ICMP quote.
    pub is_rst: bool,
    /// TCP FIN (without RST) is a graceful direction close signal.
    pub fin: bool,
    /// Full TCP header metadata; quoted TCP inside an ICMP error has none.
    pub tcp: Option<TcpMeta>,
}

/// Header metadata of a complete TCP packet (protocol 6, full header per
/// data offset). `ack` seeds the link-loss reset; `seq`/`flags`/`payload_len`
/// drive the CLOSED-endpoint response rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpMeta {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload_len: usize,
}

pub fn unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() && !ip.is_loopback()
}

pub fn parse(bytes: &[u8], from_client: bool) -> Option<Packet> {
    parse_ip(bytes, from_client, false)
}

/// Why a rejected packet is still expected noise: the local OS chatters on
/// the TUN (IPv6 RS/ND, IGMP, fragments) and none of it is a bug. `None` —
/// the packet is malformed and the drop stays an error.
pub fn unsupported(bytes: &[u8]) -> Option<String> {
    if bytes.first().is_some_and(|first| first >> 4 == 6) {
        return Some("IPv6 packet (not supported)".to_owned());
    }
    if bytes.len() >= 20 && bytes[0] >> 4 == 4 {
        let protocol = bytes[9];
        if !matches!(protocol, 1 | 6 | 17) {
            return Some(format!("unsupported IPv4 protocol {protocol}"));
        }
        if u16::from_be_bytes([bytes[6], bytes[7]]) & 0xbfff != 0 {
            return Some("fragmented IPv4 packet (not supported)".to_owned());
        }
    }
    None
}

fn parse_ip(bytes: &[u8], from_client: bool, quoted: bool) -> Option<Packet> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return None;
    }
    let header = usize::from(bytes[0] & 15) * 4;
    let total = usize::from(word(bytes, 2)?);
    if header < 20 || header > bytes.len() || total < header || (!quoted && total > bytes.len()) {
        return None;
    }
    // shortcut: drop IPv4 fragments; add bounded reassembly when fragmented traffic enters scope.
    if word(bytes, 6)? & 0xbfff != 0 {
        return None;
    }
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let protocol = bytes[9];
    let data = &bytes[header..total.min(bytes.len())];
    let mut tcp = None;
    let (mut source_port, mut destination_port, can_open, is_rst, fin) = match protocol {
        6 => {
            if data.len() < if quoted { 4 } else { 20 } {
                return None;
            }
            if !quoted {
                let tcp_header = usize::from(data[12] >> 4) * 4;
                if tcp_header < 20 || tcp_header > data.len() {
                    return None;
                }
                tcp = Some(TcpMeta {
                    seq: dword(data, 4)?,
                    ack: dword(data, 8)?,
                    flags: data[13],
                    payload_len: data.len() - tcp_header,
                });
            }
            (
                word(data, 0)?,
                word(data, 2)?,
                !quoted && data[13] & 0x17 == 0x02,
                !quoted && data[13] & 0x04 != 0,
                !quoted && data[13] & 0x01 != 0,
            )
        }
        17 => {
            if data.len() < 8 || (!quoted && usize::from(word(data, 4)?) != data.len()) {
                return None;
            }
            (word(data, 0)?, word(data, 2)?, !quoted, false, false)
        }
        1 => {
            if data.len() < 8 {
                return None;
            }
            match data[0] {
                0 | 8 if data[1] == 0 => (
                    word(data, 4)?,
                    0,
                    !quoted && from_client && data[0] == 8,
                    false,
                    false,
                ),
                3 | 11 | 12 if !quoted => {
                    let mut packet = parse_ip(&data[8..], !from_client, true)?;
                    packet.can_open = false;
                    packet.is_rst = false;
                    return Some(packet);
                }
                _ => return None,
            }
        }
        _ => return None,
    };
    let (source, destination) = if from_client {
        (source, destination)
    } else {
        if protocol != 1 {
            std::mem::swap(&mut source_port, &mut destination_port);
        }
        (destination, source)
    };
    Some(Packet {
        flow: FlowKey {
            protocol,
            source,
            destination,
            source_port,
            destination_port,
        },
        can_open,
        is_rst,
        fin,
        tcp,
    })
}

fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

pub fn dword(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// CLOSED-endpoint reset (RFC 9293 §3.10.7.1) mirroring `packet`'s tuple.
/// An incoming ACK is answered with `RST, seq = ack`; a segment without ACK
/// (SYN included) with `RST|ACK, seq = 0, ack = seq + payload_len + SYN + FIN`
/// (wrapping). A reset is never answered.
pub fn tcp_reset_for(packet: &Packet) -> Option<[u8; 40]> {
    let tcp = packet.tcp.as_ref()?;
    if tcp.flags & 0x04 != 0 {
        return None;
    }
    let (flags, seq, ack) = if tcp.flags & 0x10 != 0 {
        (0x04, tcp.ack, 0)
    } else {
        let length = tcp.payload_len as u32
            + u32::from(tcp.flags & 0x02 != 0)
            + u32::from(tcp.flags & 0x01 != 0);
        (0x14, 0, tcp.seq.wrapping_add(length))
    };
    Some(tcp_segment(reverse(packet.flow), flags, seq, ack))
}

/// Best-effort RST toward the client for a retired flow, seeded with the
/// last ACK the client kernel sent.
pub fn tcp_reset_seq(flow: FlowKey, seq: u32) -> [u8; 40] {
    tcp_segment(reverse(flow), 0x04, seq, 0)
}

/// Keepalive-style ACK-only probe one below `seq`: an idle client kernel
/// answers it with a fresh ACK, renewing the reset seed.
pub fn tcp_probe(flow: FlowKey, seq: u32) -> [u8; 40] {
    tcp_segment(reverse(flow), 0x10, seq, 0)
}

/// Swap a client→server tuple into its server→client reply direction.
fn reverse(flow: FlowKey) -> FlowKey {
    FlowKey {
        source: flow.destination,
        destination: flow.source,
        source_port: flow.destination_port,
        destination_port: flow.source_port,
        ..flow
    }
}

/// 40-byte IPv4+TCP segment without options: TTL 64, window 0, correct
/// IPv4-header and TCP pseudoheader checksums.
fn tcp_segment(flow: FlowKey, flags: u8, seq: u32, ack: u32) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&flow.source.octets());
    bytes[16..20].copy_from_slice(&flow.destination.octets());
    let mut header = [0u8; 20];
    header.copy_from_slice(&bytes[..20]);
    bytes[10..12].copy_from_slice(&internet_checksum(&header).to_be_bytes());
    bytes[20..22].copy_from_slice(&flow.source_port.to_be_bytes());
    bytes[22..24].copy_from_slice(&flow.destination_port.to_be_bytes());
    bytes[24..28].copy_from_slice(&seq.to_be_bytes());
    bytes[28..32].copy_from_slice(&ack.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = flags;
    let mut pseudo = [0u8; 32];
    pseudo[0..4].copy_from_slice(&flow.source.octets());
    pseudo[4..8].copy_from_slice(&flow.destination.octets());
    pseudo[8] = 0;
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
    pseudo[12..32].copy_from_slice(&bytes[20..40]); // TCP checksum field is still 0
    bytes[36..38].copy_from_slice(&internet_checksum(&pseudo).to_be_bytes());
    bytes
}

/// RFC 1071 internet checksum over an even-length buffer.
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair) as u32)
        .sum::<u32>();
    // RFC 1071: an odd trailing byte pads as the high half of the final pair.
    if bytes.len() % 2 == 1 {
        sum += u32::from(bytes[bytes.len() - 1]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// ICMP echo request toward the server's TUN address — the liveness probe
///: caller supplies a random payload and round-unique
/// id/seq; the server answers with the matching echo reply.
pub fn icmp_echo_request(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut bytes = vec![0u8; total];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&destination.octets());
    bytes[20] = 8;
    bytes[24..26].copy_from_slice(&id.to_be_bytes());
    bytes[26..28].copy_from_slice(&seq.to_be_bytes());
    bytes[28..].copy_from_slice(payload);
    let mut header = [0u8; 20];
    header.copy_from_slice(&bytes[..20]);
    bytes[10..12].copy_from_slice(&internet_checksum(&header).to_be_bytes());
    let icmp = internet_checksum(&bytes[20..]);
    bytes[22..24].copy_from_slice(&icmp.to_be_bytes());
    bytes
}

/// Whether `bytes` is the echo reply to our probe: echo reply type/code,
/// intact checksum, and the exact id/seq/payload we sent. The caller already
/// knows the packet arrived on the probe flow; this verifies the content.
pub fn icmp_echo_reply_matches(bytes: &[u8], id: u16, seq: u16, payload: &[u8]) -> bool {
    icmp_echo_reply_seq(bytes, id, payload) == Some(seq)
}

/// Like [`icmp_echo_reply_matches`], but the sequence number is unknown
/// upfront: the caller decides whether the returned sequence is ours.
pub fn icmp_echo_reply_seq(bytes: &[u8], id: u16, payload: &[u8]) -> Option<u16> {
    if bytes.len() < 28 || bytes[0] >> 4 != 4 {
        return None;
    }
    let header = usize::from(bytes[0] & 15) * 4;
    if header < 20 || bytes.len() < header + 8 || bytes[9] != 1 {
        return None;
    }
    if usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) != bytes.len() {
        return None;
    }
    let icmp = &bytes[header..];
    if icmp[0] != 0 || icmp[1] != 0 || !icmp_checksum_ok(icmp) {
        return None;
    }
    if icmp[4..6] != id.to_be_bytes() || icmp[8..] != *payload {
        return None;
    }
    Some(u16::from_be_bytes([icmp[6], icmp[7]]))
}

fn icmp_checksum_ok(icmp: &[u8]) -> bool {
    // A valid checksum is its own complement: summing with it in place yields 0.
    internet_checksum(icmp) == 0
}

/// Translate a fixed inner address at the local-exit boundary.
/// Updates IPv4, transport and ICMP-quote checksums without reassembly.
pub fn translate_v4(bytes: &[u8], from: Ipv4Addr, to: Ipv4Addr) -> Option<Vec<u8>> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(bytes[0] & 15) * 4;
    let total = usize::from(word(bytes, 2)?);
    if ihl < 20 || total < ihl || total > bytes.len() {
        return None;
    }
    let mut out = bytes.to_vec();
    let protocol = out[9];
    let mut deltas = Vec::new();
    for offset in [12usize, 16] {
        let address = Ipv4Addr::new(
            out[offset],
            out[offset + 1],
            out[offset + 2],
            out[offset + 3],
        );
        if address == from {
            out[offset..offset + 4].copy_from_slice(&to.octets());
            deltas.extend(address_deltas(from, to));
        }
    }
    if deltas.is_empty() && protocol != 1 {
        return Some(out);
    }
    // Only the first fragment carries a transport checksum field.
    if word(&out, 6)? & 0x1fff == 0 {
        match protocol {
            6 if !deltas.is_empty() && out.len() >= ihl + 20 => {
                let checksum = adjust_checksum(word(&out, ihl + 16)?, &deltas);
                out[ihl + 16..ihl + 18].copy_from_slice(&checksum.to_be_bytes());
            }
            17 if !deltas.is_empty() && out.len() >= ihl + 8 => {
                // Preserve an absent UDP checksum.
                let checksum = word(&out, ihl + 6)?;
                if checksum != 0 {
                    let mut adjusted = adjust_checksum(checksum, &deltas);
                    if adjusted == 0 {
                        adjusted = u16::MAX;
                    }
                    out[ihl + 6..ihl + 8].copy_from_slice(&adjusted.to_be_bytes());
                }
            }
            1 => translate_icmp_quote(&mut out, ihl, from, to),
            _ => {}
        }
    }
    out[10..12].fill(0);
    let header = internet_checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&header.to_be_bytes());
    Some(out)
}

/// Translate the datagram quoted by an ICMP error and its checksums.
fn translate_icmp_quote(out: &mut [u8], ihl: usize, from: Ipv4Addr, to: Ipv4Addr) {
    // These types quote the offending datagram.
    if ihl + 28 > out.len() || !matches!(out[ihl], 3 | 4 | 5 | 11 | 12) {
        return;
    }
    let quote = ihl + 8; // start of the quoted IPv4 header
    let mut deltas = Vec::new();
    for offset in [quote + 12, quote + 16] {
        let address = Ipv4Addr::new(
            out[offset],
            out[offset + 1],
            out[offset + 2],
            out[offset + 3],
        );
        if address == from {
            out[offset..offset + 4].copy_from_slice(&to.octets());
            deltas.extend(address_deltas(from, to));
        }
    }
    if deltas.is_empty() {
        return;
    }
    let embedded_old = u16::from_be_bytes([out[quote + 10], out[quote + 11]]);
    let embedded_new = adjust_checksum(embedded_old, &deltas);
    out[quote + 10..quote + 12].copy_from_slice(&embedded_new.to_be_bytes());
    deltas.push((embedded_old, embedded_new));

    let embedded_ihl = usize::from(out[quote] & 15) * 4;
    let embedded_offset = u16::from_be_bytes([out[quote + 6], out[quote + 7]]) & 0x1fff;
    let embedded_protocol = out[quote + 9];
    let checksum_at = match (embedded_protocol, embedded_offset) {
        (6, 0) => Some(16),
        (17, 0) => Some(6),
        _ => None,
    };
    if embedded_ihl >= 20
        && quote + embedded_ihl <= out.len()
        && let Some(checksum_at) = checksum_at
        && quote + embedded_ihl + checksum_at + 2 <= out.len()
    {
        let at = quote + embedded_ihl + checksum_at;
        let old = u16::from_be_bytes([out[at], out[at + 1]]);
        if embedded_protocol != 17 || old != 0 {
            let mut new = adjust_checksum(old, &deltas[..deltas.len() - 1]);
            if embedded_protocol == 17 && new == 0 {
                new = u16::MAX;
            }
            out[at..at + 2].copy_from_slice(&new.to_be_bytes());
            deltas.push((old, new));
        }
    }
    // Include every changed quoted field in the outer checksum.
    let outer = adjust_checksum(u16::from_be_bytes([out[ihl + 2], out[ihl + 3]]), &deltas);
    out[ihl + 2..ihl + 4].copy_from_slice(&outer.to_be_bytes());
}

/// Apply an RFC 1624 incremental checksum update.
fn adjust_checksum(checksum: u16, deltas: &[(u16, u16)]) -> u16 {
    let mut sum = u32::from(!checksum);
    for (old, new) in deltas {
        sum = sum.wrapping_add(u32::from(!old));
        sum = sum.wrapping_add(u32::from(*new));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn address_deltas(from: Ipv4Addr, to: Ipv4Addr) -> [(u16, u16); 2] {
    let (from, to) = (from.octets(), to.octets());
    [
        (
            u16::from_be_bytes([from[0], from[1]]),
            u16::from_be_bytes([to[0], to[1]]),
        ),
        (
            u16::from_be_bytes([from[2], from[3]]),
            u16::from_be_bytes([to[2], to[3]]),
        ),
    ]
}
