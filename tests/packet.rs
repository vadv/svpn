//! Packet: flow parsing, validation, TCP metadata and resets, ICMP probes.

mod common;

use std::net::Ipv4Addr;

use common::{echo_reply, udp_packet};
use svpn::packet::*;

/// Complete client TCP packet: client 10.77.0.2:40000 → server 10.77.0.1:9000.
fn full_tcp(flags: u8, seq: u32, ack: u32, payload_len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; 40 + payload_len];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(40 + payload_len as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&[10, 77, 0, 2]);
    bytes[16..20].copy_from_slice(&[10, 77, 0, 1]);
    bytes[20..22].copy_from_slice(&40000u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&9000u16.to_be_bytes());
    bytes[24..28].copy_from_slice(&seq.to_be_bytes());
    bytes[28..32].copy_from_slice(&ack.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = flags;
    bytes
}

// ── flow parsing ──

#[test]
fn matches_both_directions() {
    let outgoing = parse(&udp_packet(false), true).unwrap();
    let incoming = parse(&udp_packet(true), false).unwrap();
    assert_eq!(outgoing.flow, incoming.flow);
    assert!(outgoing.can_open);
    assert!(outgoing.flow.valid_for(Ipv4Addr::new(10, 77, 0, 2)));
}

#[test]
fn associates_icmp_error_with_quoted_flow() {
    let original = udp_packet(false);
    let mut error = udp_packet(true);
    error[9] = 1;
    error[20..28].fill(0);
    error[20] = 3;
    error[21] = 4;
    error.extend_from_slice(&original);
    let length = error.len() as u16;
    error[2..4].copy_from_slice(&length.to_be_bytes());
    let packet = parse(&error, false).unwrap();
    assert_eq!(packet.flow, parse(&original, true).unwrap().flow);
    assert!(!packet.can_open);
}

#[test]
fn echo_identifier_survives_reverse_direction() {
    let mut request = udp_packet(false);
    request[9] = 1;
    request[20..28].fill(0);
    request[20] = 8;
    request[24..26].copy_from_slice(&123u16.to_be_bytes());
    let mut reply = request.clone();
    reply[12..16].copy_from_slice(&request[16..20]);
    reply[16..20].copy_from_slice(&request[12..16]);
    reply[20] = 0;
    assert_eq!(
        parse(&request, true).unwrap().flow,
        parse(&reply, false).unwrap().flow
    );
}

// ── validation ──

#[test]
fn accepts_trailing_padding_beyond_total_length() {
    // Real-world case: Linux forwards frames with ethernet padding; TCP ACKs
    // built on those buffers keep the zero tail while total length stays 40.
    let mut bytes = vec![0u8; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&[10, 77, 0, 2]);
    bytes[16..20].copy_from_slice(&[140, 82, 121, 9]);
    bytes[20..22].copy_from_slice(&54780u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    bytes.extend_from_slice(&[0u8; 6]);
    let parsed = parse(&bytes, true).unwrap();
    assert_eq!(parsed.flow.destination_port, 443);
    assert!(!parsed.can_open);
}

#[test]
fn rejects_fragments_ipv6_and_bad_lengths() {
    let packet = udp_packet(false);
    for length in 0..packet.len() {
        assert!(parse(&packet[..length], true).is_none());
    }
    for (index, byte) in [(0, 0x65), (0, 0x44), (6, 0x20), (7, 1), (25, 9), (9, 99)] {
        let mut bad = packet.clone();
        bad[index] = byte;
        assert!(parse(&bad, true).is_none());
    }
}

// ── TCP flags and metadata ──

#[test]
fn only_initial_syn_can_open_tcp() {
    let mut tcp = udp_packet(false);
    tcp.resize(40, 0);
    tcp[2..4].copy_from_slice(&40u16.to_be_bytes());
    tcp[9] = 6;
    tcp[32] = 0x50;
    tcp[33] = 2;
    tcp[24..28].copy_from_slice(&123u32.to_be_bytes());
    let syn = parse(&tcp, true).unwrap();
    assert!(syn.can_open);
    assert!(!syn.is_rst);
    for flags in [3, 0x11, 4, 0x12, 0x10] {
        tcp[33] = flags;
        let packet = parse(&tcp, true).unwrap();
        assert!(!packet.can_open);
    }
}

#[test]
fn tcp_rst_flag_is_detected_udp_never() {
    let mut tcp = udp_packet(false);
    tcp.resize(40, 0);
    tcp[2..4].copy_from_slice(&40u16.to_be_bytes());
    tcp[9] = 6;
    tcp[32] = 0x50;
    tcp[33] = 0x04; // RST
    assert!(parse(&tcp, true).unwrap().is_rst);
    tcp[33] = 0x14; // RST+ACK
    assert!(parse(&tcp, true).unwrap().is_rst);
    tcp[33] = 0x10; // ACK
    assert!(!parse(&tcp, true).unwrap().is_rst);
    // A UDP packet is never marked as RST.
    let udp = udp_packet(false);
    assert!(!parse(&udp, true).unwrap().is_rst);
}

#[test]
fn tcp_meta_is_present_for_full_tcp_only() {
    let packet = parse(&full_tcp(0x18, 5, 6, 10), true).unwrap();
    assert_eq!(
        packet.tcp,
        Some(TcpMeta {
            seq: 5,
            ack: 6,
            flags: 0x18,
            payload_len: 10,
        })
    );
    // Options are header, not payload.
    let mut options = vec![0u8; 52];
    options[..40].copy_from_slice(&full_tcp(0x10, 1, 2, 0));
    options[2..4].copy_from_slice(&52u16.to_be_bytes());
    options[32] = 0x60; // data offset 6 → 24-byte TCP header
    assert_eq!(parse(&options, true).unwrap().tcp.unwrap().payload_len, 8);
    // Truncated TCP (data offset beyond the packet) is still rejected.
    let mut truncated = full_tcp(0x10, 1, 2, 4);
    truncated[32] = 0xf0;
    assert!(parse(&truncated, true).is_none());
    // Quoted TCP inside an ICMP error carries no TcpMeta.
    let inner = full_tcp(0x10, 1, 2, 4);
    let mut error = vec![0u8; 28 + inner.len()];
    error[0] = 0x45;
    let total = error.len() as u16;
    error[2..4].copy_from_slice(&total.to_be_bytes());
    error[9] = 1;
    error[12..16].copy_from_slice(&[10, 77, 0, 1]);
    error[16..20].copy_from_slice(&[10, 77, 0, 2]);
    error[20] = 3;
    error[21] = 1;
    error[28..].copy_from_slice(&inner);
    let quoted = parse(&error, false).unwrap();
    assert_eq!(quoted.flow, parse(&inner, true).unwrap().flow);
    assert!(quoted.tcp.is_none());
}

// ── TCP reset and probe ──

#[test]
fn tcp_reset_for_follows_closed_endpoint_rules() {
    // Incoming ACK → RST, seq = its ack.
    let reset = tcp_reset_for(&parse(&full_tcp(0x10, 7, 900, 3), true).unwrap()).unwrap();
    assert_eq!(segment_meta(&reset), (0x04, 900, 0));
    // Mirrored tuple: server 10.77.0.1:9000 → client 10.77.0.2:40000.
    assert_eq!(&reset[12..16], &[10, 77, 0, 1]);
    assert_eq!(&reset[16..20], &[10, 77, 0, 2]);
    assert_eq!(&reset[20..22], &9000u16.to_be_bytes());
    assert_eq!(&reset[22..24], &40000u16.to_be_bytes());
    assert_eq!(
        (reset[8], reset[32], reset[34], reset[35]),
        (64, 0x50, 0, 0)
    );
    // The reset itself parses back to the same flow from the server side.
    assert_eq!(
        parse(&reset, false).unwrap().flow,
        parse(&full_tcp(0x10, 7, 900, 3), true).unwrap().flow
    );
    // No ACK → RST|ACK with seq + payload_len (+ SYN/FIN), wrapping.
    assert_eq!(
        segment_meta(&tcp_reset_for(&parse(&full_tcp(0x00, 1000, 0, 5), true).unwrap()).unwrap()),
        (0x14, 0, 1005)
    );
    assert_eq!(
        segment_meta(&tcp_reset_for(&parse(&full_tcp(0x02, 2000, 0, 0), true).unwrap()).unwrap()),
        (0x14, 0, 2001)
    );
    assert_eq!(
        segment_meta(&tcp_reset_for(&parse(&full_tcp(0x02, 2000, 0, 4), true).unwrap()).unwrap()),
        (0x14, 0, 2005)
    );
    assert_eq!(
        segment_meta(&tcp_reset_for(&parse(&full_tcp(0x01, 3000, 0, 2), true).unwrap()).unwrap()),
        (0x14, 0, 3003)
    );
    assert_eq!(
        segment_meta(
            &tcp_reset_for(&parse(&full_tcp(0x02, u32::MAX, 0, 1), true).unwrap()).unwrap()
        ),
        (0x14, 0, 1)
    );
    // A reset is never answered.
    assert!(tcp_reset_for(&parse(&full_tcp(0x04, 1, 2, 0), true).unwrap()).is_none());
    assert!(tcp_reset_for(&parse(&full_tcp(0x14, 1, 2, 0), true).unwrap()).is_none());
    // No TCP metadata (ICMP-quoted) → no reset.
    let mut error = vec![0u8; 28 + 44];
    error[0] = 0x45;
    error[2..4].copy_from_slice(&72u16.to_be_bytes());
    error[9] = 1;
    error[20] = 3;
    error[21] = 1;
    error[28..].copy_from_slice(&full_tcp(0x10, 1, 2, 4));
    assert!(tcp_reset_for(&parse(&error, false).unwrap()).is_none());
}

#[test]
fn reset_and_probe_checksums_match_reference_math() {
    // Golden values from the internet-checksum math of tests/forged_rst.py.
    let key = FlowKey {
        protocol: 6,
        source: Ipv4Addr::new(10, 77, 0, 2),
        destination: Ipv4Addr::new(10, 77, 0, 1),
        source_port: 40000,
        destination_port: 9000,
    };
    let reset = tcp_reset_seq(key, 0x11223344);
    assert_eq!(
        &reset,
        &[
            0x45, 0, 0, 0x28, 0, 0, 0, 0, 64, 6, 0x66, 0x34, 10, 77, 0, 1, 10, 77, 0, 2, //
            0x23, 0x28, 0x9c, 0x40, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0x50, 0x04, 0, 0, 0x97,
            0x75, 0, 0
        ]
    );
    let probe = tcp_probe(key, 0x11223343);
    assert_eq!(
        &probe,
        &[
            0x45, 0, 0, 0x28, 0, 0, 0, 0, 64, 6, 0x66, 0x34, 10, 77, 0, 1, 10, 77, 0, 2, //
            0x23, 0x28, 0x9c, 0x40, 0x11, 0x22, 0x33, 0x43, 0, 0, 0, 0, 0x50, 0x10, 0, 0, 0x97,
            0x6a, 0, 0
        ]
    );
    // forged_rst.py's invariant: a checksummed buffer sums to 0.
    assert_eq!(internet_checksum(&reset[..20]), 0);
    assert_eq!(internet_checksum(&probe[..20]), 0);
    let mut pseudo = [0u8; 32];
    pseudo[0..4].copy_from_slice(&reset[12..16]);
    pseudo[4..8].copy_from_slice(&reset[16..20]);
    pseudo[8] = 0;
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
    pseudo[12..32].copy_from_slice(&reset[20..40]);
    assert_eq!(internet_checksum(&pseudo), 0);
}

// ── ICMP probe ──

#[test]
fn icmp_probe_round_trip() {
    let payload = [0xa5u8; 96];
    let request = icmp_echo_request(
        Ipv4Addr::new(10, 77, 0, 2),
        Ipv4Addr::new(10, 77, 0, 1),
        0x1234,
        7,
        &payload,
    );
    // Parse sees a client→server ICMP flow keyed by the echo id.
    let parsed = parse(&request, true).unwrap();
    assert_eq!(
        parsed.flow,
        FlowKey {
            protocol: 1,
            source: Ipv4Addr::new(10, 77, 0, 2),
            destination: Ipv4Addr::new(10, 77, 0, 1),
            source_port: 0x1234,
            destination_port: 0,
        }
    );
    let reply = echo_reply(&request);
    // The server normalizes the reply to the same client-side tuple.
    assert_eq!(parse(&reply, false).unwrap().flow, parsed.flow);
    assert!(icmp_echo_reply_matches(&reply, 0x1234, 7, &payload));
}

#[test]
fn icmp_probe_round_trip_odd_payload() {
    // Regression (N6): an odd payload made the builder drop the trailing
    // byte from the checksum while the verifier counted it — every probe
    // with an odd ICMP length was rejected as foreign.
    let payload = [0x5au8; 55];
    let request = icmp_echo_request(
        Ipv4Addr::new(10, 77, 0, 2),
        Ipv4Addr::new(10, 77, 0, 1),
        0xbeef,
        3,
        &payload,
    );
    assert_eq!(request.len(), 83);
    assert_eq!(internet_checksum(&request[..20]), 0);
    assert_eq!(internet_checksum(&request[20..]), 0);
    let reply = echo_reply(&request);
    assert!(icmp_echo_reply_matches(&reply, 0xbeef, 3, &payload));
}

#[test]
fn icmp_probe_rejects_foreign_content() {
    let payload = [0x5au8; 64];
    let request = icmp_echo_request(
        Ipv4Addr::new(10, 77, 0, 2),
        Ipv4Addr::new(10, 77, 0, 1),
        9,
        1,
        &payload,
    );
    // The request itself is not a reply.
    assert!(!icmp_echo_reply_matches(&request, 9, 1, &payload));
    let reply = echo_reply(&request);
    assert!(!icmp_echo_reply_matches(&reply, 10, 1, &payload));
    assert!(!icmp_echo_reply_matches(&reply, 9, 2, &payload));
    assert!(!icmp_echo_reply_matches(&reply, 9, 1, &[0x5au8; 63]));
    let mut corrupted = reply.clone();
    corrupted[30] ^= 0xff;
    corrupted[22..24].fill(0);
    let checksum = internet_checksum(&corrupted[20..]);
    corrupted[22..24].copy_from_slice(&checksum.to_be_bytes());
    assert!(!icmp_echo_reply_matches(&corrupted, 9, 1, &payload));
    assert!(!icmp_echo_reply_matches(&reply[..27], 9, 1, &payload));
    assert!(!icmp_echo_reply_matches(&[], 9, 1, &payload));
}

#[test]
fn icmp_probe_fits_mtu() {
    let request = icmp_echo_request(
        Ipv4Addr::new(10, 77, 0, 2),
        Ipv4Addr::new(10, 77, 0, 1),
        1,
        1,
        &[0u8; 1400],
    );
    assert_eq!(request.len(), 1428);
    assert!(icmp_echo_reply_matches(
        &echo_reply(&request),
        1,
        1,
        &[0u8; 1400]
    ));
}

fn segment_meta(bytes: &[u8]) -> (u8, u32, u32) {
    (
        bytes[33],
        dword(bytes, 24).unwrap(),
        dword(bytes, 28).unwrap(),
    )
}
