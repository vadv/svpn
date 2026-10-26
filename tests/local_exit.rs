//! LocalExit core: fixed inner pair validation, stateless 1:1 address
//! translation at the hub boundary, and startup failure cleanup. The full
//! handshake needs a real second TUN (privileged), so the failure path is
//! pinned instead; heartbeats are the existing session loop, covered by the
//! session tests.

mod common;

use std::net::Ipv4Addr;

use svpn::{
    link_io::Epoch,
    local_exit::{LOCAL_PAIR, LocalPair, start},
    packet::{self, internet_checksum, translate_v4},
};

const PRIMARY_SERVER: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
const PRIMARY_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
const LOCAL_SERVER: Ipv4Addr = LOCAL_PAIR.0;
const LOCAL_CLIENT: Ipv4Addr = LOCAL_PAIR.1;
const REMOTE: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

// ── inner pair ──

#[test]
fn default_pair_accepted_against_distinct_primary() {
    let pair = LocalPair::new(PRIMARY_SERVER, PRIMARY_CLIENT).unwrap();
    assert_eq!(
        pair,
        LocalPair {
            server: LOCAL_SERVER,
            client: LOCAL_CLIENT
        }
    );
}

#[test]
fn claimed_pairs_are_unique_and_owned() {
    let (first, _first_guard) = LocalPair::claim(PRIMARY_SERVER, PRIMARY_CLIENT).unwrap();
    let (second, _second_guard) = LocalPair::claim(PRIMARY_SERVER, PRIMARY_CLIENT).unwrap();
    assert_ne!(first, second);
}

#[test]
fn pair_rejected_on_any_primary_collision() {
    for (server, client) in [
        (LOCAL_SERVER, LOCAL_CLIENT),
        (LOCAL_CLIENT, LOCAL_SERVER),
        (PRIMARY_SERVER, LOCAL_SERVER),
        (LOCAL_CLIENT, PRIMARY_CLIENT),
    ] {
        assert!(
            LocalPair::new(server, client).is_err(),
            "collision {server}/{client} must be rejected"
        );
    }
}

// ── translation fixtures ──

/// Compute the transport checksum with the IPv4 pseudo-header.
fn transport_checksum(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    let mut buf = Vec::with_capacity(12 + segment.len());
    buf.extend_from_slice(&source.octets());
    buf.extend_from_slice(&destination.octets());
    buf.push(0);
    buf.push(protocol);
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(segment);
    internet_checksum(&buf)
}

fn fix_ip_checksum(bytes: &mut [u8]) {
    let ihl = usize::from(bytes[0] & 15) * 4;
    bytes[10..12].fill(0);
    let checksum = internet_checksum(&bytes[..ihl]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn source_ip(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])
}

fn destination_ip(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])
}

/// Both checksums of a packet verify with the checksum fields in place.
fn checksums_ok(bytes: &[u8]) -> bool {
    let ihl = usize::from(bytes[0] & 15) * 4;
    if internet_checksum(&bytes[..ihl]) != 0 {
        return false;
    }
    match bytes[9] {
        6 => transport_checksum(source_ip(bytes), destination_ip(bytes), 6, &bytes[ihl..]) == 0,
        17 => {
            bytes[ihl + 6..ihl + 8] == [0, 0]
                || transport_checksum(source_ip(bytes), destination_ip(bytes), 17, &bytes[ihl..])
                    == 0
        }
        1 => internet_checksum(&bytes[ihl..]) == 0,
        _ => true,
    }
}

/// IPv4 + TCP SYN with valid checksums.
fn tcp_segment(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
    let mut bytes = vec![0u8; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&destination.octets());
    bytes[20..22].copy_from_slice(&40000u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x02;
    let checksum = transport_checksum(source, destination, 6, &bytes[20..]);
    bytes[36..38].copy_from_slice(&checksum.to_be_bytes());
    fix_ip_checksum(&mut bytes);
    bytes
}

/// IPv4 + UDP datagram with valid checksums (or a zero one when `zero`).
fn udp_datagram(source: Ipv4Addr, destination: Ipv4Addr, zero: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; 36];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&36u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&destination.octets());
    bytes[20..22].copy_from_slice(&50000u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&53u16.to_be_bytes());
    bytes[24..26].copy_from_slice(&16u16.to_be_bytes());
    bytes[28..].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
    if !zero {
        let mut checksum = transport_checksum(source, destination, 17, &bytes[20..]);
        if checksum == 0 {
            checksum = u16::MAX;
        }
        bytes[26..28].copy_from_slice(&checksum.to_be_bytes());
    }
    fix_ip_checksum(&mut bytes);
    bytes
}

/// IPv4 + ICMP echo request with a valid checksum.
fn icmp_echo(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
    packet::icmp_echo_request(source, destination, 0x1234, 7, &[9u8; 16])
}

/// ICMP destination-unreachable quoting a UDP datagram, with valid
/// checksums of the outer packet, the ICMP message and the quoted header.
fn icmp_error(outer_source: Ipv4Addr, outer_destination: Ipv4Addr, quoted: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 20 + 8 + quoted.len()];
    bytes[0] = 0x45;
    let total = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&total.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&outer_source.octets());
    bytes[16..20].copy_from_slice(&outer_destination.octets());
    bytes[20] = 3; // destination unreachable
    bytes[21] = 1; // host unreachable
    bytes[24..26].copy_from_slice(&0x1234u16.to_be_bytes()); // unused
    bytes[28..].copy_from_slice(quoted);
    let checksum = internet_checksum(&bytes[20..]);
    bytes[22..24].copy_from_slice(&checksum.to_be_bytes());
    fix_ip_checksum(&mut bytes);
    bytes
}

// ── translation ──

#[test]
fn tcp_source_maps_and_round_trips() {
    let original = tcp_segment(PRIMARY_CLIENT, REMOTE);
    let translated = translate_v4(&original, PRIMARY_CLIENT, LOCAL_CLIENT).unwrap();
    assert_eq!(source_ip(&translated), LOCAL_CLIENT);
    assert_eq!(destination_ip(&translated), REMOTE);
    assert_eq!(translated[20..24], original[20..24]); // ports unchanged
    assert!(checksums_ok(&translated));
    let back = translate_v4(&translated, LOCAL_CLIENT, PRIMARY_CLIENT).unwrap();
    assert_eq!(back, original);
}

#[test]
fn tcp_destination_maps_back() {
    let reply = tcp_segment(REMOTE, LOCAL_CLIENT);
    let translated = translate_v4(&reply, LOCAL_CLIENT, PRIMARY_CLIENT).unwrap();
    assert_eq!(destination_ip(&translated), PRIMARY_CLIENT);
    assert!(checksums_ok(&translated));
    assert_eq!(
        translate_v4(&translated, PRIMARY_CLIENT, LOCAL_CLIENT).unwrap(),
        reply
    );
}

#[test]
fn udp_checksum_updated_and_zero_checksum_kept() {
    let original = udp_datagram(PRIMARY_CLIENT, REMOTE, false);
    let translated = translate_v4(&original, PRIMARY_CLIENT, LOCAL_CLIENT).unwrap();
    assert!(checksums_ok(&translated));
    assert_eq!(translated[28..], original[28..]); // payload unchanged
    assert_eq!(
        translate_v4(&translated, LOCAL_CLIENT, PRIMARY_CLIENT).unwrap(),
        original
    );
    // A sender that computed no UDP checksum keeps none.
    let zeroed = udp_datagram(PRIMARY_CLIENT, REMOTE, true);
    let translated = translate_v4(&zeroed, PRIMARY_CLIENT, LOCAL_CLIENT).unwrap();
    assert_eq!(translated[26..28], [0, 0]);
    assert!(checksums_ok(&translated));
}

#[test]
fn icmp_echo_translates_without_icmp_checksum_change() {
    let original = icmp_echo(PRIMARY_CLIENT, LOCAL_SERVER);
    let translated = translate_v4(&original, PRIMARY_CLIENT, LOCAL_CLIENT).unwrap();
    assert_eq!(source_ip(&translated), LOCAL_CLIENT);
    assert!(checksums_ok(&translated));
    // The ICMP checksum does not cover addresses: the bytes must not move.
    assert_eq!(translated[22..24], original[22..24]);
}

#[test]
fn icmp_error_quotes_the_translated_datagram() {
    let quoted = udp_datagram(LOCAL_CLIENT, REMOTE, false);
    let original = icmp_error(REMOTE, LOCAL_CLIENT, &quoted);
    let translated = translate_v4(&original, LOCAL_CLIENT, PRIMARY_CLIENT).unwrap();
    // Outer destination and the quoted source both map back.
    assert_eq!(destination_ip(&translated), PRIMARY_CLIENT);
    assert_eq!(source_ip(&translated[28..]), PRIMARY_CLIENT);
    // Outer IPv4 and ICMP checksums, and the quoted header checksum, verify.
    assert!(checksums_ok(&translated));
    assert!(internet_checksum(&translated[28..48]) == 0);
    assert!(transport_checksum(PRIMARY_CLIENT, REMOTE, 17, &translated[48..]) == 0);
    // Round trip restores the exact original error.
    assert_eq!(
        translate_v4(&translated, PRIMARY_CLIENT, LOCAL_CLIENT).unwrap(),
        original
    );
    let quote_only = icmp_error(
        REMOTE,
        PRIMARY_SERVER,
        &udp_datagram(LOCAL_CLIENT, REMOTE, false),
    );
    let translated = translate_v4(&quote_only, LOCAL_CLIENT, PRIMARY_CLIENT).unwrap();
    assert_eq!(source_ip(&translated[28..]), PRIMARY_CLIENT);
    assert!(checksums_ok(&translated));
}

#[test]
fn first_fragment_keeps_tcp_checksum_correct() {
    // First fragment of a segmented TCP datagram (MF set, offset 0) — the
    // transport header and its checksum field live in this fragment.
    let mut bytes = tcp_segment(PRIMARY_CLIENT, REMOTE);
    bytes[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // MF set, offset 0
    fix_ip_checksum(&mut bytes);
    let translated = translate_v4(&bytes, PRIMARY_CLIENT, LOCAL_CLIENT).unwrap();
    assert_eq!(source_ip(&translated), LOCAL_CLIENT);
    // The checksum verifies against the pseudo-header of the new addresses.
    assert_eq!(
        transport_checksum(LOCAL_CLIENT, REMOTE, 6, &translated[20..]),
        0
    );
    // A non-first fragment carries no transport header: only the IPv4
    // header checksum moves, the payload bytes stay identical.
    let mut tail = vec![0u8; 28];
    tail[0] = 0x45;
    tail[2..4].copy_from_slice(&28u16.to_be_bytes());
    tail[6..8].copy_from_slice(&0x2005u16.to_be_bytes()); // offset 5 = 20 bytes in
    tail[8] = 64;
    tail[9] = 6;
    tail[12..16].copy_from_slice(&LOCAL_CLIENT.octets());
    tail[16..20].copy_from_slice(&REMOTE.octets());
    tail[20..].copy_from_slice(&[7, 7, 7, 7, 7, 7, 7, 7]);
    fix_ip_checksum(&mut tail);
    let translated = translate_v4(&tail, LOCAL_CLIENT, PRIMARY_CLIENT).unwrap();
    assert_eq!(source_ip(&translated), PRIMARY_CLIENT);
    assert_eq!(translated[20..], tail[20..]);
    // No transport header here: only the IPv4 header checksum applies.
    assert_eq!(internet_checksum(&translated[..20]), 0);
}

#[test]
fn unrelated_and_malformed_packets() {
    // No occurrence of the address: byte-identical.
    let neutral = tcp_segment(REMOTE, PRIMARY_SERVER);
    assert_eq!(
        translate_v4(&neutral, LOCAL_CLIENT, PRIMARY_CLIENT).unwrap(),
        neutral
    );
    // Truncated headers are refused instead of half-translated.
    assert_eq!(
        translate_v4(&neutral[..12], LOCAL_CLIENT, PRIMARY_CLIENT),
        None
    );
    let mut short_total = tcp_segment(PRIMARY_CLIENT, REMOTE);
    short_total[2..4].copy_from_slice(&999u16.to_be_bytes());
    assert_eq!(
        translate_v4(&short_total, PRIMARY_CLIENT, LOCAL_CLIENT),
        None
    );
}

// ── startup failure cleanup ──

#[tokio::test]
async fn failed_tun_name_surfaces_the_server_error_and_ends_the_task() {
    // A too-long TUN name fails validation before any interface is touched,
    // on every platform and without privileges. The client handshake runs
    // for real up to the address exchange, then unwinds with the server-side
    // cause and no leaked serve task.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        start(
            Epoch {
                link: 0,
                generation: 1,
            },
            (PRIMARY_SERVER, PRIMARY_CLIENT),
            1400,
            None,
            None,
            Some("a_tun_name_way_too_long".to_owned()),
        ),
    )
    .await
    .expect("start must not hang");
    let error = match result {
        Ok(_) => panic!("start must fail with an invalid TUN name"),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        error.contains("TUN name must be 1..=15 bytes"),
        "server-side cause must surface: {error}"
    );
    assert!(
        error.contains("local exit handshake failed"),
        "the failure must be reported as a local-exit startup failure: {error}"
    );
}
