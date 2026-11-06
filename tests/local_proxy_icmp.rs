//! ICMP echo local-proxy: чистые функции переписывания identifier,
//! demux ответов по proxy-id и сборки кадра клиенту.

use std::collections::HashMap;

use svpn::link_io::{Delivery, Epoch, Event, Packet};
use svpn::local_proxy::icmp::{
    IcmpSlot, alloc_proxy_id, build_echo_reply, handle_reply, reply_proxy_id, rewrite_echo_request,
};
use svpn::packet::{FlowKey, internet_checksum};
use tokio::sync::mpsc;

// ── фикстуры ──

fn flow() -> FlowKey {
    FlowKey {
        protocol: 1,
        source: "10.111.0.2".parse().unwrap(),
        destination: "8.8.8.8".parse().unwrap(),
        source_port: 4444,
        destination_port: 0,
    }
}

/// Полный IP echo-request (identifier 0x1234, seq 1, payload "svpn").
fn echo_request() -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
    icmp.extend_from_slice(b"svpn");
    let sum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());

    let mut bytes = vec![0u8; 20 + icmp.len()];
    bytes[0] = 0x45;
    let total = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&total.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&flow().source.octets());
    bytes[16..20].copy_from_slice(&flow().destination.octets());
    bytes[20..].copy_from_slice(&icmp);
    let ip_sum = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    bytes
}

/// Полный IP echo-reply из WAN с данным identifier.
fn echo_reply(identifier: u16) -> Vec<u8> {
    let mut icmp = vec![0, 0, 0, 0, 0, 0, 0, 1];
    icmp.extend_from_slice(b"svpn");
    let sum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    icmp[4..6].copy_from_slice(&identifier.to_be_bytes());

    let mut bytes = vec![0u8; 20 + icmp.len()];
    bytes[0] = 0x45;
    let total = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&total.to_be_bytes());
    bytes[8] = 54;
    bytes[9] = 1;
    bytes[16..20].copy_from_slice(&flow().destination.octets());
    bytes[20..].copy_from_slice(&icmp);
    bytes
}

/// Сумма корректного checksum-блока сворачивается в ноль.
fn checksum_ok(bytes: &[u8]) -> bool {
    internet_checksum(bytes) == 0
}

// ── rewrite_echo_request ──

#[test]
fn rewrite_replaces_identifier_and_fixes_checksum() {
    let rewritten = rewrite_echo_request(&echo_request(), 0x0b_e7).unwrap();
    assert_eq!(&rewritten[4..6], &[0x0b, 0xe7]);
    assert_eq!(&rewritten[6..8], &[0, 1]); // seq не тронут
    assert_eq!(&rewritten[8..], b"svpn");
    assert!(checksum_ok(&rewritten), "icmp checksum must validate");
}

#[test]
fn rewrite_rejects_non_echo_and_malformed() {
    let mut request = echo_request();
    request[20] = 0; // echo reply, не request
    assert!(rewrite_echo_request(&request, 1).is_none());

    let mut request = echo_request();
    request[0] = 0x65; // IPv6
    assert!(rewrite_echo_request(&request, 1).is_none());

    let truncated = echo_request()[..26].to_vec(); // ICMP короче 8 байт
    assert!(rewrite_echo_request(&truncated, 1).is_none());
}

// ── reply_proxy_id ──

#[test]
fn reply_id_roundtrip_and_rejects_noise() {
    // Ответ несёт proxy-id, а не identifier клиента (0x1234).
    assert_eq!(reply_proxy_id(&echo_reply(0x0b_e7)), Some(0x0b_e7));
    assert_ne!(reply_proxy_id(&echo_reply(0x0b_e7)), Some(0x1234));

    assert!(
        reply_proxy_id(&echo_request()).is_none(),
        "request is not a reply"
    );
    let mut not_icmp = echo_reply(1);
    not_icmp[9] = 17;
    assert!(reply_proxy_id(&not_icmp).is_none());
    assert!(
        reply_proxy_id(&echo_reply(1)[..20]).is_none(),
        "no ICMP header"
    );
}

// ── build_echo_reply ──

#[test]
fn echo_reply_frame_targets_client_with_original_identifier() {
    let frame = build_echo_reply(&flow(), &echo_reply(0x0b_e7)[24..]);
    assert_eq!(frame[0] >> 4, 4);
    assert_eq!(frame[9], 1);
    assert_eq!(&frame[12..16], &flow().destination.octets());
    assert_eq!(&frame[16..20], &flow().source.octets());
    assert_eq!(frame[20], 0, "echo reply type");
    assert_eq!(u16::from_be_bytes([frame[24], frame[25]]), 4444);
    assert!(checksum_ok(&frame[20..]), "icmp checksum");
    assert!(checksum_ok(&frame[..20]), "ip checksum");
}

// ── handle_reply ──

#[test]
fn handle_reply_demuxes_proxy_id_to_flow_event() {
    let flow = flow();
    let (events_tx, mut events_rx) = mpsc::channel(4);
    let mut icmp = HashMap::new();
    let mut icmp_ids = HashMap::new();
    icmp.insert(
        flow,
        IcmpSlot {
            proxy_id: 0x0b_e7,
            seen: std::time::Instant::now(),
        },
    );
    icmp_ids.insert(0x0b_e7, flow);
    let ids = HashMap::from([(flow, 7u64)]);
    let delivery = Delivery::default();

    handle_reply(
        &events_tx,
        Epoch {
            link: 0,
            generation: 0,
        },
        &mut icmp,
        &mut icmp_ids,
        &ids,
        &delivery,
        &echo_reply(0x0b_e7),
    );

    let (_, Event::Packet(Packet { id, bytes })) = events_rx.try_recv().unwrap() else {
        panic!("expected Packet event");
    };
    assert_eq!(id, 7);
    assert_eq!(u16::from_be_bytes([bytes[24], bytes[25]]), 4444);
}

#[test]
fn handle_reply_drops_unknown_proxy_id_without_event() {
    let (events_tx, mut events_rx) = mpsc::channel(4);
    let delivery = Delivery::default();
    handle_reply(
        &events_tx,
        Epoch {
            link: 0,
            generation: 0,
        },
        &mut HashMap::new(),
        &mut HashMap::new(),
        &HashMap::new(),
        &delivery,
        &echo_reply(0x0b_e7),
    );
    assert!(events_rx.try_recv().is_err());
}

// ── alloc_proxy_id ──

#[test]
fn alloc_proxy_id_skips_taken_and_exhausts() {
    let flow = flow();
    let mut ids = HashMap::from([(1u16, flow)]);
    let mut next = 0u16;
    assert_eq!(alloc_proxy_id(&ids, &mut next), Some(2));
    ids.insert(2, flow);
    assert_eq!(alloc_proxy_id(&ids, &mut next), Some(3));

    let full: HashMap<u16, FlowKey> = (0..=u16::MAX).map(|i| (i, flow)).collect();
    let mut next = 0u16;
    assert_eq!(alloc_proxy_id(&full, &mut next), None);
}
