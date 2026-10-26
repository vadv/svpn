//! Direct ICMP engine (spec §5.4): the echo id/seq/payload round trip over
//! real loopback sockets where the platform privilege allows, plus the
//! unprivileged parser/rewrite negative cases. Linux raw sockets need
//! `CAP_NET_RAW` — unprivileged Linux reports the denial explicitly or
//! skips the socket tests with the same probe direct UDP uses. Raw ICMP
//! requires CAP_NET_RAW/root on both supported systems.

use std::{collections::HashMap, io, net::Ipv4Addr, time::Duration};

use socket2::{Domain, Socket, Type};
use svpn::{
    direct::{
        DirectConfig, DirectEvent, UDP_IDLE, Uplink,
        icmp::{
            Echo, IcmpEngine, echo_reply_packet, normalize_darwin_raw_ip, parse_echo_reply_ip,
            parse_echo_request, rewrite_icmp_error,
        },
    },
    packet::{self, FlowKey, Packet, internet_checksum},
};

const PEER: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// The loopback interface, probed with the same binding the engine uses.
/// `None` means this environment cannot bind devices (unprivileged Linux).
fn loopback_uplink() -> Option<Uplink> {
    let name = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };
    let mut manager = route_manager::RouteManager::new().ok()?;
    let list = manager.list().ok()?;
    let index = list
        .iter()
        .find(|route| route.if_name().is_some_and(|if_name| if_name == name))?
        .if_index()?;
    let probe = Socket::new(Domain::IPV4, Type::DGRAM, None).ok()?;
    #[cfg(target_os = "linux")]
    probe.bind_device(Some(name.as_bytes())).ok()?;
    #[cfg(target_os = "macos")]
    probe
        .bind_device_by_index_v4(std::num::NonZeroU32::new(index))
        .ok()?;
    Some(Uplink {
        name: name.to_owned(),
        index,
    })
}

/// The loopback interface identity without any binding probe: works
/// unprivileged, enough to reach the engine's own denial paths.
fn loopback_iface() -> Option<Uplink> {
    let name = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };
    let mut manager = route_manager::RouteManager::new().ok()?;
    let list = manager.list().ok()?;
    let index = list
        .iter()
        .find(|route| route.if_name().is_some_and(|if_name| if_name == name))?
        .if_index()?;
    Some(Uplink {
        name: name.to_owned(),
        index,
    })
}

/// A real local IPv4 address (UDP connect is a route lookup, no packets):
/// macOS binds only 127.0.0.1 by default, so the client side of the
/// loopback pair needs a genuinely assigned address; the peer side stays
/// 127.0.0.1.
fn client() -> Ipv4Addr {
    static LOCAL: std::sync::OnceLock<Ipv4Addr> = std::sync::OnceLock::new();
    *LOCAL.get_or_init(|| {
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        probe.connect("192.0.2.1:9").unwrap();
        match probe.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => *address.ip(),
            _ => panic!("IPv4 probe address"),
        }
    })
}

/// Whether the error chain carries an `EACCES`/`EPERM` from the kernel —
/// the explicit ICMP privilege denial (spec §5.4).
fn denied(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
    })
}

async fn engine(uplink: &Uplink) -> Option<IcmpEngine> {
    match IcmpEngine::new(DirectConfig {
        client: client(),
        peer: PEER,
        tun_name: "svpn0".to_owned(),
        tun_index: 3,
        mtu: 1400,
        uplink: uplink.clone(),
    })
    .await
    {
        Ok(engine) => Some(engine),
        Err(error) if denied(&error) => {
            eprintln!("skipping: raw ICMP requires CAP_NET_RAW/root");
            None
        }
        Err(error) => panic!("unexpected ICMP setup error: {error:#}"),
    }
}

async fn open_live(engine: &mut IcmpEngine, id: u64, packet: &Packet, bytes: &[u8]) -> bool {
    match engine.open_icmp(id, packet, bytes).await {
        Ok(()) => true,
        Err(error) if denied(&error) => {
            eprintln!("skipping: raw ICMP requires CAP_NET_RAW/root");
            false
        }
        Err(error) => panic!("unexpected ICMP open error: {error:#}"),
    }
}

/// Client echo request `source → destination` with a custom TTL and valid
/// checksums.
fn request_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
    ttl: u8,
) -> Vec<u8> {
    let mut bytes = packet::icmp_echo_request(source, destination, id, seq, payload);
    bytes[8] = ttl;
    let checksum = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

/// A bare ICMP echo message of `kind` (0 reply / 8 request) with a valid
/// checksum.
fn icmp_message(kind: u8, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut icmp = vec![0u8; 8 + payload.len()];
    icmp[0] = kind;
    icmp[4..6].copy_from_slice(&id.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());
    icmp[8..].copy_from_slice(payload);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    icmp
}

/// Destination-unreachable error from `outer_source` quoting the first 28
/// bytes (IP header + 8) of `quoted_request`, with valid checksums.
fn icmp_unreachable(
    outer_source: Ipv4Addr,
    outer_destination: Ipv4Addr,
    quoted_request: &[u8],
) -> Vec<u8> {
    let quote = &quoted_request[..28];
    let mut icmp = vec![0u8; 8 + quote.len()];
    icmp[0] = 3;
    icmp[1] = 1;
    icmp[8..].copy_from_slice(quote);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    let total = 20 + icmp.len();
    let mut bytes = vec![0u8; total];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[8] = 250;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&outer_source.octets());
    bytes[16..20].copy_from_slice(&outer_destination.octets());
    bytes[20..].copy_from_slice(&icmp);
    let checksum = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

/// Bare IPv4 packet carrying one ICMP message (protocol 1, TTL 64).
fn ip_packet(icmp: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 20 + icmp.len()];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&PEER.octets());
    bytes[16..20].copy_from_slice(&client().octets());
    bytes[20..].copy_from_slice(icmp);
    let checksum = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn checksums_ok(bytes: &[u8]) -> bool {
    let header = usize::from(bytes[0] & 0x0f) * 4;
    internet_checksum(&bytes[..header]) == 0 && internet_checksum(&bytes[header..]) == 0
}

fn corrupt_icmp_checksum(bytes: &mut [u8]) {
    let header = usize::from(bytes[0] & 0x0f) * 4;
    bytes[header + 2] ^= 0xff;
}

async fn next_event(engine: &mut IcmpEngine) -> DirectEvent {
    tokio::time::timeout(Duration::from_secs(3), engine.recv_event())
        .await
        .expect("event within 3 s")
}

// ── request parsing (unprivileged) ──

#[test]
fn parse_echo_request_rejects_malformed() {
    let valid = request_packet(client(), PEER, 0x4321, 7, b"probe", 64);
    let parsed = parse_echo_request(&valid).unwrap();
    assert_eq!(
        parsed,
        Echo {
            id: 0x4321,
            seq: 7,
            payload: b"probe".to_vec(),
        }
    );

    let mut short = valid.clone();
    short.truncate(20);
    assert!(parse_echo_request(&short).is_none(), "short packet");

    let mut version = valid.clone();
    version[0] = 0x65;
    assert!(parse_echo_request(&version).is_none(), "not IPv4");

    let mut protocol = valid.clone();
    protocol[9] = 17;
    assert!(parse_echo_request(&protocol).is_none(), "not protocol 1");

    let reply = echo_reply_packet(PEER, client(), 64, &parsed);
    assert!(
        parse_echo_request(&reply).is_none(),
        "an echo reply never opens a flow"
    );

    let mut code = valid.clone();
    code[21] = 1;
    let checksum = internet_checksum(&code[20..]);
    code[22..24].copy_from_slice(&checksum.to_be_bytes());
    assert!(parse_echo_request(&code).is_none(), "nonzero code");

    let mut checksum = valid.clone();
    corrupt_icmp_checksum(&mut checksum);
    assert!(parse_echo_request(&checksum).is_none(), "bad checksum");

    let mut fragment = valid.clone();
    fragment[6] |= 0x20;
    assert!(parse_echo_request(&fragment).is_none(), "fragmented");

    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(parse_echo_request(&trailing).is_none(), "trailing bytes");
}

// ── reply parsing (unprivileged) ──

#[test]
fn parse_echo_reply_rejects_malformed() {
    let echo = Echo {
        id: 0x4321,
        seq: 7,
        payload: b"probe".to_vec(),
    };
    let reply = echo_reply_packet(PEER, client(), 64, &echo);
    let (_, ttl, parsed) = parse_echo_reply_ip(&reply, 1400).unwrap();
    assert_eq!(ttl, 64);
    assert_eq!(parsed, echo);

    assert!(
        parse_echo_reply_ip(&ip_packet(&icmp_message(8, 0x4321, 7, b"probe")), 1400).is_none(),
        "a request is not a reply"
    );
    let mut bad = ip_packet(&icmp_message(0, 0x4321, 7, b"probe"));
    corrupt_icmp_checksum(&mut bad);
    assert!(parse_echo_reply_ip(&bad, 1400).is_none(), "bad checksum");
    assert!(
        parse_echo_reply_ip(&ip_packet(&[0, 0, 0]), 1400).is_none(),
        "short message"
    );

    let mut truncated = reply.clone();
    truncated.truncate(reply.len() - 1);
    assert!(
        parse_echo_reply_ip(&truncated, 1400).is_none(),
        "a truncated raw read never parses"
    );
    let mut version = reply.clone();
    version[0] = 0x60;
    assert!(parse_echo_reply_ip(&version, 1400).is_none(), "not IPv4");
    let mut protocol = reply.clone();
    protocol[9] = 17;
    assert!(
        parse_echo_reply_ip(&protocol, 1400).is_none(),
        "not protocol 1"
    );
}

#[test]
fn darwin_raw_headers_normalize_before_echo_and_error_parsing() {
    let echo = Echo {
        id: 0x4321,
        seq: 7,
        // 256-byte IP packet catches the native 0x0100 length case.
        payload: vec![0x5a; 228],
    };
    let mut reply = echo_reply_packet(PEER, client(), 64, &echo);
    let total = u16::from_be_bytes([reply[2], reply[3]]);
    let offset = u16::from_be_bytes([reply[6], reply[7]]);
    reply[2..4].copy_from_slice(&total.to_ne_bytes());
    reply[6..8].copy_from_slice(&offset.to_ne_bytes());
    normalize_darwin_raw_ip(&mut reply);
    let (_, _, parsed) = parse_echo_reply_ip(&reply, 1400).unwrap();
    assert_eq!(parsed, echo);

    let physical = Ipv4Addr::LOCALHOST;
    let client = Ipv4Addr::new(10, 77, 0, 2);
    let destination = Ipv4Addr::new(9, 9, 9, 9);
    let request = request_packet(physical, destination, 77, 3, b"quote", 54);
    let mut error = icmp_unreachable(Ipv4Addr::new(192, 0, 2, 9), physical, &request);
    let total = u16::from_be_bytes([error[2], error[3]]);
    let offset = u16::from_be_bytes([error[6], error[7]]);
    error[2..4].copy_from_slice(&total.to_ne_bytes());
    error[6..8].copy_from_slice(&offset.to_ne_bytes());
    normalize_darwin_raw_ip(&mut error);
    let (flow, rewritten) = rewrite_icmp_error(&error, client, physical).unwrap();
    assert_eq!(flow.destination, destination);
    assert_eq!(&rewritten[16..20], client.octets());
    assert_eq!(internet_checksum(&rewritten[28..48]), 0);
}

#[test]
fn oversized_replies_are_rejected_by_the_mtu_bound() {
    // A 1401-byte reply with an all-zero payload: dropping its final zero
    // byte leaves the ICMP checksum valid, so checksum verification can
    // never prove completeness (review P1). The bound is size, not the
    // checksum: the engine reads through an MTU+1 window, so the kernel
    // never truncates a larger datagram down to the MTU — it arrives one
    // byte over and is rejected whole; the parser enforces the same bound.
    let echo = Echo {
        id: 0x4321,
        seq: 7,
        payload: vec![0u8; 1401 - 28],
    };
    let reply = echo_reply_packet(PEER, client(), 64, &echo);
    assert_eq!(reply.len(), 1401);
    assert!(checksums_ok(&reply), "the fixture must be a valid reply");
    assert!(
        parse_echo_reply_ip(&reply, 1400).is_none(),
        "a reply longer than the TUN MTU never parses"
    );
    let mut truncated = reply.clone();
    truncated.truncate(1400);
    assert!(
        checksums_ok(&truncated),
        "the checksum still verifies — only the size bound exposes it"
    );
    assert!(
        parse_echo_reply_ip(&reply, 1401).is_some(),
        "the full reply fits a window one byte larger"
    );
}

#[test]
fn echo_reply_packet_restores_the_original_tuple() {
    let echo = Echo {
        id: 0x4321,
        seq: 9,
        payload: vec![0x5a; 10],
    };
    let bytes = echo_reply_packet(
        Ipv4Addr::new(9, 9, 9, 9),
        Ipv4Addr::new(10, 77, 0, 2),
        57,
        &echo,
    );
    assert_eq!(bytes.len(), 38);
    let (source, ttl, parsed) = parse_echo_reply_ip(&bytes, 1400).unwrap();
    assert_eq!(source, Ipv4Addr::new(9, 9, 9, 9));
    assert_eq!(ttl, 57, "the reply's own TTL is preserved");
    assert_eq!(parsed, echo);
    assert_eq!(&bytes[16..20], &[10, 77, 0, 2]);
    assert!(checksums_ok(&bytes));
}

// ── ICMP error rewrite (unprivileged) ──

#[test]
fn rewrite_icmp_error_restores_client_addresses() {
    let physical = Ipv4Addr::LOCALHOST;
    let client = Ipv4Addr::new(10, 77, 0, 2);
    let destination = Ipv4Addr::new(9, 9, 9, 9);
    let request = request_packet(physical, destination, 77, 3, b"quote", 54);
    let error = icmp_unreachable(Ipv4Addr::new(192, 0, 2, 9), physical, &request);

    let (flow, rewritten) = rewrite_icmp_error(&error, client, physical).unwrap();
    assert_eq!(
        flow,
        FlowKey {
            protocol: 1,
            source: client,
            destination,
            source_port: 77,
            destination_port: 0,
        }
    );
    // Outer: the reporting router stays the source, the client becomes the
    // destination; TTL rides along.
    assert_eq!(&rewritten[12..16], &[192, 0, 2, 9]);
    assert_eq!(&rewritten[16..20], client.octets());
    assert_eq!(rewritten[8], 250);
    // Embedded quote: our physical source becomes the client, the original
    // destination is untouched.
    let quote_at = 28;
    assert_eq!(&rewritten[quote_at + 12..quote_at + 16], client.octets());
    assert_eq!(
        &rewritten[quote_at + 16..quote_at + 20],
        destination.octets()
    );
    assert!(checksums_ok(&rewritten), "outer checksums recomputed");
    assert_eq!(
        internet_checksum(&rewritten[quote_at..quote_at + 20]),
        0,
        "embedded header checksum recomputed"
    );

    let foreign = request_packet(
        Ipv4Addr::LOCALHOST | Ipv4Addr::new(0, 0, 0, 2),
        destination,
        77,
        3,
        b"quote",
        54,
    );
    let error = icmp_unreachable(Ipv4Addr::new(192, 0, 2, 9), physical, &foreign);
    assert!(
        rewrite_icmp_error(&error, client, physical).is_none(),
        "an error quoting someone else's request is unrelated"
    );

    let mut bad = icmp_unreachable(Ipv4Addr::new(192, 0, 2, 9), physical, &request);
    corrupt_icmp_checksum(&mut bad);
    assert!(
        rewrite_icmp_error(&bad, client, physical).is_none(),
        "bad checksum"
    );

    let mut udp_quote = request.clone();
    udp_quote[9] = 17;
    let error = icmp_unreachable(Ipv4Addr::new(192, 0, 2, 9), physical, &udp_quote);
    assert!(
        rewrite_icmp_error(&error, client, physical).is_none(),
        "an error quoting a non-echo packet never matches"
    );

    let echo = Echo {
        id: 77,
        seq: 3,
        payload: b"quote".to_vec(),
    };
    let reply = echo_reply_packet(destination, physical, 64, &echo);
    assert!(
        rewrite_icmp_error(&reply, client, physical).is_none(),
        "an echo reply is not an error"
    );
}

// ── live loopback echo (needs the platform ICMP privilege) ──

#[tokio::test]
async fn echo_roundtrip_preserves_id_seq_payload_and_ttl() {
    let Some(uplink) = loopback_uplink() else {
        eprintln!("skipping: cannot bind sockets to loopback (needs CAP_NET_RAW on Linux)");
        return;
    };
    let Some(mut engine) = engine(&uplink).await else {
        return;
    };
    let source = engine.uplink_source();
    assert_eq!(source, PEER, "the loopback uplink pins 127.0.0.1");
    assert_ne!(
        source,
        client(),
        "the on-wire source is the physical uplink address, never the TUN client"
    );

    let flow = FlowKey {
        protocol: 1,
        source: client(),
        destination: PEER,
        source_port: 0x4321,
        destination_port: 0,
    };
    let request = request_packet(client(), PEER, 0x4321, 7, b"direct-icmp-probe", 54);
    let parsed = packet::parse(&request, true).unwrap();
    assert_eq!(parsed.flow, flow);
    assert!(parsed.can_open);
    if !open_live(&mut engine, 5, &parsed, &request).await {
        return;
    }
    assert_eq!(engine.flow_count(), 1);

    let event = next_event(&mut engine).await;
    let DirectEvent::Packet { id, bytes } = event else {
        panic!("expected a packet event, got {event:?}");
    };
    assert_eq!(id, 5, "replies carry the flow id");
    let (from, ttl, echo) = parse_echo_reply_ip(&bytes, 1400).unwrap();
    assert_eq!(from, PEER);
    assert_eq!(ttl, 64);
    assert_eq!(
        echo.id, 0x4321,
        "the app-visible id survives the platform translation"
    );
    assert_eq!(echo.seq, 7);
    assert_eq!(echo.payload, b"direct-icmp-probe".to_vec());
    assert_eq!(
        &bytes[16..20],
        client().octets(),
        "the reply returns to the client"
    );
    assert!(checksums_ok(&bytes));

    let request = request_packet(client(), PEER, 0x4321, 8, b"second", 54);
    engine.forward_icmp(5, &request).await.unwrap();
    let event = next_event(&mut engine).await;
    let DirectEvent::Packet { bytes, .. } = event else {
        panic!("expected a packet event, got {event:?}");
    };
    let (_, _, echo) = parse_echo_reply_ip(&bytes, 1400).unwrap();
    assert_eq!(echo.seq, 8);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn two_flows_same_destination_demux_by_id() {
    let Some(uplink) = loopback_uplink() else {
        eprintln!("skipping: cannot bind sockets to loopback (needs CAP_NET_RAW on Linux)");
        return;
    };
    let Some(mut engine) = engine(&uplink).await else {
        return;
    };
    for (flow_id, echo_id) in [(11u64, 0x0101u16), (22, 0x0202)] {
        let request = request_packet(client(), PEER, echo_id, 1, b"demux", 64);
        let parsed = packet::parse(&request, true).unwrap();
        if !open_live(&mut engine, flow_id, &parsed, &request).await {
            return;
        }
    }
    assert_eq!(engine.flow_count(), 2);
    let mut seen = HashMap::new();
    for _ in 0..2 {
        let event = next_event(&mut engine).await;
        let DirectEvent::Packet { id, bytes } = event else {
            panic!("expected a packet event, got {event:?}");
        };
        let (_, _, echo) = parse_echo_reply_ip(&bytes, 1400).unwrap();
        seen.insert(id, echo.id);
    }
    assert_eq!(
        seen.remove(&11),
        Some(0x0101),
        "each reply lands on its flow"
    );
    assert_eq!(seen.remove(&22), Some(0x0202));
    engine.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn icmp_idle_expiry_closes_the_flow_and_rejects_late_traffic() {
    let Some(uplink) = loopback_uplink() else {
        eprintln!("skipping: cannot bind sockets to loopback (needs CAP_NET_RAW on Linux)");
        return;
    };
    let Some(mut engine) = engine(&uplink).await else {
        return;
    };
    let request = request_packet(client(), PEER, 0x0707, 1, b"idle", 64);
    let parsed = packet::parse(&request, true).unwrap();
    if !open_live(&mut engine, 9, &parsed, &request).await {
        return;
    }
    assert_eq!(engine.flow_count(), 1);

    tokio::time::advance(UDP_IDLE + Duration::from_secs(2)).await;
    let closed = loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let Some(event) = engine.poll_event() else {
            continue;
        };
        match event {
            DirectEvent::Packet { .. } => continue, // the loopback reply may arrive first
            closed => break closed,
        }
    };
    assert!(matches!(closed, DirectEvent::Closed { id: 9, .. }));
    assert_eq!(engine.flow_count(), 0);
    assert!(
        engine.forward_icmp(9, &request).await.is_err(),
        "a late request of the closed flow is not accepted"
    );
    assert!(engine.poll_event().is_none(), "a late reply never surfaces");
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_echo_request_keeps_live_mapping() {
    let Some(uplink) = loopback_uplink() else {
        return;
    };
    let Some(mut engine) = engine(&uplink).await else {
        return;
    };
    let request = request_packet(client(), PEER, 0x0711, 1, b"validation", 64);
    let parsed = packet::parse(&request, true).unwrap();
    if !open_live(&mut engine, 11, &parsed, &request).await {
        return;
    }
    let mut invalid = request.clone();
    invalid[22] ^= 1; // ICMP checksum, while the outer IPv4 parser stays valid.
    assert!(engine.forward_icmp(11, &invalid).await.is_err());
    assert!(engine.forward_icmp(11, &request).await.is_ok());
    assert_eq!(engine.flow_count(), 1);
    engine.shutdown().await.unwrap();
}

// ── privilege denial ──

#[tokio::test]
async fn permission_denial_is_explicit_for_icmp_only() {
    let Some(uplink) = loopback_iface() else {
        eprintln!("skipping: no loopback interface identity");
        return;
    };
    let mut engine = match IcmpEngine::new(DirectConfig {
        client: client(),
        peer: PEER,
        tun_name: "svpn0".to_owned(),
        tun_index: 3,
        mtu: 1400,
        uplink,
    })
    .await
    {
        Ok(engine) => engine,
        // Unprivileged Linux denies the device bind in the probe: an
        // explicit ICMP-only condition before any flow exists.
        Err(error) => {
            assert!(denied(&error), "unexpected engine error: {error:#}");
            return;
        }
    };
    let request = request_packet(client(), PEER, 0x0909, 1, b"denied", 64);
    let parsed = packet::parse(&request, true).unwrap();
    match engine.open_icmp(3, &parsed, &request).await {
        Ok(()) => eprintln!("skipping: ICMP sockets are permitted here"),
        Err(error) => {
            assert!(denied(&error), "unexpected open error: {error:#}");
            assert_eq!(engine.flow_count(), 0, "a denied open registers no flow");
            assert!(engine.poll_event().is_none());
        }
    }
    engine.shutdown().await.unwrap();
}
