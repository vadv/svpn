//! Direct System Stack engine: NAT rewrite fidelity and TCP flow lifecycle
//! without a real TUN — kernel paths run over loopback (client 127.0.0.2,
//! peer 127.0.0.1), pure rewrite paths stay packet-level.

use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    sync::OnceLock,
    time::Duration,
};

use socket2::{Domain, Socket, Type};
use svpn::{
    direct::{DirectConfig, DirectEngine, DirectEvent, MAX_PENDING, PENDING_TIMEOUT, Uplink},
    packet::{self, FlowKey, internet_checksum},
};

const PEER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const DST: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

// These two kernel-side tests bind the same synthetic peer port range;
// serialize them so parallel test threads cannot race for a NAT port.
static KERNEL_TEST_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn kernel_test_lock() -> &'static tokio::sync::Mutex<()> {
    KERNEL_TEST_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// A real local IPv4 address (UDP connect is a route lookup, no packets):
/// macOS binds only 127.0.0.1 by default, so the client side of the loopback
/// pair needs a genuinely assigned address; the peer side stays 127.0.0.1.
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

fn config() -> DirectConfig {
    DirectConfig {
        client: client(),
        peer: PEER,
        tun_name: "svpn0".to_owned(),
        tun_index: 3,
        mtu: 1400,
        uplink: Uplink {
            name: "uplink0".to_owned(),
            index: 7,
        },
    }
}

async fn engine() -> DirectEngine {
    DirectEngine::new(config()).await.unwrap()
}

fn loopback_uplink() -> Option<Uplink> {
    let name = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };
    let mut manager = route_manager::RouteManager::new().ok()?;
    let index = manager
        .list()
        .ok()?
        .iter()
        .find(|route| route.if_name().is_some_and(|if_name| if_name == name))?
        .if_index()?;
    Some(Uplink {
        name: name.to_owned(),
        index,
    })
}

fn flow(protocol: u8, source_port: u16, destination_port: u16) -> FlowKey {
    FlowKey {
        protocol,
        source: client(),
        destination: DST,
        source_port,
        destination_port,
    }
}

/// IPv4+TCP packet with arbitrary IP options, TCP options, payload and a
/// recognizable fingerprint in every preserved header field.
fn build_tcp(
    flow: &FlowKey,
    flags: u8,
    seq: u32,
    ack: u32,
    tcp_options: &[u8],
    payload: &[u8],
    ip_options: &[u8],
) -> Vec<u8> {
    let ihl = 20 + ip_options.len();
    let segment = 20 + tcp_options.len() + payload.len();
    let total = ihl + segment;
    let mut bytes = vec![0u8; total];
    bytes[0] = 0x40 | (ihl as u8 / 4);
    bytes[1] = 0x10; // TOS
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // ID
    bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    bytes[8] = 37; // TTL
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&flow.source.octets());
    bytes[16..20].copy_from_slice(&flow.destination.octets());
    bytes[20..ihl].copy_from_slice(ip_options);
    bytes[ihl..ihl + 2].copy_from_slice(&flow.source_port.to_be_bytes());
    bytes[ihl + 2..ihl + 4].copy_from_slice(&flow.destination_port.to_be_bytes());
    bytes[ihl + 4..ihl + 8].copy_from_slice(&seq.to_be_bytes());
    bytes[ihl + 8..ihl + 12].copy_from_slice(&ack.to_be_bytes());
    bytes[ihl + 12] = ((20 + tcp_options.len()) as u8 / 4) << 4;
    bytes[ihl + 13] = flags;
    bytes[ihl + 14..ihl + 16].copy_from_slice(&0xfaf0u16.to_be_bytes()); // window
    bytes[ihl + 18..ihl + 20].copy_from_slice(&0xbeefu16.to_be_bytes()); // urgent
    bytes[ihl + 20..ihl + 20 + tcp_options.len()].copy_from_slice(tcp_options);
    bytes[ihl + 20 + tcp_options.len()..].copy_from_slice(payload);
    let checksum = transport_checksum(flow.source, flow.destination, 6, &bytes[ihl..]);
    bytes[ihl + 16..ihl + 18].copy_from_slice(&checksum.to_be_bytes());
    let header = internet_checksum(&bytes[..ihl]);
    bytes[10..12].copy_from_slice(&header.to_be_bytes());
    bytes
}

fn build_udp(flow: &FlowKey, payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut bytes = vec![0u8; total];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&flow.source.octets());
    bytes[16..20].copy_from_slice(&flow.destination.octets());
    bytes[20..22].copy_from_slice(&flow.source_port.to_be_bytes());
    bytes[22..24].copy_from_slice(&flow.destination_port.to_be_bytes());
    bytes[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes[28..].copy_from_slice(payload);
    let mut checksum = transport_checksum(flow.source, flow.destination, 17, &bytes[20..]);
    if checksum == 0 {
        checksum = u16::MAX;
    }
    bytes[26..28].copy_from_slice(&checksum.to_be_bytes());
    let header = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&header.to_be_bytes());
    bytes
}

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

/// Both checksums of a packet verify with the checksum fields in place.
fn checksums_ok(bytes: &[u8]) -> bool {
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    if internet_checksum(&bytes[..ihl]) != 0 {
        return false;
    }
    match bytes[9] {
        6 => transport_checksum(tuple_of(bytes).0, tuple_of(bytes).1, 6, &bytes[ihl..]) == 0,
        17 => transport_checksum(tuple_of(bytes).0, tuple_of(bytes).1, 17, &bytes[ihl..]) == 0,
        _ => false,
    }
}

fn tuple_of(bytes: &[u8]) -> (Ipv4Addr, Ipv4Addr) {
    (
        Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
    )
}

fn nat_port_of(rewritten: &[u8]) -> u16 {
    u16::from_be_bytes([rewritten[20], rewritten[21]])
}

// ── forward rewrite ──

#[tokio::test]
async fn syn_rewrite_preserves_options_and_recomputes_checksums() {
    let mut engine = engine().await;
    let flow = flow(6, 44444, 443);
    let options = [
        0x02, 0x04, 0x05, 0xb4, // MSS 1460
        0x01, 0x01, 0x01, 0x00, // NOPs + EOL padding
    ];
    let syn = build_tcp(&flow, 0x02, 0xdead_beef, 0, &options, &[], &[]);
    let parsed = packet::parse(&syn, true).unwrap();
    let rewritten = engine.open_tcp(1, &parsed, &syn).unwrap().unwrap();

    assert_eq!(tuple_of(&rewritten), (PEER, client()));
    assert_eq!(
        u16::from_be_bytes([rewritten[22], rewritten[23]]),
        engine.listen_port()
    );
    // Byte-exact preservation outside the rewritten tuple and checksums.
    let ihl = 20;
    for (index, (original, output)) in syn.iter().zip(rewritten.iter()).enumerate() {
        let tuple_or_checksum = (12..20).contains(&index)
            || (ihl..ihl + 4).contains(&index)
            || (10..12).contains(&index)
            || (ihl + 16..ihl + 18).contains(&index);
        if !tuple_or_checksum {
            assert_eq!(original, output, "byte {index} changed");
        }
    }
    assert!(checksums_ok(&rewritten));
    assert_eq!(rewritten[ihl + 4..ihl + 8], 0xdead_beefu32.to_be_bytes()); // seq
    assert_eq!(&rewritten[ihl + 20..ihl + 28], &options); // options intact
    assert_eq!(rewritten[ihl + 13], 0x02); // flags
    assert_eq!(rewritten[8], 37); // TTL
    assert_eq!(rewritten[4..6], 0x1234u16.to_be_bytes()); // ID
}

#[tokio::test]
async fn rewrite_keeps_variable_ip_and_tcp_headers() {
    let mut engine = engine().await;
    let flow = flow(6, 33333, 80);
    let ip_options = [0x01, 0x01, 0x01, 0x00];
    let tcp_options = [0x04, 0x02, 0x01, 0x01]; // SACK-permitted + NOPs
    let syn = build_tcp(&flow, 0x02, 77, 0, &tcp_options, &[], &ip_options);
    let parsed = packet::parse(&syn, true).unwrap();
    let rewritten = engine.open_tcp(2, &parsed, &syn).unwrap().unwrap();
    let ihl = 24;
    assert_eq!(&rewritten[20..ihl], &ip_options);
    assert_eq!(&rewritten[ihl + 20..ihl + 24], &tcp_options);
    assert!(checksums_ok(&rewritten));

    let data = build_tcp(&flow, 0x18, 78, 88, &tcp_options, b"data", &ip_options);
    let forwarded = engine.forward_tcp(2, &data).unwrap().unwrap();
    assert!(checksums_ok(&forwarded));
    assert_eq!(&forwarded[20..ihl], &ip_options);
    assert_eq!(&forwarded[ihl + 20..ihl + 24], &tcp_options);
    assert_eq!(&forwarded[forwarded.len() - 4..], b"data");
}

#[tokio::test]
async fn forward_rewrite_odd_payload_checksums() {
    let mut engine = engine().await;
    let flow = flow(6, 22222, 443);
    let syn = build_tcp(&flow, 0x02, 5, 0, &[], &[], &[]);
    let parsed = packet::parse(&syn, true).unwrap();
    engine.open_tcp(3, &parsed, &syn).unwrap().unwrap();
    let payload = build_tcp(&flow, 0x18, 6, 1, &[], b"hello", &[]); // odd length
    let rewritten = engine.forward_tcp(3, &payload).unwrap().unwrap();
    assert!(checksums_ok(&rewritten));
    assert_eq!(&rewritten[rewritten.len() - 5..], b"hello");
    assert_eq!(tuple_of(&rewritten), (PEER, client()));
}

// ── reverse rewrite ──

#[tokio::test]
async fn reverse_synack_maps_back_to_original_tuple() {
    let mut engine = engine().await;
    let flow = flow(6, 44444, 443);
    let syn = build_tcp(&flow, 0x02, 1000, 0, &[], &[], &[]);
    let parsed = packet::parse(&syn, true).unwrap();
    let rewritten = engine.open_tcp(1, &parsed, &syn).unwrap().unwrap();
    let nat_port = nat_port_of(&rewritten);

    // Kernel listener answer: client:listen → peer:nat.
    let kernel = FlowKey {
        protocol: 6,
        source: client(),
        destination: PEER,
        source_port: engine.listen_port(),
        destination_port: nat_port,
    };
    let synack = build_tcp(
        &kernel,
        0x12,
        9000,
        1001,
        &[0x01, 0x01, 0x01, 0x01],
        &[],
        &[],
    );
    let back = engine.rewrite_reverse(&synack).unwrap();
    let parsed = packet::parse(&back, true).unwrap();
    assert_eq!(
        parsed.flow,
        FlowKey {
            protocol: 6,
            source: DST,
            destination: client(),
            source_port: 443,
            destination_port: 44444,
        }
    );
    let ihl = 20;
    assert_eq!(back[ihl + 4..ihl + 8], 9000u32.to_be_bytes()); // seq kept
    assert_eq!(back[ihl + 8..ihl + 12], 1001u32.to_be_bytes()); // ack kept
    assert!(checksums_ok(&back));
    // A listener packet for a foreign tuple is not touched.
    let foreign = build_tcp(
        &FlowKey {
            protocol: 6,
            source: client(),
            destination: PEER,
            source_port: engine.listen_port() + 1,
            destination_port: nat_port,
        },
        0x12,
        1,
        1,
        &[],
        &[],
        &[],
    );
    assert!(engine.rewrite_reverse(&foreign).is_none());
}

// ── reservations ──

#[tokio::test]
async fn syn_retransmission_keeps_one_reservation() {
    let mut engine = engine().await;
    let key = flow(6, 11111, 443);
    let syn = build_tcp(&key, 0x02, 42, 0, &[], &[], &[]);
    let parsed = packet::parse(&syn, true).unwrap();
    let first = engine.open_tcp(5, &parsed, &syn).unwrap().unwrap();
    let second = engine.open_tcp(5, &parsed, &syn).unwrap().unwrap();
    assert_eq!(nat_port_of(&first), nat_port_of(&second));
    assert_eq!(engine.flow_count(), 1);
    // A different tuple gets a different reservation.
    let other = build_tcp(&flow(6, 11112, 443), 0x02, 1, 0, &[], &[], &[]);
    let parsed_other = packet::parse(&other, true).unwrap();
    let third = engine.open_tcp(6, &parsed_other, &other).unwrap().unwrap();
    assert_ne!(nat_port_of(&first), nat_port_of(&third));
}

#[tokio::test(start_paused = true)]
async fn pending_timeout_frees_the_reservation() {
    let mut engine = engine().await;
    let flow = flow(6, 12345, 443);
    let syn = build_tcp(&flow, 0x02, 7, 0, &[], &[], &[]);
    let parsed = packet::parse(&syn, true).unwrap();
    let first = engine.open_tcp(9, &parsed, &syn).unwrap().unwrap();
    tokio::time::advance(PENDING_TIMEOUT + Duration::from_secs(2)).await;
    let closed = loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if let Some(event) = engine.poll_event() {
            break event;
        }
    };
    assert!(matches!(closed, DirectEvent::Closed { id: 9, .. }));
    assert_eq!(engine.flow_count(), 0);
    let reopened = engine.open_tcp(10, &parsed, &syn).unwrap().unwrap();
    assert_ne!(nat_port_of(&first), nat_port_of(&reopened));
}

// ── teardown dwell ──

/// Complete the loopback kernel side so outbound failure retains the mapping.
#[tokio::test]
async fn failed_connect_retains_nat_mapping_for_kernel_fin() {
    let Some(uplink) = loopback_uplink() else {
        return;
    };
    let _kernel_guard = kernel_test_lock().lock().await;
    let destination = tokio::net::TcpListener::bind((PEER, 0)).await.unwrap();
    let destination_port = destination.local_addr().unwrap().port();
    drop(destination); // The outbound connect is refused.
    let mut cfg = config();
    cfg.uplink = uplink;
    let mut engine = DirectEngine::new(cfg).await.unwrap();
    let flow = FlowKey {
        protocol: 6,
        source: client(),
        destination: PEER,
        source_port: 44445,
        destination_port,
    };
    let syn = build_tcp(&flow, 0x02, 1000, 0, &[], &[], &[]);
    let parsed = packet::parse(&syn, true).unwrap();
    let rewritten = engine.open_tcp(70, &parsed, &syn).unwrap().unwrap();
    let nat_port = nat_port_of(&rewritten);
    let kernel_side = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    kernel_side.set_reuse_address(true).unwrap();
    kernel_side
        .bind(&socket2::SockAddr::from(SocketAddrV4::new(PEER, nat_port)))
        .unwrap();
    kernel_side
        .connect(&socket2::SockAddr::from(SocketAddrV4::new(
            client(),
            engine.listen_port(),
        )))
        .unwrap();
    drop(kernel_side);
    let event = tokio::time::timeout(Duration::from_secs(5), engine.recv_event())
        .await
        .expect("failed connect must report a terminal failure");
    assert!(matches!(event, DirectEvent::Failed { id: 70, .. }));
    assert!(engine.tcp_in_dwell(flow));
    assert_eq!(engine.flow_count(), 1);
    let fin = build_tcp(&flow, 0x11, 2000, 3000, &[], &[], &[]);
    assert!(engine.forward_tcp(70, &fin).unwrap().is_some());
    let kernel_fin = build_tcp(
        &FlowKey {
            protocol: 6,
            source: client(),
            destination: PEER,
            source_port: engine.listen_port(),
            destination_port: nat_port,
        },
        0x11,
        3001,
        2001,
        &[],
        &[],
        &[],
    );
    assert!(engine.rewrite_reverse(&kernel_fin).is_some());
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn dwell_keeps_both_mappings_then_retires_the_tuple() {
    let Some(uplink) = loopback_uplink() else {
        return;
    };
    let _kernel_guard = kernel_test_lock().lock().await;
    let destination = tokio::net::TcpListener::bind((PEER, 0)).await.unwrap();
    let destination_port = destination.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = destination.accept().await.unwrap();
        drop(stream);
    });
    let mut cfg = config();
    cfg.uplink = uplink;
    let mut engine = DirectEngine::new(cfg).await.unwrap();
    let flow = FlowKey {
        protocol: 6,
        source: client(),
        destination: PEER,
        source_port: 44444,
        destination_port,
    };
    let syn = build_tcp(&flow, 0x02, 1000, 0, &[], &[], &[]);
    let parsed = packet::parse(&syn, true).unwrap();
    let rewritten = engine.open_tcp(7, &parsed, &syn).unwrap().unwrap();
    let nat_port = nat_port_of(&rewritten);

    let kernel_side = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    // Reuse clears a TIME_WAIT left by an earlier run of the same test.
    kernel_side.set_reuse_address(true).unwrap();
    kernel_side
        .bind(&socket2::SockAddr::from(SocketAddrV4::new(PEER, nat_port)))
        .unwrap();
    kernel_side
        .connect(&socket2::SockAddr::from(SocketAddrV4::new(
            client(),
            engine.listen_port(),
        )))
        .unwrap();
    drop(kernel_side);

    server.await.unwrap();
    // Relay completion enters dwell but must not emit the terminal close
    // until the NAT mapping actually retires.
    tokio::time::timeout(Duration::from_secs(5), async {
        while !engine.tcp_in_dwell(flow) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        engine.poll_event().is_none(),
        "close is deferred until dwell ends"
    );
    // Real kernel accept/connect needs wall-clock I/O; pause only after it
    // completes so FIN_DWELL itself can be advanced deterministically.
    tokio::time::pause();

    // Retransmitted FIN keeps flowing in both directions during the dwell.
    let fin = build_tcp(&flow, 0x11, 2000, 3000, &[], &[], &[]);
    assert!(engine.forward_tcp(7, &fin).unwrap().is_some());
    let kernel_fin = build_tcp(
        &FlowKey {
            protocol: 6,
            source: client(),
            destination: PEER,
            source_port: engine.listen_port(),
            destination_port: nat_port,
        },
        0x11,
        3001,
        2001,
        &[],
        &[],
        &[],
    );
    let back = engine.rewrite_reverse(&kernel_fin).unwrap();
    assert_eq!(
        packet::parse(&back, true).unwrap().flow.destination,
        client()
    );
    assert!(checksums_ok(&back));

    // A fresh SYN on the same original tuple is rejected during the dwell.
    assert!(engine.open_tcp(8, &parsed, &syn).is_err());

    // After FIN_DWELL the tuple retires and reopens with a new nat port.
    let reopened = loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if let Ok(rewritten) = engine.open_tcp(8, &parsed, &syn) {
            break rewritten.unwrap();
        }
    };
    assert_ne!(nat_port_of(&reopened), nat_port);
    let closed = tokio::time::timeout(Duration::from_secs(5), engine.recv_event())
        .await
        .unwrap();
    assert!(matches!(closed, DirectEvent::Closed { id: 7, .. }));
}

// ── guards and capacity ──

#[tokio::test]
async fn pending_capacity_is_bounded() {
    let mut engine = engine().await;
    for port in 1..=MAX_PENDING as u16 {
        let syn = build_tcp(&flow(6, 20000 + port, 443), 0x02, 1, 0, &[], &[], &[]);
        let parsed = packet::parse(&syn, true).unwrap();
        engine
            .open_tcp(u64::from(port), &parsed, &syn)
            .unwrap_or_else(|error| panic!("reservation {port} must fit: {error:#}"));
    }
    let syn = build_tcp(&flow(6, 40000, 443), 0x02, 1, 0, &[], &[], &[]);
    let parsed = packet::parse(&syn, true).unwrap();
    let error = engine.open_tcp(999, &parsed, &syn).unwrap_err();
    assert!(error.to_string().contains("pending"));
    assert_eq!(engine.flow_count(), MAX_PENDING);
}

#[tokio::test]
async fn icmp_and_fragments_are_rejected() {
    let mut engine = engine().await;
    let tcp = flow(6, 1000, 443);
    let syn = build_tcp(&tcp, 0x02, 1, 0, &[], &[], &[]);
    let parsed = packet::parse(&syn, true).unwrap();
    engine.open_tcp(1, &parsed, &syn).unwrap().unwrap();

    let udp = build_udp(&flow(17, 1000, 53), b"x");
    assert!(engine.forward_udp(1, &udp).await.is_err());
    let icmp = svpn::packet::icmp_echo_request(client(), DST, 4, 1, b"probe");
    if let Some(parsed) = packet::parse(&icmp, true) {
        assert!(engine.open_tcp(2, &parsed, &icmp).is_err());
        assert!(engine.open_udp(2, &parsed, &icmp).await.is_err());
    }

    let mut fragmented = syn.clone();
    fragmented[6] |= 0x20; // more-fragments flag
    assert!(engine.forward_tcp(1, &fragmented).is_err());
    let mut stale = build_tcp(&tcp, 0x18, 5, 5, &[], b"z", &[]);
    stale[20..22].copy_from_slice(&9999u16.to_be_bytes()); // foreign source port
    assert!(engine.forward_tcp(1, &stale).is_err());
}

#[tokio::test]
async fn stale_flow_id_is_rejected() {
    let mut engine = engine().await;
    let syn = build_tcp(&flow(6, 15000, 443), 0x02, 1, 0, &[], &[], &[]);
    let parsed = packet::parse(&syn, true).unwrap();
    engine.open_tcp(4, &parsed, &syn).unwrap().unwrap();
    let data = build_tcp(&flow(6, 15000, 443), 0x18, 2, 1, &[], b"x", &[]);
    assert!(engine.forward_tcp(5, &data).is_err()); // stale generation
    assert!(engine.forward_tcp(4, &data).is_ok());
}

// ── uplink discovery and route ownership ──

#[test]
fn uplink_discovery_pins_the_ipv4_default_route() {
    let mut manager = route_manager::RouteManager::new().unwrap();
    let routes = manager.list().unwrap();
    let is_default = |route: &route_manager::Route| {
        route.destination() == std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED) && route.prefix() == 0
    };
    if !routes.iter().any(&is_default) {
        eprintln!("skipping: this environment has no IPv4 default route");
        return;
    }
    let uplink = svpn::direct::discover_uplink().unwrap();
    // Never a longest-prefix pick: the returned interface must carry an
    // actual default route (a 0.0.0.0/1 tunnel route does not count).
    assert!(routes.iter().any(|route| {
        is_default(route)
            && route.if_index() == Some(uplink.index)
            && route.if_name().is_some_and(|name| name == &uplink.name)
    }));
}

#[test]
fn local_network_down_is_not_icmp_feedback() {
    assert!(svpn::direct::is_icmp_feedback(&io::Error::from(
        io::ErrorKind::ConnectionRefused,
    )));
    assert!(svpn::direct::is_icmp_feedback(&io::Error::from(
        io::ErrorKind::HostUnreachable,
    )));
    assert!(!svpn::direct::is_icmp_feedback(&io::Error::from(
        io::ErrorKind::NetworkDown,
    )));
    assert!(!svpn::direct::is_icmp_feedback(&io::Error::from(
        io::ErrorKind::PermissionDenied,
    )));
}

#[cfg(target_os = "linux")]
#[test]
fn default_route_without_metric_beats_positive_metric_backup() {
    use std::net::IpAddr;
    let primary = route_manager::Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        .with_if_name("eth0".to_string())
        .with_if_index(1)
        .with_table(254);
    let backup = route_manager::Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        .with_if_name("eth1".to_string())
        .with_if_index(2)
        .with_table(254)
        .with_metric(100);
    let selected = svpn::direct::select_uplink(&[backup, primary]).unwrap();
    assert_eq!(selected.name, "eth0");
    assert_eq!(selected.index, 1);
}

#[test]
fn missing_route_cleanup_accepts_enoent_and_esrch() {
    for errno in [2, 3] {
        assert!(svpn::direct::route_error_is_missing(
            &std::io::Error::from_raw_os_error(errno)
        ));
    }
    assert!(!svpn::direct::route_error_is_missing(
        &std::io::Error::from_raw_os_error(13)
    ));
}

#[test]
fn peer_route_match_requires_exact_prefix_and_interface() {
    use std::net::IpAddr;
    let peer = Ipv4Addr::new(10, 77, 0, 1);
    let route = route_manager::Route::new(IpAddr::V4(peer), 32).with_if_index(3);
    #[cfg(target_os = "linux")]
    let route = route.with_table(254);
    assert!(svpn::direct::peer_route_matches(&route, peer, 3));
    assert!(
        !svpn::direct::peer_route_matches(&route, peer, 4),
        "a route via another interface is foreign"
    );
    let wide = route_manager::Route::new(IpAddr::V4(peer), 24).with_if_index(3);
    assert!(
        !svpn::direct::peer_route_matches(&wide, peer, 3),
        "only the /32 return route counts"
    );
    let other =
        route_manager::Route::new(IpAddr::V4(Ipv4Addr::new(10, 77, 0, 9)), 32).with_if_index(3);
    assert!(
        !svpn::direct::peer_route_matches(&other, peer, 3),
        "a different destination is not the peer route"
    );
    #[cfg(target_os = "linux")]
    {
        let off_table = route_manager::Route::new(IpAddr::V4(peer), 32)
            .with_if_index(3)
            .with_table(200);
        assert!(
            !svpn::direct::peer_route_matches(&off_table, peer, 3),
            "a non-main-table route is not the return route"
        );
    }
}

// ── shutdown ──

#[tokio::test]
async fn shutdown_is_bounded() {
    let mut engine = engine().await;
    for port in 1..=8u16 {
        let syn = build_tcp(&flow(6, 30000 + port, 443), 0x02, 1, 0, &[], &[], &[]);
        let parsed = packet::parse(&syn, true).unwrap();
        engine
            .open_tcp(u64::from(port), &parsed, &syn)
            .unwrap()
            .unwrap();
    }
    let port = engine.listen_port();
    engine.shutdown().await.unwrap();
    // The listener is gone: the OS port is free again.
    tokio::net::TcpListener::bind((client(), port))
        .await
        .unwrap();
}
