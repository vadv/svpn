//! Direct engine socket paths over loopback: UDP relay sizes, idle expiry,
//! table capacity and the full TCP relay. These bind sockets to the loopback
//! interface the same way production binds the physical uplink — Linux
//! SO_BINDTODEVICE needs CAP_NET_RAW, so unprivileged Linux skips them.

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use socket2::{Domain, Socket, Type};
use svpn::{
    direct::{DirectConfig, DirectEngine, DirectEvent, MAX_FLOWS, UDP_IDLE, Uplink},
    packet::{self, FlowKey, internet_checksum},
};

const PEER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

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

async fn engine(uplink: &Uplink) -> DirectEngine {
    DirectEngine::new(DirectConfig {
        client: client(),
        peer: PEER,
        tun_name: "svpn0".to_owned(),
        tun_index: 3,
        mtu: 1400,
        uplink: uplink.clone(),
    })
    .await
    .unwrap()
}

fn udp_packet(flow: &FlowKey, payload: &[u8]) -> Vec<u8> {
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
    let checksum = transport_checksum(flow.source, flow.destination, 17, &bytes[20..]);
    let checksum = if checksum == 0 { u16::MAX } else { checksum };
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

fn checksums_ok(bytes: &[u8]) -> bool {
    internet_checksum(&bytes[..20]) == 0
        && transport_checksum(
            Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
            Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
            17,
            &bytes[20..],
        ) == 0
}

async fn next_packet(engine: &mut DirectEngine) -> DirectEvent {
    tokio::time::timeout(Duration::from_secs(3), engine.recv_event())
        .await
        .expect("event within 3 s")
}

fn event_packet_len(event: &DirectEvent) -> usize {
    let DirectEvent::Packet { bytes, .. } = event else {
        panic!("expected a packet event, got {event:?}");
    };
    bytes.len()
}

// ── UDP relay ──

#[tokio::test]
async fn udp_relay_sizes_zero_full_and_oversize() {
    let Some(uplink) = loopback_uplink() else {
        eprintln!("skipping: cannot bind sockets to loopback (needs CAP_NET_RAW on Linux)");
        return;
    };
    let mut engine = engine(&uplink).await;
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        while let Ok((len, from)) = echo.recv_from(&mut buf).await {
            let reply: Vec<u8> = match &buf[..len] {
                b"big" => vec![0xAB; 1373], // one byte past the MTU-28 limit
                other => other.to_vec(),
            };
            let _ = echo.send_to(&reply, from).await;
        }
    });

    let flow = FlowKey {
        protocol: 17,
        source: client(),
        destination: Ipv4Addr::LOCALHOST,
        source_port: 50001,
        destination_port: echo_port,
    };
    let request = udp_packet(&flow, b"ping");
    let parsed = packet::parse(&request, true).unwrap();
    engine.open_udp(5, &parsed, &request).await.unwrap();
    let event = next_packet(&mut engine).await;
    let DirectEvent::Packet { id, bytes } = event else {
        panic!("expected a packet event");
    };
    assert_eq!(id, 5, "replies carry the flow id");
    assert_eq!(&bytes[28..], b"ping");
    let parsed = packet::parse(&bytes, true).unwrap();
    assert_eq!(
        parsed.flow,
        FlowKey {
            protocol: 17,
            source: Ipv4Addr::LOCALHOST,
            destination: client(),
            source_port: echo_port,
            destination_port: 50001,
        }
    );
    assert!(checksums_ok(&bytes));

    // Zero-length datagram relays both ways.
    engine
        .forward_udp(5, &udp_packet(&flow, b""))
        .await
        .unwrap();
    let event = next_packet(&mut engine).await;
    assert_eq!(event_packet_len(&event), 28);

    // A full MTU reply (payload MTU-28) passes uncut.
    engine
        .forward_udp(5, &udp_packet(&flow, &vec![0x5a; 1372]))
        .await
        .unwrap();
    let event = next_packet(&mut engine).await;
    assert_eq!(event_packet_len(&event), 1400);

    // An oversized reply is rejected whole, not truncated into a valid one,
    // and the flow survives it.
    engine
        .forward_udp(5, &udp_packet(&flow, b"big"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        engine.poll_event().is_none(),
        "oversized reply must not surface"
    );
    engine
        .forward_udp(5, &udp_packet(&flow, b"alive"))
        .await
        .unwrap();
    let event = next_packet(&mut engine).await;
    let DirectEvent::Packet { bytes, .. } = event else {
        panic!("expected a packet event");
    };
    assert_eq!(&bytes[28..], b"alive");
    server.abort();
    engine.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn udp_idle_expiry_closes_the_flow() {
    let Some(uplink) = loopback_uplink() else {
        eprintln!("skipping: cannot bind sockets to loopback (needs CAP_NET_RAW on Linux)");
        return;
    };
    let mut engine = engine(&uplink).await;
    // A silent listener: datagrams land, nothing comes back.
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = silent.local_addr().unwrap().port();
    let flow = FlowKey {
        protocol: 17,
        source: client(),
        destination: Ipv4Addr::LOCALHOST,
        source_port: 50002,
        destination_port: port,
    };
    let request = udp_packet(&flow, b"probe");
    let parsed = packet::parse(&request, true).unwrap();
    engine.open_udp(8, &parsed, &request).await.unwrap();
    assert_eq!(engine.flow_count(), 1);

    tokio::time::advance(UDP_IDLE + Duration::from_secs(2)).await;
    let closed = loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if let Some(event) = engine.poll_event() {
            break event;
        }
    };
    assert!(matches!(closed, DirectEvent::Closed { id: 8, .. }));
    assert_eq!(engine.flow_count(), 0);
    // A late datagram of the closed flow is not accepted anywhere.
    assert!(engine.forward_udp(8, &request).await.is_err());
    assert!(engine.poll_event().is_none());
    engine.shutdown().await.unwrap();
}

// ── capacity ──

#[tokio::test]
async fn flow_table_capacity_is_bounded() {
    let Some(uplink) = loopback_uplink() else {
        eprintln!("skipping: cannot bind sockets to loopback (needs CAP_NET_RAW on Linux)");
        return;
    };
    let (soft, hard) = rlimit::Resource::NOFILE.get().unwrap();
    if hard < MAX_FLOWS as u64 + 512 || !rlimit::Resource::NOFILE.set(hard, hard).is_ok() {
        eprintln!("skipping: NOFILE hard limit {hard} (soft {soft}) cannot hold {MAX_FLOWS} flows");
        return;
    }
    let mut engine = engine(&uplink).await;
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = silent.local_addr().unwrap().port();
    for port_offset in 0..MAX_FLOWS as u16 {
        let flow = FlowKey {
            protocol: 17,
            source: client(),
            destination: Ipv4Addr::LOCALHOST,
            source_port: 40000 + port_offset,
            destination_port: port,
        };
        let request = udp_packet(&flow, b"x");
        let parsed = packet::parse(&request, true).unwrap();
        engine
            .open_udp(u64::from(port_offset) + 1, &parsed, &request)
            .await
            .unwrap_or_else(|error| panic!("flow {port_offset} must fit: {error:#}"));
    }
    assert_eq!(engine.flow_count(), MAX_FLOWS);
    let flow = FlowKey {
        protocol: 17,
        source: client(),
        destination: Ipv4Addr::LOCALHOST,
        source_port: 40000 + MAX_FLOWS as u16,
        destination_port: port,
    };
    let request = udp_packet(&flow, b"x");
    let parsed = packet::parse(&request, true).unwrap();
    let error = engine.open_udp(9999, &parsed, &request).await.unwrap_err();
    assert!(error.to_string().contains("capacity"));
    engine.shutdown().await.unwrap();
}

// ── full TCP relay ──

#[tokio::test]
async fn failed_udp_dial_cannot_leave_an_untracked_flow() {
    let uplink = Uplink {
        name: "svpn-invalid0".to_owned(),
        index: u32::MAX,
    };
    let mut engine = engine(&uplink).await;
    let flow = FlowKey {
        protocol: 17,
        source: client(),
        destination: Ipv4Addr::LOCALHOST,
        source_port: 50999,
        destination_port: 9,
    };
    let request = udp_packet(&flow, b"x");
    let parsed = packet::parse(&request, true).unwrap();
    engine.open_udp(77, &parsed, &request).await.unwrap();

    let event = tokio::time::timeout(Duration::from_secs(3), engine.recv_event())
        .await
        .expect("failed dial must close the registered flow");
    assert!(matches!(event, DirectEvent::Closed { id: 77, .. }));
    assert_eq!(engine.flow_count(), 0);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_relay_with_half_close() {
    let Some(uplink) = loopback_uplink() else {
        eprintln!("skipping: cannot bind sockets to loopback (needs CAP_NET_RAW on Linux)");
        return;
    };
    let mut engine = engine(&uplink).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let (mut reader, mut writer) = sock.split();
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
    });

    let flow = FlowKey {
        protocol: 6,
        source: client(),
        destination: Ipv4Addr::LOCALHOST,
        source_port: 51001,
        destination_port: echo_port,
    };
    let syn = tcp_syn(&flow);
    let parsed = packet::parse(&syn, true).unwrap();
    let rewritten = engine.open_tcp(9, &parsed, &syn).unwrap().unwrap();
    let nat_port = u16::from_be_bytes([rewritten[20], rewritten[21]]);
    let listen_port = engine.listen_port();

    // The application side of the kernel connection: peer:nat → client:listen.
    let client = tokio::task::spawn_blocking(move || {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        socket.set_reuse_address(true).unwrap();
        socket
            .bind(&socket2::SockAddr::from(SocketAddrV4::new(PEER, nat_port)))
            .unwrap();
        socket
            .connect(&socket2::SockAddr::from(SocketAddrV4::new(
                client(),
                listen_port,
            )))
            .unwrap();
        let mut stream: std::net::TcpStream = socket.into();
        stream.write_all(b"ping").unwrap();
        let mut echo = [0u8; 4];
        stream.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping");
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut tail = [0u8; 1];
        assert_eq!(stream.read(&mut tail).unwrap(), 0, "half-close reaches EOF");
    });
    client.await.unwrap();

    // Copy completion keeps the mapping in dwell and reports the close once.
    let closed = tokio::time::timeout(Duration::from_secs(3), engine.recv_event())
        .await
        .unwrap();
    assert!(matches!(closed, DirectEvent::Closed { id: 9, .. }));
    assert_eq!(engine.flow_count(), 1);
    engine.shutdown().await.unwrap();
}

fn tcp_syn(flow: &FlowKey) -> Vec<u8> {
    let mut bytes = vec![0u8; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&flow.source.octets());
    bytes[16..20].copy_from_slice(&flow.destination.octets());
    bytes[20..22].copy_from_slice(&flow.source_port.to_be_bytes());
    bytes[22..24].copy_from_slice(&flow.destination_port.to_be_bytes());
    bytes[24..28].copy_from_slice(&1000u32.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x02;
    let checksum = transport_checksum(flow.source, flow.destination, 6, &bytes[20..]);
    bytes[36..38].copy_from_slice(&checksum.to_be_bytes());
    let header = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&header.to_be_bytes());
    bytes
}
