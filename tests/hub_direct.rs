//! Hub direct dispatch with a real engine over host addresses; no TUN.

use std::{net::Ipv4Addr, sync::Arc, time::Instant as StdInstant};

use svpn::{
    direct::{DirectConfig, DirectEngine, DirectEvent, Uplink},
    geo::Geo,
    hub::{Dispatched, Hub, Owner, QUEUE, Routes, StickyStats, Target},
    link_io::{Epoch, FIRST_PROBE_ID},
    packet::{self, FlowKey, internet_checksum},
    pool::Pool,
    server_spec::LinkParams,
    session, stats,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

const PEER: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
const HOME_DST: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 5);
const AWAY_DST: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);

/// Return a local IPv4 address that the engine listener can bind.
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

fn link_params(server: Ipv4Addr) -> LinkParams {
    LinkParams {
        server: server.to_string(),
        weight: 1,
        countries: Vec::new(),
        identity: None,
        user: None,
        ssh_port: 22,
        host_key: None,
        remote_bin: "svpn".to_string(),
        peer_tun_name: None,
        log_level: svpn::logging::Level::Info,
        udp_port_range: (0, 0),
        mimic: Vec::new(),
        remeasure_interval: None,
        tcp_port: None,
        tun_addr: Ipv4Addr::new(10, 77, 0, 2),
        peer_addr: PEER,
        addr_auto: false,
        mtu: 1280,
        tun_name: None,
        server_up: None,
        server_down: None,
    }
}

/// Country table: 1.0.0.0/24 → RU (home); 9.9.9.9 is a deliberate miss.
fn home_country() -> u32 {
    svpn::geo::pack_country("RU").unwrap()
}

fn country_table() -> Geo {
    Geo::from_ranges(vec![(0x0100_0000, 0x0100_00FF, home_country())])
}

/// Build a ready two-link hub with direct admitted through a real engine.
async fn direct_hub(direct: Option<DirectEngine>) -> (Hub, mpsc::Receiver<svpn::link_io::Packet>) {
    let (events, incoming) = mpsc::channel(QUEUE);
    let (outgoing, remote) = mpsc::channel(QUEUE);
    let mut pool = Pool::new([1, 1]);
    let now = tokio::time::Instant::now();
    for link in 0..2 {
        pool.ready(
            Epoch {
                link,
                generation: 1,
            },
            now,
        );
    }
    let hub = Hub {
        links: [
            Ipv4Addr::new(203, 0, 113, 10),
            Ipv4Addr::new(198, 51, 100, 7),
        ]
        .into_iter()
        .enumerate()
        .map(|(link, server)| {
            let mut params = link_params(server);
            params.peer_addr = PEER;
            svpn::hub::Link {
                params,
                outgoing: Some(outgoing.clone()),
                delivery: Arc::default(),
                epoch: Some(Epoch {
                    link,
                    generation: 1,
                }),
                latest: None,
                stats: stats::Snapshot::default(),
                last_reason: String::new(),
                assigned: Arc::default(),
            }
        })
        .collect(),
        pool,
        geo: None,
        country: Some(country_table()),
        home_country: Some(home_country()),
        uplink: None,
        direct,
        icmp: None,
        nodes: Vec::new(),
        exit_owners: std::collections::HashMap::new(),
        exit_state: None,
        sticky: StickyStats::default(),
        direct_stats: Default::default(),
        grace_until: None,
        tasks: JoinSet::new(),
        events,
        incoming,
        routes: Routes::default(),
        tombstones: session::Tombstones::default(),
        pair: watch::channel(None).0,
    };
    (hub, remote)
}

async fn engine() -> DirectEngine {
    DirectEngine::new(DirectConfig {
        client: client(),
        peer: PEER,
        tun_name: "svpn0".to_owned(),
        tun_index: 3,
        mtu: 1400,
        uplink: Uplink {
            name: "uplink0".to_owned(),
            index: 7,
        },
    })
    .await
    .unwrap()
}

fn syn(source_port: u16, destination: Ipv4Addr, destination_port: u16) -> Vec<u8> {
    tcp_packet(&FlowKey {
        protocol: 6,
        source: client(),
        destination,
        source_port,
        destination_port,
    })
}

/// Minimal valid TCP SYN with correct checksums.
fn tcp_packet(flow: &FlowKey) -> Vec<u8> {
    let mut bytes = vec![0u8; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&flow.source.octets());
    bytes[16..20].copy_from_slice(&flow.destination.octets());
    bytes[20..22].copy_from_slice(&flow.source_port.to_be_bytes());
    bytes[22..24].copy_from_slice(&flow.destination_port.to_be_bytes());
    bytes[24..26].copy_from_slice(&20u16.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = 0x02; // SYN
    let checksum = transport_checksum(flow, 6, &bytes[20..]);
    bytes[36..38].copy_from_slice(&checksum.to_be_bytes());
    let header = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&header.to_be_bytes());
    bytes
}

fn ack_of(flow: &FlowKey) -> Vec<u8> {
    let mut bytes = tcp_packet(flow);
    bytes[33] = 0x10; // ACK
    let checksum = transport_checksum(flow, 6, &bytes[20..]);
    bytes[36..38].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn transport_checksum(flow: &FlowKey, protocol: u8, segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + segment.len());
    buf.extend_from_slice(&flow.source.octets());
    buf.extend_from_slice(&flow.destination.octets());
    buf.push(0);
    buf.push(protocol);
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(segment);
    internet_checksum(&buf)
}

// ── classification: home before any VPN owner (spec §3.1) ──

#[tokio::test]
async fn home_syn_opens_direct_and_non_home_goes_remote() {
    let (mut hub, mut remote) = direct_hub(Some(engine().await)).await;
    let ip = client();

    // Home country: a rewritten `peer:nat → client:listen` SYN comes back
    // and the owner table records the direct flow id, not a link.
    let opened = hub.dispatch(&syn(40000, HOME_DST, 443), ip).await.unwrap();
    let Dispatched::Direct(rewritten) = opened.expect("the rewritten SYN returns") else {
        unreachable!()
    };
    let key = packet::parse(&syn(40000, HOME_DST, 443), true)
        .unwrap()
        .flow;
    let Target::Direct(id) = hub.routes.by_key[&key] else {
        panic!("home flow must be owned by direct");
    };
    assert!(id < FIRST_PROBE_ID);
    assert!(
        rewritten.len() == 40,
        "the rewrite preserves the packet size"
    );
    assert!(remote.try_recv().is_err(), "no VPN link sees the home SYN");

    // A later segment of the same flow forwards through the engine.
    let forwarded = hub.dispatch(&ack_of(&key), ip).await.unwrap();
    assert!(
        matches!(forwarded, Some(Dispatched::Direct(_))),
        "an established direct flow keeps rewriting through the engine"
    );
    assert!(remote.try_recv().is_err());

    // A non-home destination classifies exactly as before: remote owner.
    let away = syn(40001, AWAY_DST, 443);
    let key = packet::parse(&away, true).unwrap().flow;
    assert_eq!(hub.dispatch(&away, ip).await.unwrap(), None);
    let seen = remote.try_recv().unwrap();
    assert_eq!(seen.bytes, away);
    assert!(matches!(
        hub.routes.by_key[&key],
        Target::Remote(Owner { id, .. }) if id == seen.id
    ));
}

#[tokio::test]
async fn home_packets_without_an_engine_never_fall_back_to_the_vpn() {
    let (mut hub, mut remote) = direct_hub(None).await;
    let ip = client();
    let syn = syn(40010, HOME_DST, 443);
    let echo = packet::icmp_echo_request(ip, HOME_DST, 0x4321, 1, b"probe");
    for bytes in [&syn[..], &echo] {
        assert_eq!(hub.dispatch(bytes, ip).await.unwrap(), None);
    }
    assert!(
        remote.try_recv().is_err(),
        "the home country never leaks into the VPN"
    );
    assert!(hub.routes.by_key.is_empty(), "no owner is recorded");

    // ICMP degrades alone (spec §5.4): with a TCP/UDP engine present but
    // the ICMP sibling absent, home ICMP still must not use the VPN.
    let (mut hub, mut remote) = direct_hub(Some(engine().await)).await;
    assert_eq!(hub.dispatch(&echo, ip).await.unwrap(), None);
    assert!(remote.try_recv().is_err());
    assert!(hub.routes.by_key.is_empty());
}

// ── close reconciliation (spec §5.5) ──

#[tokio::test]
async fn direct_close_tombstones_only_the_current_generation() {
    let (mut hub, _remote) = direct_hub(Some(engine().await)).await;
    let ip = client();
    let syn = syn(40020, HOME_DST, 443);
    let key = packet::parse(&syn, true).unwrap().flow;
    hub.dispatch(&syn, ip).await.unwrap();
    let Target::Direct(id) = hub.routes.by_key[&key] else {
        panic!("direct owner expected");
    };

    // A late close from a replaced generation changes nothing.
    let replacement = id + 1;
    hub.routes.by_key.insert(key, Target::Direct(replacement));
    hub.handle_direct_event(DirectEvent::Closed { id, key }, &mut None)
        .await
        .unwrap();
    assert_eq!(hub.routes.by_key[&key], Target::Direct(replacement));
    assert!(
        hub.tombstones.entries.is_empty(),
        "a stale close must not tombstone the tuple"
    );

    // The current close forgets the route and tombstones TCP.
    hub.handle_direct_event(
        DirectEvent::Closed {
            id: replacement,
            key,
        },
        &mut None,
    )
    .await
    .unwrap();
    assert!(hub.routes.by_key.is_empty());
    assert!(hub.tombstones.active(&key, StdInstant::now()));
    let expected =
        packet::tcp_reset_for(&packet::parse(&ack_of(&key), true).unwrap()).map(Dispatched::Reset);
    assert_eq!(hub.dispatch(&ack_of(&key), ip).await.unwrap(), expected);
}

#[tokio::test]
async fn stale_direct_packet_is_dropped_before_tun_write() {
    let (mut hub, _remote) = direct_hub(None).await;
    let datagram = udp_reply(AWAY_DST, 53, 40031);
    let key = packet::parse(&datagram, false).unwrap().flow;
    hub.routes.by_key.insert(key, Target::Direct(9));
    // No TUN is available in this unit test. A stale generation must be
    // discarded before the missing-TUN error path is reached.
    hub.handle_direct_event(
        DirectEvent::Packet {
            id: 8,
            bytes: datagram,
        },
        &mut None,
    )
    .await
    .unwrap();
    assert_eq!(hub.routes.by_key[&key], Target::Direct(9));
}

#[tokio::test]
async fn current_direct_reply_reaches_the_tun_write_path() {
    let (mut hub, _remote) = direct_hub(None).await;
    let reply = udp_reply(AWAY_DST, 53, 40032);
    let key = packet::parse(&reply, false).unwrap().flow;
    hub.routes.by_key.insert(key, Target::Direct(9));
    let error = hub
        .handle_direct_event(
            DirectEvent::Packet {
                id: 9,
                bytes: reply,
            },
            &mut None,
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("direct packet without client TUN")
    );
}

#[tokio::test]
async fn direct_dispatch_error_reconciles_without_a_close_event() {
    let (mut hub, _remote) = direct_hub(None).await;
    let datagram = udp_datagram(40033, AWAY_DST, 53);
    let key = packet::parse(&datagram, true).unwrap().flow;
    hub.routes.by_key.insert(key, Target::Direct(12));
    assert_eq!(hub.dispatch(&datagram, client()).await.unwrap(), None);
    assert!(!hub.routes.by_key.contains_key(&key));
    assert!(hub.tombstones.entries.is_empty());
    assert_eq!((hub.direct_stats.failed, hub.direct_stats.closed), (1, 1));
}

#[tokio::test]
async fn direct_failed_event_counts_background_failure() {
    let (mut hub, _remote) = direct_hub(None).await;
    let datagram = udp_datagram(40034, AWAY_DST, 53);
    let key = packet::parse(&datagram, true).unwrap().flow;
    hub.routes.by_key.insert(key, Target::Direct(13));
    hub.handle_direct_event(DirectEvent::Failed { id: 13, key }, &mut None)
        .await
        .unwrap();
    assert!(!hub.routes.by_key.contains_key(&key));
    assert_eq!((hub.direct_stats.failed, hub.direct_stats.closed), (1, 1));
}

#[tokio::test]
async fn udp_close_forgets_without_a_tombstone() {
    let (mut hub, mut remote) = direct_hub(Some(engine().await)).await;
    let ip = client();
    // A UDP direct owner (no socket path needed: the owner table is the
    // subject here, the engine only supplies the id space).
    // The freed tuple classifies again without a tombstone block — over
    // the VPN for an away destination, as a normal flow.
    let datagram = udp_datagram(40030, AWAY_DST, 53);
    let key = packet::parse(&datagram, true).unwrap().flow;
    hub.routes.by_key.insert(key, Target::Direct(7));
    hub.handle_direct_event(DirectEvent::Closed { id: 7, key }, &mut None)
        .await
        .unwrap();
    assert!(
        hub.tombstones.entries.is_empty(),
        "only TCP tuples are tombstoned"
    );
    // The freed tuple classifies again — over the VPN, as a normal flow.
    assert_eq!(hub.dispatch(&datagram, ip).await.unwrap(), None);
    assert!(matches!(
        hub.routes.by_key[&key],
        Target::Remote(Owner { .. })
    ));
    assert_eq!(remote.try_recv().unwrap().bytes, datagram);
}

fn udp_reply(source: Ipv4Addr, source_port: u16, client_port: u16) -> Vec<u8> {
    let mut bytes = udp_datagram(client_port, source, source_port);
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&client().octets());
    bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
    bytes[22..24].copy_from_slice(&client_port.to_be_bytes());
    let flow = FlowKey {
        protocol: 17,
        source,
        destination: client(),
        source_port,
        destination_port: client_port,
    };
    let checksum = transport_checksum(&flow, 17, &bytes[20..]);
    bytes[26..28].copy_from_slice(&checksum.to_be_bytes());
    let header = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&header.to_be_bytes());
    bytes
}

fn udp_datagram(source_port: u16, destination: Ipv4Addr, destination_port: u16) -> Vec<u8> {
    let flow = FlowKey {
        protocol: 17,
        source: client(),
        destination,
        source_port,
        destination_port,
    };
    let payload = b"q";
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
    let checksum = transport_checksum(&flow, 17, &bytes[20..]);
    bytes[26..28].copy_from_slice(&checksum.to_be_bytes());
    let header = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&header.to_be_bytes());
    bytes
}

// ── reverse-NAT before admission (spec §5.5) ──

#[tokio::test]
async fn kernel_listener_packet_maps_back_before_admission() {
    let (mut hub, mut remote) = direct_hub(Some(engine().await)).await;
    let ip = client();
    let syn = syn(40040, HOME_DST, 443);
    let key = packet::parse(&syn, true).unwrap().flow;
    let Dispatched::Direct(rewritten) = hub.dispatch(&syn, ip).await.unwrap().unwrap() else {
        unreachable!()
    };
    let nat_port = u16::from_be_bytes([rewritten[20], rewritten[21]]);
    let listen_port = u16::from_be_bytes([rewritten[22], rewritten[23]]);

    // The kernel listener's SYN-ACK `client:listen → peer:nat` must map
    // back to the original tuple — not be classified as a new flow.
    let kernel = FlowKey {
        protocol: 6,
        source: client(),
        destination: PEER,
        source_port: listen_port,
        destination_port: nat_port,
    };
    let mut bytes = tcp_packet(&kernel);
    bytes[33] = 0x12; // SYN-ACK
    let checksum = transport_checksum(&kernel, 6, &bytes[20..]);
    bytes[36..38].copy_from_slice(&checksum.to_be_bytes());
    let mapped = hub.dispatch(&bytes, ip).await.unwrap().unwrap();
    let Dispatched::Direct(back) = mapped else {
        panic!("the reverse segment is rewritten, not admitted");
    };
    assert_eq!(
        packet::parse(&back, true).unwrap().flow,
        FlowKey {
            protocol: 6,
            source: HOME_DST,
            destination: client(),
            source_port: 443,
            destination_port: 40040,
        }
    );
    // The original owner stays; the kernel tuple is not an owner.
    assert!(matches!(hub.routes.by_key[&key], Target::Direct(_)));
    assert!(remote.try_recv().is_err());
}

#[tokio::test]
async fn direct_owner_survives_the_failure_of_an_unrelated_link() {
    let (mut hub, _remote) = direct_hub(Some(engine().await)).await;
    let ip = client();
    let syn = syn(40050, HOME_DST, 443);
    let key = packet::parse(&syn, true).unwrap().flow;
    hub.dispatch(&syn, ip).await.unwrap();

    // A link task dying retires its own owners only (spec §5.5).
    let retired = hub.routes.remove_epoch(Epoch {
        link: 0,
        generation: 1,
    });
    assert!(retired.is_empty());
    assert!(matches!(hub.routes.by_key[&key], Target::Direct(_)));
}
