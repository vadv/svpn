//! Shared session fixtures: link-level Session builders and packet helpers.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use svpn::control::{Control, Stats};
use svpn::link_io::{self, LinkIo};
use svpn::packet::FlowKey;
use svpn::selector::{Allowed, Selector};
use svpn::session::*;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

#[allow(dead_code)] // unused by some of the including test targets
pub fn link_session(tcp: bool) -> (Session, mpsc::Receiver<(link_io::Epoch, link_io::Event)>) {
    link_session_with(tcp, Control::new(tokio::io::empty(), tokio::io::sink()))
}

/// `link_session` with an injectable control transport: tests read the
/// JSONL the session actually puts on the wire.
#[allow(dead_code)] // unused by some of the including test targets
pub fn link_session_with(
    tcp: bool,
    control: Control,
) -> (Session, mpsc::Receiver<(link_io::Epoch, link_io::Event)>) {
    link_session_cap_with(tcp, control, 1)
}

#[allow(dead_code)] // unused by some of the including test targets
pub fn link_session_cap(
    tcp: bool,
    events_capacity: usize,
) -> (Session, mpsc::Receiver<(link_io::Epoch, link_io::Event)>) {
    link_session_cap_with(
        tcp,
        Control::new(tokio::io::empty(), tokio::io::sink()),
        events_capacity,
    )
}

fn link_session_cap_with(
    tcp: bool,
    control: Control,
    events_capacity: usize,
) -> (Session, mpsc::Receiver<(link_io::Epoch, link_io::Event)>) {
    let (events, returned) = mpsc::channel(events_capacity);
    let (_, packets) = mpsc::channel(1);
    let server_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
    let plane = if tcp {
        Plane::Tcp(TcpPlane {
            mode: svpn::tcp::Mode {
                port: 9000,
                camouflage: svpn::framing::Camouflage::None,
            },
            server_ip,
            token_index: HashMap::new(),
            flows: HashMap::new(),
            by_key: HashMap::new(),
            next_flow_id: 1,
        })
    } else {
        let mut plane = test_plane(Some(Selector::new(Allowed {
            mosh: true,
            ..Allowed::default()
        })));
        plane.server_ip = server_ip;
        Plane::Channels(Box::new(plane))
    };
    (
        Session {
            control,
            io: PacketIo::Link(LinkIo {
                epoch: link_io::Epoch {
                    link: 2,
                    generation: 7,
                },
                peer_ip: Ipv4Addr::new(10, 77, 0, 1),
                tag: String::new(),
                packets,
                events,
                stats: tokio::sync::watch::channel(Stats::default()).0,
                delivery: std::sync::Arc::default(),
            }),
            last_link_id: 0,
            readiness: None,
            client_ip: Ipv4Addr::new(10, 77, 0, 2),
            drop_prefix: String::new(),
            mtu: 1400,
            plane,
            tcp_listener: None,
            tasks: JoinSet::new(),
            task_events: mpsc::channel(64),
            incoming: mpsc::channel(CHANNEL_QUEUE),
            tcp_events: mpsc::channel(CHANNEL_QUEUE),
            tombstones: Tombstones::default(),
            stats: Stats::default(),
            round: None,
            next_round_attempt: u64::MAX / 2,
            health_at: None,
            burst: None,
            challenge: None,
            path_stats: HashMap::new(),
            switch_cooldown_until: std::time::Instant::now() - std::time::Duration::from_secs(1),
            // Unit tests drive challenges by hand: no cadence gate.
            remeasure: Some(tokio::time::Duration::ZERO),
            next_challenge_at: None,
        },
        returned,
    )
}

#[allow(dead_code)] // unused by some of the including test targets
pub fn assert_closed(event: (link_io::Epoch, link_io::Event), id: u64, key: FlowKey) {
    assert_eq!(
        event.0,
        link_io::Epoch {
            link: 2,
            generation: 7
        }
    );
    let link_io::Event::Closed {
        id: closed,
        key: closed_key,
    } = event.1
    else {
        panic!("expected close event");
    };
    assert_eq!((closed, closed_key), (id, key));
}

#[allow(dead_code)] // unused by some of the including test targets
pub fn tcp_packet(flags: u8) -> Vec<u8> {
    let mut bytes = super::udp_packet(false);
    bytes.resize(40, 0);
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[9] = 6;
    bytes[32] = 0x50;
    bytes[33] = flags;
    bytes
}

#[allow(dead_code)] // unused by some of the including test targets
pub fn test_key() -> FlowKey {
    FlowKey {
        protocol: 6,
        source: Ipv4Addr::new(10, 77, 0, 2),
        destination: Ipv4Addr::new(10, 77, 0, 1),
        source_port: 12345,
        destination_port: 9000,
    }
}

#[allow(dead_code)] // unused by some of the including test targets
pub fn test_plane(selector: Option<Selector>) -> ChannelsPlane {
    ChannelsPlane {
        prepared: HashMap::new(),
        selector,
        server_ip: None,
        quic_pin: None,
        tcp_port: None,
        tcp_camouflage: None,
        token_index: HashMap::new(),
        ports: HashMap::new(),
        bind: Ipv4Addr::UNSPECIFIED,
        quic: None,
        channels: HashMap::new(),
        draining: HashSet::new(),
        next_channel_id: 0,
        attempt: None,
        flows: HashMap::new(),
        by_key: HashMap::new(),
        next_client_flow_id: 1,
    }
}
