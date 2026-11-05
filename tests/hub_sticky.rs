//! Explicit sticky dispatch: first-match order, via owner semantics, local.

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use svpn::geo::Geo;
use svpn::hub::*;
use svpn::link_io::Epoch;
use svpn::pool::Pool;
use svpn::server_spec::LinkParams;
use svpn::sticky::{Selector, StickyBlock, Via};
use svpn::{session, stats};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);

fn params(server: &str, label: &str) -> LinkParams {
    LinkParams {
        label: label.to_owned(),
        server: server.to_owned(),
        weight: 1,
        identity: None,
        user: None,
        ssh_port: 22,
        host_key: None,
        remote_bin: "svpn".to_owned(),
        peer_tun_name: None,
        log_level: svpn::logging::Level::Info,
        udp_port_range: (0, 0),
        mimic: Vec::new(),
        remeasure_interval: None,
        tcp_port: None,
        tun_addr: Ipv4Addr::new(10, 77, 0, 2),
        peer_addr: Ipv4Addr::new(10, 77, 0, 1),
        addr_auto: false,
        mtu: 1280,
        tun_name: None,
        server_up: None,
        server_down: None,
    }
}

fn block(label: &str, selector: Selector, via: Via) -> StickyBlock {
    StickyBlock {
        label: label.to_owned(),
        selector,
        via,
        every: Duration::from_secs(300),
    }
}

/// Two ready links (s0, s1) with the given sticky blocks.
fn sticky_hub(blocks: Vec<StickyBlock>) -> Hub {
    let (events, incoming) = mpsc::channel(QUEUE);
    // Keep receivers alive for the hub's lifetime, or try_send fails closed.
    // Leaked intentionally: test-only fixture, the OS reclaims at exit.
    let keep: &'static [_] = Box::leak(
        (0..2)
            .map(|_| mpsc::channel::<svpn::link_io::Packet>(8))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
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
    let sticky_via: Vec<svpn::sticky::ResolvedVia> = blocks
        .iter()
        .map(|b| match &b.via {
            Via::Local => svpn::sticky::ResolvedVia::Local,
            Via::Servers(labels) => svpn::sticky::ResolvedVia::Links(
                labels
                    .iter()
                    .map(|label| match label.as_str() {
                        "s0" => 0usize,
                        "s1" => 1usize,
                        other => panic!("unknown label {other}"),
                    })
                    .collect(),
            ),
        })
        .collect();
    Hub {
        links: ["a.example", "b.example"]
            .iter()
            .enumerate()
            .map(|(link, server)| Link {
                params: params(server, if link == 0 { "s0" } else { "s1" }),
                outgoing: Some(keep[link].0.clone()),
                delivery: Arc::default(),
                epoch: Some(Epoch {
                    link,
                    generation: 1,
                }),
                latest: None,
                stats: stats::Snapshot::default(),
                last_reason: String::new(),
                assigned: Arc::default(),
            })
            .collect(),
        policy: svpn::cli::ExitPolicy::Balance,
        pool,
        geo: None,
        country: None,
        stickies: blocks
            .into_iter()
            .map(svpn::sticky::RuntimeSticky::new)
            .collect(),
        sticky_via,
        sticky_updates: None,
        sticky_task: None,
        local: None,
        local_task: None,
        local_cleanup: None,
        nodes: vec![("a.example".to_owned(), 1), ("b.example".to_owned(), 1)],
        exit_owners: Default::default(),
        exit_state: None,
        sticky: StickyStats::default(),
        local_stats: LocalStats::default(),
        grace_until: None,
        tasks: JoinSet::new(),
        events,
        incoming,
        routes: Routes::default(),
        tombstones: session::Tombstones::default(),
        pair: watch::channel(None).0,
    }
}

fn packet_to(destination: Ipv4Addr, source_port: u16) -> Vec<u8> {
    let mut bytes = common::tcp_packet(false);
    bytes[16..20].copy_from_slice(&destination.octets());
    bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
    bytes
}

/// Dispatch one SYN and report the link it landed on, if remote.
fn dispatch_link(hub: &mut Hub, destination: Ipv4Addr, port: u16) -> Option<Option<usize>> {
    hub.dispatch(&packet_to(destination, port), CLIENT).unwrap();
    let flow = svpn::packet::FlowKey {
        source: CLIENT,
        destination,
        protocol: 6,
        source_port: port,
        destination_port: 9000,
    };
    match hub.routes.by_key.get(&flow) {
        Some(Target::Remote(owner)) => Some(Some(owner.epoch.link)),
        Some(Target::Direct(_)) => Some(None),
        None => None,
    }
}

#[test]
fn first_matching_block_wins() {
    // Both blocks match 1.2.3.4; the first (longest intent) wins.
    let mut hub = sticky_hub(vec![
        block(
            "exact",
            Selector::Ips(vec![svpn::sticky::IpNet::parse("1.2.3.4").unwrap()]),
            Via::Servers(vec!["s1".into()]),
        ),
        block(
            "prefix",
            Selector::Ips(vec![svpn::sticky::IpNet::parse("1.2.3.0/24").unwrap()]),
            Via::Servers(vec!["s0".into()]),
        ),
    ]);
    let dest = Ipv4Addr::new(1, 2, 3, 4);
    assert_eq!(dispatch_link(&mut hub, dest, 1000), Some(Some(1)));
    assert_eq!(hub.sticky.block_hit, 1);
    // An unmatched destination uses the automatic strategy.
    assert!(dispatch_link(&mut hub, Ipv4Addr::new(9, 9, 9, 9), 1001).is_some());
    assert_eq!(hub.sticky.block_hit, 1, "auto traffic matches no block");
}

#[test]
fn via_owner_is_stable_and_fails_over_without_snapback() {
    let mut hub = sticky_hub(vec![block(
        "cf",
        Selector::Ips(vec![svpn::sticky::IpNet::parse("1.2.3.4").unwrap()]),
        Via::Servers(vec!["s0".into(), "s1".into()]),
    )]);
    let dest = Ipv4Addr::new(1, 2, 3, 4);
    let owner = dispatch_link(&mut hub, dest, 1000).unwrap().unwrap();
    assert_eq!(dispatch_link(&mut hub, dest, 1001), Some(Some(owner)));
    hub.pool
        .failed(
            Epoch {
                link: owner,
                generation: 1,
            },
            tokio::time::Instant::now(),
            "test",
        )
        .unwrap();
    let reserve = dispatch_link(&mut hub, dest, 1002).unwrap().unwrap();
    assert_ne!(reserve, owner, "failover moves off the dead owner");
    let retries = hub
        .pool
        .retry_due(tokio::time::Instant::now() + Duration::from_secs(2))
        .unwrap();
    assert!(hub.pool.ready(retries[0], tokio::time::Instant::now()));
    assert_eq!(
        dispatch_link(&mut hub, dest, 1003),
        Some(Some(reserve)),
        "no snap-back after the owner recovers"
    );
    assert_eq!(hub.sticky.failover_moves, 1);
}

#[test]
fn via_local_routes_to_the_local_path() {
    let mut hub = sticky_hub(vec![block(
        "home",
        Selector::Ips(vec![svpn::sticky::IpNet::parse("1.2.3.4").unwrap()]),
        Via::Local,
    )]);
    hub.dispatch(&packet_to(Ipv4Addr::new(1, 2, 3, 4), 1000), CLIENT)
        .unwrap();
    assert!(
        hub.routes.by_key.is_empty(),
        "local traffic never picks a link"
    );
    assert_eq!(
        hub.local_stats.failed, 1,
        "no local server started: counted, never leaked to VPN"
    );
}

#[test]
fn local_block_wins_over_a_later_server_block() {
    let mut hub = sticky_hub(vec![
        block(
            "keep-local",
            Selector::Ips(vec![svpn::sticky::IpNet::parse("1.2.3.4").unwrap()]),
            Via::Local,
        ),
        block(
            "vpn",
            Selector::Ips(vec![svpn::sticky::IpNet::parse("1.2.3.4").unwrap()]),
            Via::Servers(vec!["s0".into()]),
        ),
    ]);
    hub.dispatch(&packet_to(Ipv4Addr::new(1, 2, 3, 4), 1000), CLIENT)
        .unwrap();
    assert!(hub.routes.by_key.is_empty());
    assert_eq!(hub.local_stats.failed, 1);
}

#[test]
fn countries_selector_uses_the_country_table() {
    let dest = Ipv4Addr::new(93, 184, 216, 34);
    let packed = svpn::geo::pack_country("DE").unwrap();
    let mut hub = sticky_hub(vec![block(
        "eu",
        Selector::Countries(vec!["DE".to_owned()]),
        Via::Servers(vec!["s1".into()]),
    )]);
    hub.country = Some(Geo::from_ranges(vec![(
        u32::from(dest),
        u32::from(dest),
        packed,
    )]));
    assert_eq!(dispatch_link(&mut hub, dest, 1000), Some(Some(1)));
    assert_eq!(hub.sticky.block_hit, 1);
    // A country miss is automatic traffic.
    assert!(dispatch_link(&mut hub, Ipv4Addr::new(8, 8, 8, 8), 1001).is_some());
    assert_eq!(hub.sticky.block_hit, 1);
}

#[test]
fn names_selector_uses_the_resolved_set() {
    let dest = Ipv4Addr::new(203, 0, 113, 10);
    let mut hub = sticky_hub(vec![block(
        "claude",
        Selector::Names(vec!["claude.ai".to_owned()]),
        Via::Servers(vec!["s0".into()]),
    )]);
    // Before the first resolve nothing is pinned: automatic pick.
    assert!(dispatch_link(&mut hub, dest, 1000).is_some());
    assert_eq!(hub.sticky.block_hit, 0);
    // The resolver fills the set; the next flow pins to s0.
    hub.stickies[0].resolved.insert(dest);
    assert_eq!(dispatch_link(&mut hub, dest, 1001), Some(Some(0)));
    assert_eq!(hub.sticky.block_hit, 1);
}

#[test]
fn restored_owner_removed_from_via_relinquishes_the_group() {
    // The persisted owner is restored, then the config drops it from via.
    let mut hub = sticky_hub(vec![block(
        "cf",
        Selector::Ips(vec![svpn::sticky::IpNet::parse("1.2.3.4").unwrap()]),
        Via::Servers(vec!["s0".into(), "s1".into()]),
    )]);
    let dest = Ipv4Addr::new(1, 2, 3, 4);
    let owner = dispatch_link(&mut hub, dest, 1000).unwrap().unwrap();
    // Simulate a restored owner that no longer serves the changed via list.
    hub.sticky_via = vec![svpn::sticky::ResolvedVia::Links(vec![1 - owner])];
    let after = dispatch_link(&mut hub, dest, 1001).unwrap().unwrap();
    assert_ne!(after, owner, "a removed owner cannot keep the group");
}

#[test]
fn sticky_failover_persists_under_the_canonical_key() {
    let dir = std::env::temp_dir().join(format!("svpn-sticky-state-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.json");
    let mut hub = sticky_hub(vec![block(
        "cf",
        Selector::Ips(vec![svpn::sticky::IpNet::parse("1.2.3.4").unwrap()]),
        Via::Servers(vec!["s0".into(), "s1".into()]),
    )]);
    hub.exit_state = Some(svpn::exit_state::ExitState::load(Some(path.clone())));
    let dest = Ipv4Addr::new(1, 2, 3, 4);
    let owner = dispatch_link(&mut hub, dest, 1000).unwrap().unwrap();
    hub.pool
        .failed(
            Epoch {
                link: owner,
                generation: 1,
            },
            tokio::time::Instant::now(),
            "test",
        )
        .unwrap();
    let reserve = dispatch_link(&mut hub, dest, 1001).unwrap().unwrap();
    hub.exit_state.as_mut().unwrap().flush();
    let reloaded = svpn::exit_state::ExitState::load(Some(path.clone()));
    assert_eq!(
        reloaded
            .owner(&svpn::exit_state::ExitKey::Sticky("ip:1.2.3.4".to_owned()))
            .map(String::as_str),
        Some(hub.nodes[reserve].0.as_str()),
        "the failover deviation persists under the canonical key"
    );
    let _ = std::fs::remove_dir_all(dir);
}
