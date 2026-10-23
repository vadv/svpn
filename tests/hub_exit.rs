//! Sticky exit: hub picks a fixed owner per destination group.

use std::net::Ipv4Addr;
use std::sync::Arc;

use svpn::geo::Geo;
use svpn::hub::*;
use svpn::link_io::Epoch;
use svpn::pool::Pool;
use svpn::server_spec::LinkParams;
use svpn::{packet, session, stats};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

fn link_params(server: Ipv4Addr, weight: u32) -> LinkParams {
    LinkParams {
        server: server.to_string(),
        weight,
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
        peer_addr: Ipv4Addr::new(10, 77, 0, 1),
        addr_auto: false,
        mtu: 1280,
        tun_name: None,
        server_up: None,
        server_down: None,
    }
}

/// Two fake ASNs: 1.0.0.0/24 → AS100, 2.0.0.0/24 → AS200.
fn sticky_hub(weights: &[u32]) -> Hub {
    sticky_hub_state(weights, true)
}

/// All links stay Connecting (never Ready): the startup grace window.
fn connecting_hub(weights: &[u32]) -> Hub {
    sticky_hub_state(weights, false)
}

fn sticky_hub_state(weights: &[u32], ready: bool) -> Hub {
    let servers: Vec<Ipv4Addr> = weights
        .iter()
        .enumerate()
        .map(|(i, _)| Ipv4Addr::new(192, 0, 2, i as u8 + 1))
        .collect();
    let (events, incoming) = mpsc::channel(QUEUE);
    let mut pool = Pool::new(weights.iter().copied());
    let now = Instant::now();
    if ready {
        for link in 0..weights.len() {
            pool.ready(
                Epoch {
                    link,
                    generation: 1,
                },
                now,
            );
        }
    }
    Hub {
        links: servers
            .iter()
            .enumerate()
            .map(|(link, &server)| Link {
                params: link_params(server, weights[link]),
                outgoing: None,
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
        pool,
        geo: Some(Geo::from_ranges(vec![
            (0x0100_0000, 0x0100_00FF, 100),
            (0x0200_0000, 0x0200_00FF, 200),
        ])),
        nodes: servers
            .iter()
            .enumerate()
            .map(|(i, s)| (s.to_string(), weights[i]))
            .collect(),
        exit_owners: std::collections::HashMap::new(),
        exit_state: None,
        sticky: StickyStats::default(),
        grace_until: None,
        tasks: JoinSet::new(),
        events,
        incoming,
        routes: Routes::default(),
        tombstones: session::Tombstones::default(),
        pair: watch::channel(None).0,
    }
}

fn flow(destination: Ipv4Addr, source_port: u16) -> packet::FlowKey {
    packet::FlowKey {
        protocol: 6,
        source: Ipv4Addr::new(10, 77, 0, 2),
        destination,
        source_port,
        destination_port: 443,
    }
}

fn pick_link(hub: &mut Hub, key: packet::FlowKey) -> Epoch {
    hub.pick(&key).expect("a Ready link exists")
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("svpn-hub-exit-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── sticky pick ──

#[test]
fn same_asn_always_same_node() {
    let mut hub = sticky_hub(&[1, 1]);
    let first = pick_link(&mut hub, flow(Ipv4Addr::new(1, 0, 0, 5), 1000));
    for port in 1001..1050 {
        assert_eq!(
            pick_link(&mut hub, flow(Ipv4Addr::new(1, 0, 0, 7), port)),
            first,
            "same ASN must keep the node"
        );
    }
}

#[test]
fn uncovered_address_sticks_per_32() {
    let mut hub = sticky_hub(&[1, 1]);
    let first = pick_link(&mut hub, flow(Ipv4Addr::new(9, 9, 9, 9), 1000));
    for port in 1001..1050 {
        assert_eq!(
            pick_link(&mut hub, flow(Ipv4Addr::new(9, 9, 9, 9), port)),
            first,
            "uncovered /32 must keep the node"
        );
    }
}

#[test]
fn dead_owner_falls_to_next_in_order() {
    let mut hub = sticky_hub(&[1, 1]);
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let primary = pick_link(&mut hub, key);
    hub.pool.failed(primary, Instant::now(), "test").unwrap();
    assert_ne!(
        pick_link(&mut hub, key),
        primary,
        "group must move to the reserve"
    );
}

#[test]
fn recovered_node_does_not_take_the_group_back() {
    let mut hub = sticky_hub(&[1, 1]);
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let primary = pick_link(&mut hub, key);
    let now = Instant::now();
    hub.pool.failed(primary, now, "test").unwrap();
    let reserve = pick_link(&mut hub, key);
    // The primary reconnects: retry_due bumps the generation, then Ready.
    let retries = hub
        .pool
        .retry_due(now + std::time::Duration::from_secs(2))
        .unwrap();
    assert!(hub.pool.ready(retries[0], now));
    assert_eq!(
        pick_link(&mut hub, flow(Ipv4Addr::new(1, 0, 0, 9), 2000)),
        reserve,
        "an alive owner keeps the group — no snap-back"
    );
}

#[test]
fn reserve_is_not_recaptured_by_a_recovered_reserve() {
    // A dies → group on B; B dies → group on C; B recovers → group stays on C.
    let mut hub = sticky_hub(&[1, 1, 1]);
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let now = Instant::now();
    let later = now + std::time::Duration::from_secs(2);
    let a = pick_link(&mut hub, key);
    hub.pool.failed(a, now, "test").unwrap();
    let b = pick_link(&mut hub, key);
    hub.pool.failed(b, now, "test").unwrap();
    let c = pick_link(&mut hub, key);
    // B reconnects (new generation) while C keeps serving.
    let retry_b = hub
        .pool
        .retry_due(later)
        .unwrap()
        .into_iter()
        .find(|epoch| epoch.link == b.link)
        .expect("B retries");
    assert!(hub.pool.ready(retry_b, later));
    assert_eq!(
        pick_link(&mut hub, key),
        c,
        "a recovered reserve must not recapture the group from its alive owner"
    );
}

#[test]
fn checking_owner_gets_no_new_flows() {
    let mut hub = sticky_hub(&[1, 1]);
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let primary = pick_link(&mut hub, key);
    assert!(hub.pool.checking(primary));
    assert_ne!(
        pick_link(&mut hub, key),
        primary,
        "Checking is excluded from new picks"
    );
}

#[test]
fn sticky_counters_track_lookup_and_failover() {
    let mut hub = sticky_hub(&[1, 1]);
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let primary = pick_link(&mut hub, key);
    assert_eq!(
        (hub.sticky.lookup_miss, hub.sticky.lookup_hit),
        (1, 0),
        "the first pick of a group is a rendezvous miss"
    );
    pick_link(&mut hub, key);
    assert_eq!(hub.sticky.lookup_hit, 1, "a served owner is a hit");

    hub.pool.failed(primary, Instant::now(), "test").unwrap();
    pick_link(&mut hub, key);
    assert_eq!(
        hub.sticky.failover_moves, 1,
        "a dead owner moves the group once"
    );
}

#[test]
fn connecting_owner_keeps_group_in_grace() {
    let mut hub = connecting_hub(&[1, 1]);
    hub.grace_until = Some(std::time::Instant::now() + svpn::hub::STARTUP_GRACE);
    let group = svpn::geo::asn_key(100);
    hub.exit_owners.insert(group, 0);
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);

    assert!(
        hub.pick(&key).is_none(),
        "a saved owner still connecting holds the group: no flows yet"
    );
    assert_eq!(
        hub.exit_owners.get(&group),
        Some(&0),
        "grace must not reassign the group"
    );

    let now = Instant::now();
    assert!(hub.pool.ready(
        Epoch {
            link: 0,
            generation: 1
        },
        now
    ));
    assert_eq!(
        hub.pick(&key),
        Some(Epoch {
            link: 0,
            generation: 1
        }),
        "once Ready, the saved owner serves its group"
    );
}

#[test]
fn grace_deadline_expired_fails_over() {
    // Owner 0 restored from state but still Connecting; link 1 is Ready.
    let mut hub = sticky_hub(&[1, 1]);
    let now = Instant::now();
    hub.pool
        .failed(
            Epoch {
                link: 0,
                generation: 1,
            },
            now,
            "startup connect failed",
        )
        .unwrap();
    // A failed startup round leaves the slot Connecting again after retry.
    let retries = hub
        .pool
        .retry_due(now + std::time::Duration::from_secs(2))
        .unwrap();
    assert_eq!(retries.len(), 1);
    assert!(hub.pool.is_connecting(0));

    let group = svpn::geo::asn_key(100);
    hub.exit_owners.insert(group, 0);
    // The grace deadline has passed: the group must not starve behind a
    // connecting owner while a healthy reserve exists.
    hub.grace_until = Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let moved = pick_link(&mut hub, key);
    assert_eq!(moved.link, 1, "expired grace must fail over to the reserve");
    assert_eq!(hub.exit_owners.get(&group), Some(&1));
    assert_eq!(hub.sticky.failover_moves, 1);
}

#[test]
fn checking_owner_falls_back_without_migration() {
    let mut hub = sticky_hub(&[1, 1]);
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let primary = pick_link(&mut hub, key);
    assert!(hub.pool.checking(primary));

    let reserve = pick_link(&mut hub, key);
    assert_ne!(reserve, primary, "Checking is excluded from new picks");
    let group = svpn::geo::asn_key(100);
    assert_eq!(
        hub.exit_owners.get(&group),
        Some(&primary.link),
        "a Checking owner keeps the group — no migration"
    );
    assert_eq!(hub.sticky.failover_moves, 0, "Checking is not a failover");

    // The verdict arrives: owner is Ready again and serves its group.
    assert!(hub.pool.ready(primary, Instant::now()));
    assert_eq!(
        pick_link(&mut hub, key),
        primary,
        "a recovered Checking owner resumes serving"
    );
}

#[test]
fn normal_assignment_is_not_persisted() {
    let mut hub = sticky_hub(&[1, 1]);
    let dir = temp_dir("normal-assign");
    let path = dir.join("exit-state.json");
    hub.exit_state = Some(svpn::exit_state::ExitState::load(Some(path.clone())));
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let primary = pick_link(&mut hub, key);
    let group = svpn::geo::asn_key(100);
    assert_eq!(
        hub.exit_state.as_ref().unwrap().owner(group),
        None,
        "a baseline rendezvous assignment reproduces itself — nothing to persist"
    );
    assert!(
        !path.exists(),
        "no state file may be written before a failover"
    );

    hub.pool.failed(primary, Instant::now(), "test").unwrap();
    let reserve = pick_link(&mut hub, key);
    let id = hub.nodes[reserve.link].0.clone();
    assert_eq!(
        hub.exit_state.as_ref().unwrap().owner(group),
        Some(&id),
        "a failover transition is persisted"
    );
    assert!(path.exists(), "failover persistence is write-ahead");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn uncovered_ip_is_stateless() {
    let mut hub = sticky_hub(&[1, 1]);
    let dir = temp_dir("uncovered");
    let path = dir.join("exit-state.json");
    hub.exit_state = Some(svpn::exit_state::ExitState::load(Some(path.clone())));
    let first = pick_link(&mut hub, flow(Ipv4Addr::new(9, 9, 9, 9), 1000));
    assert!(
        hub.exit_owners.is_empty(),
        "an uncovered /32 is never recorded in exit_owners"
    );
    assert!(!path.exists(), "an uncovered /32 is never persisted");
    // Deterministic rendezvous: the same address maps to the same exit.
    assert_eq!(
        pick_link(&mut hub, flow(Ipv4Addr::new(9, 9, 9, 9), 1001)),
        first
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn balance_mode_unchanged_without_geo() {
    let mut hub = sticky_hub(&[1, 1]);
    hub.geo = None;
    let mut seen = std::collections::HashSet::new();
    for port in 1000..1100 {
        seen.insert(pick_link(&mut hub, flow(Ipv4Addr::new(1, 0, 0, 5), port)).link);
    }
    assert_eq!(seen.len(), 2, "balance must use both links");
}
