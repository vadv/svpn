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
        label: String::new(),
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
    selector_hub(weights, ready, Some(asn_table()), None)
}

/// Selector hub: `geo` — the ASN affinity table, `country` — the country
/// table used by countries selectors.
fn selector_hub(weights: &[u32], ready: bool, geo: Option<Geo>, country: Option<Geo>) -> Hub {
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
        policy: svpn::cli::ExitPolicy::StickyAsn,
        sticky_asn_mode: Default::default(),
        pool,
        geo,
        country,
        stickies: Vec::new(),
        sticky_via: Vec::new(),
        sticky_updates: None,
        sticky_task: None,
        job_events: None,
        job_task: None,
        job_stats: JobStats::default(),
        geo_path: None,
        country_path: None,
        geo_pending: None,
        country_pending: None,
        local: None,
        local_cleanup: None,
        nodes: servers
            .iter()
            .enumerate()
            .map(|(i, s)| (s.to_string(), weights[i]))
            .collect(),
        exit_owners: svpn::exit_state::StickyOwners::default(),
        sticky: StickyStats::default(),
        local_stats: Default::default(),
        tasks: JoinSet::new(),
        events,
        incoming,
        routes: Routes::default(),
        tombstones: session::Tombstones::default(),
        pair: watch::channel(None).0,
    }
}

/// ASN table: 1.0.0.0/24 → AS100, 2.0.0.0/24 → AS200, 6.0.0.0/24 → AS100
/// (a second AS100 range outside the country table), 8.0.0.0/24 → AS300.
fn asn_table() -> Geo {
    Geo::from_ranges(vec![
        (0x0100_0000, 0x0100_00FF, 100),
        (0x0200_0000, 0x0200_00FF, 200),
        (0x0600_0000, 0x0600_00FF, 100),
        (0x0800_0000, 0x0800_00FF, 300),
    ])
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
    hub.pick(&key).0.expect("a Ready link exists")
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
    // Failover moves A→B→C and does not snap back when B recovers.
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
    assert_eq!(hub.pick(&key).0, None, "Checking cannot split an ASN");
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
    assert_eq!((hub.sticky.asn_miss, hub.sticky.asn_hit), (1, 1));

    hub.pool.failed(primary, Instant::now(), "test").unwrap();
    pick_link(&mut hub, key);
    assert_eq!(
        hub.sticky.failover_moves, 1,
        "a dead owner moves the group once"
    );
}

#[test]
fn connecting_owner_with_ready_reserve_fails_over() {
    // No grace window any more: a restored owner still Connecting hands the
    // group to the first Ready link immediately (counted as a failover).
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
    let retries = hub
        .pool
        .retry_due(now + std::time::Duration::from_secs(2))
        .unwrap();
    assert_eq!(retries.len(), 1);
    assert!(hub.pool.is_connecting(0));

    let group = svpn::geo::asn_key(100);
    hub.exit_owners.assign(group, 0);
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let moved = pick_link(&mut hub, key);
    assert_eq!(
        moved.link, 1,
        "a Connecting owner fails over to the reserve"
    );
    assert_eq!(hub.exit_owners.link_of(group), Some(1));
    assert_eq!(hub.sticky.failover_moves, 1);
}

#[test]
fn connecting_owner_without_ready_reserve_returns_none() {
    // All links Connecting: no pick, binding untouched.
    let mut hub = connecting_hub(&[1, 1]);
    let group = svpn::geo::asn_key(100);
    hub.exit_owners.assign(group, 0);
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);

    assert!(
        hub.pick(&key).0.is_none(),
        "a connecting owner without any Ready link yields no flow"
    );
    assert_eq!(
        hub.exit_owners.link_of(group),
        Some(0),
        "the binding must survive a pick that found no Ready link"
    );

    assert!(hub.pool.ready(
        Epoch {
            link: 0,
            generation: 1
        },
        Instant::now()
    ));
    assert_eq!(
        hub.pick(&key).0,
        Some(Epoch {
            link: 0,
            generation: 1
        }),
        "once Ready, the owner serves its group"
    );
}

#[test]
fn checking_owner_waits_without_migration() {
    let mut hub = sticky_hub(&[1, 1]);
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let primary = pick_link(&mut hub, key);
    assert!(hub.pool.checking(primary));

    assert_eq!(hub.pick(&key).0, None);
    let group = svpn::geo::asn_key(100);
    assert_eq!(
        hub.exit_owners.link_of(group),
        Some(primary.link),
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
fn baseline_assignment_is_recorded_in_ram_only() {
    let mut hub = sticky_hub(&[1, 1]);
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let primary = pick_link(&mut hub, key);
    let group = svpn::geo::asn_key(100);
    let baseline = svpn::geo::rendezvous(group, &hub.nodes)[0];
    assert_eq!(
        primary.link, baseline,
        "a baseline rendezvous assignment lands on the primary"
    );
    assert_eq!(
        hub.exit_owners.link_of(group),
        Some(baseline),
        "the binding lives in RAM"
    );
    assert_eq!(
        hub.sticky.failover_moves, 0,
        "a baseline assignment is not a failover"
    );
}

#[test]
fn first_assignment_skipping_unavailable_primary_is_kept() {
    // The first rendezvous node stays unavailable; with only the reserve
    // Ready the first assignment deviates from the baseline and is recorded
    // in RAM without counting as a failover.
    let mut hub = connecting_hub(&[1, 1]);
    let group = svpn::geo::asn_key(100);
    let order = svpn::geo::rendezvous(group, &hub.nodes);
    let reserve = order[1];
    assert!(hub.pool.ready(
        Epoch {
            link: reserve,
            generation: 1
        },
        Instant::now()
    ));

    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    assert_eq!(pick_link(&mut hub, key).link, reserve);
    assert_eq!(
        hub.sticky.failover_moves, 0,
        "a first assignment is not a failover"
    );
    assert_eq!(
        hub.exit_owners.link_of(group),
        Some(reserve),
        "a first assignment that skipped the unavailable primary is kept"
    );
}

#[test]
fn uncovered_ip_is_stateless() {
    let mut hub = sticky_hub(&[1, 1]);
    let first = pick_link(&mut hub, flow(Ipv4Addr::new(9, 9, 9, 9), 1000));
    assert!(
        hub.exit_owners.is_empty(),
        "an uncovered /32 is never recorded in exit_owners"
    );
    // Deterministic rendezvous: the same address maps to the same exit.
    assert_eq!(
        pick_link(&mut hub, flow(Ipv4Addr::new(9, 9, 9, 9), 1001)),
        first
    );
}

#[test]
fn balance_mode_ignores_the_geo_table() {
    // geo may be loaded for an asn selector while the fallback stays balance.
    let mut hub = selector_hub(&[1, 1], true, Some(asn_table()), None);
    hub.policy = svpn::cli::ExitPolicy::Balance;
    let mut seen = std::collections::HashSet::new();
    for port in 1000..1020u16 {
        seen.insert(pick_link(&mut hub, flow(Ipv4Addr::new(1, 0, 0, 5), port)).link);
    }
    assert_eq!(
        seen.len(),
        2,
        "balance spreads per flow despite the geo table"
    );
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

// ── country constraint (spec §3) ──

// ── owner registry (RAM-only, no restore) ──
