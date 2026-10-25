//! Sticky exit: hub picks a fixed owner per destination group.

use std::net::Ipv4Addr;
use std::sync::Arc;

use svpn::exit_state::ExitKey;
use svpn::geo::Geo;
use svpn::hub::*;
use svpn::link_io::Epoch;
use svpn::pool::Pool;
use svpn::server_spec::LinkParams;
use svpn::{packet, session, stats};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

fn link_params(server: Ipv4Addr, weight: u32, countries: &[&str]) -> LinkParams {
    LinkParams {
        server: server.to_string(),
        weight,
        countries: countries.iter().map(|code| code.to_string()).collect(),
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
    selector_hub(weights, ready, &[&[]], Some(asn_table()), None)
}

/// Selector hub: `geo` — the ASN affinity table, `country` — the country
/// constraint table, `countries[i]` — the country codes of link i.
fn selector_hub(
    weights: &[u32],
    ready: bool,
    countries: &[&[&str]],
    geo: Option<Geo>,
    country: Option<Geo>,
) -> Hub {
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
                params: link_params(
                    server,
                    weights[link],
                    countries.get(link).copied().unwrap_or(&[]),
                ),
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
        geo,
        country,
        home_country: None,
        uplink: None,
        direct: None,
        icmp: None,
        nodes: servers
            .iter()
            .enumerate()
            .map(|(i, s)| (s.to_string(), weights[i]))
            .collect(),
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
    }
}

/// Sticky-asn hub with the country constraint active: link `i` serves
/// `countries[i]` (empty — none).
fn country_hub(weights: &[u32], countries: &[&[&str]]) -> Hub {
    selector_hub(
        weights,
        true,
        countries,
        Some(asn_table()),
        Some(country_table()),
    )
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

/// Country table: 1.0.0.0/24 and 3-4.0.0.0/24 → DE, 2.0.0.0/24 and
/// 5.0.0.0/24 → FR. 8.0.0.0/24 is a deliberate miss.
fn country_table() -> Geo {
    let de = svpn::geo::pack_country("DE").unwrap();
    let fr = svpn::geo::pack_country("FR").unwrap();
    Geo::from_ranges(vec![
        (0x0100_0000, 0x0100_00FF, de),
        (0x0200_0000, 0x0200_00FF, fr),
        (0x0300_0000, 0x0300_00FF, de),
        (0x0400_0000, 0x0400_00FF, de),
        (0x0500_0000, 0x0500_00FF, fr),
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
    assert_eq!((hub.sticky.asn_miss, hub.sticky.asn_hit), (1, 1));

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
    assert_eq!(
        hub.exit_state
            .as_ref()
            .unwrap()
            .owner(&svpn::exit_state::ExitKey::Asn(100)),
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
        hub.exit_state
            .as_ref()
            .unwrap()
            .owner(&svpn::exit_state::ExitKey::Asn(100)),
        Some(&id),
        "a failover transition is recorded"
    );
    // Persistence is batched (spec): pick marks dirty, flush_due / clean stop write.
    assert!(!path.exists(), "batched: no sync write inside pick");
    hub.exit_state.as_mut().unwrap().flush();
    assert!(path.exists(), "flush persists the failover transition");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn first_assignment_skipping_unavailable_primary_is_persisted() {
    // The first rendezvous node stays unavailable; with only the reserve
    // Ready the first assignment deviates from the baseline and must be
    // persisted, otherwise a restart with the primary back would snap the
    // group back (review P0).
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
    let dir = temp_dir("deviation");
    let path = dir.join("exit-state.json");
    hub.exit_state = Some(svpn::exit_state::ExitState::load(Some(path.clone())));

    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    assert_eq!(pick_link(&mut hub, key).link, reserve);
    assert_eq!(
        hub.sticky.failover_moves, 0,
        "a first assignment is not a failover"
    );
    assert_eq!(
        hub.exit_state
            .as_ref()
            .unwrap()
            .owner(&svpn::exit_state::ExitKey::Asn(100)),
        Some(&hub.nodes[reserve].0),
        "a first assignment that skipped the unavailable primary is recorded"
    );
    hub.exit_state.as_mut().unwrap().flush();
    assert!(path.exists());
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

// ── country constraint (spec §3) ──

#[test]
fn assigned_country_scopes_the_asn_group() {
    let mut hub = country_hub(&[1, 1, 1], &[&["DE"], &["DE"], &[]]);
    let de = svpn::geo::pack_country("DE").unwrap();
    // A DE destination with AS100 uses the (DE, AS100) scoped group.
    let scoped_owner = svpn::geo::rendezvous(svpn::geo::scoped_asn_key(de, 100), &hub.nodes)
        .into_iter()
        .find(|&link| link < 2)
        .unwrap();
    assert_eq!(
        pick_link(&mut hub, flow(Ipv4Addr::new(1, 0, 0, 5), 1000)).link,
        scoped_owner,
        "the group is scoped to the country, not the bare ASN"
    );
    // The same AS100 outside every country constraint stays global.
    assert_eq!(
        pick_link(&mut hub, flow(Ipv4Addr::new(6, 0, 0, 5), 1000)).link,
        svpn::geo::rendezvous(svpn::geo::asn_key(100), &hub.nodes)[0],
        "a country-miss destination keeps the global AS100 group"
    );
    assert_eq!((hub.sticky.country_miss, hub.sticky.asn_miss), (1, 1));
}

#[test]
fn asn_miss_inside_constraint_uses_the_country_owner() {
    let mut hub = country_hub(&[1, 1, 1], &[&["DE"], &["DE"], &[]]);
    // 4.0.0.5 is DE without ASN coverage: the sticky country group.
    let owner = pick_link(&mut hub, flow(Ipv4Addr::new(4, 0, 0, 5), 1000));
    assert!(owner.link < 2, "only DE candidates serve DE");
    // Every ASN-less DE destination shares the one country owner.
    assert_eq!(
        pick_link(&mut hub, flow(Ipv4Addr::new(3, 0, 0, 5), 1000)),
        owner,
        "an ASN miss inside the constraint is one sticky country owner"
    );
}

#[test]
fn assigned_country_restricts_balance_to_candidates() {
    // exit-policy=balance (no ASN database): the constraint still holds.
    let mut hub = selector_hub(
        &[1, 1, 1],
        true,
        &[&["DE"], &["DE"], &[]],
        None,
        Some(country_table()),
    );
    let mut seen = std::collections::HashSet::new();
    for port in 1000..1020u16 {
        seen.insert(pick_link(&mut hub, flow(Ipv4Addr::new(3, 0, 0, 5), port)).link);
    }
    assert!(
        seen.iter().all(|link| *link < 2),
        "only DE candidates serve DE"
    );
    assert_eq!(seen.len(), 1, "one stable owner per country");
    // An unassigned country and a database miss are no constraint.
    let mut all = std::collections::HashSet::new();
    for port in 1020..1080u16 {
        all.insert(pick_link(&mut hub, flow(Ipv4Addr::new(5, 0, 0, 5), port)).link);
        all.insert(pick_link(&mut hub, flow(Ipv4Addr::new(9, 9, 9, 9), port)).link);
    }
    assert_eq!(
        all.len(),
        3,
        "unconstrained destinations balance over all links"
    );
}

#[test]
fn unassigned_country_keeps_global_asn_selection() {
    let mut hub = country_hub(&[1, 1, 1], &[&["DE"], &["DE"], &[]]);
    // A miss in both databases keeps the stateless per-32 pick.
    let bare = pick_link(&mut hub, flow(Ipv4Addr::new(9, 9, 9, 9), 1000));
    assert_eq!(
        pick_link(&mut hub, flow(Ipv4Addr::new(9, 9, 9, 9), 1001)),
        bare
    );
    assert!(hub.exit_owners.is_empty(), "no group is recorded");
    // 8.0.0.5 is AS300 outside the country table: the global ASN group.
    let first = pick_link(&mut hub, flow(Ipv4Addr::new(8, 0, 0, 5), 1000));
    assert_eq!(
        pick_link(&mut hub, flow(Ipv4Addr::new(8, 0, 0, 9), 1001)),
        first,
        "an unassigned country keeps the global sticky-ASN owner"
    );
    // The DE constraint does not apply: with both DE links dead the
    // unconstrained group fails over to the foreign link.
    for link in 0..2 {
        hub.pool
            .failed(
                Epoch {
                    link,
                    generation: 1,
                },
                Instant::now(),
                "test",
            )
            .unwrap();
    }
    let moved = pick_link(&mut hub, flow(Ipv4Addr::new(8, 0, 0, 5), 1000));
    assert_eq!(moved.link, 2, "a global group fails over to any link");
}

#[test]
fn constrained_flow_never_spills_to_non_candidates() {
    // No DE candidate is Ready while a heavy foreign link is: still no flow.
    let mut hub = selector_hub(
        &[1, 1, 9],
        false,
        &[&["DE"], &["DE"], &[]],
        Some(asn_table()),
        Some(country_table()),
    );
    assert!(hub.pool.ready(
        Epoch {
            link: 2,
            generation: 1
        },
        Instant::now()
    ));
    let key = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    assert!(
        hub.pick(&key).is_none(),
        "a constrained flow waits instead of spilling to a foreign exit"
    );
    // A Ready candidate takes over.
    assert!(hub.pool.ready(
        Epoch {
            link: 0,
            generation: 1
        },
        Instant::now()
    ));
    assert_eq!(pick_link(&mut hub, key).link, 0);
}

#[test]
fn country_failover_stays_inside_candidates_without_snapback() {
    let mut hub = country_hub(&[1, 1, 1], &[&["DE"], &["DE"], &[]]);
    let key = flow(Ipv4Addr::new(4, 0, 0, 5), 1000);
    let owner = pick_link(&mut hub, key);
    assert!(owner.link < 2);
    hub.pool.failed(owner, Instant::now(), "test").unwrap();
    let reserve = pick_link(&mut hub, key);
    assert!(
        reserve.link < 2 && reserve != owner,
        "failover moves inside the candidates"
    );
    // The recovered owner does not take the group back.
    let now = Instant::now();
    let retries = hub
        .pool
        .retry_due(now + std::time::Duration::from_secs(2))
        .unwrap();
    assert!(hub.pool.ready(retries[0], now));
    assert_eq!(
        pick_link(&mut hub, key),
        reserve,
        "an alive owner keeps the group — no snap-back"
    );
}

#[test]
fn checking_constrained_owner_serves_from_candidate_reserve() {
    let mut hub = country_hub(&[1, 1, 1], &[&["DE"], &["DE"], &[]]);
    let key = flow(Ipv4Addr::new(4, 0, 0, 5), 1000);
    let owner = pick_link(&mut hub, key);
    assert!(hub.pool.checking(owner));
    let reserve = pick_link(&mut hub, key);
    assert_ne!(reserve, owner, "Checking is excluded from new picks");
    assert!(reserve.link < 2, "the reserve stays inside the candidates");
    let group = svpn::geo::country_key(svpn::geo::pack_country("DE").unwrap());
    assert_eq!(
        hub.exit_owners.get(&group),
        Some(&owner.link),
        "a Checking owner keeps the group — no migration"
    );
    assert_eq!(hub.sticky.failover_moves, 0, "Checking is not a failover");
    assert!(hub.pool.ready(owner, Instant::now()));
    assert_eq!(pick_link(&mut hub, key), owner);
}

#[test]
fn constrained_failovers_persist_under_typed_keys() {
    // Three DE candidates: two failovers still leave a serving candidate.
    let mut hub = country_hub(&[1, 1, 1, 1], &[&["DE"], &["DE"], &["DE"], &[]]);
    let dir = temp_dir("country-state");
    let path = dir.join("exit-state.json");
    hub.exit_state = Some(svpn::exit_state::ExitState::load(Some(path.clone())));

    // DE + AS100: a failover persists the scoped key, never a global ASN.
    let scoped = flow(Ipv4Addr::new(1, 0, 0, 5), 1000);
    let owner = pick_link(&mut hub, scoped);
    hub.pool.failed(owner, Instant::now(), "test").unwrap();
    let reserve = pick_link(&mut hub, scoped);
    assert_eq!(
        hub.exit_state
            .as_ref()
            .unwrap()
            .owner(&ExitKey::ScopedAsn("DE".into(), 100)),
        Some(&hub.nodes[reserve.link].0),
        "the scoped failover transition is recorded"
    );
    assert_eq!(
        hub.exit_state.as_ref().unwrap().owner(&ExitKey::Asn(100)),
        None,
        "a scoped group never touches the global ASN domain"
    );

    // DE without ASN coverage: the country key.
    let bare = flow(Ipv4Addr::new(4, 0, 0, 5), 1000);
    let owner = pick_link(&mut hub, bare);
    assert!(owner.link < 3);
    hub.pool.failed(owner, Instant::now(), "test").unwrap();
    let reserve = pick_link(&mut hub, bare);
    assert!(owner.link < 3 && reserve.link < 3);
    assert_eq!(
        hub.exit_state
            .as_ref()
            .unwrap()
            .owner(&ExitKey::Country("DE".into())),
        Some(&hub.nodes[reserve.link].0),
        "the country failover transition is recorded"
    );
    let _ = std::fs::remove_dir_all(dir);
}

// ── restore (spec §4) ──

#[test]
fn restored_typed_owners_map_to_disjoint_groups_and_filter_candidates() {
    let codes: [&[&str]; 3] = [&["DE"], &["DE"], &[]];
    let servers: Vec<LinkParams> = codes
        .iter()
        .enumerate()
        .map(|(link, countries)| {
            link_params(Ipv4Addr::new(192, 0, 2, link as u8 + 1), 1, countries)
        })
        .collect();
    let de = svpn::geo::pack_country("DE").unwrap();
    assert_eq!(
        restored_group(&servers, ExitKey::Asn(100), 2),
        Some(svpn::geo::asn_key(100)),
        "a global ASN owner restores onto any link"
    );
    assert_eq!(
        restored_group(&servers, ExitKey::Country("DE".into()), 1),
        Some(svpn::geo::country_key(de))
    );
    assert_eq!(
        restored_group(&servers, ExitKey::ScopedAsn("DE".into(), 100), 0),
        Some(svpn::geo::scoped_asn_key(de, 100)),
        "the scoped key keeps its country before the first flow"
    );
    // A node that is no longer a candidate for its country is dropped,
    // not leaked into the constraint.
    assert_eq!(
        restored_group(&servers, ExitKey::Country("DE".into()), 2),
        None
    );
    assert_eq!(
        restored_group(&servers, ExitKey::ScopedAsn("DE".into(), 100), 2),
        None
    );
    // Disjoint domains: restored groups never collide across key kinds.
    assert_ne!(
        restored_group(&servers, ExitKey::ScopedAsn("DE".into(), 100), 0),
        restored_group(&servers, ExitKey::Asn(100), 0)
    );
    assert_ne!(
        restored_group(&servers, ExitKey::Country("DE".into()), 0),
        Some(svpn::geo::asn_key(de))
    );
}

#[test]
fn restored_constrained_owner_holds_its_group_in_grace() {
    let mut hub = selector_hub(
        &[1, 1, 1],
        false,
        &[&["DE"], &["DE"], &[]],
        Some(asn_table()),
        Some(country_table()),
    );
    hub.grace_until = Some(std::time::Instant::now() + svpn::hub::STARTUP_GRACE);
    let de = svpn::geo::pack_country("DE").unwrap();
    let scoped = flow(Ipv4Addr::new(1, 0, 0, 5), 1000); // DE + AS100
    let bare = flow(Ipv4Addr::new(4, 0, 0, 5), 1000); // DE, ASN gap
    hub.exit_owners
        .insert(svpn::geo::scoped_asn_key(de, 100), 1);
    hub.exit_owners.insert(svpn::geo::country_key(de), 0);
    assert!(hub.pick(&scoped).is_none(), "grace holds the scoped owner");
    assert!(hub.pick(&bare).is_none(), "grace holds the country owner");

    // Once Ready, each restored owner serves its own group.
    assert!(hub.pool.ready(
        Epoch {
            link: 1,
            generation: 1
        },
        Instant::now()
    ));
    assert_eq!(
        pick_link(&mut hub, scoped).link,
        1,
        "the scoped owner resumes"
    );
    assert!(hub.pool.ready(
        Epoch {
            link: 0,
            generation: 1
        },
        Instant::now()
    ));
    assert_eq!(
        pick_link(&mut hub, bare).link,
        0,
        "the country owner resumes"
    );
}
