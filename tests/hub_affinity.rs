//! Automatic ASN affinity: live-flow balance versus persistent hashed owners.

mod common;

use std::net::Ipv4Addr;

use svpn::{
    cli::{ExitPolicy, StickyAsnMode},
    geo::{Geo, asn_key},
    hub::{Hub, Owner, Target},
    link_io::Epoch,
    packet::FlowKey,
    pool::Pool,
};
use tokio::{sync::mpsc, time::Instant};

fn hub(mode: StickyAsnMode, weights: [u32; 2]) -> Hub {
    let mut hub = common::hub::dashboard_hub();
    hub.policy = ExitPolicy::StickyAsn;
    hub.sticky_asn_mode = mode;
    hub.geo = Some(Geo::from_ranges(vec![(0x0100_0000, 0x0100_00ff, 100)]));
    hub.pool = Pool::new(weights);
    for (link, weight) in weights.into_iter().enumerate() {
        hub.nodes[link].1 = weight;
        hub.pool.ready(epoch(link), Instant::now());
    }
    hub
}

// ── live groups, not packets or remembered assignments ──

#[test]
fn balanced_counts_unique_automatic_asns_and_weights_not_flows() {
    let mut hub = hub(StickyAsnMode::Balanced, [4, 1]);
    for group in 1..=8 {
        register(&mut hub, group, 0, group as u16, None);
    }
    for group in 9..=13 {
        register(&mut hub, group, 1, group as u16, None);
    }
    // 100 extra flows of the same ASN still count as one group.
    for port in 1000..1100 {
        register(&mut hub, 1, 0, port, None);
    }
    // Explicit rules don't count even when they carry an ASN-like key.
    for group in 200..230 {
        register(&mut hub, group, 0, group as u16, Some(0));
    }
    let (picked, group) = hub.pick(&key(5000));
    assert_eq!(picked, Some(epoch(0)), "8/4 is less than 5/1");
    assert_eq!(group, Some(asn_key(100)));
    assert!(hub.exit_owners.is_empty());
    assert_eq!(hub.routes.asn_owners().len(), 13);
}

#[test]
fn balanced_places_live_groups_in_weighted_proportions() {
    let mut hub = hub(StickyAsnMode::Balanced, [4, 1]);
    hub.geo = Some(Geo::from_ranges(
        (1..=25).map(|asn| (asn, asn, asn)).collect(),
    ));
    let mut counts = [0; 2];
    for asn in 1..=25 {
        let mut key = key(asn as u16);
        key.destination = Ipv4Addr::from(asn);
        let (owner, group) = hub.pick(&key);
        let owner = owner.unwrap();
        counts[owner.link] += 1;
        hub.routes.insert(
            key,
            Target::Remote(Owner {
                epoch: owner,
                id: u64::from(asn),
            }),
            None,
            group,
        );
    }
    assert_eq!(counts, [20, 5]);
    assert_eq!(hub.routes.asn_owners().len(), 25);
    assert!(hub.exit_owners.is_empty());
}

#[test]
fn balanced_owner_lookup_excludes_explicit_rules_and_local_flows() {
    let mut hub = hub(StickyAsnMode::Balanced, [1, 1]);
    register(&mut hub, 100, 1, 1, Some(0));
    hub.routes
        .insert(key(2), Target::Direct(2), None, Some(asn_key(100)));
    assert_eq!(hub.routes.asn_owner(asn_key(100)), None);

    register(&mut hub, 100, 0, 3, None);
    assert_eq!(hub.routes.asn_owner(asn_key(100)), Some(epoch(0)));
    assert_eq!(hub.pick(&key(4)).0, Some(epoch(0)));
    hub.pool.checking(epoch(0));
    assert_eq!(hub.pick(&key(4)).0, None, "no reserve for a live ASN");
}

#[test]
fn snapshot_uses_live_asn_groups_only_in_balanced_mode() {
    for mode in [StickyAsnMode::Balanced, StickyAsnMode::Hashed] {
        let mut hub = hub(mode, [1, 1]);
        register(&mut hub, 100, 0, 1, None);
        let snapshot = svpn::web::snapshot(&hub);
        if mode == StickyAsnMode::Balanced {
            assert_eq!(snapshot.groups.len(), 1);
            assert_eq!(snapshot.groups[0].group, "asn 100");
        } else {
            assert!(snapshot.groups.is_empty(), "hashed uses remembered owners");
            hub.exit_owners.assign(asn_key(100), 0);
            let snapshot = svpn::web::snapshot(&hub);
            assert_eq!(snapshot.groups.len(), 1);
            assert_eq!(snapshot.groups[0].group, "asn 100");
        }
    }
}

#[test]
fn equal_scores_use_rendezvous_and_extreme_weights_do_not_overflow() {
    let mut hub = hub(StickyAsnMode::Balanced, [u32::MAX, u32::MAX]);
    register(&mut hub, 1, 0, 1, None);
    register(&mut hub, 2, 1, 2, None);
    let expected = svpn::geo::rendezvous(asn_key(100), &hub.nodes)[0];
    assert_eq!(hub.pick(&key(3)).0, Some(epoch(expected)));
    register(&mut hub, 3, expected, 4, None);
    assert_eq!(hub.pick(&key(3)).0, Some(epoch(1 - expected)));
}

#[test]
fn balanced_keeps_closing_flow_owner_then_forgets_the_last_flow() {
    let mut hub = hub(StickyAsnMode::Balanced, [1, 1]);
    register(&mut hub, 100, 0, 100, None);
    let owner = Owner {
        epoch: epoch(0),
        id: 100,
    };
    hub.routes.mark_closing(key(100), owner);
    assert_eq!(hub.pick(&key(101)).0, Some(epoch(0)));
    assert_eq!(svpn::web::snapshot(&hub).groups.len(), 1);
    hub.routes.forget(key(100), owner);
    assert!(svpn::web::snapshot(&hub).groups.is_empty());
    register(&mut hub, 200, 0, 200, None);
    assert_eq!(hub.pick(&key(101)).0, Some(epoch(1)));
    assert!(hub.exit_owners.is_empty());
}

#[test]
fn existing_group_uses_pinned_asn_after_geo_reload() {
    let mut hub = hub(StickyAsnMode::Balanced, [1, 1]);
    register(&mut hub, 100, 0, 10, None);
    // Old destination now resolves to 200; old flow must remain in group 100.
    hub.geo = Some(Geo::from_ranges(vec![
        (0x0100_0000, 0x0100_00ff, 200),
        (0x0200_0000, 0x0200_00ff, 100),
    ]));
    assert_eq!(hub.pick(&key(11)).0, Some(epoch(1)));
    let mut other_range = key(12);
    other_range.destination = Ipv4Addr::new(2, 0, 0, 1);
    assert_eq!(hub.pick(&other_range).0, Some(epoch(0)));
    assert_eq!(hub.routes.asn_owners().get(&asn_key(100)), Some(&epoch(0)));
    hub.routes.forget(
        key(10),
        Owner {
            epoch: epoch(0),
            id: 10,
        },
    );
    assert!(hub.routes.asn_owners().is_empty());
}

// ── admission and lifecycle ──

#[test]
fn failed_enqueue_does_not_count_and_next_successful_flow_is_visible() {
    let mut hub = hub(StickyAsnMode::Balanced, [1, 1]);
    let bytes = syn(100);
    let picked = hub.pick(&key(100)).0.unwrap();
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    hub.links[picked.link].outgoing = Some(tx);
    hub.dispatch(&bytes, key(100).source).unwrap();
    assert!(hub.routes.asn_owners().is_empty());
    assert!(hub.exit_owners.is_empty());

    let (tx, mut rx) = mpsc::channel(1);
    hub.links[picked.link].outgoing = Some(tx);
    hub.dispatch(&bytes, key(100).source).unwrap();
    assert!(rx.try_recv().is_ok());
    assert_eq!(hub.routes.asn_owners().get(&asn_key(100)), Some(&picked));
    hub.dispatch(&syn(101), key(101).source).unwrap();
    assert!(rx.try_recv().is_ok());
    hub.dispatch(&syn(102), key(102).source).unwrap();
    hub.dispatch(&syn(103), key(103).source).unwrap(); // full queue
    assert!(!hub.routes.by_key.contains_key(&key(103)));
    assert_eq!(hub.routes.asn_owners().len(), 1);
}

#[test]
fn checking_and_failure_cannot_split_live_asn_in_either_mode() {
    for mode in [StickyAsnMode::Balanced, StickyAsnMode::Hashed] {
        let mut hub = hub(mode, [1, 1]);
        let owner = hub.pick(&key(100)).0.unwrap();
        register(&mut hub, 100, owner.link, 100, None);
        assert!(hub.pool.checking(owner));
        assert_eq!(hub.pick(&key(101)).0, None);
        assert_eq!(hub.routes.by_key.len(), 1, "Checking does not close flows");
        hub.pool.ready(owner, Instant::now());
        assert_eq!(hub.pick(&key(101)).0, Some(owner));
        hub.pool.failed(owner, Instant::now(), "test").unwrap();
        assert_eq!(
            hub.pick(&key(101)).0,
            None,
            "retire old flows before failover"
        );
        hub.routes.remove_epoch(owner);
        assert_eq!(hub.pick(&key(101)).0, Some(epoch(1 - owner.link)));
    }
}

#[test]
fn no_ready_link_means_no_assignment_in_either_mode() {
    for mode in [StickyAsnMode::Balanced, StickyAsnMode::Hashed] {
        let mut hub = hub(mode, [1, 1]);
        hub.pool.checking(epoch(0));
        hub.pool.checking(epoch(1));
        assert_eq!(hub.pick(&key(1)).0, None);
        assert!(hub.exit_owners.is_empty());
        assert!(hub.routes.asn_owners().is_empty());
    }
}

#[test]
fn unknown_asn_is_stateless_ip_hash_in_both_modes() {
    for mode in [StickyAsnMode::Balanced, StickyAsnMode::Hashed] {
        let mut hub = hub(mode, [1, 1]);
        let mut unknown = key(100);
        unknown.destination = Ipv4Addr::new(9, 9, 9, 9);
        let expected = svpn::geo::rendezvous(svpn::geo::ip_key(unknown.destination), &hub.nodes)[0];
        assert_eq!(hub.pick(&unknown), (Some(epoch(expected)), None));
        assert!(hub.exit_owners.is_empty());
    }
}

#[test]
fn udp_retirement_and_stale_close_use_the_recorded_owner() {
    let mut hub = hub(StickyAsnMode::Balanced, [1, 1]);
    let mut udp = key(100);
    udp.protocol = 17;
    let owner = Owner {
        epoch: epoch(0),
        id: 100,
    };
    hub.routes
        .insert(udp, Target::Remote(owner), None, Some(asn_key(100)));
    hub.routes.forget(udp, Owner { id: 99, ..owner });
    assert_eq!(
        hub.pick(&key(101)).0,
        Some(epoch(0)),
        "stale close cannot release ASN"
    );
    hub.routes.forget(udp, owner);
    assert!(hub.routes.asn_owners().is_empty());
    register(&mut hub, 200, 0, 200, None);
    assert_eq!(hub.pick(&key(101)).0, Some(epoch(1)));
}

// ── hashed history ──

#[test]
fn hashed_retains_idle_owner_and_can_return_after_a_second_failure() {
    let mut hub = hub(StickyAsnMode::Hashed, [1, 1]);
    let first = hub.pick(&key(100)).0.unwrap();
    register(&mut hub, 100, first.link, 100, None);
    hub.routes.remove_epoch(first);
    // Flow closure doesn't release a hashed binding.
    assert_eq!(hub.pick(&key(101)).0, Some(first));
    let now = Instant::now();
    hub.pool.failed(first, now, "first failure").unwrap();
    let second = hub.pick(&key(101)).0.unwrap();
    let later = now + std::time::Duration::from_secs(2);
    let recovered = hub.pool.retry_due(later).unwrap()[0];
    hub.pool.ready(recovered, later);
    assert_eq!(hub.pick(&key(102)).0, Some(second), "no recovery snap-back");
    hub.pool.failed(second, later, "second failure").unwrap();
    assert_eq!(hub.pick(&key(103)).0, Some(recovered));
    assert_eq!(hub.exit_owners.len(), 1);
}

// ── helpers ──

fn epoch(link: usize) -> Epoch {
    Epoch {
        link,
        generation: 1,
    }
}

fn key(port: u16) -> FlowKey {
    FlowKey {
        protocol: 6,
        source: Ipv4Addr::new(10, 77, 0, 2),
        destination: Ipv4Addr::new(1, 0, 0, 1),
        source_port: port,
        destination_port: 443,
    }
}

fn register(hub: &mut Hub, asn: u32, link: usize, port: u16, rule: Option<usize>) {
    hub.routes.insert(
        key(port),
        Target::Remote(Owner {
            epoch: epoch(link),
            id: u64::from(port),
        }),
        rule,
        Some(asn_key(asn)),
    );
}

fn syn(port: u16) -> Vec<u8> {
    let key = key(port);
    let mut bytes = common::tcp_packet(false);
    bytes[16..20].copy_from_slice(&key.destination.octets());
    bytes[20..22].copy_from_slice(&port.to_be_bytes());
    bytes[22..24].copy_from_slice(&key.destination_port.to_be_bytes());
    bytes
}
