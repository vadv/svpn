//! Dashboard accounting across snapshot boundaries, retirement and a long destination tail.

mod common;

use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};
use svpn::{
    hub::{Owner, Routes, Target, UsageMeter},
    link_io::Epoch,
    packet,
};

// ── live and completed flows ──

#[test]
fn completed_between_ticks_is_counted_once_even_when_the_tuple_changes_exit() {
    let mut routes = Routes::default();
    let now = Instant::now();
    assert!(routes.sample_usage(now).is_none());
    routes.usage = Some(UsageMeter::default());
    assert_eq!(routes.sample_usage(now).unwrap().seconds, None);
    let key = packet::parse(&common::udp_packet(false), true)
        .unwrap()
        .flow;
    let owner = Owner {
        epoch: Epoch {
            link: 1,
            generation: 5,
        },
        id: 1,
    };
    routes.insert(key, Target::Remote(owner), None, None);
    routes.by_key.get_mut(&key).unwrap().asn = Some(64500);
    routes.record(key, 20, 10);
    let t = now + Duration::from_secs(2);
    let first = routes.sample_usage(t).unwrap();
    assert_eq!(first.seconds, Some(2.));
    assert_eq!(
        first.interval.destinations.named[&key.destination].rx_bytes,
        10
    );
    routes.record(key, 0, 5);
    routes.remove_epoch(owner.epoch);
    routes.insert(key, Target::Direct(2), Some(0), None);
    routes.record(key, 40, 0);
    assert!(routes.forget_direct(key, 2));
    let next = routes.sample_usage(t + Duration::from_secs(1)).unwrap();
    assert_eq!(next.interval.exits[&1].rx_bytes, 5);
    assert_eq!(next.interval.local.tx_bytes, 40);
    assert_eq!(next.session.networks.named[&64500].rx_bytes, 15);
    assert_eq!(next.session.unknown_asn.tx_bytes, 40);
    assert_eq!(
        next.session.destinations.named[&key.destination].tx_bytes,
        60
    );
    let idle = routes.sample_usage(t + Duration::from_secs(2)).unwrap();
    assert!(idle.interval.destinations.named.is_empty());
    assert_eq!(
        idle.session.destinations.named[&key.destination].rx_bytes,
        15
    );
}

#[tokio::test]
async fn published_snapshot_follows_queue_acceptance_and_keeps_the_original_network() {
    let mut hub = common::hub::dashboard_hub();
    hub.routes.usage = Some(UsageMeter::default());
    let bytes = common::udp_packet(false);
    let key = packet::parse(&bytes, true).unwrap().flow;
    let ip = u32::from(key.destination);
    hub.geo = Some(svpn::geo::Geo::from_ranges(vec![(ip, ip, 64512)]));
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    hub.links[0].outgoing = Some(tx);
    hub.dispatch(&bytes, key.source).unwrap();
    hub.geo = None;
    hub.dispatch(&bytes, key.source).unwrap(); // Full queue, no charge.
    let state = svpn::web::sample(&mut hub);
    assert_eq!(state.flows[0].asn, Some(64512));
    let json = serde_json::to_value(state).unwrap();
    let session = &json["usage"]["session"];
    assert_eq!(
        session["networks"]["named"]["64512"]["tx_bytes"],
        bytes.len()
    );
    assert_eq!(session["exits"]["0"]["tx_bytes"], bytes.len());
}

// ── bounded memory ──

#[test]
fn long_tail_conserves_both_directions_and_admits_a_late_busy_destination() {
    let mut routes = Routes {
        usage: Some(UsageMeter::default()),
        ..Routes::default()
    };
    let mut key = packet::parse(&common::udp_packet(false), true)
        .unwrap()
        .flow;
    for i in 1..=1025 {
        key.destination = Ipv4Addr::from(i);
        routes.insert(key, Target::Direct(1), None, None);
        routes.by_key.get_mut(&key).unwrap().asn = Some(i);
        routes.record(key, if i == 1025 { 1000 } else { 1 }, 2);
        routes.forget_direct(key, 1);
        if i == 1024 {
            routes.sample_usage(Instant::now());
        }
    }
    let s = routes.sample_usage(Instant::now()).unwrap().session;
    assert_eq!(s.destinations.named[&key.destination].tx_bytes, 1000);
    assert_eq!(s.networks.named[&1025].tx_bytes, 1000);
    assert_eq!(s.destinations.named.len(), 256);
    assert_eq!(s.networks.named.len(), 256);
    assert_eq!(
        s.destinations.other.tx_bytes
            + s.destinations
                .named
                .values()
                .map(|v| v.tx_bytes)
                .sum::<u64>(),
        s.local.tx_bytes
    );
    assert_eq!(
        s.networks.other.rx_bytes + s.networks.named.values().map(|v| v.rx_bytes).sum::<u64>(),
        2050
    );
}
