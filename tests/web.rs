//! Dashboard snapshot: servers, rules, groups and live flows.

mod common;

use std::{net::Ipv4Addr, time::Duration};

use svpn::{
    MimicArg,
    control::{RoundEntry, RoundOutcome, RoundReport, RoundStage, Stats},
    geo::{Geo, pack_country},
    hub::{Hub, Owner, Target},
    link_io::Epoch,
    packet::FlowKey,
    selector::Reason,
    sticky::{ResolvedVia, RuntimeSticky, Selector, StickyBlock, Via},
    web,
};
use tokio::sync::watch;

fn hub() -> Hub {
    common::hub::dashboard_hub()
}

fn flow(protocol: u8, source_port: u16, destination_port: u16) -> FlowKey {
    FlowKey {
        protocol,
        source: Ipv4Addr::new(10, 77, 0, 2),
        destination: Ipv4Addr::new(1, 2, 3, 4),
        source_port,
        destination_port,
    }
}

// ── servers ──

#[test]
fn snapshot_reports_server_state_and_node_ids() {
    let mut hub = hub();
    hub.links[1].last_reason = "handshake failed".to_owned();
    let snapshot = web::snapshot(&hub);
    assert_eq!(snapshot.policy, "balance");
    assert_eq!(snapshot.servers.len(), 2);
    assert_eq!(snapshot.servers[0].state, "ready");
    assert_eq!(snapshot.servers[0].id, "192.0.2.1");
    assert_eq!(snapshot.servers[1].state, "failed");
    assert_eq!(snapshot.servers[1].reason, "handshake failed");
    assert!(!snapshot.asn_table);
    assert!(!snapshot.country_table);
    assert_eq!(snapshot.servers[0].country, None, "no table, no country");
}

#[test]
fn server_country_comes_from_its_address_and_unknown_stays_null() {
    let mut hub = hub();
    let first = u32::from(Ipv4Addr::new(192, 0, 2, 1));
    hub.country = Some(Geo::from_ranges(vec![(
        first,
        first,
        pack_country("NL").unwrap(),
    )]));
    hub.links[1].params.server = "vps.example".to_owned();
    let json = serde_json::to_value(web::snapshot(&hub)).unwrap();
    assert_eq!(json["servers"][0]["country"], "NL");
    assert!(
        json["servers"][1]["country"].is_null(),
        "a hostname is not resolved inside the snapshot"
    );
    hub.links[1].params.server = "192.0.2.2".to_owned();
    let snapshot = web::snapshot(&hub);
    assert_eq!(
        snapshot.servers[1].country, None,
        "an uncovered address has no country"
    );
}

#[test]
fn snapshot_reports_configured_mimic_without_debug_names() {
    use MimicArg::*;
    for (configured, expected) in [
        (vec![], serde_json::json!([])),
        (vec![WebRtc], serde_json::json!(["webrtc"])),
        (
            vec![Quic, Mosh, Obfs, Ssh],
            serde_json::json!(["quic", "mosh", "obfs", "ssh"]),
        ),
        (vec![Banner, None], serde_json::json!(["banner", "none"])),
    ] {
        let mut hub = hub();
        hub.links[0].params.mimic = configured;
        let json = serde_json::to_value(web::snapshot(&hub)).unwrap();
        assert_eq!(json["servers"][0]["mimic"], expected);
    }
}

#[test]
fn snapshot_carries_live_link_counters() {
    let hub = hub();
    let snapshot = web::snapshot(&hub);
    // The running session publishes them; the hub only sums them up later.
    assert_eq!(snapshot.servers[0].stats.inner_rx_bytes, 4242);
    assert_eq!(snapshot.servers[0].stats.inner_rx_packets, 7);
    assert_eq!(snapshot.servers[0].stats.active_flows, 3);
}

#[test]
fn snapshot_keeps_cumulative_counters_across_reconnect() {
    let mut hub = hub();
    let live = hub.links[0]
        .latest
        .as_ref()
        .expect("live session")
        .borrow()
        .clone();
    assert_eq!(web::snapshot(&hub).servers[0].stats.inner_rx_bytes, 4242);

    // A periodic log report folds live counters into the totals: showing
    // total + live directly would double them here.
    hub.links[0].stats.observe(live.clone());
    assert_eq!(web::snapshot(&hub).servers[0].stats.inner_rx_bytes, 4242);

    // Session ends: the hub observes the last value and resets the generation.
    let last = hub.links[0].latest.take().expect("live session");
    hub.links[0].stats.observe(last.borrow().clone());
    hub.links[0].stats.reset();
    assert_eq!(web::snapshot(&hub).servers[0].stats.inner_rx_bytes, 4242);

    // A new generation starts its own counters at zero, but the dashboard
    // must stay monotonic instead of dropping back to 10 bytes.
    let (_, latest) = watch::channel(Stats {
        inner_rx_bytes: 10,
        ..Stats::default()
    });
    hub.links[0].latest = Some(latest);
    assert_eq!(web::snapshot(&hub).servers[0].stats.inner_rx_bytes, 4252);
}

#[test]
fn snapshot_falls_back_to_the_collected_totals_of_a_dead_link() {
    let mut hub = hub();
    hub.links[0].latest = None;
    let mut stats = svpn::stats::Snapshot::default();
    stats.observe(Stats {
        inner_tx_bytes: 100,
        inner_rx_bytes: 200,
        active_flows: 3,
        ..svpn::control::Stats::default()
    });
    hub.links[0].stats = stats;
    let snapshot = web::snapshot(&hub);
    assert_eq!(snapshot.servers[0].stats.inner_tx_bytes, 100);
    assert_eq!(snapshot.servers[0].stats.inner_rx_bytes, 200);
    assert_eq!(snapshot.servers[0].stats.active_flows, 3);
}

// ── selection ──

#[test]
fn snapshot_exposes_the_live_transport_and_its_race() {
    let mut hub = hub();
    let (_sender, latest) = watch::channel(Stats {
        active_candidate: Some("tcp-ssh".to_owned()),
        last_round: Some(RoundReport {
            finished_at_ms: 1_730_000_000_000,
            winner: Some("tcp".to_owned()),
            entries: vec![
                RoundEntry {
                    candidate: "tcp".to_owned(),
                    outcome: RoundOutcome::Verified {
                        rtt_ms: 41,
                        penalty: true,
                    },
                },
                RoundEntry {
                    candidate: "quic".to_owned(),
                    outcome: RoundOutcome::Verified {
                        rtt_ms: 63,
                        penalty: false,
                    },
                },
                RoundEntry {
                    candidate: "webrtc".to_owned(),
                    outcome: RoundOutcome::Failed {
                        reason: Reason::PathTimeout,
                    },
                },
                RoundEntry {
                    candidate: "obfs".to_owned(),
                    outcome: RoundOutcome::Unanswered {
                        stage: RoundStage::Handshake,
                    },
                },
            ],
        }),
        ..Stats::default()
    });
    hub.links[0].latest = Some(latest);
    let json = serde_json::to_value(web::snapshot(&hub)).unwrap();
    assert_eq!(json["servers"][0]["selection"]["active"], "tcp-ssh");
    assert_eq!(json["servers"][0]["selection"]["round"]["winner"], "tcp");
    assert_eq!(
        json["servers"][0]["selection"]["round"]["finished_at_ms"],
        1_730_000_000_000u64
    );
    assert_eq!(
        json["servers"][0]["selection"]["round"]["entries"],
        serde_json::json!([
            { "candidate": "tcp", "status": "verified", "rtt_ms": 41, "penalty": true },
            { "candidate": "quic", "status": "verified", "rtt_ms": 63, "penalty": false },
            { "candidate": "webrtc", "status": "failed", "reason": "path_timeout" },
            { "candidate": "obfs", "status": "unanswered", "stage": "handshake" },
        ])
    );
    // A link without a live session has no verdict yet.
    assert!(json["servers"][1]["selection"]["active"].is_null());
    assert!(json["servers"][1]["selection"]["round"].is_null());

    // Session end: the collected totals keep the race for the dead link.
    let last = hub.links[0].latest.take().expect("live session");
    hub.links[0].stats.observe(last.borrow().clone());
    let snapshot = web::snapshot(&hub);
    assert_eq!(snapshot.servers[0].selection.active, None);
    assert!(snapshot.servers[0].selection.round.is_some());
}

// ── rules and groups ──

#[test]
fn snapshot_shows_sticky_rule_with_its_owner() {
    let mut hub = hub();
    let block = StickyBlock {
        label: "gaming".to_owned(),
        selector: Selector::Asn(vec![64500]),
        via: Via::Servers(vec!["192.0.2.2".to_owned()]),
        every: Duration::from_secs(60),
    };
    let group = svpn::sticky::group_key(&block.canonical_key());
    hub.exit_owners.insert(group, 1);
    hub.stickies.push(RuntimeSticky::new(block));
    hub.sticky_via.push(ResolvedVia::Links(vec![1]));

    let snapshot = web::snapshot(&hub);
    assert_eq!(snapshot.rules.len(), 1);
    let rule = &snapshot.rules[0];
    assert_eq!(rule.label, "gaming");
    assert_eq!(rule.selector, "asn: 64500");
    assert_eq!(rule.via, "servers: 192.0.2.2");
    assert_eq!(rule.every_secs, 60);
    assert_eq!(rule.owner.as_deref(), Some("192.0.2.2"));
    assert_eq!(snapshot.groups.len(), 1);
    assert_eq!(snapshot.groups[0].group, "gaming");
    assert_eq!(snapshot.groups[0].server, "192.0.2.2");
}

#[test]
fn snapshot_names_asn_groups() {
    let mut hub = hub();
    hub.exit_owners.insert(64500, 0);
    let snapshot = web::snapshot(&hub);
    assert_eq!(snapshot.groups.len(), 1);
    assert_eq!(snapshot.groups[0].group, "asn 64500");
    assert_eq!(snapshot.groups[0].server, "192.0.2.1");
}

// ── flows ──

#[test]
fn snapshot_maps_live_flows_to_their_server() {
    let mut hub = hub();
    hub.routes.insert(
        flow(6, 40000, 443),
        Target::Remote(Owner {
            epoch: Epoch {
                link: 1,
                generation: 1,
            },
            id: 7,
        }),
        None,
    );
    hub.routes
        .insert(flow(17, 9000, 53), Target::Direct(9), None);
    let snapshot = web::snapshot(&hub);
    assert_eq!(snapshot.flows.len(), 2);
    // Sorted by protocol: tcp before udp.
    assert_eq!(snapshot.flows[0].protocol, "tcp");
    assert_eq!(snapshot.flows[0].via, "192.0.2.2");
    assert_eq!(snapshot.flows[0].destination, "1.2.3.4:443");
    assert_eq!(snapshot.flows[1].protocol, "udp");
    assert_eq!(snapshot.flows[1].via, "local");
    assert!(
        snapshot
            .flows
            .iter()
            .all(|flow| flow.country.is_none() && flow.asn.is_none())
    );
}

#[test]
fn destination_geo_is_independent_of_exit_policy_and_unknown_ranges_stay_null() {
    let mut hub = hub();
    let start = u32::from(Ipv4Addr::new(1, 2, 3, 0));
    hub.geo = Some(Geo::from_ranges(vec![(start, start + 255, 13335)]));
    hub.country = Some(Geo::from_ranges(vec![(
        start,
        start + 255,
        pack_country("US").unwrap(),
    )]));
    hub.routes
        .insert(flow(6, 40000, 443), Target::Direct(1), None);
    let mut unknown = flow(17, 40001, 53);
    unknown.destination = Ipv4Addr::new(203, 0, 113, 1);
    hub.routes.insert(unknown, Target::Direct(2), None);
    let json = serde_json::to_value(web::snapshot(&hub)).unwrap();
    assert_eq!(json["policy"], "balance");
    assert_eq!(json["flows"][0]["country"], "US");
    assert_eq!(json["flows"][0]["asn"], 13335);
    assert_eq!(json["flows"][0]["via"], "local");
    assert!(json["flows"][1]["country"].is_null());
    assert!(json["flows"][1]["asn"].is_null());
    hub.country = None;
    let snapshot = web::snapshot(&hub);
    assert_eq!(snapshot.flows[0].asn, Some(13335));
    assert_eq!(snapshot.flows[0].country, None);
    hub.geo = None;
    hub.country = Some(Geo::from_ranges(vec![(
        start,
        start + 255,
        pack_country("DE").unwrap(),
    )]));
    let snapshot = web::snapshot(&hub);
    assert_eq!(snapshot.flows[0].country.as_deref(), Some("DE"));
    assert_eq!(snapshot.flows[0].asn, None);
}

// ── json ──

#[test]
fn snapshot_serializes_to_json() {
    let hub = hub();
    let json = serde_json::to_value(web::snapshot(&hub)).expect("snapshot serializes");
    for key in [
        "generated_at",
        "policy",
        "servers",
        "sticky",
        "rules",
        "groups",
        "local",
        "flows",
        "jobs",
    ] {
        assert!(json.get(key).is_some(), "missing key {key}");
    }
    assert_eq!(json["servers"].as_array().map(Vec::len), Some(2));
    assert_eq!(json["local"]["enabled"], serde_json::json!(false));
    assert_eq!(json["rules"].as_array().map(Vec::len), Some(0));
}

#[test]
fn empty_hub_has_no_flows_or_groups() {
    let hub = hub();
    let json = serde_json::to_value(web::snapshot(&hub)).expect("snapshot serializes");
    assert_eq!(json["flows"].as_array().map(Vec::len), Some(0));
    assert_eq!(json["groups"].as_array().map(Vec::len), Some(0));
    assert_eq!(json["jobs"]["runs"], serde_json::json!(0));
    assert_eq!(json["sticky"]["lookup_hit"], serde_json::json!(0));
}
