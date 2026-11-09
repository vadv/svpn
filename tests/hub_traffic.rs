//! Per-rule IP accounting: first match, fallback, queue loss, retirement and local exit.

mod common;

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use svpn::{
    hub::{Hub, LocalExitState, Owner, Target, Traffic},
    link_io::{Epoch, Event, Packet},
    packet,
    sticky::{ResolvedVia, RuntimeSticky, Selector, StickyBlock, Via},
    web,
};
use tokio::sync::{mpsc, watch};

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);

// ── attribution ──

#[tokio::test]
async fn first_match_is_pinned_even_after_dns_changes() {
    let mut hub = common::hub::dashboard_hub();
    rules(&mut hub, false);
    let (tx, mut rx) = mpsc::channel(4);
    hub.links[0].outgoing = Some(tx);
    let bytes = common::udp_packet(false);
    hub.dispatch(&bytes, CLIENT).unwrap();
    rx.recv().await.unwrap();
    // A refreshed name set no longer matches this tuple. Ownership and accounting stay pinned.
    hub.stickies[0].resolved.clear();
    hub.dispatch(&bytes, CLIENT).unwrap();
    rx.recv().await.unwrap();
    let state = web::snapshot(&hub);
    assert_eq!(state.flows[0].rule, Some(0));
    assert_eq!(state.rules[0].traffic.tx_bytes, 56);
    assert_eq!(state.rules[0].traffic.active_flows, 1);
    assert_eq!(state.rules[1].traffic.tx_bytes, 0);
    assert_eq!(state.fallback.tx_bytes, 0);
}

#[tokio::test]
async fn fallback_is_explicit_and_queue_loss_never_counts_as_traffic() {
    let mut hub = common::hub::dashboard_hub();
    let (tx, mut rx) = mpsc::channel(1);
    hub.links[0].outgoing = Some(tx.clone());
    let bytes = common::udp_packet(false);
    hub.dispatch(&bytes, CLIENT).unwrap();
    // The same flow and a new tuple both hit a full queue.
    hub.dispatch(&bytes, CLIENT).unwrap();
    let mut other = bytes.clone();
    other[20..22].copy_from_slice(&40001u16.to_be_bytes());
    hub.dispatch(&other, CLIENT).unwrap();
    assert_eq!(web::snapshot(&hub).fallback.tx_bytes, 28);
    assert_eq!(hub.routes.by_key.len(), 1);
    rx.recv().await.unwrap();
    drop(rx);
    hub.dispatch(&bytes, CLIENT).unwrap();
    assert_eq!(web::snapshot(&hub).fallback.tx_bytes, 28);
    assert_eq!(hub.routes.by_key.len(), 1);
}

#[tokio::test]
async fn local_rule_counts_accepted_packets_and_keeps_totals_after_close() {
    let mut hub = common::hub::dashboard_hub();
    rules(&mut hub, true);
    let (tx, mut rx) = mpsc::channel(1);
    local(&mut hub, tx);
    let bytes = common::udp_packet(false);
    hub.dispatch(&bytes, CLIENT).unwrap();
    let sent = rx.recv().await.unwrap();
    hub.dispatch(&bytes, CLIENT).unwrap();
    // Full queue: no extra charge.
    hub.dispatch(&bytes, CLIENT).unwrap();
    assert_eq!(web::snapshot(&hub).rules[0].traffic.tx_bytes, 56);
    let key = packet::parse(&bytes, true).unwrap().flow;
    hub.handle_local_event((epoch(1), Event::Closed { id: sent.id, key }), &mut None)
        .await
        .unwrap();
    let state = web::snapshot(&hub);
    assert_eq!(state.rules[0].traffic.tx_bytes, 56);
    assert_eq!(state.rules[0].traffic.active_flows, 0);
    assert!(state.flows.is_empty());
    assert_eq!(state.fallback.tx_bytes, 0);
}

#[test]
fn local_not_ready_is_visible_and_never_falls_back_or_counts() {
    let mut hub = common::hub::dashboard_hub();
    rules(&mut hub, true);
    hub.dispatch(&common::udp_packet(false), CLIENT).unwrap();
    let state = web::snapshot(&hub);
    assert!(state.local.enabled);
    assert!(!state.local.ready);
    assert_eq!(state.local.failed, 1);
    assert!(state.flows.is_empty());
    assert_eq!(state.rules[0].traffic.tx_bytes, 0);
    assert_eq!(state.fallback.tx_bytes, 0);
}

// ── retirement, RX boundary and saturation ──

#[tokio::test]
async fn stale_local_reply_or_missing_tun_cannot_increase_rx() {
    let mut hub = common::hub::dashboard_hub();
    rules(&mut hub, true);
    let (tx, mut rx) = mpsc::channel(1);
    local(&mut hub, tx);
    hub.dispatch(&common::udp_packet(false), CLIENT).unwrap();
    let id = rx.recv().await.unwrap().id;
    let reply = common::udp_packet(true);
    // Stale id is ignored before touching the absent TUN.
    hub.handle_local_event(
        (
            epoch(1),
            Event::Packet(Packet {
                id: id + 1,
                bytes: reply.clone(),
            }),
        ),
        &mut None,
    )
    .await
    .unwrap();
    assert!(
        hub.handle_local_event(
            (epoch(1), Event::Packet(Packet { id, bytes: reply })),
            &mut None
        )
        .await
        .is_err()
    );
    assert_eq!(web::snapshot(&hub).rules[0].traffic.rx_bytes, 0);
}

#[test]
fn totals_survive_retirement_and_new_generation_without_double_charging() {
    let mut hub = common::hub::dashboard_hub();
    let key = packet::parse(&common::udp_packet(false), true)
        .unwrap()
        .flow;
    hub.routes.insert(
        key,
        Target::Remote(Owner {
            epoch: epoch(1),
            id: 1,
        }),
        Some(0),
    );
    hub.routes.record(key, 28, 100);
    assert_eq!(hub.routes.remove_epoch(epoch(1)), vec![key]);
    // A late delivery is not attributable after retirement.
    hub.routes.record(key, 0, 100);
    hub.routes.insert(
        key,
        Target::Remote(Owner {
            epoch: epoch(2),
            id: 2,
        }),
        Some(0),
    );
    hub.routes.record(key, 28, 200);
    let totals = hub.routes.traffic[&Some(0)];
    assert_eq!((totals.tx_bytes, totals.rx_bytes), (56, 300));
    assert_eq!(hub.routes.by_key.len(), 1);
    // The reinserted flow starts its own count; the rule keeps the history.
    let flow = hub.routes.by_key[&key].traffic;
    assert_eq!((flow.tx_bytes, flow.rx_bytes), (28, 200));
    let json = serde_json::to_value(svpn::web::snapshot(&hub)).unwrap();
    assert_eq!(json["flows"][0]["rx_bytes"], 200);
    assert_eq!(json["flows"][0]["tx_bytes"], 28);
}

#[test]
fn counters_saturate_instead_of_wrapping() {
    let mut hub = common::hub::dashboard_hub();
    let key = packet::parse(&common::udp_packet(false), true)
        .unwrap()
        .flow;
    hub.routes.insert(key, Target::Direct(1), Some(0));
    hub.routes.traffic.insert(
        Some(0),
        Traffic {
            rx_bytes: u64::MAX,
            tx_bytes: u64::MAX - 1,
        },
    );
    hub.routes.record(key, 28, 28);
    assert_eq!(hub.routes.traffic[&Some(0)].tx_bytes, u64::MAX);
    assert_eq!(hub.routes.traffic[&Some(0)].rx_bytes, u64::MAX);
}

// ── helpers ──

fn rules(hub: &mut Hub, is_local: bool) {
    hub.stickies = ["first", "second"]
        .into_iter()
        .map(|label| {
            let mut runtime = RuntimeSticky::new(StickyBlock {
                label: label.to_owned(),
                selector: Selector::Names(vec!["example.test".to_owned()]),
                via: if is_local {
                    Via::Local
                } else {
                    Via::Servers(vec![hub.nodes[0].0.clone()])
                },
                every: Duration::from_secs(300),
            });
            runtime.resolved.insert(Ipv4Addr::new(10, 77, 0, 1));
            runtime
        })
        .collect();
    hub.sticky_via = (0..2)
        .map(|_| {
            if is_local {
                ResolvedVia::Local
            } else {
                ResolvedVia::Links(vec![0])
            }
        })
        .collect();
}

fn local(hub: &mut Hub, outgoing: mpsc::Sender<Packet>) {
    hub.local = Some(LocalExitState {
        outgoing,
        events: None,
        latest: watch::channel(Default::default()).1,
        delivery: Arc::default(),
        server: svpn::local_proxy::LocalServer::new(tokio::spawn(std::future::pending())),
        ready: true,
    });
}

fn epoch(generation: u64) -> Epoch {
    Epoch {
        link: 0,
        generation,
    }
}
