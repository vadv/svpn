//! Hub routes: flow-table ownership across epochs, queue and write accounting.

mod common;

use std::time::Duration;

use common::tcp_packet;
use svpn::hub::*;
use svpn::link_io::{Delivery, Epoch, FIRST_PROBE_ID, Packet};
use svpn::packet;
use tokio::sync::mpsc;

// ── ownership across epochs ──

#[test]
fn stale_close_cannot_forget_a_reused_tuple() {
    let key = packet::parse(&common::udp_packet(false), true)
        .unwrap()
        .flow;
    let mut routes = Routes::default();
    let first = Owner {
        epoch: epoch(1),
        id: routes.allocate().unwrap(),
    };
    let second = Owner {
        epoch: epoch(2),
        id: routes.allocate().unwrap(),
    };
    routes.by_key.insert(key, second);
    routes.forget(key, first);
    let retired = routes.remove_epoch(first.epoch);
    assert!(retired.is_empty(), "first owner was already forgotten");
    assert_eq!(routes.by_key.get(&key), Some(&second));
    routes.forget(key, second);
    assert!(routes.by_key.is_empty());
}

#[test]
fn remove_epoch_returns_tcp_and_udp_keys_for_tombstoning() {
    let udp = packet::parse(&common::udp_packet(false), true).unwrap();
    let tcp = tcp_packet(false);
    let mut routes = Routes::default();
    routes.by_key.insert(
        udp.flow,
        Owner {
            epoch: epoch(1),
            id: 1,
        },
    );
    routes.by_key.insert(
        packet::parse(&tcp, true).unwrap().flow,
        Owner {
            epoch: epoch(1),
            id: 2,
        },
    );
    routes.by_key.insert(
        packet::parse(&common::udp_packet(true), true).unwrap().flow,
        Owner {
            epoch: epoch(2),
            id: 3,
        },
    );
    let mut retired = routes.remove_epoch(epoch(1));
    retired.sort_by_key(|key| (key.protocol, key.source_port));
    assert_eq!(retired.len(), 2);
    assert_eq!(retired[0].protocol, 6, "TCP key is tombstone material");
    assert_eq!(retired[1].protocol, 17);
    assert_eq!(routes.by_key.len(), 1, "epoch-2 owner survives");
}

#[test]
fn old_epoch_and_flow_id_cannot_deliver_after_tuple_reuse() {
    let bytes = common::udp_packet(true);
    let key = packet::parse(&bytes, false).unwrap().flow;
    let mut routes = Routes::default();
    routes.by_key.insert(
        key,
        Owner {
            epoch: epoch(2),
            id: 9,
        },
    );
    assert!(!routes.accepts(
        epoch(1),
        &Packet {
            id: 9,
            bytes: bytes.clone()
        }
    ));
    assert!(!routes.accepts(
        epoch(2),
        &Packet {
            id: 8,
            bytes: bytes.clone()
        }
    ));
    assert!(routes.accepts(epoch(2), &Packet { id: 9, bytes }));
}

#[test]
fn flow_ids_never_enter_the_reserved_probe_space() {
    let mut routes = Routes {
        next: FIRST_PROBE_ID - 2,
        ..Routes::default()
    };
    assert_eq!(routes.allocate().unwrap(), FIRST_PROBE_ID - 1);
    assert!(routes.allocate().is_err());
}

// ── queue and write accounting ──

#[tokio::test]
async fn full_queue_counts_loss_without_installing_a_new_owner() {
    let (outgoing, mut incoming) = mpsc::channel(1);
    let delivery = Delivery::default();
    let mut routes = Routes::default();
    outgoing
        .try_send(Packet {
            id: 99,
            bytes: vec![],
        })
        .unwrap();
    let bytes = common::udp_packet(false);
    let ip = packet::parse(&bytes, true).unwrap().flow.source;
    routes
        .enqueue(&bytes, ip, epoch(1), &outgoing, &delivery, &[])
        .unwrap();
    assert!(routes.by_key.is_empty());
    let mut stats = svpn::control::Stats::default();
    delivery.apply(&mut stats);
    assert_eq!(stats.dropped_packets, 1);
    incoming.recv().await.unwrap();
    routes
        .enqueue(&bytes, ip, epoch(1), &outgoing, &delivery, &[])
        .unwrap();
    assert_eq!(routes.by_key.len(), 1);
    let id = incoming.recv().await.unwrap().id;
    assert_eq!(routes.by_key.values().next().unwrap().id, id);
    drop(incoming);
    routes
        .enqueue(&bytes, ip, epoch(1), &outgoing, &delivery, &[])
        .unwrap();
}

#[tokio::test]
async fn tun_timeout_is_loss_not_successful_delivery() {
    let delivery = Delivery::default();
    let timed_out = tokio::time::timeout(Duration::ZERO, std::future::pending()).await;
    finish_write(&delivery, 100, timed_out).unwrap();
    finish_write(&delivery, 100, Ok(Ok(100))).unwrap();
    assert!(finish_write(&delivery, 100, Ok(Ok(99))).is_err());
    let mut stats = svpn::control::Stats::default();
    delivery.apply(&mut stats);
    assert_eq!(
        (
            stats.inner_rx_packets,
            stats.inner_rx_bytes,
            stats.dropped_packets
        ),
        (1, 100, 2)
    );
}

fn epoch(generation: u64) -> Epoch {
    Epoch {
        link: 0,
        generation,
    }
}
