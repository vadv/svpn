//! Hub routes: flow-table ownership across epochs, queue and write accounting.

mod common;

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
    routes.insert(key, Target::Remote(second), None);
    routes.forget(key, first);
    let retired = routes.remove_epoch(first.epoch);
    assert!(retired.is_empty(), "first owner was already forgotten");
    assert_eq!(routes.target(&key), Some(&Target::Remote(second)));
    routes.forget(key, second);
    assert!(routes.by_key.is_empty());
}

#[test]
fn remove_epoch_returns_tcp_and_udp_keys_for_tombstoning() {
    let udp = packet::parse(&common::udp_packet(false), true).unwrap();
    let tcp = tcp_packet(false);
    let mut routes = Routes::default();
    routes.insert(
        udp.flow,
        Target::Remote(Owner {
            epoch: epoch(1),
            id: 1,
        }),
        None,
    );
    routes.insert(
        packet::parse(&tcp, true).unwrap().flow,
        Target::Remote(Owner {
            epoch: epoch(1),
            id: 2,
        }),
        None,
    );
    routes.insert(
        packet::parse(&common::udp_packet(true), true).unwrap().flow,
        Target::Remote(Owner {
            epoch: epoch(2),
            id: 3,
        }),
        None,
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
    routes.insert(
        key,
        Target::Remote(Owner {
            epoch: epoch(2),
            id: 9,
        }),
        None,
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

// ── flow activity ──

#[test]
fn record_refreshes_last_activity_but_not_the_open_time() {
    let key = packet::parse(&tcp_packet(false), true).unwrap().flow;
    let mut routes = Routes::default();
    routes.insert(key, Target::Direct(1), None);
    let then = std::time::Instant::now() - std::time::Duration::from_secs(60);
    let flow = routes.by_key.get_mut(&key).unwrap();
    (flow.opened, flow.active) = (then, then);
    routes.record(key, 40, 0);
    let flow = &routes.by_key[&key];
    assert_eq!(flow.opened, then);
    assert!(
        flow.active.elapsed().as_secs() < 1,
        "a packet marks the flow active now"
    );
}

// ── closing flows ──

#[test]
fn closing_marks_only_the_current_owner_and_a_new_syn_reopens_the_tuple() {
    let syn = tcp_packet(false);
    let key = packet::parse(&syn, true).unwrap().flow;
    let mut data = syn.clone();
    data[33] = 0x18;
    let mut routes = Routes::default();
    let owner = Owner {
        epoch: epoch(1),
        id: routes.allocate().unwrap(),
    };
    routes.insert(key, Target::Remote(owner), None);
    let stale = Owner {
        epoch: epoch(2),
        id: routes.allocate().unwrap(),
    };
    routes.mark_closing(key, stale);
    assert!(
        !routes.by_key[&key].closing,
        "a stale owner cannot mark closing"
    );
    routes.mark_closing(key, owner);
    assert!(routes.by_key[&key].closing);
    let (outgoing, _incoming) = mpsc::channel(2);
    let delivery = Delivery::default();
    // Ordinary traffic keeps the mark; a new SYN on the tuple clears it.
    routes
        .enqueue(&data, key.source, epoch(1), &outgoing, &delivery, &[])
        .unwrap();
    assert!(routes.by_key[&key].closing);
    routes
        .enqueue(&syn, key.source, epoch(1), &outgoing, &delivery, &[])
        .unwrap();
    assert!(!routes.by_key[&key].closing, "a re-SYN reopens the tuple");
}

// ── direct ownership (spec §5.5) ──

#[test]
fn forget_direct_removes_only_the_current_generation() {
    let key = packet::parse(&common::udp_packet(false), true)
        .unwrap()
        .flow;
    let mut routes = Routes::default();
    routes.insert(key, Target::Direct(2), None);
    // A late close of the previous generation leaves the new owner.
    assert!(!routes.forget_direct(key, 1));
    assert_eq!(routes.target(&key), Some(&Target::Direct(2)));
    // A remote owner is never a direct generation either.
    let owner = Owner {
        epoch: epoch(1),
        id: routes.allocate().unwrap(),
    };
    routes.insert(key, Target::Remote(owner), None);
    assert!(!routes.forget_direct(key, owner.id));
    assert_eq!(routes.target(&key), Some(&Target::Remote(owner)));
    // Only the current direct generation removes and reports success.
    routes.insert(key, Target::Direct(5), None);
    assert!(routes.forget_direct(key, 5));
    assert!(routes.by_key.is_empty());
}

#[test]
fn direct_owner_survives_epoch_removal_and_never_accepts_link_packets() {
    let bytes = common::udp_packet(false);
    let key = packet::parse(&bytes, false).unwrap().flow;
    let mut routes = Routes::default();
    routes.insert(key, Target::Direct(7), None);
    // A dying link retires only its own owners: direct survives (spec §5.5).
    assert!(routes.remove_epoch(epoch(1)).is_empty());
    assert_eq!(routes.target(&key), Some(&Target::Direct(7)));
    // Server-link packets of a direct-owned tuple are never accepted.
    assert!(!routes.accepts(
        epoch(1),
        &Packet {
            id: 7,
            bytes: bytes.clone()
        }
    ));
    assert!(!routes.accepts(epoch(2), &Packet { id: 8, bytes }));
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
    assert!(matches!(
        routes.by_key.values().next().map(|flow| &flow.target),
        Some(Target::Remote(Owner { id: seen, .. })) if *seen == id
    ));
    drop(incoming);
    routes
        .enqueue(&bytes, ip, epoch(1), &outgoing, &delivery, &[])
        .unwrap();
}

#[tokio::test]
async fn tun_timeout_is_loss_not_successful_delivery() {
    let delivery = Delivery::default();
    finish_write(&delivery, 100, None).unwrap();
    finish_write(&delivery, 100, Some(Ok(100))).unwrap();
    assert!(finish_write(&delivery, 100, Some(Ok(99))).is_err());
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
