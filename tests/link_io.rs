use std::net::Ipv4Addr;
use std::sync::Arc;

use svpn::control::Stats;
use svpn::link_io::*;
use tokio::sync::{mpsc, watch};

#[test]
fn delivery_counts_only_completed_writes_and_never_double_counts_drops() {
    let delivery = Delivery::default();
    let mut stats = Stats {
        dropped_packets: 3,
        ..Stats::default()
    };
    delivery.dropped();
    delivery.apply(&mut stats);
    assert_eq!(
        (
            stats.inner_rx_packets,
            stats.inner_rx_bytes,
            stats.dropped_packets
        ),
        (0, 0, 4)
    );
    delivery.received(40);
    delivery.received(60);
    delivery.apply(&mut stats);
    delivery.apply(&mut stats);
    assert_eq!(
        (
            stats.inner_rx_packets,
            stats.inner_rx_bytes,
            stats.dropped_packets
        ),
        (2, 100, 4)
    );
}

#[tokio::test]
async fn bounded_port_preserves_packet_id_and_epoch() {
    let epoch = Epoch {
        link: 3,
        generation: 17,
    };
    let (packets, incoming) = mpsc::channel(1);
    let (events, mut returned) = mpsc::channel(1);
    let (stats, latest) = watch::channel(Stats::default());
    let mut io = LinkIo {
        epoch,
        peer_ip: Ipv4Addr::new(10, 77, 0, 1),
        tag: String::new(),
        packets: incoming,
        events,
        stats,
        delivery: Arc::default(),
    };
    packets
        .try_send(Packet {
            id: 91,
            bytes: vec![1, 2, 3],
        })
        .unwrap();
    assert!(matches!(
        packets.try_send(Packet {
            id: 92,
            bytes: vec![],
        }),
        Err(mpsc::error::TrySendError::Full(_))
    ));
    let packet = io.packets.recv().await.unwrap();
    assert_eq!(packet.id, 91);
    assert_eq!(packet.bytes, [1, 2, 3]);
    io.events
        .try_send((io.epoch, Event::Packet(packet)))
        .unwrap();
    assert!(matches!(
        io.events.try_send((io.epoch, Event::Ready)),
        Err(mpsc::error::TrySendError::Full(_))
    ));
    for packets in 1..=3 {
        io.stats.send_replace(Stats {
            inner_rx_packets: packets,
            ..Stats::default()
        });
    }
    assert_eq!(latest.borrow().inner_rx_packets, 3);
    let (received_epoch, event) = returned.recv().await.unwrap();
    assert_eq!(received_epoch, epoch);
    let Event::Packet(packet) = event else {
        panic!("expected packet event");
    };
    assert_eq!(packet.id, 91);
    assert_eq!(packet.bytes, [1, 2, 3]);
}
