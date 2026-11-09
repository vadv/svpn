//! Burst draining of the session packet ports: one wake processes the
//! queued packets in order, bounded by `DRAIN_BATCH` so the select loop
//! still runs.

mod common;

use common::session::{
    activate, activate_with_cap, link_session_cap, link_session_port, reply, tcp_packet,
};
use svpn::link_io::{Event, Packet};
use svpn::session::{DRAIN_BATCH, PacketIo};
use svpn::udp::Incoming;

/// Reply packets distinguishable per index without changing the flow tuple.
fn replies(count: u64) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let mut bytes = reply(0x10);
            bytes[38] = i as u8;
            bytes
        })
        .collect()
}

/// Client ACK packets distinguishable per index: upload-path traffic.
fn acks(count: u64) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let mut bytes = tcp_packet(0x10);
            bytes[38] = i as u8;
            bytes
        })
        .collect()
}

// ── download: channel packets → hub event port ──

#[tokio::test(start_paused = true)]
async fn download_burst_keeps_queue_order() {
    let (mut session, mut events) = link_session_cap(false, 16);
    session
        .handle_tun_packet(&tcp_packet(2), Some(1))
        .await
        .unwrap();
    let _outgoing = activate(&mut session, 1);
    let packets = replies(5);
    for bytes in &packets {
        session
            .incoming
            .0
            .send(Incoming {
                generation: 1,
                id: 1,
                channel: None,
                packet: bytes.clone(),
            })
            .await
            .unwrap();
    }
    let first = session.incoming.1.try_recv().unwrap();
    session.deliver_to_tun_burst(first).await.unwrap();
    for bytes in &packets {
        assert!(
            matches!(&events.try_recv().unwrap().1, Event::Packet(p) if &p.bytes == bytes),
            "packet {bytes:?} in queue order"
        );
    }
    assert!(events.try_recv().is_err());
    assert!(session.incoming.1.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn download_burst_is_bounded_by_drain_batch() {
    let (mut session, mut events) = link_session_cap(false, 64);
    session
        .handle_tun_packet(&tcp_packet(2), Some(1))
        .await
        .unwrap();
    let _outgoing = activate(&mut session, 1);
    let packets = replies(DRAIN_BATCH as u64 + 3);
    for bytes in &packets {
        session
            .incoming
            .0
            .send(Incoming {
                generation: 1,
                id: 1,
                channel: None,
                packet: bytes.clone(),
            })
            .await
            .unwrap();
    }
    let first = session.incoming.1.try_recv().unwrap();
    session.deliver_to_tun_burst(first).await.unwrap();
    for bytes in &packets[..DRAIN_BATCH] {
        assert!(matches!(&events.try_recv().unwrap().1, Event::Packet(p) if &p.bytes == bytes));
    }
    // Exactly the bound is delivered; the rest keep their queue order.
    for bytes in &packets[DRAIN_BATCH..] {
        assert!(
            matches!(&session.incoming.1.try_recv().unwrap(), incoming if &incoming.packet == bytes)
        );
    }
    assert!(session.incoming.1.try_recv().is_err());
}

// ── upload: hub packet port → flow channels ──

#[tokio::test(start_paused = true)]
async fn upload_burst_keeps_queue_order() {
    let (mut session, _events, port) = link_session_port(false);
    session
        .handle_tun_packet(&tcp_packet(2), Some(1))
        .await
        .unwrap();
    let mut outgoing = activate(&mut session, 1);
    let packets = acks(4);
    for bytes in &packets {
        port.send(Packet {
            id: 1,
            bytes: bytes.clone(),
        })
        .await
        .unwrap();
    }
    let first = match &mut session.io {
        PacketIo::Link(io) => io.packets.try_recv().unwrap(),
        PacketIo::Device(_) => unreachable!("link fixture"),
    };
    session
        .handle_tun_packet_burst(&first.bytes, Some(first.id))
        .await
        .unwrap();
    for bytes in &packets {
        assert_eq!(outgoing.recv().await.unwrap(), *bytes);
    }
}

#[tokio::test(start_paused = true)]
async fn upload_burst_is_bounded_by_drain_batch() {
    let (mut session, _events, port) = link_session_port(false);
    session
        .handle_tun_packet(&tcp_packet(2), Some(1))
        .await
        .unwrap();
    let mut outgoing = activate_with_cap(&mut session, 1, 64);
    let packets = acks(DRAIN_BATCH as u64 + 3);
    for bytes in &packets {
        port.send(Packet {
            id: 1,
            bytes: bytes.clone(),
        })
        .await
        .unwrap();
    }
    let first = match &mut session.io {
        PacketIo::Link(io) => io.packets.try_recv().unwrap(),
        PacketIo::Device(_) => unreachable!("link fixture"),
    };
    session
        .handle_tun_packet_burst(&first.bytes, Some(first.id))
        .await
        .unwrap();
    for bytes in &packets[..DRAIN_BATCH] {
        assert_eq!(outgoing.recv().await.unwrap(), *bytes);
    }
    for bytes in &packets[DRAIN_BATCH..] {
        let next = match &mut session.io {
            PacketIo::Link(io) => io.packets.try_recv().unwrap(),
            PacketIo::Device(_) => unreachable!("link fixture"),
        };
        assert_eq!(next.bytes, *bytes);
    }
}
