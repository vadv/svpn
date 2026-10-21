//! Session tombstones: closed-rule resets, rate limiting, bounded table, retire.

mod common;

use std::time::Duration;
use std::time::Instant as StdInstant;

use common::session::{link_session, link_session_cap, tcp_packet, test_key};
use svpn::link_io;
use svpn::packet::{self, FlowKey};
use svpn::session::*;

#[test]
fn tombstones_answer_by_closed_rules_and_rate_limit() {
    let mut tombstones = Tombstones::default();
    let t0 = StdInstant::now();
    let key = test_key();
    assert!(!tombstones.active(&key, t0));
    tombstones.insert(key, t0);
    assert!(tombstones.active(&key, t0 + TOMBSTONE_TTL - Duration::from_millis(1)));

    // Incoming ACK → RST with seq = its ack.
    let mut ack_segment = tcp_packet(0x10);
    ack_segment[24..28].copy_from_slice(&5u32.to_be_bytes());
    ack_segment[28..32].copy_from_slice(&900u32.to_be_bytes());
    let ack_packet = packet::parse(&ack_segment, true).unwrap();
    let reset = tombstones.respond(&key, &ack_packet, t0).unwrap();
    assert_eq!(reset[33], 0x04);
    assert_eq!(&reset[24..28], &900u32.to_be_bytes());

    // Within the minimum interval: silent drop.
    assert!(
        tombstones
            .respond(&key, &ack_packet, t0 + Duration::from_millis(100))
            .is_none()
    );
    // After it: answers again.
    assert!(
        tombstones
            .respond(&key, &ack_packet, t0 + Duration::from_millis(250))
            .is_some()
    );

    // SYN (no ACK) → RST|ACK acknowledging seq + 1.
    let mut syn = tcp_packet(0x02);
    syn[24..28].copy_from_slice(&1234u32.to_be_bytes());
    let syn_packet = packet::parse(&syn, true).unwrap();
    let reset = tombstones
        .respond(&key, &syn_packet, t0 + Duration::from_millis(500))
        .unwrap();
    assert_eq!(reset[33], 0x14);
    assert_eq!(&reset[28..32], &1235u32.to_be_bytes());

    // An incoming RST is never answered.
    let rst_packet = packet::parse(&tcp_packet(0x04), true).unwrap();
    assert!(
        tombstones
            .respond(&key, &rst_packet, t0 + Duration::from_millis(600))
            .is_none()
    );

    // TTL expiry frees the tuple for normal admission.
    assert!(!tombstones.active(&key, t0 + TOMBSTONE_TTL));
}

#[test]
fn tombstone_table_is_bounded_and_evicts_oldest() {
    let mut tombstones = Tombstones::default();
    let t0 = StdInstant::now();
    let first = FlowKey {
        source_port: 1,
        ..test_key()
    };
    for i in 0..(TOMBSTONE_CAP + 3) as u16 {
        tombstones.insert(
            FlowKey {
                source_port: i + 1,
                ..test_key()
            },
            t0,
        );
    }
    assert_eq!(tombstones.entries.len(), TOMBSTONE_CAP);
    assert!(!tombstones.active(&first, t0));
    assert!(tombstones.active(
        &FlowKey {
            source_port: TOMBSTONE_CAP as u16 + 2,
            ..test_key()
        },
        t0
    ));
}

#[tokio::test]
async fn retire_resets_tcp_flows_with_known_ack_and_drops_the_rest() {
    for tcp in [false, true] {
        let (mut session, _events) = link_session(tcp);
        // TCP flow with a known last client ACK.
        let syn = tcp_packet(0x02);
        let key = packet::parse(&syn, true).unwrap().flow;
        session.handle_tun_packet(&syn, Some(41)).await.unwrap();
        let mut data = tcp_packet(0x10);
        data[24..28].copy_from_slice(&100u32.to_be_bytes());
        data[28..32].copy_from_slice(&777u32.to_be_bytes());
        session.handle_tun_packet(&data, Some(41)).await.unwrap();
        // TCP flow without any ACK: respond-on-arrival covers it.
        let mut orphan_syn = tcp_packet(0x02);
        orphan_syn[20..22].copy_from_slice(&40001u16.to_be_bytes());
        session
            .handle_tun_packet(&orphan_syn, Some(42))
            .await
            .unwrap();
        // A UDP flow: retired silently, no tombstone, no reset.
        let udp_key = FlowKey {
            protocol: 17,
            ..key
        };
        if let Plane::Channels(plane) = &mut session.plane {
            plane
                .flows
                .insert(7, Flow::new(udp_key, tokio::time::Instant::now()));
            plane.by_key.insert(udp_key, 7);
        }
        assert!(session.has_flow(41) && session.has_flow(42));

        let retired = session.retire_flows_of();
        // Exactly one RST + one probe, for the acked flow.
        assert_eq!(retired.len(), 2);
        let (id, reset) = retired[0];
        assert_eq!(id, 41);
        let parsed = packet::parse(&reset, false).unwrap();
        assert_eq!(parsed.flow, key);
        assert_eq!(parsed.tcp.as_ref().unwrap().flags, 0x04);
        assert_eq!(parsed.tcp.as_ref().unwrap().seq, 777);
        let (_, probe) = retired[1];
        let parsed = packet::parse(&probe, false).unwrap();
        assert_eq!(parsed.tcp.as_ref().unwrap().flags, 0x10);
        assert_eq!(parsed.tcp.as_ref().unwrap().seq, 776);
        // All flows are gone; every TCP tuple is tombstoned, UDP is not.
        assert_eq!(session.flow_count(), 0);
        let now = StdInstant::now();
        assert!(session.tombstones.active(&key, now));
        assert!(
            session
                .tombstones
                .active(&packet::parse(&orphan_syn, true).unwrap().flow, now)
        );
        assert!(!session.tombstones.active(&udp_key, now));
        // Idempotent.
        assert!(session.retire_flows_of().is_empty());
    }
}

#[tokio::test]
async fn emit_retired_pushes_resets_through_the_packet_port() {
    let (mut session, mut events) = link_session_cap(false, 8);
    let syn = tcp_packet(0x02);
    session.handle_tun_packet(&syn, Some(41)).await.unwrap();
    let mut data = tcp_packet(0x10);
    data[28..32].copy_from_slice(&777u32.to_be_bytes());
    session.handle_tun_packet(&data, Some(41)).await.unwrap();

    session.emit_retired_resets();
    for expected_flags in [0x04u8, 0x10] {
        let (epoch, event) = events.recv().await.unwrap();
        assert_eq!(
            epoch,
            link_io::Epoch {
                link: 2,
                generation: 7
            }
        );
        let link_io::Event::Packet(packet) = event else {
            panic!("expected a packet event");
        };
        assert_eq!(packet.id, 41);
        let parsed = packet::parse(&packet.bytes, false).unwrap();
        assert_eq!(parsed.tcp.as_ref().unwrap().flags, expected_flags);
    }
    assert!(events.try_recv().is_err());
    assert_eq!(session.flow_count(), 0);
}

#[tokio::test]
async fn tombstoned_packets_get_closed_rule_reset_and_never_admit() {
    let (mut session, mut events) = link_session_cap(false, 8);
    let mut data = tcp_packet(0x10);
    data[24..28].copy_from_slice(&500u32.to_be_bytes());
    data[28..32].copy_from_slice(&900u32.to_be_bytes());
    data[2..4].copy_from_slice(&44u16.to_be_bytes());
    data.resize(44, 0);
    let key = packet::parse(&data, true).unwrap().flow;
    session.tombstones.insert(key, StdInstant::now());

    session.handle_tun_packet(&data, Some(41)).await.unwrap();
    let (_, event) = events.recv().await.unwrap();
    let link_io::Event::Packet(packet) = event else {
        panic!("expected a packet event");
    };
    let parsed = packet::parse(&packet.bytes, false).unwrap();
    assert_eq!(parsed.flow, key);
    assert_eq!(parsed.tcp.as_ref().unwrap().flags, 0x04);
    // CLOSED rule: the reply's seq is the incoming packet's ack.
    assert_eq!(parsed.tcp.as_ref().unwrap().seq, 900);
    assert!(!session.has_flow(41));
    assert_eq!(session.flow_count(), 0);

    // Rate limit: an immediate repeat is silently dropped, still unadmitted.
    session.handle_tun_packet(&data, Some(41)).await.unwrap();
    assert!(events.try_recv().is_err());
    assert_eq!(session.flow_count(), 0);

    // A client RST into the tombstone: no response, no admission.
    session
        .handle_tun_packet(&tcp_packet(0x04), Some(41))
        .await
        .unwrap();
    assert!(events.try_recv().is_err());
    assert_eq!(session.flow_count(), 0);

    // A re-SYN for the same tuple is still refused while the tombstone lives.
    let syn = tcp_packet(0x02);
    assert_eq!(packet::parse(&syn, true).unwrap().flow, key);
    session.handle_tun_packet(&syn, Some(41)).await.unwrap();
    assert_eq!(session.flow_count(), 0);
    assert!(!session.has_flow(41));
}
