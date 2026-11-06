//! Zombie-SYN hardening (EPIC-023): the flow table displaces unproven
//! flows instead of refusing new handshakes, unproven TCP flows die at
//! FLOW_BUDGET even when active and flushed, and proven flows are never
//! displaced. A capacity refusal is visible: a reset toward the client.

mod common;

use std::time::Duration;

use common::session::{activate, assert_closed, fill, link_session_cap, reply, tcp_packet};
use svpn::link_io;
use svpn::packet;
use svpn::session::*;
use svpn::udp::Incoming;
use tokio::time::{Instant, advance};

// ── displacement admission ──

#[tokio::test]
async fn zombie_storm_displaces_the_oldest_unproven_flows_instead_of_refusing() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 8);
        fill(&mut session, false);
        stagger(&mut session);
        for (step, port) in [65000u16, 65001].into_iter().enumerate() {
            let mut bytes = tcp_packet(2);
            bytes[20..22].copy_from_slice(&port.to_be_bytes());
            let id = FLOW_CAP as u64 + step as u64 + 1;
            session.handle_tun_packet(&bytes, Some(id)).await.unwrap();
            assert!(session.has_flow(id), "a new handshake must always pass");
            let victim = step as u64 + 1;
            assert!(!session.has_flow(victim), "the oldest unproven slot yields");
            assert_closed(events.try_recv().unwrap(), victim, fill_key(victim));
            assert_eq!(session.flow_count(), FLOW_CAP);
        }
        assert_eq!(session.stats.open_failed_flows, 0);
    }
}

#[tokio::test]
async fn proven_slots_are_never_displaced_and_the_refusal_resets() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 8);
        fill(&mut session, true);
        stagger(&mut session);
        let mut bytes = tcp_packet(2);
        bytes[20..22].copy_from_slice(&65000u16.to_be_bytes());
        let key = packet::parse(&bytes, true).unwrap().flow;
        let id = FLOW_CAP as u64 + 1;
        session.handle_tun_packet(&bytes, Some(id)).await.unwrap();
        assert!(!session.has_flow(id));
        assert!(session.has_flow(1), "proven flows are never evicted");
        // The refusal is visible: a reset toward the client, then closed.
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Packet(ref p) if packet::parse(&p.bytes, false).is_some_and(|r| r.is_rst)
        ));
        assert_closed(events.try_recv().unwrap(), id, key);
        assert_eq!(session.flow_count(), FLOW_CAP);
        assert_eq!(session.stats.open_failed_flows, 1);
    }
}

// ── flow budget ──

#[tokio::test(start_paused = true)]
async fn zombie_syn_flows_die_at_the_flow_budget_even_when_active() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        let key = packet::parse(&tcp_packet(2), true).unwrap().flow;
        session
            .handle_tun_packet(&tcp_packet(2), Some(1))
            .await
            .unwrap();
        let _outgoing = activate(&mut session, 1);
        let budget = svpn::selector::FLOW_BUDGET;
        advance(budget - Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(session.has_flow(1));
        assert!(events.try_recv().is_err());
        advance(Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(!session.has_flow(1), "an unanswered SYN is a zombie");
        assert_closed(events.try_recv().unwrap(), 1, key);
    }
}

#[tokio::test(start_paused = true)]
async fn answered_flows_outlive_the_flow_budget() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        session
            .handle_tun_packet(&tcp_packet(2), Some(1))
            .await
            .unwrap();
        let _outgoing = activate(&mut session, 1);
        let greeting = reply(0x10);
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: 1,
                channel: None,
                packet: greeting.clone(),
            })
            .await
            .unwrap();
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Packet(p) if p.bytes == greeting
        ));
        advance(svpn::selector::FLOW_BUDGET + Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(session.has_flow(1), "proof of life beats the budget");
    }
}

#[tokio::test(start_paused = true)]
async fn target_reset_does_not_prove_the_flow() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        session
            .handle_tun_packet(&tcp_packet(2), Some(1))
            .await
            .unwrap();
        let _outgoing = activate(&mut session, 1);
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: 1,
                channel: None,
                packet: reply(4),
            })
            .await
            .unwrap();
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Packet(_)
        ));
        assert!(
            session.has_flow(1),
            "a target reset leaves the decision to the client"
        );
        let budget = svpn::selector::FLOW_BUDGET;
        advance(budget - Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(session.has_flow(1));
        advance(Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(!session.has_flow(1), "a reset answer proves nothing");
    }
}

// ── helpers ──

/// The `fill` fixture key of flow `id` (source_port = 10000 + id).
fn fill_key(id: u64) -> packet::FlowKey {
    let mut key = packet::parse(&tcp_packet(2), true).unwrap().flow;
    key.source_port = 10000 + id as u16;
    key
}

/// Backdate creations so displacement order is deterministic:
/// flow 1 is the oldest victim.
fn stagger(session: &mut Session) {
    let now = Instant::now();
    match &mut session.plane {
        Plane::Channels(plane) => {
            for (id, flow) in plane.flows.iter_mut() {
                flow.created = now - Duration::from_secs(FLOW_CAP as u64 - *id);
            }
        }
        Plane::Tcp(plane) => {
            for (id, flow) in plane.flows.iter_mut() {
                flow.created = now - Duration::from_secs(FLOW_CAP as u64 - *id);
            }
        }
    }
}
