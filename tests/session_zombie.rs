//! Zombie-SYN hardening (EPIC-023): the flow table displaces unproven
//! flows instead of refusing new handshakes, unproven TCP flows die at
//! FLOW_BUDGET even when active and flushed, and proven flows are never
//! displaced. Proof of life is a completed TCP handshake — a SYN-ACK alone
//! is not — and a capacity refusal is visible: a reset toward the client
//! under the flow's hub owner id.

mod common;

use std::time::Duration;

use common::session::{activate, assert_closed, fill, link_session_cap, reply, tcp_packet};
use svpn::hub::{Owner, Routes, Target};
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
        let epoch = link_io::Epoch {
            link: 2,
            generation: 7,
        };
        let mut bytes = tcp_packet(2);
        bytes[20..22].copy_from_slice(&65000u16.to_be_bytes());
        let key = packet::parse(&bytes, true).unwrap().flow;
        let id = FLOW_CAP as u64 + 1;
        session.handle_tun_packet(&bytes, Some(id)).await.unwrap();
        assert!(!session.has_flow(id));
        assert!(session.has_flow(1), "proven flows are never evicted");
        // The refusal is visible: a reset toward the client, then closed.
        // It must ride the flow's hub owner id — an id of 0 never reaches
        // the client behind a hub route map.
        let (_, event) = events.try_recv().unwrap();
        let link_io::Event::Packet(reset) = event else {
            panic!("expected a visible refusal reset");
        };
        assert!(
            packet::parse(&reset.bytes, false).is_some_and(|parsed| parsed.is_rst),
            "the refusal is a reset"
        );
        let mut routes = Routes::default();
        routes.insert(key, Target::Remote(Owner { epoch, id }), None);
        assert_eq!(reset.id, id, "the reset rides the flow's owner id");
        assert!(
            routes.accepts(epoch, &reset),
            "the hub route map accepts the reset"
        );
        assert_closed(events.try_recv().unwrap(), id, key);
        assert_eq!(session.flow_count(), FLOW_CAP);
        assert_eq!(session.stats.open_failed_flows, 1);
    }
}

// ── flow budget ──

#[tokio::test]
async fn a_full_pending_pool_frees_only_pending_slots() {
    for tcp in [false, true] {
        let (mut session, mut events) = link_session_cap(tcp, 8);
        fill(&mut session, false);
        stagger(&mut session);
        make_newest_pending(&mut session, svpn::selector::PENDING_FLOWS as u64);
        let mut bytes = tcp_packet(2);
        bytes[20..22].copy_from_slice(&65000u16.to_be_bytes());
        let id = FLOW_CAP as u64 + 1;
        session.handle_tun_packet(&bytes, Some(id)).await.unwrap();
        assert!(session.has_flow(id), "a new handshake must always pass");
        let mut closed = 0;
        while let Ok((_, event)) = events.try_recv() {
            if matches!(event, link_io::Event::Closed { .. }) {
                closed += 1;
            }
        }
        let oldest_pending = FLOW_CAP as u64 - svpn::selector::PENDING_FLOWS as u64 + 1;
        assert_eq!(closed, 1, "pending pressure frees pending slots only");
        assert!(
            !session.has_flow(oldest_pending),
            "the oldest pending zombie yields"
        );
        assert!(session.has_flow(oldest_pending - 1), "active slots survive");
        assert_eq!(session.flow_count(), FLOW_CAP);
    }
}

#[tokio::test]
async fn a_repeated_open_never_displaces_its_own_flow() {
    let (mut session, mut events) = link_session_cap(true, 8);
    fill(&mut session, false);
    stagger(&mut session);
    if let Plane::Tcp(plane) = &mut session.plane {
        plane.server_ip = None; // server side: Open handling
    }
    session.tcp_open_server(1, 1, fill_key(1)).await.unwrap();
    // A stale generation for the same id is ignored, not evicted.
    if let Plane::Tcp(plane) = &mut session.plane
        && let Some(flow) = plane.flows.get_mut(&1)
    {
        flow.generation = 2;
    }
    session.tcp_open_server(1, 1, fill_key(1)).await.unwrap();
    assert!(session.has_flow(1), "the binding keeps its slot");
    assert!(events.try_recv().is_err(), "no flow is closed for a repeat");
    assert_eq!(session.flow_count(), FLOW_CAP);
}

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
        advance(RST_DWELL - Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(session.has_flow(1));
        advance(Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(
            !session.has_flow(1),
            "a reset answer proves nothing and ends the flow"
        );
    }
}

// ── proof of life ──

#[tokio::test(start_paused = true)]
async fn a_synack_alone_does_not_prove_the_flow() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        let key = packet::parse(&tcp_packet(2), true).unwrap().flow;
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
                packet: reply(0x12), // SYN|ACK: the handshake is still open
            })
            .await
            .unwrap();
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Packet(_)
        ));
        advance(svpn::selector::FLOW_BUDGET + Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(!session.has_flow(1), "a SYN-ACK alone proves nothing");
        assert_closed(events.try_recv().unwrap(), 1, key);
    }
}

#[tokio::test(start_paused = true)]
async fn the_clients_final_ack_completes_the_handshake() {
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
                packet: reply(0x12),
            })
            .await
            .unwrap();
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Packet(_)
        ));
        // The client kernel's final ACK: the handshake is complete.
        session
            .handle_tun_packet(&tcp_packet(0x10), Some(1))
            .await
            .unwrap();
        advance(svpn::selector::FLOW_BUDGET + Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(
            session.has_flow(1),
            "a completed handshake is proof of life"
        );
    }
}

// ── helpers ──

/// Leave the newest `count` flows without a binding: they count toward
/// the pending pool while the older ones stay active.
fn make_newest_pending(session: &mut Session, count: u64) {
    let cutoff = FLOW_CAP as u64 - count;
    match &mut session.plane {
        Plane::Channels(plane) => {
            for (id, flow) in plane.flows.iter_mut() {
                if *id > cutoff {
                    flow.active = false;
                }
            }
        }
        Plane::Tcp(plane) => {
            for (id, flow) in plane.flows.iter_mut() {
                if *id > cutoff {
                    flow.active = false;
                }
            }
        }
    }
}

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
