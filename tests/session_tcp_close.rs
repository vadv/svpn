//! TCP close tracking (FIN dwell, reset grace) and independent
//! user/probe admission limits.

mod common;

use std::time::Duration;

use common::session::{
    activate, assert_closed, assert_closing, link_session, link_session_cap, reply, tcp_packet,
};
use svpn::link_io::{self, FIRST_PROBE_ID};
use svpn::packet::{self, FlowKey, Packet};
use svpn::session::{
    FIN_DWELL, FLOW_CAP, Flow, PROBE_FLOW_RESERVE, Plane, RST_DWELL, Session, TcpClose, TcpFlow,
};
use svpn::udp::Incoming;
use tokio::sync::mpsc;
use tokio::time::{Instant, advance};

// ── close tracking ──

#[test]
fn observe_reports_the_dwell_arming_once_and_again_after_a_reopen() {
    let now = Instant::now();
    let mut close = TcpClose::default();
    assert!(
        !close.observe(&segment(0x11, 100, 200), true, now),
        "one FIN is a half-close"
    );
    assert!(close.observe(&segment(0x11, 200, 101), false, now));
    assert!(
        !close.observe(&segment(0x11, 200, 101), false, now),
        "a retransmitted FIN does not re-arm the dwell"
    );
    close.observe(&segment(0x02, 500, 0), true, now);
    assert!(!close.finished(), "a new SYN resets the close state");
    assert!(!close.observe(&segment(0x11, 600, 501), true, now));
    assert!(
        close.observe(&segment(0x11, 700, 601), false, now),
        "the reopened tuple reports closing again"
    );
}

#[test]
fn new_syn_clears_the_previous_connections_close_state() {
    let now = Instant::now();
    let mut close = completed_close(now);
    close.observe(&segment(0x02, 500, 0), true, now);
    close.observe(&segment(0x12, 600, 501), false, now);
    close.observe(&segment(0x10, 501, 601), true, now);
    assert!(!close.finished());
    assert!(close.deadline().is_none());
    close.observe(
        &segment(0x10, 600, 501),
        false,
        now + FIN_DWELL + Duration::from_secs(1),
    );
    assert!(!close.finished());
    assert!(close.deadline().is_none());
}

#[test]
fn an_ack_observed_before_the_fin_still_records_it_and_arms_the_dwell() {
    for expected in [200u32, 0] {
        let now = Instant::now();
        let mut close = TcpClose::default();
        close.observe(&segment(0x10, 100, expected), true, now);
        close.observe(&segment(0x11, expected.wrapping_sub(1), 100), false, now);
        assert!(!close.finished(), "one direction is not a close");
        assert!(close.deadline().is_none());
        close.observe(&segment(0x10, 100, expected), true, now);
        close.observe(&segment(0x11, 100, expected), true, now);
        close.observe(&segment(0x10, expected, 101), false, now);
        assert!(
            close.finished(),
            "the lost final ACKs must not pin the flow"
        );
        assert_eq!(close.deadline(), Some(now + FIN_DWELL));
    }
}

#[test]
fn a_fin_reusing_the_syn_sequence_no_longer_blocks_the_dwell() {
    let now = Instant::now();
    let mut close = TcpClose::default();
    close.observe(&segment(0x02, 100, 0), true, now);
    close.observe(&segment(0x12, 200, 101), false, now);
    close.observe(&segment(0x11, 100, 201), true, now);
    close.observe(&segment(0x10, 201, 101), false, now);
    assert!(!close.finished(), "only the client direction closed");
    assert!(close.deadline().is_none());
    close.observe(&segment(0x11, 201, 101), false, now);
    close.observe(&segment(0x10, 101, 202), true, now);
    assert!(close.finished());
    assert_eq!(close.deadline(), Some(now + FIN_DWELL));
}

#[test]
fn completed_close_deadline_is_not_extended_by_unrelated_packets() {
    let now = Instant::now();
    let mut close = completed_close(now);
    let deadline = close.deadline().unwrap();
    for packet in [
        segment(0x10, 900, 901),
        segment(0x14, 900, 901),
        segment(0x11, 900, 901),
        segment(0x11, 200, 101),
    ] {
        close.observe(&packet, false, deadline - Duration::from_secs(1));
        assert!(close.finished());
        assert_eq!(close.deadline(), Some(deadline));
    }
}

// ── reset grace ──

#[test]
fn a_reset_in_either_direction_arms_a_cancelable_short_deadline() {
    let now = Instant::now();
    let mut close = TcpClose::default();
    close.observe(&segment(0x04, 900, 901), false, now);
    assert_eq!(close.deadline(), Some(now + RST_DWELL));
    assert!(!close.finished(), "a reset is not a graceful close");
    close.observe(&segment(0x18, 100, 101), true, now);
    assert_eq!(
        close.deadline(),
        Some(now + RST_DWELL),
        "the peer's in-flight data crossing the reset does not cancel it"
    );
    close.observe(&segment(0x10, 901, 101), false, now);
    assert_eq!(
        close.deadline(),
        None,
        "the reset sender speaking again means the reset was forged"
    );
    close.observe(&segment(0x14, 100, 101), true, now);
    assert_eq!(
        close.deadline(),
        Some(now + RST_DWELL),
        "an RST|ACK from the other side re-arms"
    );
    close.observe(&segment(0x10, 100, 101), true, now);
    assert_eq!(close.deadline(), None, "and its sender cancels it");
}

#[tokio::test(start_paused = true)]
async fn target_reset_then_silence_closes_the_flow_after_the_grace() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        let key = committed(&mut session).await.1;
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
            events.try_recv().is_err(),
            "a reset never reports the flow closing"
        );
        advance(RST_DWELL - Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(session.has_flow(1), "the reset grace has not passed");
        advance(Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(!session.has_flow(1), "a target reset retires the flow");
        assert_closed(events.try_recv().unwrap(), 1, key);
    }
}

#[tokio::test(start_paused = true)]
async fn an_undelivered_client_reset_closes_the_flow_after_the_grace() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        let (mut outgoing, key) = committed(&mut session).await;
        session
            .handle_tun_packet(&tcp_packet(4), Some(1))
            .await
            .unwrap();
        assert_eq!(outgoing.try_recv().unwrap(), tcp_packet(4));
        assert!(session.has_flow(1), "an ingress reset never closes at once");
        advance(RST_DWELL - Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(session.has_flow(1));
        advance(Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(
            !session.has_flow(1),
            "a lost client reset still retires the flow"
        );
        assert_closed(events.try_recv().unwrap(), 1, key);
    }
}

#[tokio::test(start_paused = true)]
async fn traffic_after_a_reset_cancels_the_grace() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        let _key = committed(&mut session).await.1;
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
        // The connection lives on: the reset was forged or out of window.
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: 1,
                channel: None,
                packet: reply(0x10),
            })
            .await
            .unwrap();
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Packet(_)
        ));
        advance(RST_DWELL + Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(
            session.has_flow(1),
            "resumed traffic cancels the reset grace"
        );
        assert!(events.try_recv().is_err());
    }
}

// ── fin dwell ──

#[tokio::test(start_paused = true)]
async fn both_fins_report_the_flow_closing_once_before_the_dwell_ends() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        let (mut outgoing, key) = committed(&mut session).await;
        // A half-close is not closing: nothing is reported yet.
        session
            .handle_tun_packet(&tcp_packet(0x11), Some(1))
            .await
            .unwrap();
        assert_eq!(outgoing.try_recv().unwrap(), tcp_packet(0x11));
        assert!(
            events.try_recv().is_err(),
            "a single FIN never reports closing"
        );
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: 1,
                channel: None,
                packet: reply(0x11),
            })
            .await
            .unwrap();
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Packet(_)
        ));
        assert_closing(events.try_recv().unwrap(), 1, key);
        // A retransmitted segment on the finished tuple does not report twice.
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: 1,
                channel: None,
                packet: reply(0x11),
            })
            .await
            .unwrap();
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Packet(_)
        ));
        assert!(
            events.try_recv().is_err(),
            "closing is reported exactly once"
        );
        advance(FIN_DWELL + Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert_closed(events.try_recv().unwrap(), 1, key);
    }
}

#[tokio::test(start_paused = true)]
async fn both_fins_close_the_flow_after_the_dwell_even_without_the_final_acks() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        let (mut outgoing, key) = committed(&mut session).await;
        session
            .handle_tun_packet(&tcp_packet(0x11), Some(1))
            .await
            .unwrap();
        assert_eq!(outgoing.try_recv().unwrap(), tcp_packet(0x11));
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: 1,
                channel: None,
                packet: reply(0x11),
            })
            .await
            .unwrap();
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Packet(_)
        ));
        assert_closing(events.try_recv().unwrap(), 1, key);
        advance(FIN_DWELL - Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(session.has_flow(1), "the dwell has not passed");
        advance(Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(
            !session.has_flow(1),
            "a lost final ACK must not pin the flow"
        );
        assert_closed(events.try_recv().unwrap(), 1, key);
    }
}

#[tokio::test(start_paused = true)]
async fn a_single_fin_half_close_keeps_the_flow() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        let (mut outgoing, _key) = committed(&mut session).await;
        session
            .handle_tun_packet(&tcp_packet(0x11), Some(1))
            .await
            .unwrap();
        assert_eq!(outgoing.try_recv().unwrap(), tcp_packet(0x11));
        advance(FIN_DWELL + Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(session.has_flow(1), "a half-close is not a close");
        assert!(events.try_recv().is_err());
    }
}

// ── admission ──

#[tokio::test]
async fn probes_do_not_reduce_the_user_allowance() {
    for fixed_tcp in [false, true] {
        let (mut session, _events) = server(fixed_tcp);
        for index in 0..PROBE_FLOW_RESERVE {
            open(
                &mut session,
                FIRST_PROBE_ID + index as u64,
                key(index as u16),
            )
            .await;
        }
        for id in 1..FLOW_CAP as u64 {
            let key = key(id as u16 + 100);
            match &mut session.plane {
                Plane::Channels(plane) => {
                    let mut flow = Flow::new(key, Instant::now());
                    flow.active = true;
                    flow.data_started = true;
                    flow.proven = true;
                    plane.flows.insert(id, flow);
                    plane.by_key.insert(key, id);
                }
                Plane::Tcp(plane) => {
                    let mut flow = TcpFlow::new(key, Instant::now());
                    flow.active = true;
                    flow.data_started = true;
                    flow.proven = true;
                    plane.flows.insert(id, flow);
                    plane.by_key.insert(key, id);
                }
            }
        }
        let id = FLOW_CAP as u64;
        open(&mut session, id, key(6000)).await;
        assert!(session.has_flow(id));
        assert_eq!(session.flow_count(), FLOW_CAP);
        // In a full table the next binding displaces the only unproven
        // flow — the one just opened (EPIC-023 displacement admission).
        open(&mut session, id + 1, key(6001)).await;
        assert!(session.has_flow(id + 1));
        assert!(!session.has_flow(id));
        assert_eq!(session.flow_count(), FLOW_CAP);
    }
}

#[tokio::test]
async fn probe_reserve_is_bounded_when_there_are_no_user_flows() {
    for fixed_tcp in [false, true] {
        let (mut session, _events) = server(fixed_tcp);
        for index in 0..PROBE_FLOW_RESERVE {
            let id = FIRST_PROBE_ID + index as u64;
            open(&mut session, id, key(index as u16)).await;
            assert!(session.has_flow(id));
        }
        let excess = FIRST_PROBE_ID + PROBE_FLOW_RESERVE as u64;
        open(&mut session, excess, key(PROBE_FLOW_RESERVE as u16)).await;
        assert!(!session.has_flow(excess));
        assert_eq!(session.flow_count(), 0);
    }
}

// ── helpers ──

fn segment(flags: u8, seq: u32, ack: u32) -> Packet {
    let mut packet = packet::parse(&tcp_packet(flags), true).unwrap();
    let tcp = packet.tcp.as_mut().unwrap();
    tcp.seq = seq;
    tcp.ack = ack;
    packet
}

fn completed_close(now: Instant) -> TcpClose {
    let mut close = TcpClose::default();
    close.observe(&segment(0x11, 100, 200), true, now);
    close.observe(&segment(0x10, 200, 101), false, now);
    close.observe(&segment(0x11, 200, 101), false, now);
    close.observe(&segment(0x10, 101, 201), true, now);
    assert!(close.finished());
    assert_eq!(close.deadline(), Some(now + FIN_DWELL));
    close
}

/// Open flow 1 (client SYN, id 1) and commit it with a live transport:
/// the state an established connection has when a reset or FIN arrives.
async fn committed(session: &mut Session) -> (mpsc::Receiver<Vec<u8>>, FlowKey) {
    let syn = tcp_packet(2);
    let key = packet::parse(&syn, true).unwrap().flow;
    session.handle_tun_packet(&syn, Some(1)).await.unwrap();
    let outgoing = activate(session, 1);
    (outgoing, key)
}

fn key(port: u16) -> FlowKey {
    let mut key = packet::parse(&tcp_packet(2), true).unwrap().flow;
    key.source_port = 10000 + port;
    key
}

fn server(
    fixed_tcp: bool,
) -> (
    Session,
    tokio::sync::mpsc::Receiver<(svpn::link_io::Epoch, svpn::link_io::Event)>,
) {
    let (mut session, events) = link_session(fixed_tcp);
    match &mut session.plane {
        Plane::Channels(plane) => {
            plane.server_ip = None;
            plane.selector = None;
            plane.tcp_port = Some(9000);
        }
        Plane::Tcp(plane) => plane.server_ip = None,
    }
    (session, events)
}

async fn open(session: &mut Session, id: u64, key: FlowKey) {
    match session.plane {
        Plane::Channels(_) => session.channels_tcp_open(id, 1, key).await.unwrap(),
        Plane::Tcp(_) => session.tcp_open_server(id, 1, key).await.unwrap(),
    }
}
