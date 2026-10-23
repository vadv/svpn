//! TCP close tracking and independent user/probe admission limits.

mod common;

use std::time::Duration;

use common::session::{link_session, tcp_packet};
use svpn::link_io::FIRST_PROBE_ID;
use svpn::packet::{self, FlowKey, Packet};
use svpn::session::{
    FIN_DWELL, FLOW_CAP, Flow, PROBE_FLOW_RESERVE, Plane, Session, TcpClose, TcpFlow,
};
use tokio::time::Instant;

// ── close tracking ──

#[test]
fn new_syn_clears_the_previous_connections_close_state() {
    let now = Instant::now();
    let mut close = completed_close(now);
    close.observe(&segment(0x02, 500, 0), true, now);
    close.observe(&segment(0x12, 600, 501), false, now);
    close.observe(&segment(0x10, 501, 601), true, now);
    assert!(!close.finished());
    assert!(close.deadline.is_none());
    close.observe(
        &segment(0x10, 600, 501),
        false,
        now + FIN_DWELL + Duration::from_secs(1),
    );
    assert!(!close.finished());
    assert!(close.deadline.is_none());
}

#[test]
fn a_duplicate_ack_does_not_validate_an_old_fin() {
    for expected in [200u32, 0] {
        let now = Instant::now();
        let mut close = TcpClose::default();
        close.observe(&segment(0x10, 100, expected), true, now);
        close.observe(&segment(0x11, expected.wrapping_sub(1), 100), false, now);
        close.observe(&segment(0x10, 100, expected), true, now);
        close.observe(&segment(0x11, 100, expected), true, now);
        close.observe(&segment(0x10, expected, 101), false, now);
        assert!(!close.finished());
        assert!(close.deadline.is_none());
        close.observe(&segment(0x10, expected, 101), false, now + FIN_DWELL);
        assert!(close.deadline.is_none());
    }
}

#[test]
fn syn_ack_history_rejects_a_fin_reusing_the_syn_sequence() {
    let now = Instant::now();
    let mut close = TcpClose::default();
    close.observe(&segment(0x02, 100, 0), true, now);
    close.observe(&segment(0x12, 200, 101), false, now);
    close.observe(&segment(0x11, 100, 201), true, now);
    close.observe(&segment(0x10, 201, 101), false, now);
    close.observe(&segment(0x11, 201, 101), false, now);
    close.observe(&segment(0x10, 101, 202), true, now);
    assert!(!close.finished());
    assert!(close.deadline.is_none());
}

#[test]
fn completed_close_deadline_is_not_extended_by_unrelated_packets() {
    let now = Instant::now();
    let mut close = completed_close(now);
    let deadline = close.deadline.unwrap();
    for packet in [
        segment(0x10, 900, 901),
        segment(0x14, 900, 901),
        segment(0x11, 900, 901),
        segment(0x11, 200, 101),
    ] {
        close.observe(&packet, false, deadline - Duration::from_secs(1));
        assert!(close.finished());
        assert_eq!(close.deadline, Some(deadline));
    }
}

// ── admission ──

#[tokio::test]
async fn probes_do_not_reduce_the_user_allowance() {
    for fixed_tcp in [false, true] {
        let mut session = server(fixed_tcp);
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
                    plane.flows.insert(id, flow);
                    plane.by_key.insert(key, id);
                }
                Plane::Tcp(plane) => {
                    let mut flow = TcpFlow::new(key, Instant::now());
                    flow.active = true;
                    flow.data_started = true;
                    plane.flows.insert(id, flow);
                    plane.by_key.insert(key, id);
                }
            }
        }
        let id = FLOW_CAP as u64;
        open(&mut session, id, key(6000)).await;
        assert!(session.has_flow(id));
        assert_eq!(session.flow_count(), FLOW_CAP);
        open(&mut session, id + 1, key(6001)).await;
        assert!(!session.has_flow(id + 1));
    }
}

#[tokio::test]
async fn probe_reserve_is_bounded_when_there_are_no_user_flows() {
    for fixed_tcp in [false, true] {
        let mut session = server(fixed_tcp);
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
    assert_eq!(close.deadline, Some(now + FIN_DWELL));
    close
}

fn key(port: u16) -> FlowKey {
    let mut key = packet::parse(&tcp_packet(2), true).unwrap().flow;
    key.source_port = 10000 + port;
    key
}

fn server(fixed_tcp: bool) -> Session {
    let (mut session, _events) = link_session(fixed_tcp);
    match &mut session.plane {
        Plane::Channels(plane) => {
            plane.server_ip = None;
            plane.selector = None;
            plane.tcp_port = Some(9000);
        }
        Plane::Tcp(plane) => plane.server_ip = None,
    }
    session
}

async fn open(session: &mut Session, id: u64, key: FlowKey) {
    match session.plane {
        Plane::Channels(_) => session.channels_tcp_open(id, 1, key).await.unwrap(),
        Plane::Tcp(_) => session.tcp_open_server(id, 1, key).await.unwrap(),
    }
}
