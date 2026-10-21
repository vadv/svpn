//! Probe bursts (EPIC-016): pacing, echo accounting, deadlines, p90, timer wiring.

mod common;

use std::time::Duration;

use svpn::session::Readiness;
use svpn::session::burst::{BURST_LEN, BURST_SPACING, BURST_TAIL, Burst};
use tokio::time::Instant;

fn probe() -> Burst {
    Burst::new(7, 1000, 4242, 100, vec![1, 2, 3])
}

// ── pacing ──

#[test]
fn echoes_are_spaced_after_arming() {
    let t0 = Instant::now();
    let mut burst = probe();
    assert_eq!(burst.due(t0), None, "an unarmed burst sends nothing");
    burst.arm(t0);
    for index in 0..BURST_LEN {
        let at = t0 + BURST_SPACING * index as u32;
        assert_eq!(burst.due(at), Some(index));
        burst.mark_sent(at);
    }
    assert_eq!(burst.due(t0 + BURST_SPACING * BURST_LEN as u32), None);
}

// ── echo accounting ──

#[test]
fn echoes_record_rtt_once_and_reject_strays() {
    let t0 = Instant::now();
    let mut burst = probe();
    burst.arm(t0);
    // An echo for a probe that never left is not ours.
    assert!(!burst.record_echo(burst.seq(1), t0));
    burst.mark_sent(t0);
    assert!(burst.record_echo(burst.seq(0), t0 + Duration::from_millis(40)));
    // A duplicate echo is ignored.
    assert!(!burst.record_echo(burst.seq(0), t0 + Duration::from_millis(50)));
    // Sequence numbers outside the burst window are rejected.
    assert!(!burst.record_echo(burst.seq(0).wrapping_add(BURST_LEN as u16), t0));
    assert!(!burst.record_echo(burst.seq(0).wrapping_sub(1), t0));
    let outcome = burst.outcome();
    assert_eq!((outcome.received, outcome.lost), (1, BURST_LEN - 1));
    assert_eq!(outcome.p90, Some(Duration::from_millis(40)));
}

// ── deadlines ──

#[test]
fn burst_finishes_on_all_echoes_or_the_tail_deadline() {
    let t0 = Instant::now();
    let mut burst = probe();
    burst.arm(t0);
    let deadline = t0 + BURST_SPACING * (BURST_LEN as u32 - 1) + BURST_TAIL;
    for index in 0..BURST_LEN {
        burst.mark_sent(t0 + BURST_SPACING * index as u32);
    }
    assert!(!burst.finished(deadline - Duration::from_millis(1)));
    assert!(burst.finished(deadline));
    // With every echo back the burst ends before the deadline.
    let mut complete = probe();
    complete.arm(t0);
    for index in 0..BURST_LEN {
        let at = t0 + BURST_SPACING * index as u32;
        complete.mark_sent(at);
        assert!(complete.record_echo(complete.seq(index), at));
    }
    assert!(complete.finished(t0 + BURST_SPACING * 9));
}

#[test]
fn wake_points_at_the_next_send_then_the_deadline() {
    let t0 = Instant::now();
    let mut burst = probe();
    assert_eq!(burst.wake_at(), None);
    burst.arm(t0);
    assert_eq!(burst.wake_at(), Some(t0));
    for index in 0..BURST_LEN {
        burst.mark_sent(t0 + BURST_SPACING * index as u32);
    }
    assert_eq!(
        burst.wake_at(),
        Some(t0 + BURST_SPACING * (BURST_LEN as u32 - 1) + BURST_TAIL)
    );
}

// ── p90 ──

#[test]
fn p90_is_nearest_rank() {
    let t0 = Instant::now();
    let mut burst = probe();
    burst.arm(t0);
    for index in 0..BURST_LEN {
        let at = t0 + BURST_SPACING * index as u32;
        burst.mark_sent(at);
        // RTTs 100, 90, …, 10 ms — unsorted on purpose.
        let rtt = Duration::from_millis((BURST_LEN - index) as u64 * 10);
        assert!(burst.record_echo(burst.seq(index), at + rtt));
    }
    assert_eq!(burst.outcome().p90, Some(Duration::from_millis(90)));

    let mut single = probe();
    single.arm(t0);
    single.mark_sent(t0);
    assert!(single.record_echo(single.seq(0), t0 + Duration::from_millis(7)));
    assert_eq!(single.outcome().p90, Some(Duration::from_millis(7)));
}

// ── timer wiring ──

#[tokio::test]
async fn health_wake_follows_the_timer_then_the_burst() {
    let (mut session, _events) = common::session::link_session(false);
    assert_eq!(session.health_wake(), None, "no bursts before Ready");
    session.readiness = Some(Readiness::Ready);
    let at = Instant::now() + Duration::from_secs(30);
    session.health_at = Some(at);
    assert_eq!(session.health_wake(), Some(at));
    // A burst in flight takes over the schedule.
    let mut burst = probe();
    burst.arm(Instant::now());
    session.burst = Some(burst);
    assert_eq!(
        session.health_wake(),
        session.burst.as_ref().unwrap().wake_at()
    );
}

// ── session wiring ──

#[tokio::test]
async fn committed_arms_burst_and_sends_first_echo() {
    use svpn::selector::Candidate;
    use svpn::session::ChannelHandle;
    use svpn::session::TaskCommand;

    let (mut session, _events) = common::session::link_session(false);
    let channel = 1u64;
    let (command, mut commands) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(async move {});
    let svpn::session::Plane::Channels(plane) = &mut session.plane else {
        panic!("channels plane")
    };
    plane.channels.insert(
        channel,
        ChannelHandle {
            candidate: Candidate::Mosh,
            cancel: None,
            command,
            task,
            relay: None,
        },
    );
    // Probe flows live above FIRST_PROBE_ID, like round attempts.
    let attempt = svpn::link_io::FIRST_PROBE_ID;
    let now = tokio::time::Instant::now();
    let mut probe = Burst::new(channel, attempt, 4242, 100, vec![9; 32]);
    let key = svpn::packet::FlowKey {
        protocol: 1,
        source: session.client_ip,
        destination: std::net::Ipv4Addr::new(10, 77, 0, 1),
        source_port: 4242,
        destination_port: 0,
    };
    let mut flow = svpn::session::Flow::new(key, now);
    flow.channel = Some(channel);
    plane.flows.insert(attempt, flow);
    session.burst = Some(probe);

    session.committed(attempt).await.unwrap();

    let burst = session.burst.as_ref().unwrap();
    assert!(burst.finished(now + BURST_TAIL + BURST_SPACING * 10));
    let outcome = burst.outcome();
    assert_eq!((outcome.received, outcome.lost), (0, BURST_LEN));
    match commands.try_recv() {
        Ok(TaskCommand::Data(id, packet)) => {
            assert_eq!(id, attempt);
            assert_eq!(
                svpn::packet::icmp_echo_reply_seq(&packet, 4242, &[9; 32]),
                None,
                "outgoing request is no reply"
            );
        }
        _ => panic!("expected the first echo Data"),
    }
}

// ── flow_opened wiring ──

#[tokio::test]
async fn health_probe_flow_opened_commits_on_the_wire() {
    // Regression: a health-burst probe is owned by neither the round nor the
    // challenge; flow_opened fell through to the selector, no Commit ever
    // left, the server never sent Committed — the burst stayed unarmed
    // forever and health silently stalled.
    let (client_half, mut wire) = tokio::io::duplex(4096);
    let control = svpn::control::Control::new(tokio::io::empty(), client_half);
    let (mut session, _events) = common::session::link_session_with(false, control);
    session.readiness = Some(Readiness::Ready);
    let attempt = svpn::link_io::FIRST_PROBE_ID;
    let channel = 7u64;
    let key = svpn::packet::FlowKey {
        protocol: 1,
        source: session.client_ip,
        destination: std::net::Ipv4Addr::new(10, 77, 0, 1),
        source_port: 4242,
        destination_port: 0,
    };
    let mut flow = svpn::session::Flow::new(key, Instant::now());
    flow.channel = Some(channel);
    let svpn::session::Plane::Channels(plane) = &mut session.plane else {
        panic!("channels plane")
    };
    plane.flows.insert(attempt, flow);
    session.burst = Some(Burst::new(channel, attempt, 4242, 100, vec![9; 32]));

    session
        .dispatch_control(svpn::control::Message::FlowOpened {
            flow_id: attempt,
            flow: key,
            channel,
        })
        .await
        .unwrap();

    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(&mut wire);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_millis(100), lines.read_line(&mut line))
        .await
        .expect("a Commit must leave right away")
        .unwrap();
    let message: svpn::control::Message = serde_json::from_str(line.trim()).unwrap();
    assert!(
        matches!(message, svpn::control::Message::Commit { flow_id, .. } if flow_id == attempt),
        "health probe commits: {line}"
    );
}
