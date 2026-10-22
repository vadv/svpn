//! Background re-selection (EPIC-016 S2): trigger conditions, re-ban on
//! challenger failure, burst queueing, the verdict, and the round abort.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use svpn::selector::{Candidate, Reason};
use svpn::session::burst::{BURST_LEN, Outcome};
use svpn::session::challenge::Challenge;
use svpn::session::{ChannelHandle, ChannelReadyParams, Plane, Readiness};
use tokio::time::Instant;

fn outcome(p90_ms: u64) -> Outcome {
    Outcome {
        p90: Some(Duration::from_millis(p90_ms)),
        received: BURST_LEN,
        lost: 0,
    }
}

fn channels(session: &mut svpn::session::Session) -> &mut svpn::session::ChannelsPlane {
    let Plane::Channels(plane) = &mut session.plane else {
        panic!("channels plane")
    };
    plane
}

fn set_tcp_incumbent(session: &mut svpn::session::Session) {
    session.readiness = Some(Readiness::Ready);
    channels(session).selector.as_mut().unwrap().last_good = Some(Candidate::Tcp);
}

fn dummy_handle() -> ChannelHandle {
    ChannelHandle {
        candidate: Candidate::Mosh,
        cancel: None,
        command: tokio::sync::mpsc::channel(8).0,
        task: tokio::spawn(async move {}),
        relay: None,
    }
}

// Measured challenger flows live in the probe-id range (>= u64::MAX/2):
// there `close_flow` skips the link Closed event an undrained fixture
// channel would block on.
const PROBE_A: u64 = u64::MAX / 2;
const PROBE_B: u64 = PROBE_A + 1;
const PROBE_C: u64 = PROBE_A + 2;
const PROBE_I: u64 = PROBE_A + 3; // the incumbent's probe

fn dummy_icmp_key(id: u16) -> svpn::packet::FlowKey {
    svpn::packet::FlowKey {
        protocol: 1,
        source: std::net::Ipv4Addr::new(10, 77, 0, 2),
        destination: std::net::Ipv4Addr::new(10, 77, 0, 1),
        source_port: id,
        destination_port: 0,
    }
}

// ── trigger ──

#[tokio::test]
async fn challenge_starts_on_tcp_incumbent_with_udp_allowed() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.maybe_start_challenge(false).await.unwrap();
    let challenge = session.challenge.as_ref().expect("challenge started");
    assert_eq!(challenge.attempts.len(), 1, "only mosh is allowed");
    let challenger = challenge.attempts.values().next().unwrap();
    assert_eq!(challenger.candidate, Candidate::Mosh);
    assert_eq!(challenger.channel, None, "not bound yet");
    // A second trigger while one runs is a no-op.
    session.maybe_start_challenge(false).await.unwrap();
    assert_eq!(session.challenge.as_ref().unwrap().attempts.len(), 1);
}

#[tokio::test]
async fn no_challenge_on_udp_incumbent() {
    let (mut session, _events) = common::session::link_session(false);
    session.readiness = Some(Readiness::Ready);
    channels(&mut session).selector.as_mut().unwrap().last_good = Some(Candidate::Mosh);
    session.maybe_start_challenge(false).await.unwrap();
    assert!(session.challenge.is_none());
}

#[tokio::test]
async fn no_challenge_before_ready() {
    let (mut session, _events) = common::session::link_session(false);
    channels(&mut session).selector.as_mut().unwrap().last_good = Some(Candidate::Tcp);
    session.maybe_start_challenge(false).await.unwrap();
    assert!(session.challenge.is_none(), "not Ready yet");
}

#[tokio::test]
async fn remeasure_gate_holds_until_due_and_zero_disables() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.remeasure = Some(Duration::from_secs(600));
    session.next_challenge_at = Some(std::time::Instant::now() + Duration::from_secs(60));
    session.maybe_start_challenge(false).await.unwrap();
    assert!(session.challenge.is_none(), "too early: the gate holds");
    session.maybe_start_challenge(true).await.unwrap();
    assert!(
        session.challenge.is_none(),
        "the degraded trigger obeys the same gate"
    );
    session.next_challenge_at = Some(std::time::Instant::now() - Duration::from_secs(1));
    session.maybe_start_challenge(false).await.unwrap();
    assert!(session.challenge.is_some(), "due: the challenge starts");
    assert!(
        session.next_challenge_at.unwrap() > std::time::Instant::now(),
        "the next round is re-armed"
    );

    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.remeasure = None;
    session.maybe_start_challenge(false).await.unwrap();
    assert!(
        session.challenge.is_none(),
        "remeasure-interval = 0 disables re-selection"
    );
}

// ── failures ──

#[tokio::test]
async fn failed_prepare_rebans_and_finishes() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.maybe_start_challenge(false).await.unwrap();
    let attempt = *session
        .challenge
        .as_ref()
        .unwrap()
        .attempts
        .keys()
        .next()
        .unwrap();
    session
        .channel_failed(Some(attempt), None, Reason::PathTimeout)
        .await
        .unwrap();
    assert!(session.challenge.is_none(), "last challenger failed: done");
    let selector = channels(&mut session).selector.as_ref().unwrap();
    assert!(
        selector
            .banned
            .iter()
            .any(|&(c, r)| c == Candidate::Mosh && r == Reason::PathTimeout),
        "mosh re-banned"
    );
    assert!(
        !selector.allowed.contains(&Candidate::Mosh),
        "banned candidate is not eligible"
    );
}

// ── binding and bursts ──

#[tokio::test]
async fn bound_challenger_builds_probe_flow_and_burst() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.maybe_start_challenge(false).await.unwrap();
    let attempt = *session
        .challenge
        .as_ref()
        .unwrap()
        .attempts
        .keys()
        .next()
        .unwrap();
    session
        .channel_ready(ChannelReadyParams {
            attempt,
            channel: 77,
            port: 0,
            key: [7; 16],
            max_wire: 1500,
            hello: None,
            relay: None,
        })
        .await
        .unwrap();
    // Binding builds the probe flow and the burst inline; the commit arms it.
    let challenge = session.challenge.as_ref().unwrap();
    assert_eq!(challenge.attempts[&attempt].channel, Some(77));
    let burst = challenge.attempts[&attempt].burst.as_ref().unwrap();
    assert!(burst.armed.is_none(), "armed only at Committed");
    {
        let plane = channels(&mut session);
        assert!(plane.channels.contains_key(&77), "channel task spawned");
        let flow = plane.flows.get(&attempt).expect("probe flow");
        assert_eq!(flow.key.protocol, 1, "ICMP echo");
        assert_eq!(flow.key.destination, std::net::Ipv4Addr::new(10, 77, 0, 1));
        assert_eq!(
            flow.channel,
            Some(77),
            "bound at open — committed() insists on it"
        );
    }
    session.committed(attempt).await.unwrap();
    let challenge = session.challenge.as_ref().unwrap();
    let burst = challenge.attempts[&attempt].burst.as_ref().unwrap();
    assert!(burst.armed.is_some(), "commit armed the burst");
    assert!(!burst.finished(Instant::now()), "armed, in flight");
}

// ── verdict ──

#[tokio::test]
async fn bound_challenger_sends_flow_open_on_the_wire() {
    let (client_half, mut wire) = tokio::io::duplex(4096);
    let control = svpn::control::Control::new(tokio::io::empty(), client_half);
    let (mut session, _events) = common::session::link_session_with(false, control);
    set_tcp_incumbent(&mut session);
    session.maybe_start_challenge(false).await.unwrap();
    let attempt = *session
        .challenge
        .as_ref()
        .unwrap()
        .attempts
        .keys()
        .next()
        .unwrap();
    session
        .channel_ready(ChannelReadyParams {
            attempt,
            channel: 77,
            port: 0,
            key: [7; 16],
            max_wire: 1500,
            hello: None,
            relay: None,
        })
        .await
        .unwrap();
    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(&mut wire);
    let mut line = String::new();
    lines.read_line(&mut line).await.unwrap();
    let prepare: svpn::control::Message = serde_json::from_str(line.trim()).unwrap();
    assert!(matches!(
        prepare,
        svpn::control::Message::ChannelPrepare { .. }
    ));
    // The bind itself must stay silent on the wire: announcing the probe
    // before the channel task runs races the server-side spawn, and the
    // `Established` handler announces it — a bind-time send duplicates the
    // FlowOpen and draws a FlowReject (review: challenge never wins).
    line.clear();
    let early = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        lines.read_line(&mut line),
    )
    .await;
    assert!(early.is_err(), "no FlowOpen before Established: {line}");
    session
        .dispatch_task_event(svpn::session::TaskEvent::Established { channel: 77 })
        .await
        .unwrap();
    // Without the FlowOpen on the wire the server never registers the
    // probe flow and drops every burst echo reply (review finding 1).
    let mut opened = None;
    for _ in 0..4 {
        line.clear();
        lines.read_line(&mut line).await.unwrap();
        if let Ok(message @ svpn::control::Message::FlowOpen { .. }) =
            serde_json::from_str::<svpn::control::Message>(line.trim())
        {
            opened = Some(message);
            break;
        }
    }
    let Some(svpn::control::Message::FlowOpen {
        flow_id,
        flow,
        channel,
    }) = opened
    else {
        panic!("expected FlowOpen after Established");
    };
    assert_eq!(flow_id, attempt);
    assert_eq!(channel, Some(77));
    assert_eq!(flow.protocol, 1, "ICMP probe flow");
}

#[tokio::test]
async fn fastest_challenger_wins_and_losers_retire() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    {
        let plane = channels(&mut session);
        plane.channels.insert(77, dummy_handle());
        let mut quic = dummy_handle();
        quic.candidate = Candidate::Quic;
        plane.channels.insert(78, quic);
        plane.flows.insert(
            PROBE_A,
            svpn::session::Flow::new(dummy_icmp_key(1), Instant::now()),
        );
        plane.flows.insert(
            PROBE_B,
            svpn::session::Flow::new(dummy_icmp_key(2), Instant::now()),
        );
    }
    session.challenge = Some(Challenge {
        incumbent: None,
        attempts: HashMap::new(),
        measured: vec![
            (Candidate::Mosh, 77, PROBE_A, outcome(100)),
            (Candidate::Quic, 78, PROBE_B, outcome(50)),
        ],
        deadline: Instant::now() + Duration::from_secs(30),
    });
    session.finish_challenge(false).await.unwrap();
    assert!(session.challenge.is_none(), "nothing left: verdict");
    // S3: the first win only arms the retry — the incumbent still serves,
    // and the winner's channel retires like any loser's.
    let pending = session.switch_pending.map(|(candidate, _)| candidate);
    {
        let plane = channels(&mut session);
        let selector = plane.selector.as_ref().unwrap();
        assert_eq!(selector.last_good, Some(Candidate::Tcp), "no switch yet");
        assert_eq!(pending, Some(Candidate::Quic), "quic won the round");
        assert!(
            !plane.channels.contains_key(&77) && !plane.channels.contains_key(&78),
            "every challenger channel retires, the winner's included"
        );
        assert!(
            !plane.flows.contains_key(&PROBE_A) && !plane.flows.contains_key(&PROBE_B),
            "every probe flow closes"
        );
    }
    // The confirming round (at least one health interval later) lands it.
    session.switch_pending = Some((
        Candidate::Quic,
        std::time::Instant::now() - Duration::from_secs(31),
    ));
    {
        let plane = channels(&mut session);
        let mut quic = dummy_handle();
        quic.candidate = Candidate::Quic;
        plane.channels.insert(79, quic);
        plane.flows.insert(
            PROBE_C,
            svpn::session::Flow::new(dummy_icmp_key(3), Instant::now()),
        );
    }
    session.challenge = Some(Challenge {
        incumbent: None,
        attempts: HashMap::new(),
        measured: vec![(Candidate::Quic, 79, PROBE_C, outcome(50))],
        deadline: Instant::now() + Duration::from_secs(30),
    });
    session.finish_challenge(false).await.unwrap();
    assert!(session.switch_pending.is_none(), "pending consumed");
    let plane = channels(&mut session);
    let selector = plane.selector.as_ref().unwrap();
    assert_eq!(
        selector.last_good,
        Some(Candidate::Quic),
        "confirmed: switch"
    );
    assert_eq!(
        selector.baseline_p90,
        Some(Duration::from_millis(50)),
        "the baseline is the winner's raw p90"
    );
    assert!(plane.channels.contains_key(&79), "winner channel stays");
}

#[tokio::test]
async fn challenger_within_margin_keeps_the_incumbent() {
    let (mut session, _events) = common::session::link_session(false);
    session.readiness = Some(Readiness::Ready);
    {
        let plane = channels(&mut session);
        plane.channels.insert(77, dummy_handle());
        let mut quic = dummy_handle();
        quic.candidate = Candidate::Quic;
        plane.channels.insert(78, quic);
        plane.flows.insert(
            PROBE_I,
            svpn::session::Flow::new(dummy_icmp_key(10), Instant::now()),
        );
        plane.flows.insert(
            PROBE_A,
            svpn::session::Flow::new(dummy_icmp_key(1), Instant::now()),
        );
        let selector = plane.selector.as_mut().unwrap();
        selector.last_good = Some(Candidate::Mosh);
        selector
            .channels
            .insert(Candidate::Mosh, svpn::selector::ReadyChannel::new(77, true));
        selector.baseline_p90 = Some(Duration::from_millis(50));
        selector.allowed.push(Candidate::Quic);
    }
    // Incumbent p90 50 ms: the margin is max(50/5, 5) = 10 ms, so 45 ms
    // does not win (45 + 10 > 50).
    session.challenge = Some(Challenge {
        incumbent: Some((PROBE_I, Candidate::Mosh, 77)),
        attempts: HashMap::new(),
        measured: vec![
            (Candidate::Mosh, 77, PROBE_I, outcome(50)),
            (Candidate::Quic, 78, PROBE_A, outcome(45)),
        ],
        deadline: Instant::now() + Duration::from_secs(30),
    });
    session.finish_challenge(false).await.unwrap();
    assert!(session.switch_pending.is_none(), "no win, no pending");
    let plane = channels(&mut session);
    let selector = plane.selector.as_ref().unwrap();
    assert_eq!(
        selector.last_good,
        Some(Candidate::Mosh),
        "margin not met: the incumbent holds"
    );
    assert!(plane.channels.contains_key(&77), "incumbent keeps serving");
    assert!(!plane.channels.contains_key(&78), "challenger retired");
    assert!(
        selector.allowed.contains(&Candidate::Quic),
        "slower, not dead: stays eligible"
    );
}

#[tokio::test]
async fn replaced_incumbent_drains_then_retires() {
    let (mut session, _events) = common::session::link_session(false);
    session.readiness = Some(Readiness::Ready);
    {
        let plane = channels(&mut session);
        plane.channels.insert(77, dummy_handle());
        let mut quic = dummy_handle();
        quic.candidate = Candidate::Quic;
        plane.channels.insert(78, quic);
        // One live data flow bound to the incumbent's channel.
        let mut data = svpn::session::Flow::new(
            svpn::packet::FlowKey {
                protocol: 6,
                source: std::net::Ipv4Addr::new(10, 77, 0, 2),
                destination: std::net::Ipv4Addr::new(10, 77, 0, 1),
                source_port: 40000,
                destination_port: 9000,
            },
            Instant::now(),
        );
        data.channel = Some(77);
        plane.flows.insert(7, data);
        plane.flows.insert(
            PROBE_I,
            svpn::session::Flow::new(dummy_icmp_key(10), Instant::now()),
        );
        plane.flows.insert(
            PROBE_A,
            svpn::session::Flow::new(dummy_icmp_key(1), Instant::now()),
        );
        let selector = plane.selector.as_mut().unwrap();
        selector.last_good = Some(Candidate::Mosh);
        selector
            .channels
            .insert(Candidate::Mosh, svpn::selector::ReadyChannel::new(77, true));
        selector.baseline_p90 = Some(Duration::from_millis(100));
    }
    // Quic at 10 ms beats the 100 ms incumbent by the margin; the
    // confirming round is aged past the interval.
    session.switch_pending = Some((
        Candidate::Quic,
        std::time::Instant::now() - Duration::from_secs(31),
    ));
    session.challenge = Some(Challenge {
        incumbent: Some((PROBE_I, Candidate::Mosh, 77)),
        attempts: HashMap::new(),
        measured: vec![
            (Candidate::Mosh, 77, PROBE_I, outcome(100)),
            (Candidate::Quic, 78, PROBE_A, outcome(10)),
        ],
        deadline: Instant::now() + Duration::from_secs(30),
    });
    session.finish_challenge(false).await.unwrap();
    {
        let plane = channels(&mut session);
        let selector = plane.selector.as_ref().unwrap();
        assert_eq!(selector.last_good, Some(Candidate::Quic));
        assert!(
            selector.ready_channel(Candidate::Mosh).is_none(),
            "replaced: no new flows to mosh"
        );
        assert!(plane.draining.contains(&77), "old channel draining");
        assert!(plane.channels.contains_key(&77), "data flow still served");
    }
    // The last bound flow closes: the drained channel retires.
    session.close_flow(7, true).await.unwrap();
    let plane = channels(&mut session);
    assert!(plane.draining.is_empty(), "drain done");
    assert!(!plane.channels.contains_key(&77), "drained channel retired");
    assert!(plane.channels.contains_key(&78), "winner keeps serving");
}

#[tokio::test]
async fn all_lost_challenge_keeps_tcp_incumbent() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    {
        let plane = channels(&mut session);
        plane.channels.insert(77, dummy_handle());
        plane.flows.insert(
            PROBE_A,
            svpn::session::Flow::new(dummy_icmp_key(1), Instant::now()),
        );
    }
    session.challenge = Some(Challenge {
        incumbent: None,
        attempts: HashMap::new(),
        measured: vec![(
            Candidate::Mosh,
            77,
            PROBE_A,
            Outcome {
                p90: None,
                received: 0,
                lost: BURST_LEN,
            },
        )],
        deadline: Instant::now() + Duration::from_secs(30),
    });
    session.finish_challenge(false).await.unwrap();
    let plane = channels(&mut session);
    assert_eq!(
        plane.selector.as_ref().unwrap().last_good,
        Some(Candidate::Tcp)
    );
    assert!(!plane.channels.contains_key(&77), "loser retired");
    assert!(!plane.flows.contains_key(&PROBE_A), "probe flow closed");
    let selector = plane.selector.as_ref().unwrap();
    assert!(
        !selector.allowed.contains(&Candidate::Mosh),
        "a dead challenger re-bans: no challenge loop every health tick"
    );
}

// ── abort ──

#[tokio::test]
async fn fresh_round_aborts_the_challenge() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.maybe_start_challenge(false).await.unwrap();
    assert!(session.challenge.is_some());
    session.arm_round().await.unwrap();
    assert!(session.challenge.is_none(), "round kills the challenge");
    assert!(session.round.is_some(), "round armed");
}
