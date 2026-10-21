//! Background re-selection (EPIC-016 S2): trigger conditions, re-ban on
//! challenger failure, burst queueing, the verdict, and the round abort.

mod common;

use std::collections::{HashMap, VecDeque};
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
const PROBE_B: u64 = PROBE_A - 1;

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
    session.maybe_start_challenge().await.unwrap();
    let challenge = session.challenge.as_ref().expect("challenge started");
    assert_eq!(challenge.attempts.len(), 1, "only mosh is allowed");
    let challenger = challenge.attempts.values().next().unwrap();
    assert_eq!(challenger.candidate, Candidate::Mosh);
    assert_eq!(challenger.channel, None, "not bound yet");
    // A second trigger while one runs is a no-op.
    session.maybe_start_challenge().await.unwrap();
    assert_eq!(session.challenge.as_ref().unwrap().attempts.len(), 1);
}

#[tokio::test]
async fn no_challenge_on_udp_incumbent() {
    let (mut session, _events) = common::session::link_session(false);
    session.readiness = Some(Readiness::Ready);
    channels(&mut session).selector.as_mut().unwrap().last_good = Some(Candidate::Mosh);
    session.maybe_start_challenge().await.unwrap();
    assert!(session.challenge.is_none());
}

#[tokio::test]
async fn no_challenge_before_ready() {
    let (mut session, _events) = common::session::link_session(false);
    channels(&mut session).selector.as_mut().unwrap().last_good = Some(Candidate::Tcp);
    session.maybe_start_challenge().await.unwrap();
    assert!(session.challenge.is_none(), "not Ready yet");
}

// ── failures ──

#[tokio::test]
async fn failed_prepare_rebans_and_finishes() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.maybe_start_challenge().await.unwrap();
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
async fn bound_challenger_builds_probe_flow_and_queues_burst() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.maybe_start_challenge().await.unwrap();
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
    // The drive runs right inside channel_ready, so the burst already sits
    // in the session slot; the commit arms it.
    let challenge = session.challenge.as_ref().unwrap();
    assert_eq!(challenge.attempts[&attempt].channel, Some(77));
    assert!(
        challenge.attempts[&attempt].burst.is_none(),
        "burst left the queue"
    );
    assert!(challenge.queue.is_empty());
    assert!(session.burst.is_some(), "burst occupies the slot");
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
    let burst = session.burst.as_ref().unwrap();
    assert!(!burst.finished(Instant::now()), "armed, in flight");
}

// ── verdict ──

#[tokio::test]
async fn bound_challenger_sends_flow_open_on_the_wire() {
    let (client_half, mut wire) = tokio::io::duplex(4096);
    let control = svpn::control::Control::new(tokio::io::empty(), client_half);
    let (mut session, _events) = common::session::link_session_with(false, control);
    set_tcp_incumbent(&mut session);
    session.maybe_start_challenge().await.unwrap();
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
        attempts: HashMap::new(),
        queue: VecDeque::new(),
        measured: vec![
            (Candidate::Mosh, 77, PROBE_A, outcome(100)),
            (Candidate::Quic, 78, PROBE_B, outcome(50)),
        ],
        deadline: Instant::now() + Duration::from_secs(30),
    });
    session.challenge_drive(Instant::now()).await.unwrap();
    assert!(session.challenge.is_none(), "nothing left: verdict");
    let plane = channels(&mut session);
    let selector = plane.selector.as_ref().unwrap();
    assert_eq!(selector.last_good, Some(Candidate::Quic), "lowest p90 wins");
    assert!(plane.channels.contains_key(&78), "winner channel stays");
    assert!(!plane.channels.contains_key(&77), "loser channel retired");
    assert!(
        !plane.flows.contains_key(&PROBE_A) && !plane.flows.contains_key(&PROBE_B),
        "every probe flow closes, winner included"
    );
    assert!(
        selector.allowed.contains(&Candidate::Mosh),
        "a living loser is slower, not dead: stays eligible"
    );
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
        attempts: HashMap::new(),
        queue: VecDeque::new(),
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
    session.challenge_drive(Instant::now()).await.unwrap();
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
    session.maybe_start_challenge().await.unwrap();
    assert!(session.challenge.is_some());
    session.arm_round().await.unwrap();
    assert!(session.challenge.is_none(), "round kills the challenge");
    assert!(session.round.is_some(), "round armed");
}
