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
    }
    channels(&mut session)
        .flows
        .get_mut(&attempt)
        .unwrap()
        .channel = Some(77);
    session.committed(attempt).await.unwrap();
    let burst = session.burst.as_ref().unwrap();
    assert!(!burst.finished(Instant::now()), "armed, in flight");
}

// ── verdict ──

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
    }
    session.challenge = Some(Challenge {
        attempts: HashMap::new(),
        queue: VecDeque::new(),
        measured: vec![
            (Candidate::Mosh, 77, outcome(100)),
            (Candidate::Quic, 78, outcome(50)),
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
}

#[tokio::test]
async fn all_lost_challenge_keeps_tcp_incumbent() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    {
        let plane = channels(&mut session);
        plane.channels.insert(77, dummy_handle());
    }
    session.challenge = Some(Challenge {
        attempts: HashMap::new(),
        queue: VecDeque::new(),
        measured: vec![(
            Candidate::Mosh,
            77,
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
