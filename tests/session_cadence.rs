//! Re-measure cadence of background re-selection: the next round is due at
//! the remeasure gate rather than at the 30 s health tick, a running round
//! leaves no due tick behind, and a challenger that lost its handshake
//! leaves its round at once instead of holding the verdict to the cap.

mod common;

use std::time::Duration;

use svpn::selector::{Candidate, Reason};
use svpn::session::{Plane, Readiness, Session, TaskEvent};
use tokio::time::Instant;

const TICK: Duration = Duration::from_secs(30);
/// An attempt of the round in flight (probe-id range).
const PROBE: u64 = u64::MAX / 2;

fn set_tcp_incumbent(session: &mut Session) {
    session.readiness = Some(Readiness::Ready);
    let Plane::Channels(plane) = &mut session.plane else {
        panic!("channels plane")
    };
    let selector = plane.selector.as_mut().unwrap();
    selector.last_good = Some(Candidate::Tcp);
}

/// Allow one more challenger besides the fixture's mosh.
fn allow(session: &mut Session, candidate: Candidate) {
    let Plane::Channels(plane) = &mut session.plane else {
        panic!("channels plane")
    };
    plane.selector.as_mut().unwrap().allowed.push(candidate);
}

/// The candidates still probed by the round in flight.
fn probed(session: &Session) -> Vec<Candidate> {
    session
        .challenge
        .as_ref()
        .expect("a round in flight")
        .attempts
        .values()
        .map(|challenger| challenger.candidate)
        .collect()
}

fn probe_of(session: &Session, candidate: Candidate) -> u64 {
    session
        .challenge
        .as_ref()
        .expect("a round in flight")
        .attempts
        .iter()
        .find(|(_, challenger)| challenger.candidate == candidate)
        .map(|(attempt, _)| *attempt)
        .unwrap_or_else(|| panic!("{candidate:?} is probed"))
}

/// The handshake task gave up on `attempt`: what QUIC reports from its
/// detached handshake.
async fn handshake_lost(session: &mut Session, attempt: u64, candidate: Candidate) {
    session
        .dispatch_task_event(TaskEvent::Handshake {
            attempt,
            channel: 9,
            candidate,
            key: [7; 16],
            max_wire: 1500,
            io: None,
        })
        .await
        .unwrap();
}

// ── what is due next ──

#[tokio::test]
async fn the_next_measurement_is_whichever_comes_first() {
    let (mut session, _events) = common::session::link_session(false);
    let now = Instant::now();
    // No re-selection: the health tick alone.
    session.remeasure = None;
    session.next_challenge_at = None;
    assert_eq!(session.next_measurement_at(now), now + TICK);
    // A round a minute out: the tick still comes first.
    let gate = std::time::Instant::now() + Duration::from_secs(60);
    session.next_challenge_at = Some(gate);
    assert_eq!(session.next_measurement_at(now), now + TICK);
    // A round a second out: the round comes first.
    let gate = std::time::Instant::now() + Duration::from_secs(1);
    session.next_challenge_at = Some(gate);
    assert_eq!(session.next_measurement_at(now), Instant::from_std(gate));
}

#[tokio::test]
async fn a_finished_round_arms_the_next_round_not_the_health_tick() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.remeasure = Some(Duration::from_secs(5));
    let started = std::time::Instant::now();
    session.maybe_start_challenge().await.unwrap();
    let mosh = probe_of(&session, Candidate::Mosh);
    session
        .channel_failed(Some(mosh), None, Reason::PathTimeout)
        .await
        .unwrap();
    assert!(session.challenge.is_none(), "its only challenger failed");
    let gate = session.next_challenge_at.expect("the gate is re-armed");
    assert_eq!(
        session.health_at,
        Some(Instant::from_std(gate)),
        "the next measurement waits for the gate, not for a whole tick"
    );
    // One interval after the round began, with the usual ±50 % jitter.
    let slack = Duration::from_millis(100);
    assert!(gate > started + Duration::from_millis(2500) - slack);
    assert!(gate < started + Duration::from_millis(7500) + slack);
}

#[tokio::test]
async fn a_running_round_leaves_no_due_tick_behind() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    // A health tick that fell due just as the round starts.
    session.health_at = Some(Instant::now() - Duration::from_secs(1));
    session.maybe_start_challenge().await.unwrap();
    assert!(
        session.health_at.is_some_and(|at| at > Instant::now()),
        "a due tick would wake the loop in a tight loop for the whole round"
    );
}

// ── a challenger that lost its handshake ──

#[tokio::test]
async fn a_lost_handshake_removes_the_challenger_and_bans_it() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    allow(&mut session, Candidate::Quic);
    session.maybe_start_challenge().await.unwrap();
    assert_eq!(probed(&session).len(), 2);
    let quic = probe_of(&session, Candidate::Quic);
    handshake_lost(&mut session, quic, Candidate::Quic).await;
    assert_eq!(
        probed(&session),
        [Candidate::Mosh],
        "the failed challenger no longer holds the verdict"
    );
    let Plane::Channels(plane) = &session.plane else {
        panic!("channels plane")
    };
    let selector = plane.selector.as_ref().unwrap();
    assert!(
        !selector.allowed.contains(&Candidate::Quic),
        "banned until its backoff expires"
    );
    assert!(
        selector
            .banned
            .iter()
            .any(|&(candidate, reason)| candidate == Candidate::Quic
                && reason == Reason::PathTimeout)
    );
}

#[tokio::test]
async fn the_last_lost_handshake_ends_the_round_at_once() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.maybe_start_challenge().await.unwrap();
    let mosh = probe_of(&session, Candidate::Mosh);
    handshake_lost(&mut session, mosh, Candidate::Mosh).await;
    assert!(
        session.challenge.is_none(),
        "the round is over, not waiting out its 30 s cap"
    );
}

#[tokio::test]
async fn a_lost_handshake_outside_any_round_is_only_a_ban() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    handshake_lost(&mut session, PROBE, Candidate::Mosh).await;
    assert!(session.challenge.is_none());
    let Plane::Channels(plane) = &session.plane else {
        panic!("channels plane")
    };
    // Not the selector's own preparation either: nothing to ban.
    assert!(plane.selector.as_ref().unwrap().banned.is_empty());
}
