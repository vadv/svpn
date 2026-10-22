//! Background re-selection: trigger conditions, re-ban on
//! challenger failure, burst queueing, the verdict, and the round abort.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use svpn::selector::{Candidate, Reason};
use svpn::session::burst::{BURST_LEN, Burst, Outcome};
use svpn::session::challenge::{Challenge, Challenger};
use svpn::session::{ChannelHandle, ChannelReadyParams, Plane, Readiness};
use tokio::time::Instant;

fn outcome(p90_ms: u64) -> Outcome {
    Outcome {
        p90: Some(Duration::from_millis(p90_ms)),
        received: BURST_LEN,
        lost: 0,
    }
}

fn seed_stats(session: &mut svpn::session::Session, candidate: Candidate, p90_ms: u64) {
    session.path_stats.entry(candidate).or_default().push(
        std::time::Instant::now(),
        Some(Duration::from_millis(p90_ms)),
    );
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
        key: [7; 16],
        established: true,
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
async fn no_challenge_without_alternatives() {
    let (mut session, _events) = common::session::link_session(false);
    session.readiness = Some(Readiness::Ready);
    channels(&mut session).selector.as_mut().unwrap().last_good = Some(Candidate::Mosh);
    // Allowed holds only the incumbent itself: nothing to probe.
    session.maybe_start_challenge().await.unwrap();
    assert!(session.challenge.is_none());
}

#[tokio::test]
async fn challenge_probes_alternatives_of_udp_incumbent() {
    let (mut session, _events) = common::session::link_session(false);
    session.readiness = Some(Readiness::Ready);
    {
        let plane = channels(&mut session);
        let selector = plane.selector.as_mut().unwrap();
        selector.last_good = Some(Candidate::Mosh);
        selector.allowed.push(Candidate::Quic);
    }
    // A healthy UDP incumbent is still probed against its alternatives,
    // just less eagerly than a degraded one.
    session.maybe_start_challenge().await.unwrap();
    assert!(session.challenge.is_some(), "alternatives get probed");
}

#[tokio::test]
async fn no_challenge_before_ready() {
    let (mut session, _events) = common::session::link_session(false);
    channels(&mut session).selector.as_mut().unwrap().last_good = Some(Candidate::Tcp);
    session.maybe_start_challenge().await.unwrap();
    assert!(session.challenge.is_none(), "not Ready yet");
}

#[tokio::test]
async fn challenge_burst_records_echo_replies() {
    // Regression: parallel bursts moved challenge bursts out of the health
    // slot; deliver_to_tun checked only the slot and dropped every
    // challenger echo — no winner could ever emerge.
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    let channel = 7u64;
    let attempt = PROBE_A;
    let icmp_id = 4242u16;
    let payload = vec![9u8; 32];
    let mut burst = Burst::new(channel, attempt, icmp_id, 100, payload.clone());
    burst.armed = Some(Instant::now());
    burst.mark_sent(Instant::now()); // seq 100 (index 0) is in flight
    let mut attempts = HashMap::new();
    attempts.insert(
        attempt,
        Challenger {
            candidate: Candidate::Mosh,
            channel: Some(channel),
            owned: true,
            peer: None,
            burst: Some(burst),
        },
    );
    session.challenge = Some(Challenge {
        attempts,
        measured: Vec::new(),
        incumbent: None,
        deadline: Instant::now() + Duration::from_secs(30),
    });
    let key = dummy_icmp_key(icmp_id);
    let mut flow = svpn::session::Flow::new(key, Instant::now());
    flow.channel = Some(channel);
    flow.active = true;
    channels(&mut session).flows.insert(attempt, flow);
    let request =
        svpn::packet::icmp_echo_request(key.source, key.destination, icmp_id, 100, &payload);
    session
        .deliver_to_tun(svpn::udp::Incoming {
            id: attempt,
            channel: Some(channel),
            packet: common::echo_reply(&request),
        })
        .await
        .unwrap();
    let challenge = session.challenge.as_ref().unwrap();
    let burst = challenge.attempts[&attempt].burst.as_ref().unwrap();
    assert_eq!(
        burst.outcome().received,
        1,
        "the challenger recorded the echo"
    );
}

#[tokio::test]
async fn remeasure_gate_holds_until_due_and_zero_disables() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.remeasure = Some(Duration::from_secs(600));
    session.next_challenge_at = Some(std::time::Instant::now() + Duration::from_secs(60));
    session.maybe_start_challenge().await.unwrap();
    assert!(session.challenge.is_none(), "too early: the gate holds");
    session.maybe_start_challenge().await.unwrap();
    assert!(
        session.challenge.is_none(),
        "the periodic trigger obeys the same gate"
    );
    session.next_challenge_at = Some(std::time::Instant::now() - Duration::from_secs(1));
    session.maybe_start_challenge().await.unwrap();
    assert!(session.challenge.is_some(), "due: the challenge starts");
    assert!(
        session.next_challenge_at.unwrap() > std::time::Instant::now(),
        "the next round is re-armed"
    );

    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    session.remeasure = None;
    session.maybe_start_challenge().await.unwrap();
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
async fn bound_challenger_builds_probe_flow_and_burst() {
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
    // probe flow and drops every burst echo reply.
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
async fn fastest_challenger_wins_and_losers_stay_bound() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    {
        let plane = channels(&mut session);
        plane.channels.insert(77, dummy_handle());
        let mut quic = dummy_handle();
        quic.candidate = Candidate::Quic;
        plane.channels.insert(78, quic);
        let selector = plane.selector.as_mut().unwrap();
        selector.allowed.push(Candidate::Quic);
        selector
            .channels
            .insert(Candidate::Quic, svpn::selector::ReadyChannel::new(78, true));
        plane.flows.insert(
            PROBE_A,
            svpn::session::Flow::new(dummy_icmp_key(1), Instant::now()),
        );
        plane.flows.insert(
            PROBE_B,
            svpn::session::Flow::new(dummy_icmp_key(2), Instant::now()),
        );
    }
    seed_stats(&mut session, Candidate::Mosh, 100);
    seed_stats(&mut session, Candidate::Quic, 50);
    session.challenge = Some(Challenge {
        incumbent: None,
        attempts: HashMap::new(),
        measured: vec![
            (Candidate::Mosh, 77, PROBE_A, outcome(100), true),
            (Candidate::Quic, 78, PROBE_B, outcome(50), true),
        ],
        deadline: Instant::now() + Duration::from_secs(30),
    });
    session.finish_challenge(false).await.unwrap();
    assert!(session.challenge.is_none(), "verdict reached");
    {
        let plane = channels(&mut session);
        let selector = plane.selector.as_ref().unwrap();
        assert_eq!(
            selector.last_good,
            Some(Candidate::Quic),
            "one round lands the switch: no incumbent to defer to"
        );
        assert!(
            plane.channels.contains_key(&78),
            "the winner keeps its measured channel"
        );
        assert!(
            plane.channels.contains_key(&77),
            "a live loser stays bound for the next round"
        );
        assert!(
            !plane.flows.contains_key(&PROBE_A) && !plane.flows.contains_key(&PROBE_B),
            "every probe flow closes"
        );
    }
    assert!(
        session.switch_cooldown_until > std::time::Instant::now(),
        "the switch arms the cooldown"
    );
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
        selector.allowed.push(Candidate::Quic);
    }
    // Incumbent ewma 50 ms: the margin floor is max(5% × 50, 5 ms) = 5 ms,
    // so a 46 ms challenger does not win (46 + 5 > 50).
    seed_stats(&mut session, Candidate::Mosh, 50);
    seed_stats(&mut session, Candidate::Quic, 46);
    session.challenge = Some(Challenge {
        incumbent: Some((PROBE_I, Candidate::Mosh, 77)),
        attempts: HashMap::new(),
        measured: vec![
            (Candidate::Mosh, 77, PROBE_I, outcome(50), true),
            (Candidate::Quic, 78, PROBE_A, outcome(46), true),
        ],
        deadline: Instant::now() + Duration::from_secs(30),
    });
    session.finish_challenge(false).await.unwrap();
    let plane = channels(&mut session);
    let selector = plane.selector.as_ref().unwrap();
    assert_eq!(
        selector.last_good,
        Some(Candidate::Mosh),
        "margin not met: the incumbent holds"
    );
    assert!(plane.channels.contains_key(&77), "incumbent keeps serving");
    assert!(plane.channels.contains_key(&78), "the loser stays bound");
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
    }
    // Quic at 10 ms separates from the 100 ms incumbent by more than the
    // noise bands and clears the margin floor: three samples settle its
    // estimate past the minimum-sample gate, the switch is immediate.
    seed_stats(&mut session, Candidate::Mosh, 100);
    for _ in 0..3 {
        seed_stats(&mut session, Candidate::Quic, 10);
    }
    session.challenge = Some(Challenge {
        incumbent: Some((PROBE_I, Candidate::Mosh, 77)),
        attempts: HashMap::new(),
        measured: vec![
            (Candidate::Mosh, 77, PROBE_I, outcome(100), true),
            (Candidate::Quic, 78, PROBE_A, outcome(10), true),
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
            true,
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

// ── separation noise bands ──

// ── verdicts need statistics, not one lucky burst ──
#[tokio::test]
async fn single_sample_challenger_waits_for_statistics() {
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
        selector.allowed.push(Candidate::Quic);
        selector
            .channels
            .insert(Candidate::Quic, svpn::selector::ReadyChannel::new(78, true));
    }
    let incumbent = session.path_stats.entry(Candidate::Mosh).or_default();
    for _ in 0..4 {
        incumbent.push(std::time::Instant::now(), Some(Duration::from_millis(100)));
    }
    // One lucky 40 ms burst against a settled 100 ms incumbent.
    seed_stats(&mut session, Candidate::Quic, 40);
    let round = |session: &mut svpn::session::Session| {
        session.challenge = Some(Challenge {
            incumbent: Some((PROBE_I, Candidate::Mosh, 77)),
            attempts: HashMap::new(),
            measured: vec![
                (Candidate::Mosh, 77, PROBE_I, outcome(100), true),
                (Candidate::Quic, 78, PROBE_A, outcome(40), true),
            ],
            deadline: Instant::now() + Duration::from_secs(30),
        });
    };
    round(&mut session);
    session.finish_challenge(false).await.unwrap();
    assert_eq!(
        channels(&mut session).selector.as_ref().unwrap().last_good,
        Some(Candidate::Mosh),
        "one sample is noise, not a verdict"
    );
    // Two more bursts land the statistics — now it is a real win.
    let challenger = session.path_stats.entry(Candidate::Quic).or_default();
    for _ in 0..2 {
        challenger.push(std::time::Instant::now(), Some(Duration::from_millis(40)));
    }
    round(&mut session);
    session.finish_challenge(false).await.unwrap();
    assert_eq!(
        channels(&mut session).selector.as_ref().unwrap().last_good,
        Some(Candidate::Quic),
        "three samples settle the verdict"
    );
}

#[tokio::test]
async fn overlapping_noise_bands_do_not_switch() {
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
        selector.allowed.push(Candidate::Quic);
        selector
            .channels
            .insert(Candidate::Quic, svpn::selector::ReadyChannel::new(78, true));
    }
    // A flapping incumbent (20/60 ms) settles near 29 ms with a wide
    // deviation band; a stable 30 ms challenger sits inside it — overlap,
    // not "better".
    let stats = session.path_stats.entry(Candidate::Mosh).or_default();
    for ms in [20, 60, 20, 60] {
        stats.push(std::time::Instant::now(), Some(Duration::from_millis(ms)));
    }
    seed_stats(&mut session, Candidate::Quic, 30);
    session.challenge = Some(Challenge {
        incumbent: Some((PROBE_I, Candidate::Mosh, 77)),
        attempts: HashMap::new(),
        measured: vec![
            (Candidate::Mosh, 77, PROBE_I, outcome(29), true),
            (Candidate::Quic, 78, PROBE_A, outcome(30), true),
        ],
        deadline: Instant::now() + Duration::from_secs(30),
    });
    session.finish_challenge(false).await.unwrap();
    let plane = channels(&mut session);
    let selector = plane.selector.as_ref().unwrap();
    assert_eq!(
        selector.last_good,
        Some(Candidate::Mosh),
        "overlapping bands: no switch"
    );
    assert!(
        plane.channels.contains_key(&78),
        "the challenger stays bound"
    );
    assert!(
        selector.allowed.contains(&Candidate::Quic),
        "not dead: stays eligible"
    );
}

#[tokio::test]
async fn switch_cooldown_blocks_back_to_back_switches() {
    let (mut session, _events) = common::session::link_session(false);
    set_tcp_incumbent(&mut session);
    {
        let plane = channels(&mut session);
        let mut quic = dummy_handle();
        quic.candidate = Candidate::Quic;
        plane.channels.insert(78, quic);
        let mut webrtc = dummy_handle();
        webrtc.candidate = Candidate::WebRtc;
        plane.channels.insert(79, webrtc);
        let selector = plane.selector.as_mut().unwrap();
        selector.allowed.push(Candidate::Quic);
        selector.allowed.push(Candidate::WebRtc);
        selector
            .channels
            .insert(Candidate::Quic, svpn::selector::ReadyChannel::new(78, true));
        selector.channels.insert(
            Candidate::WebRtc,
            svpn::selector::ReadyChannel::new(79, true),
        );
        for id in [PROBE_B, PROBE_C] {
            plane.flows.insert(
                id,
                svpn::session::Flow::new(dummy_icmp_key(2), Instant::now()),
            );
        }
    }
    // Round 1: quic (50 ms) replaces the TCP incumbent outright.
    seed_stats(&mut session, Candidate::Quic, 50);
    session.challenge = Some(Challenge {
        incumbent: None,
        attempts: HashMap::new(),
        measured: vec![(Candidate::Quic, 78, PROBE_B, outcome(50), true)],
        deadline: Instant::now() + Duration::from_secs(30),
    });
    session.finish_challenge(false).await.unwrap();
    assert_eq!(
        channels(&mut session).selector.as_ref().unwrap().last_good,
        Some(Candidate::Quic)
    );
    // Round 2 seconds later: webrtc (20 ms) is clearly better, but the
    // cooldown from round 1 has not elapsed — the switch waits.
    seed_stats(&mut session, Candidate::WebRtc, 20);
    session.challenge = Some(Challenge {
        incumbent: None,
        attempts: HashMap::new(),
        measured: vec![(Candidate::WebRtc, 79, PROBE_C, outcome(20), true)],
        deadline: Instant::now() + Duration::from_secs(30),
    });
    session.finish_challenge(false).await.unwrap();
    let plane = channels(&mut session);
    let selector = plane.selector.as_ref().unwrap();
    assert_eq!(
        selector.last_good,
        Some(Candidate::Quic),
        "the cooldown holds the fresh winner back"
    );
    assert!(plane.channels.contains_key(&79), "webrtc stays bound");
    assert!(
        !plane.flows.contains_key(&PROBE_C),
        "its probe flow still closes"
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
