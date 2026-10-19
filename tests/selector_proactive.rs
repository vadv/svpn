//! Selector proactive mode: attempt bans, exhaustion, channel-loss fallback.

mod common;

use std::time::{Duration, Instant};

use common::selector::{all, key, succeed};
use svpn::selector::*;

// ── attempt failure ──

#[test]
fn proactive_attempt_failure_bans_until_end_of_session() {
    let mut selector = Selector::new_proactive(all());
    let now = Instant::now();
    let actions = selector
        .request(1, key(1), b"first", now)
        .expect("admission");
    assert!(matches!(
        actions.as_slice(),
        [Action::PrepareChannel {
            candidate: Candidate::Quic,
            attempt: 1
        }]
    ));
    let actions = selector.attempt_failed(Candidate::Quic, 1, Reason::PathTimeout, now);
    assert!(matches!(
        actions.as_slice(),
        [Action::PrepareChannel {
            candidate: Candidate::WebRtc,
            attempt: 2
        }]
    ));
    // Hold-down expired, but the ban lasts the session: quic does not return
    // (webrtc preparation is already running for flow 1 — a new flow waits).
    let later = now + HOLD_DOWN + Duration::from_secs(1);
    // poll at later also bans webrtc (its preparation expired by then
    // too) — the point of the check: quic did NOT return after hold-down.
    selector.poll(later);
    assert!(!selector.allowed.contains(&Candidate::Quic));
    assert!(
        selector
            .banned
            .contains(&(Candidate::Quic, Reason::PathTimeout))
    );
}

// ── exhaustion ──

#[test]
fn proactive_exhaustion_emits_exhausted_once() {
    let mut selector = Selector::new_proactive(all());
    let now = Instant::now();
    selector
        .request(1, key(1), b"first", now)
        .expect("admission");
    selector.attempt_failed(Candidate::Quic, 1, Reason::PathTimeout, now);
    selector.attempt_failed(Candidate::WebRtc, 2, Reason::OneWay, now);
    selector.attempt_failed(Candidate::Obfs, 3, Reason::SizeProbeFailed, now);
    let actions = selector.attempt_failed(Candidate::Mosh, 4, Reason::PathTimeout, now);
    // The last UDP is banned but TCP is alive — we try connect.
    assert!(matches!(
        actions.as_slice(),
        [Action::TryTcp {
            flow_id: 1,
            attempt: 5
        }]
    ));
    let actions = selector.bind_failed(1, Reason::PathTimeout, now);
    assert_eq!(
        actions,
        vec![Action::Exhausted {
            reasons: vec![
                (Candidate::Quic, Reason::PathTimeout),
                (Candidate::WebRtc, Reason::OneWay),
                (Candidate::Obfs, Reason::SizeProbeFailed),
                (Candidate::Mosh, Reason::PathTimeout),
                (Candidate::Tcp, Reason::PathTimeout),
            ]
        }]
    );
    // No repeat is emitted: new flows get an honest failure, not a second stop
    // (flow 1 is also cleaned up — Exhausted was returned before its fail).
    let actions = selector
        .request(2, key(2), b"second", now)
        .expect("admission");
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Exhausted { .. }))
    );
    // The fail order is not deterministic (HashMap): we check both are present.
    for failed in [1, 2] {
        assert!(actions.iter().any(|action| matches!(
            action,
            Action::FailFlow { flow_id, .. } if *flow_id == failed
        )));
    }
}

#[test]
fn proactive_tcp_failure_bans_tcp_but_keeps_udp_flow_fallback() {
    let only_tcp = Allowed {
        tcp: true,
        ..Allowed::default()
    };
    let mut selector = Selector::new_proactive(only_tcp);
    let now = Instant::now();
    selector
        .request(1, key(1), b"first", now)
        .expect("admission");
    // flow 1 is on TCP; the connect failure bans TCP, no other candidates remain.
    let actions = selector.bind_failed(1, Reason::EndpointUnavailable, now);
    assert!(matches!(actions.as_slice(), [Action::Exhausted { .. }]));
}

// ── channel loss ──

#[test]
fn proactive_unverified_channel_loss_bans_candidate_and_falls_back() {
    for (self_verified, peer_verified) in [(false, false), (true, false), (false, true)] {
        let now = Instant::now();
        let mut selector = Selector::new_proactive(Allowed {
            mosh: true,
            tcp: true,
            ..Allowed::default()
        });
        selector.request(1, key(1), b"syn", now).unwrap();
        selector.channel_ready(Candidate::Mosh, 1, 10, now);
        if self_verified {
            selector.probes_passed(Candidate::Mosh, 10, now);
        }
        if peer_verified {
            selector.peer_verified(Candidate::Mosh, 10, now);
        }
        // A foreign/stale ID does not remove the current channel.
        assert!(
            selector
                .channel_lost(Candidate::Mosh, 9, Reason::ChannelFailed, now)
                .is_empty()
        );
        assert_eq!(
            selector.channel_lost(Candidate::Mosh, 10, Reason::ChannelFailed, now),
            vec![Action::TryTcp {
                flow_id: 1,
                attempt: 2
            }]
        );
        assert_eq!(
            selector.banned,
            vec![(Candidate::Mosh, Reason::ChannelFailed)]
        );
        assert!(
            selector
                .channel_lost(Candidate::Mosh, 10, Reason::ChannelFailed, now)
                .is_empty()
        );
        assert_eq!(
            selector.bind_failed(1, Reason::PathTimeout, now),
            vec![Action::Exhausted {
                reasons: vec![
                    (Candidate::Mosh, Reason::ChannelFailed),
                    (Candidate::Tcp, Reason::PathTimeout)
                ],
            }]
        );
    }
}

#[test]
fn proactive_channel_lost_is_not_banned() {
    let mut selector = Selector::new_proactive(all());
    succeed(&mut selector, 1, Candidate::Quic);
    selector.finished(1);
    // A working channel died — hold-down, not a ban: the candidate will return.
    selector.channel_lost(Candidate::Quic, 100, Reason::ChannelFailed, Instant::now());
    assert!(selector.banned.is_empty());
    let later = Instant::now() + HOLD_DOWN + Duration::from_secs(1);
    selector.poll(later);
    let actions = selector
        .request(2, key(2), b"second", later)
        .expect("admission");
    assert!(matches!(
        actions.as_slice(),
        [Action::PrepareChannel {
            candidate: Candidate::Quic,
            ..
        }]
    ));
}
