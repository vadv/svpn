//! Selector fixed mode: cold order, hold-down, last-good hint, exclusion.

mod common;

use std::time::{Duration, Instant};

use common::selector::{all, key, request, succeed, udp_only};
use svpn::selector::*;

// ── cold order ──

#[test]
fn cold_order_with_fallback_to_tcp() {
    let mut selector = Selector::new(all());
    let now = Instant::now();
    let actions = selector
        .request(1, key(1), b"first", now)
        .expect("admission");
    assert_eq!(
        actions,
        vec![Action::PrepareChannel {
            candidate: Candidate::Quic,
            attempt: 1
        }]
    );
    let actions = selector.attempt_failed(Candidate::Quic, 1, Reason::PathTimeout, now);
    assert_eq!(
        actions,
        vec![Action::PrepareChannel {
            candidate: Candidate::WebRtc,
            attempt: 2
        }]
    );
    let actions = selector.attempt_failed(Candidate::WebRtc, 2, Reason::OneWay, now);
    assert_eq!(
        actions,
        vec![Action::PrepareChannel {
            candidate: Candidate::Obfs,
            attempt: 3
        }]
    );
    let actions = selector.attempt_failed(Candidate::Obfs, 3, Reason::SizeProbeFailed, now);
    assert_eq!(
        actions,
        vec![Action::PrepareChannel {
            candidate: Candidate::Mosh,
            attempt: 4
        }]
    );
    let actions = selector.attempt_failed(Candidate::Mosh, 4, Reason::PathTimeout, now);
    // All UDP in hold-down: TCP with a per-flow connect remains.
    assert_eq!(
        actions,
        vec![Action::TryTcp {
            flow_id: 1,
            attempt: 5
        }]
    );
}

// ── hold-down ──

#[test]
fn fixed_mode_keeps_hold_down_after_attempt_failure() {
    let mut selector = Selector::new(all());
    let now = Instant::now();
    selector
        .request(1, key(1), b"first", now)
        .expect("admission");
    selector.attempt_failed(Candidate::Quic, 1, Reason::PathTimeout, now);
    let later = now + HOLD_DOWN + Duration::from_secs(1);
    selector.poll(later);
    // Fixed mode: after hold-down quic is available again.
    let later = now + HOLD_DOWN + Duration::from_secs(1);
    selector.poll(later);
    assert!(selector.available(Candidate::Quic, later));
}

#[test]
fn hold_down_blocks_new_flows_until_expiry() {
    let mut selector = Selector::new(udp_only());
    let start = Instant::now();
    selector.request(1, key(1), b"x", start).expect("admission");
    let actions = selector.attempt_failed(Candidate::Quic, 1, Reason::PathTimeout, start);
    assert_eq!(
        actions,
        vec![Action::PrepareChannel {
            candidate: Candidate::WebRtc,
            attempt: 2
        }]
    );
    selector.attempt_failed(Candidate::WebRtc, 2, Reason::PathTimeout, start);
    selector.attempt_failed(Candidate::Obfs, 3, Reason::PathTimeout, start);
    let actions = selector.attempt_failed(Candidate::Mosh, 4, Reason::PathTimeout, start);
    // The last UDP candidate failed, TCP is forbidden: the flow is closed.
    assert_eq!(
        actions,
        vec![
            Action::FailFlow {
                flow_id: 1,
                flow: key(1),
                reason: Reason::PathTimeout
            },
            Action::CloseFlow { flow_id: 1 }
        ]
    );
    // Everyone in hold-down: a new flow gets an immediate failure.
    let actions = selector
        .request(2, key(2), b"x", start + Duration::from_secs(1))
        .expect("admission");
    assert_eq!(
        actions,
        vec![
            Action::FailFlow {
                flow_id: 2,
                flow: key(2),
                reason: Reason::PathTimeout
            },
            Action::CloseFlow { flow_id: 2 }
        ]
    );
    // After the hold-down expires, a new flow tries quic again.
    let actions = selector
        .request(3, key(3), b"x", start + HOLD_DOWN + Duration::from_secs(1))
        .expect("admission");
    assert_eq!(
        actions,
        vec![Action::PrepareChannel {
            candidate: Candidate::Quic,
            attempt: 5
        }]
    );
}

#[test]
fn fixed_unverified_channel_loss_keeps_hold_down() {
    let now = Instant::now();
    let mut selector = Selector::new(Allowed {
        mosh: true,
        ..Allowed::default()
    });
    selector.request(1, key(1), b"syn", now).unwrap();
    selector.channel_ready(Candidate::Mosh, 1, 10, now);
    let actions = selector.channel_lost(Candidate::Mosh, 10, Reason::ChannelFailed, now);
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::CloseFlow { flow_id: 1 }))
    );
    assert!(selector.banned.is_empty());
    let later = now + HOLD_DOWN + Duration::from_secs(1);
    assert!(matches!(
        selector
            .request(2, key(2), b"syn", later)
            .unwrap()
            .as_slice(),
        [Action::PrepareChannel {
            candidate: Candidate::Mosh,
            ..
        }]
    ));
}

// ── last good ──

#[test]
fn last_good_goes_first_and_is_dropped_after_its_failure() {
    let mut selector = Selector::new(all());
    succeed(&mut selector, 1, Candidate::Quic);
    selector.finished(1);
    // A ready verified channel lives: a new flow goes straight to bind, no prepare.
    assert_eq!(selector.last_good, Some(Candidate::Quic));
    let actions = request(&mut selector, 2);
    assert!(matches!(
        actions.as_slice(),
        [Action::OpenFlow {
            flow_id: 2,
            candidate: Candidate::Quic,
            channel: 100
        }]
    ));
    // The hint is erased only by the candidate's own failure, not someone else's.
    let now = Instant::now();
    let actions = selector.channel_lost(Candidate::Quic, 100, Reason::ChannelFailed, now);
    assert_eq!(selector.last_good, None);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::CloseFlow { flow_id: 2 }))
    );
    // quic is in hold-down: the next flow starts with webrtc.
    let actions = request(&mut selector, 3);
    assert!(matches!(
        actions.as_slice(),
        [Action::PrepareChannel {
            candidate: Candidate::WebRtc,
            ..
        }]
    ));
}

#[test]
fn channel_loss_erases_hint_and_restarts_cold() {
    let mut selector = Selector::new(all());
    succeed(&mut selector, 1, Candidate::Quic);
    selector.finished(1);
    let actions =
        selector.channel_lost(Candidate::Quic, 100, Reason::ChannelFailed, Instant::now());
    // No ready flows — cleanup only; no waiting flows, no preparation.
    assert!(actions.is_empty());
    assert_eq!(selector.last_good, None);
    // quic in a 30 s hold-down: the cold order starts with webrtc.
    let actions = request(&mut selector, 2);
    assert_eq!(
        actions,
        vec![Action::PrepareChannel {
            candidate: Candidate::WebRtc,
            attempt: 3
        }]
    );
}

// ── candidate exclusion ──

#[test]
fn unsupported_candidate_is_excluded_for_session() {
    let mut selector = Selector::new(all());
    request(&mut selector, 1);
    let actions = selector.attempt_failed(Candidate::Quic, 1, Reason::Unsupported, Instant::now());
    // unsupported excludes the candidate for the session: the next one is webrtc.
    assert_eq!(
        actions,
        vec![Action::PrepareChannel {
            candidate: Candidate::WebRtc,
            attempt: 2
        }]
    );
    assert!(!selector.allowed.contains(&Candidate::Quic));
}

#[test]
fn empty_allowed_rejects_immediately() {
    let mut selector = Selector::new(Allowed::default());
    let actions = selector
        .request(1, key(1), b"x", Instant::now())
        .expect("admission");
    assert_eq!(
        actions,
        vec![
            Action::FailFlow {
                flow_id: 1,
                flow: key(1),
                reason: Reason::PathTimeout
            },
            Action::CloseFlow { flow_id: 1 }
        ]
    );
}
