//! Selector deadlines: attempt, flow and bind budgets driven by poll.

mod common;

use std::time::{Duration, Instant};

use common::selector::{all, key};
use svpn::selector::*;

// ── attempt budget ──

#[test]
fn poll_aborts_channel_on_attempt_deadline() {
    let mut selector = Selector::new(all());
    let start = Instant::now();
    selector.request(1, key(1), b"a", start).expect("admission");
    // The driver is silent: the attempt deadline extinguishes it and moves to the next.
    let actions = selector.poll(start + ATTEMPT_BUDGET);
    assert_eq!(
        actions,
        vec![Action::PrepareChannel {
            candidate: Candidate::WebRtc,
            attempt: 2
        }]
    );
    assert!(
        selector
            .preparation
            .is_some_and(|p| p.candidate == Candidate::WebRtc)
    );
}

// ── flow budget ──

#[test]
fn commit_barrier_has_no_fallback() {
    let mut selector = Selector::new(all());
    let start = Instant::now();
    selector.request(1, key(1), b"a", start).expect("admission");
    selector.channel_ready(Candidate::Quic, 1, 100, start);
    selector.probes_passed(Candidate::Quic, 100, start);
    selector.peer_verified(Candidate::Quic, 100, start);
    selector.bind_succeeded(1, start);
    // committed did not arrive: the flow deadline closes it without trying webrtc.
    let actions = selector.poll(start + FLOW_BUDGET);
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

#[test]
fn udp_blocked_flow_falls_back_to_tcp_within_budget() {
    // All UDP candidates are silent: each attempt dies at the preparation
    // deadline, hold-down piles up — TCP must be picked before FLOW_BUDGET.
    let mut selector = Selector::new(all());
    let start = Instant::now();
    selector.request(1, key(1), b"a", start).expect("admission");
    let mut seen_tcp = false;
    let mut now = start;
    while now < start + FLOW_BUDGET - Duration::from_millis(100) {
        now += Duration::from_secs(1);
        for action in selector.poll(now) {
            println!("t={:?} {action:?}", now - start);
            match action {
                Action::PrepareChannel { .. } | Action::AbortChannel { .. } => {}
                Action::TryTcp { .. } => {
                    seen_tcp = true;
                    break;
                }
                other => panic!("unexpected action before TCP: {other:?}"),
            }
        }
        if seen_tcp {
            break;
        }
    }
    assert!(seen_tcp, "flow never reached TCP candidate");
}

#[test]
fn active_flow_survives_budget_deadline() {
    // Regression: flow.deadline (created+FLOW_BUDGET) must not kill an
    // already established Active channel — it lives until the session's idle sweep.
    let mut selector = Selector::new(all());
    let start = Instant::now();
    selector.request(1, key(1), b"a", start).expect("admission");
    selector.channel_ready(Candidate::Quic, 1, 100, start);
    selector.probes_passed(Candidate::Quic, 100, start);
    selector.peer_verified(Candidate::Quic, 100, start);
    let _ = selector.poll(start + Duration::from_secs(1));
    let _ = selector.bind_succeeded(1, start + Duration::from_secs(1));
    let _ = selector.committed(1);
    let now = start + FLOW_BUDGET + Duration::from_secs(5);
    let actions = selector.poll(now);
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::CloseFlow { .. }))
    );
    assert!(
        selector.poll(now).is_empty(),
        "an active flow must not generate actions"
    );
}

// ── bind budget ──

#[test]
fn bind_deadline_moves_flow_to_next_candidate() {
    let mut selector = Selector::new(all());
    let start = Instant::now();
    selector.request(1, key(1), b"a", start).expect("admission");
    selector.channel_ready(Candidate::Quic, 1, 100, start);
    selector.probes_passed(Candidate::Quic, 100, start);
    selector.peer_verified(Candidate::Quic, 100, start);
    // flow_open hung: the bind deadline moves from quic to a webrtc channel,
    // but the quic channel itself lives — one flow's bind failure does not crash it.
    let actions = selector.poll(start + Duration::from_secs(6));
    assert!(matches!(
        actions.as_slice(),
        [Action::PrepareChannel {
            candidate: Candidate::WebRtc,
            ..
        }]
    ));
    assert!(selector.channels.contains_key(&Candidate::Quic));
}
