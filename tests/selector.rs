use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use svpn::packet::FlowKey;
use svpn::selector::*;

fn all() -> Allowed {
    Allowed {
        quic: true,
        webrtc: true,
        obfs: true,
        mosh: true,
        tcp: true,
    }
}

fn udp_only() -> Allowed {
    Allowed {
        quic: true,
        webrtc: true,
        obfs: true,
        mosh: true,
        tcp: false,
    }
}

fn key(id: u64) -> FlowKey {
    FlowKey {
        protocol: 17,
        source: Ipv4Addr::LOCALHOST,
        source_port: 1000 + id as u16,
        destination: Ipv4Addr::LOCALHOST,
        destination_port: 2000,
    }
}

fn request(selector: &mut Selector, id: u64) -> Vec<Action> {
    selector
        .request(id, key(id), b"first", Instant::now())
        .expect("admission")
}

/// Full candidate success: prepare → ready → probes → peer → open →
/// opened → commit → committed.
fn succeed(selector: &mut Selector, id: u64, candidate: Candidate) {
    let now = Instant::now();
    let attempt = selector
        .request(id, key(id), b"first", now)
        .expect("admission")
        .first()
        .map(|action| match action {
            Action::PrepareChannel { attempt, .. } => *attempt,
            _ => panic!("expected prepare, got {action:?}"),
        })
        .unwrap();
    selector.channel_ready(candidate, attempt, 100, now);
    assert!(selector.probes_passed(candidate, 100, now).is_empty());
    let now = Instant::now();
    let actions = selector.peer_verified(candidate, 100, now);
    assert_eq!(
        actions,
        vec![Action::OpenFlow {
            flow_id: id,
            candidate,
            channel: 100
        }]
    );
    assert_eq!(
        selector.bind_succeeded(id, now),
        vec![Action::Commit {
            flow_id: id,
            candidate,
            attempt: attempt + 1
        }]
    );
    assert!(selector.committed(id).is_empty());
}

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

#[test]
fn many_flows_share_one_preparation() {
    let mut selector = Selector::new(all());
    let now = Instant::now();
    selector.request(1, key(1), b"a", now).expect("admission");
    // The second flow waits for the same process: no new prepare is emitted.
    assert!(
        selector
            .request(2, key(2), b"b", now)
            .expect("admission")
            .is_empty()
    );
    selector.channel_ready(Candidate::Quic, 1, 100, now);
    selector.probes_passed(Candidate::Quic, 100, now);
    let actions = selector.peer_verified(Candidate::Quic, 100, now);
    // The flow order is not deterministic (HashMap): compare as a set.
    let mut opened: Vec<u64> = actions
        .iter()
        .map(|action| match action {
            Action::OpenFlow { flow_id, .. } => *flow_id,
            other => panic!("expected open, got {other:?}"),
        })
        .collect();
    opened.sort();
    assert_eq!(opened, vec![1, 2]);
}

#[test]
fn bind_failure_is_scoped_to_flow() {
    let mut selector = Selector::new(all());
    let now = Instant::now();
    selector.request(1, key(1), b"a", now).expect("admission");
    selector.request(2, key(2), b"b", now).expect("admission");
    selector.channel_ready(Candidate::Quic, 1, 100, now);
    selector.probes_passed(Candidate::Quic, 100, now);
    let opened = selector.peer_verified(Candidate::Quic, 100, now);
    assert_eq!(opened.len(), 2);
    // The first flow's bind failed: the channel is ready, the second continues.
    // quic is excluded only for flow 1: the next candidate is webrtc.
    let actions = selector.bind_failed(1, Reason::OneWay, now);
    assert!(matches!(
        actions.as_slice(),
        [Action::PrepareChannel {
            candidate: Candidate::WebRtc,
            ..
        }]
    ));
    assert!(matches!(
        selector.bind_succeeded(2, now).as_slice(),
        [Action::Commit {
            flow_id: 2,
            candidate: Candidate::Quic,
            ..
        }]
    ));
    // The quic channel stays ready: quic is not in hold-down.
    assert!(selector.channels.contains_key(&Candidate::Quic));
}

#[test]
fn channel_lost_closes_all_its_flows_without_fallback() {
    let mut selector = Selector::new(all());
    let now = Instant::now();
    selector.request(1, key(1), b"a", now).expect("admission");
    selector.request(2, key(2), b"b", now).expect("admission");
    selector.channel_ready(Candidate::Quic, 1, 100, now);
    selector.probes_passed(Candidate::Quic, 100, now);
    selector.peer_verified(Candidate::Quic, 100, now);
    assert!(matches!(
        selector.bind_succeeded(1, now).as_slice(),
        [Action::Commit {
            flow_id: 1,
            candidate: Candidate::Quic,
            ..
        }]
    ));
    selector.bind_succeeded(2, Instant::now());
    selector.committed(1);
    let actions =
        selector.channel_lost(Candidate::Quic, 100, Reason::ChannelFailed, Instant::now());
    // Both flows closed (FailFlow+CloseFlow each), quic in hold-down,
    // last_good erased; no new waiting flows — no preparation starts.
    assert!(actions.contains(&Action::CloseFlow { flow_id: 1 }));
    assert!(actions.contains(&Action::CloseFlow { flow_id: 2 }));
    assert_eq!(actions.len(), 4);
    assert!(!selector.channels.contains_key(&Candidate::Quic));
}

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
fn stale_events_never_touch_new_attempts() {
    let mut selector = Selector::new(all());
    let now = Instant::now();
    request(&mut selector, 1);
    let actions = selector.attempt_failed(Candidate::Quic, 1, Reason::PathTimeout, now);
    assert_eq!(
        actions,
        vec![Action::PrepareChannel {
            candidate: Candidate::WebRtc,
            attempt: 2
        }]
    );
    // A late channel_ready of the old attempt is ignored.
    assert!(
        selector
            .channel_ready(Candidate::Quic, 1, 999, now)
            .is_empty()
    );
    assert!(!selector.channels.contains_key(&Candidate::Quic));
    // A foreign attempt is ignored too.
    assert!(
        selector
            .attempt_failed(Candidate::WebRtc, 7, Reason::OneWay, now)
            .is_empty()
    );
    assert!(selector.preparation.is_some());
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
fn preactive_queue_bounds() {
    let mut selector = Selector::new(all());
    let now = Instant::now();
    selector
        .request(1, key(1), b"first", now)
        .expect("admission");
    for _ in 0..3 {
        assert!(selector.enqueue(1, &[0u8; 10]).is_ok());
    }
    // 4 packets (1 + 3): the fifth is rejected.
    assert_eq!(selector.enqueue(1, &[0u8; 10]), Err(Reject::PendingFull));
    // An active flow gets the queue after committed.
    selector.channel_ready(Candidate::Quic, 1, 100, now);
    selector.probes_passed(Candidate::Quic, 100, now);
    selector.peer_verified(Candidate::Quic, 100, now);
    selector.bind_succeeded(1, now);
    assert!(selector.take_queue(1).is_none()); // still Committing
    selector.committed(1);
    let queue = selector.take_queue(1).expect("active queue");
    assert_eq!(queue.len(), 4);
    assert_eq!(queue[0], b"first".to_vec());
    assert!(selector.take_queue(1).expect("second take").is_empty());
}

#[test]
fn pending_flow_limit_fails_closed() {
    let mut selector = Selector::new(all());
    let now = Instant::now();
    for id in 1..=PENDING_FLOWS as u64 {
        assert!(selector.request(id, key(id), b"x", now).is_ok());
    }
    assert_eq!(
        selector.request(65, key(65), b"x", now),
        Err(Reject::PendingFull)
    );
}

#[test]
fn duplicate_flow_id_rejected() {
    let mut selector = Selector::new(all());
    request(&mut selector, 1);
    assert_eq!(
        selector.request(1, key(1), b"x", Instant::now()),
        Err(Reject::Duplicate)
    );
    // A closed flow_id does not resurrect either.
    selector.closed(1, Reason::ChannelFailed, Instant::now());
    assert_eq!(
        selector.request(1, key(1), b"x", Instant::now()),
        Err(Reject::Duplicate)
    );
}

#[test]
fn tcp_binding_retains_the_queue_until_commit() {
    let mut selector = Selector::new(Allowed {
        tcp: true,
        ..Allowed::default()
    });
    let _ = request(&mut selector, 1);
    assert!(selector.tcp_binding(1));
    assert!(!selector.tcp_binding(2));
    assert!(selector.take_queue(1).is_none());
    selector.bind_succeeded(1, Instant::now());
    assert!(!selector.tcp_binding(1));
    assert!(selector.take_queue(1).is_none());
    selector.committed(1);
    assert_eq!(
        selector.take_queue(1).expect("active queue"),
        VecDeque::from([b"first".to_vec()])
    );
}

#[test]
fn tcp_only_mode_uses_tcp_for_every_flow() {
    let mut selector = Selector::new(Allowed {
        tcp: true,
        ..Allowed::default()
    });
    let actions = request(&mut selector, 1);
    assert_eq!(
        actions,
        vec![Action::TryTcp {
            flow_id: 1,
            attempt: 1
        }]
    );
    // TCP does not block the second flow: each gets its own connect.
    let actions = request(&mut selector, 2);
    assert_eq!(
        actions,
        vec![Action::TryTcp {
            flow_id: 2,
            attempt: 2
        }]
    );
}

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
