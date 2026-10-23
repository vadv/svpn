//! Selector flows: admission limits, queues, shared preparation, TCP flows.

mod common;

use std::collections::VecDeque;
use std::time::Instant;

use common::selector::{all, key, request};
use svpn::selector::*;

// ── admission ──

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
    selector.finished(1);
    assert_eq!(
        selector.request(1, key(1), b"x", Instant::now()),
        Err(Reject::Duplicate)
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

// ── queue ──

#[test]
fn preactive_queue_bounds() {
    let mut selector = Selector::new(all());
    let now = Instant::now();
    selector
        .request(1, key(1), b"first", now)
        .expect("admission");
    for _ in 0..63 {
        assert!(selector.enqueue(1, &[0u8; 10]).is_ok());
    }
    // 64 packets (1 + 63): the 65th is rejected.
    assert_eq!(selector.enqueue(1, &[0u8; 10]), Err(Reject::PendingFull));
    // An active flow gets the queue after committed.
    selector.channel_ready(Candidate::Quic, 1, 100, now);
    selector.probes_passed(Candidate::Quic, 100, now);
    selector.peer_verified(Candidate::Quic, 100, now);
    selector.bind_succeeded(1, 1, now);
    assert!(selector.take_queue(1).is_none()); // still Committing
    selector.committed(1, 1);
    let queue = selector.take_queue(1).expect("active queue");
    assert_eq!(queue.len(), 64);
    assert_eq!(queue[0], b"first".to_vec());
    assert!(selector.take_queue(1).expect("second take").is_empty());
}

#[test]
fn preactive_queue_byte_budget_holds_before_the_packet_limit() {
    let mut selector = Selector::new(all());
    let now = Instant::now();
    selector
        .request(1, key(1), &[0u8; PREACTIVE_BYTES - 100], now)
        .expect("admission");
    assert_eq!(
        selector.enqueue(1, &[0u8; 200]),
        Err(Reject::PendingFull),
        "2 MiB budget beats the per-flow packet limit"
    );
    assert!(selector.enqueue(1, &[0u8; 50]).is_ok());
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
    selector.bind_succeeded(1, 1, Instant::now());
    assert!(!selector.tcp_binding(1));
    assert!(selector.take_queue(1).is_none());
    selector.committed(1, 1);
    assert_eq!(
        selector.take_queue(1).expect("active queue"),
        VecDeque::from([b"first".to_vec()])
    );
}

// ── shared preparation ──

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
            Action::OpenFlow {
                generation: 1,
                flow_id,
                ..
            } => *flow_id,
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
    let actions = selector.bind_failed(1, 1, Reason::OneWay, now);
    assert!(matches!(
        actions.as_slice(),
        [
            Action::ResetBinding {
                flow_id: 1,
                generation: 2,
                from: Some(Candidate::Quic),
                reason: Reason::OneWay
            },
            Action::PrepareChannel {
                candidate: Candidate::WebRtc,
                ..
            }
        ]
    ));
    assert!(matches!(
        selector.bind_succeeded(2, 1, now).as_slice(),
        [Action::Commit {
            flow_id: 2,
            candidate: Candidate::Quic,
            ..
        }]
    ));
    // Both queues survive; only the failed flow waits for a new binding.
    assert_eq!(selector.queued_bytes(), 2);
    assert!(selector.take_queue(1).is_none());
    selector.committed(2, 1);
    assert_eq!(
        selector.take_queue(2).unwrap(),
        VecDeque::from([b"b".to_vec()])
    );
    assert_eq!(selector.queued_bytes(), 1);
    assert!(selector.has_queued(1));
    assert!(selector.channels.contains_key(&Candidate::Quic));
}

#[test]
fn channel_lost_invalidates_cache_without_retiring_bindings() {
    let mut selector = Selector::new(all());
    let now = Instant::now();
    selector.request(1, key(1), b"a", now).expect("admission");
    selector.request(2, key(2), b"b", now).expect("admission");
    selector.channel_ready(Candidate::Quic, 1, 100, now);
    selector.probes_passed(Candidate::Quic, 100, now);
    selector.peer_verified(Candidate::Quic, 100, now);
    assert!(matches!(
        selector.bind_succeeded(1, 1, now).as_slice(),
        [Action::Commit {
            flow_id: 1,
            candidate: Candidate::Quic,
            ..
        }]
    ));
    selector.bind_succeeded(2, 1, Instant::now());
    selector.committed(1, 1);
    let actions =
        selector.channel_lost(Candidate::Quic, 100, Reason::ChannelFailed, Instant::now());
    // Session resolves actual channel ownership; selector only invalidates the cache.
    assert!(actions.is_empty());
    assert_eq!(selector.last_good, None);
    assert_eq!(
        selector.take_queue(1).unwrap(),
        VecDeque::from([b"a".to_vec()])
    );
    selector.committed(2, 1);
    assert_eq!(
        selector.take_queue(2).unwrap(),
        VecDeque::from([b"b".to_vec()])
    );
    assert!(!selector.channels.contains_key(&Candidate::Quic));
}

// ── tcp flows ──

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
            generation: 1
        }]
    );
    // TCP does not block the second flow: each gets its own connect.
    let actions = request(&mut selector, 2);
    assert_eq!(
        actions,
        vec![Action::TryTcp {
            flow_id: 2,
            generation: 1
        }]
    );
}
