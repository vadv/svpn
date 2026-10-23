//! Binding retries: generation fences, paused queues, budgets and TCP recovery.

mod common;

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use common::selector::{all, key};
use svpn::selector::*;

// ── generation fences ──

#[test]
fn abandoned_binding_events_cannot_commit_or_reset_its_replacement() {
    let now = Instant::now();
    let mut selector = Selector::new(all());
    selector.adopt(Candidate::Quic, Some(10));
    selector.request(1, key(1), b"first", now).unwrap();
    selector.enqueue(1, b"second").unwrap();
    selector.adopt(Candidate::Mosh, Some(20));
    assert_eq!(
        selector.bind_failed(1, 1, Reason::OneWay, now),
        vec![
            Action::ResetBinding {
                flow_id: 1,
                generation: 2,
                from: Some(Candidate::Quic),
                reason: Reason::OneWay,
            },
            Action::OpenFlow {
                flow_id: 1,
                generation: 2,
                candidate: Candidate::Mosh,
                channel: 20,
            },
        ]
    );
    for generation in [0, 1, 3] {
        assert!(selector.bind_succeeded(1, generation, now).is_empty());
        assert!(
            selector
                .bind_failed(1, generation, Reason::ChannelFailed, now)
                .is_empty()
        );
        assert!(selector.committed(1, generation).is_empty());
        assert!(selector.take_queue(1).is_none());
        assert_eq!(selector.queued_bytes(), 11);
    }
    assert_eq!(
        selector.bind_succeeded(1, 2, now),
        vec![Action::Commit {
            flow_id: 1,
            generation: 2,
            candidate: Candidate::Mosh
        }]
    );
    selector.committed(1, 1);
    assert!(selector.take_queue(1).is_none());
    selector.committed(1, 2);
    assert_eq!(
        selector.take_queue(1).unwrap(),
        VecDeque::from([b"first".to_vec(), b"second".to_vec()])
    );
    assert_eq!(selector.queued_bytes(), 0);
}

// ── suspension ──

#[test]
fn checking_preserves_binding_and_committing_queues_until_resume() {
    for committing in [false, true] {
        let now = Instant::now();
        let mut selector = Selector::new(all());
        selector.adopt(Candidate::Quic, Some(10));
        selector.request(1, key(1), b"first", now).unwrap();
        if committing {
            selector.bind_succeeded(1, 1, now);
        }
        assert_eq!(
            selector.enter_checking(now),
            vec![Action::ResetBinding {
                flow_id: 1,
                generation: 2,
                from: Some(Candidate::Quic),
                reason: Reason::ChannelFailed
            }]
        );
        assert!(selector.enter_checking(now).is_empty());
        selector.enqueue(1, b"second").unwrap();
        assert_eq!(selector.queued_bytes(), 11);
        assert!(selector.take_queue(1).is_none());
        assert!(selector.bind_succeeded(1, 1, now).is_empty());
        assert!(selector.committed(1, 1).is_empty());
        selector.adopt(Candidate::Mosh, Some(20));
        assert!(selector.poll(now + Duration::from_secs(1)).is_empty());
        assert_eq!(
            selector.resume(now + Duration::from_secs(1)),
            vec![Action::OpenFlow {
                flow_id: 1,
                generation: 2,
                candidate: Candidate::Mosh,
                channel: 20
            }]
        );
        selector.bind_succeeded(1, 2, now + Duration::from_secs(1));
        selector.committed(1, 2);
        assert_eq!(
            selector.take_queue(1).unwrap(),
            VecDeque::from([b"first".to_vec(), b"second".to_vec()])
        );
    }
}

#[test]
fn late_channel_verification_cannot_release_a_paused_queue() {
    let now = Instant::now();
    let mut selector = Selector::new(all());
    selector.adopt(Candidate::Quic, Some(10));
    selector.request(1, key(1), b"queued", now).unwrap();
    selector.enter_checking(now);
    selector.adopt(Candidate::Mosh, Some(20));
    assert!(selector.peer_verified(Candidate::Mosh, 20, now).is_empty());
    assert!(selector.probes_passed(Candidate::Mosh, 20, now).is_empty());
    assert!(selector.take_queue(1).is_none());
    assert_eq!(selector.queued_bytes(), 6);
    assert_eq!(
        selector.resume(now),
        vec![Action::OpenFlow {
            flow_id: 1,
            generation: 2,
            candidate: Candidate::Mosh,
            channel: 20
        }]
    );
}

// ── original deadlines ──

#[test]
fn checking_and_repeated_bind_failures_do_not_renew_admission_budget() {
    let start = Instant::now();
    let mut selector = Selector::new(all());
    selector.adopt(Candidate::Quic, Some(10));
    selector.request(1, key(1), b"first", start).unwrap();
    selector.bind_succeeded(1, 1, start);
    selector.enter_checking(start + Duration::from_secs(2));
    let late = start + FLOW_BUDGET - Duration::from_secs(1);
    selector.enqueue(1, b"late").unwrap();
    selector.adopt(Candidate::Mosh, Some(20));
    selector.resume(late);
    selector.bind_succeeded(1, 2, late);
    selector.bind_failed(1, 2, Reason::OneWay, late);
    selector.adopt(Candidate::Obfs, Some(30));
    selector.poll(late);
    selector.bind_succeeded(1, 3, late);
    let actions = selector.poll(start + FLOW_BUDGET);
    assert_eq!(
        actions,
        vec![
            Action::FailFlow {
                flow_id: 1,
                flow: key(1),
                reason: Reason::PathTimeout
            },
            Action::CloseFlow { flow_id: 1 },
        ]
    );
    assert_eq!(selector.queued_bytes(), 0);
    assert_eq!(selector.pre_active_count(), 0);
}

#[test]
fn committed_but_unsent_binding_failure_keeps_the_admission_deadline() {
    let start = Instant::now();
    let mut selector = Selector::new(Allowed {
        quic: true,
        ..Allowed::default()
    });
    selector.adopt(Candidate::Quic, Some(10));
    selector.request(1, key(1), b"unsent", start).unwrap();
    selector.bind_succeeded(1, 1, start);
    selector.committed(1, 1);
    let late = start + FLOW_BUDGET - Duration::from_secs(1);
    assert_eq!(
        selector.bind_failed(1, 1, Reason::ChannelFailed, late),
        vec![Action::ResetBinding {
            flow_id: 1,
            generation: 2,
            from: Some(Candidate::Quic),
            reason: Reason::ChannelFailed
        }]
    );
    assert!(selector.take_queue(1).is_none());
    assert_eq!(selector.queued_bytes(), 6);
    assert_eq!(
        selector.poll(start + FLOW_BUDGET),
        vec![
            Action::FailFlow {
                flow_id: 1,
                flow: key(1),
                reason: Reason::PathTimeout
            },
            Action::CloseFlow { flow_id: 1 },
        ]
    );
    assert_eq!(selector.queued_bytes(), 0);
}

#[test]
fn fully_paused_flow_expires_at_its_original_deadline() {
    let start = Instant::now();
    let mut selector = Selector::new(all());
    selector.request(1, key(1), b"queued", start).unwrap();
    assert_eq!(
        selector.enter_checking(start),
        vec![Action::AbortChannel {
            candidate: Candidate::Quic,
            attempt: 1
        }]
    );
    assert!(
        selector
            .poll(start + FLOW_BUDGET - Duration::from_nanos(1))
            .is_empty()
    );
    assert_eq!(
        selector.poll(start + FLOW_BUDGET),
        vec![
            Action::FailFlow {
                flow_id: 1,
                flow: key(1),
                reason: Reason::PathTimeout
            },
            Action::CloseFlow { flow_id: 1 },
        ]
    );
    assert_eq!(selector.queued_bytes(), 0);
    assert!(selector.resume(start + FLOW_BUDGET).is_empty());
}

// ── active user TCP ──

#[test]
fn active_tcp_recovers_only_on_verified_datagram_channels() {
    let start = Instant::now();
    let mut selector = Selector::new(all());
    let tcp = svpn::packet::FlowKey {
        protocol: 6,
        ..key(1)
    };
    selector.adopt(Candidate::Quic, Some(10));
    selector.request(1, tcp, b"sent", start).unwrap();
    selector.bind_succeeded(1, 1, start);
    selector.committed(1, 1);
    assert_eq!(selector.pop_packet(1).unwrap(), b"sent");
    selector.adopt(Candidate::Tcp, None);
    let now = start + FLOW_BUDGET + Duration::from_secs(1);
    selector.enqueue(1, b"unsent").unwrap();
    assert_eq!(
        selector.recover(1, 1, Reason::ChannelFailed, now),
        vec![
            Action::ResetBinding {
                flow_id: 1,
                generation: 2,
                from: Some(Candidate::Quic),
                reason: Reason::ChannelFailed
            },
            Action::PrepareChannel {
                candidate: Candidate::WebRtc,
                attempt: 1
            },
        ]
    );
    selector.channel_ready(Candidate::WebRtc, 1, 20, now);
    assert!(
        selector
            .probes_passed(Candidate::WebRtc, 20, now)
            .is_empty()
    );
    assert!(selector.take_queue(1).is_none());
    assert_eq!(
        selector.peer_verified(Candidate::WebRtc, 20, now),
        vec![Action::OpenFlow {
            flow_id: 1,
            generation: 2,
            candidate: Candidate::WebRtc,
            channel: 20
        }]
    );
    selector.bind_succeeded(1, 2, now);
    selector.committed(1, 2);
    assert_eq!(
        selector.take_queue(1).unwrap(),
        VecDeque::from([b"unsent".to_vec()])
    );
}

#[test]
fn active_tcp_recovery_never_falls_back_to_outer_tcp_or_renews_its_budget() {
    let start = Instant::now();
    let mut selector = Selector::new(Allowed {
        quic: true,
        mosh: true,
        tcp: true,
        ..Allowed::default()
    });
    let tcp = svpn::packet::FlowKey {
        protocol: 6,
        ..key(1)
    };
    selector.adopt(Candidate::Quic, Some(10));
    selector.request(1, tcp, b"sent", start).unwrap();
    selector.bind_succeeded(1, 1, start);
    selector.committed(1, 1);
    selector.pop_packet(1).unwrap();
    selector.adopt(Candidate::Mosh, Some(20));
    let now = start + FLOW_BUDGET + Duration::from_secs(1);
    selector.enqueue(1, b"unsent").unwrap();
    selector.recover(1, 1, Reason::ChannelFailed, now);
    let late = now + RECOVERY_BUDGET - Duration::from_secs(1);
    assert_eq!(
        selector.recover(1, 2, Reason::OneWay, late),
        vec![Action::ResetBinding {
            flow_id: 1,
            generation: 3,
            from: Some(Candidate::Mosh),
            reason: Reason::OneWay
        }]
    );
    assert!(selector.poll(late).is_empty());
    assert!(selector.has_queued(1));
    assert_eq!(
        selector.poll(now + RECOVERY_BUDGET),
        vec![
            Action::FailFlow {
                flow_id: 1,
                flow: tcp,
                reason: Reason::PathTimeout
            },
            Action::CloseFlow { flow_id: 1 },
        ]
    );
    assert_eq!(selector.queued_bytes(), 0);
}

// ── queue visibility during recovery ──

#[test]
fn recovery_queue_is_visible_but_not_poppable() {
    // The session drain loop (src/session/recovery.rs) pops while
    // has_queued() is true; during a recovery stage pop_packet() must
    // yield None — neither deliver nor panic — so the pair is the contract.
    let start = Instant::now();
    let mut selector = Selector::new(all());
    let tcp = svpn::packet::FlowKey {
        protocol: 6,
        ..key(1)
    };
    selector.adopt(Candidate::Quic, Some(10));
    selector.request(1, tcp, b"sent", start).unwrap();
    selector.bind_succeeded(1, 1, start);
    selector.committed(1, 1);
    assert_eq!(selector.pop_packet(1).unwrap(), b"sent");
    selector.enqueue(1, b"unsent").unwrap();
    selector.recover(1, 1, Reason::ChannelFailed, start + FLOW_BUDGET);
    assert!(selector.has_queued(1));
    assert_eq!(selector.pop_packet(1), None);
}
