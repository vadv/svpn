//! Selector proactive mode: attempt bans, exhaustion, channel-loss fallback.

mod common;

use std::time::{Duration, Instant};

use common::selector::{all, key, succeed};
use svpn::selector::*;

// ── attempt failure ──

#[test]
fn proactive_attempt_failure_bans_until_the_backoff_expires() {
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
    // Hold-down expired, but the ban holds until its backoff expires: quic
    // does not return (webrtc preparation is already running for flow 1).
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
            generation: 1
        }]
    ));
    let actions = selector.bind_failed(1, 1, Reason::PathTimeout, now);
    assert_eq!(
        actions,
        vec![Action::ResetBinding {
            flow_id: 1,
            generation: 2,
            from: Some(Candidate::Tcp),
            reason: Reason::PathTimeout
        }]
    );
    assert!(selector.has_queued(1));
    let actions = selector.poll(now + FLOW_BUDGET);
    assert!(actions.contains(&Action::CloseFlow { flow_id: 1 }));
    assert!(actions.contains(&Action::Exhausted {
        reasons: vec![
            (Candidate::Quic, Reason::PathTimeout),
            (Candidate::WebRtc, Reason::OneWay),
            (Candidate::Obfs, Reason::SizeProbeFailed),
            (Candidate::Mosh, Reason::PathTimeout),
            (Candidate::Tcp, Reason::PathTimeout),
        ]
    }));
    // New admissions wait for a fresh budget without repeating the stop signal.
    let later = now + FLOW_BUDGET;
    let actions = selector
        .request(2, key(2), b"second", later)
        .expect("admission");
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Exhausted { .. }))
    );
    assert!(actions.is_empty());
    assert!(selector.has_queued(2));
    let actions = selector.poll(later + FLOW_BUDGET);
    assert!(actions.contains(&Action::CloseFlow { flow_id: 2 }));
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Exhausted { .. }))
    );
}

#[test]
fn proactive_tcp_failure_or_timeout_bans_tcp_until_the_queue_expires() {
    for timeout in [false, true] {
        let mut selector = Selector::new_proactive(Allowed {
            tcp: true,
            ..Allowed::default()
        });
        let now = Instant::now();
        selector.adopt(Candidate::Tcp, None);
        selector.request(1, key(1), b"first", now).unwrap();
        for generation in [0, 2] {
            assert!(
                selector
                    .bind_failed(1, generation, Reason::PathTimeout, now)
                    .is_empty()
            );
        }
        assert!(selector.banned.is_empty());
        let actions = if timeout {
            selector.poll(now + ATTEMPT_BUDGET)
        } else {
            selector.bind_failed(1, 1, Reason::PathTimeout, now)
        };
        assert_eq!(
            actions,
            vec![Action::ResetBinding {
                flow_id: 1,
                generation: 2,
                from: Some(Candidate::Tcp),
                reason: Reason::PathTimeout
            }]
        );
        assert!(!selector.allowed.contains(&Candidate::Tcp));
        assert_eq!(selector.last_good, None);
        assert_eq!(selector.banned, vec![(Candidate::Tcp, Reason::PathTimeout)]);
        assert!(selector.poll(now + ATTEMPT_BUDGET * 2).is_empty());
        assert!(selector.has_queued(1));
        assert_eq!(selector.queued_bytes(), 5);
        let actions = selector.poll(now + FLOW_BUDGET);
        assert!(actions.contains(&Action::CloseFlow { flow_id: 1 }));
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, Action::Exhausted { .. }))
                .count(),
            1
        );
        assert!(actions.contains(&Action::Exhausted {
            reasons: vec![(Candidate::Tcp, Reason::PathTimeout)]
        }));
        assert_eq!(selector.queued_bytes(), 0);
        assert!(
            selector
                .poll(now + FLOW_BUDGET + Duration::from_secs(1))
                .is_empty()
        );
    }
}

#[test]
fn proactive_tcp_failure_keeps_udp_flow_queue_for_a_verified_alternative() {
    let mut selector = Selector::new_proactive(Allowed {
        quic: true,
        tcp: true,
        ..Allowed::default()
    });
    let now = Instant::now();
    selector.adopt(Candidate::Quic, Some(10));
    selector.adopt(Candidate::Tcp, None);
    assert_eq!(
        selector.request(1, key(1), b"first", now).unwrap(),
        vec![Action::TryTcp {
            flow_id: 1,
            generation: 1
        }]
    );
    selector.enqueue(1, b"second").unwrap();
    assert_eq!(
        selector.bind_failed(1, 1, Reason::EndpointUnavailable, now),
        vec![
            Action::ResetBinding {
                flow_id: 1,
                generation: 2,
                from: Some(Candidate::Tcp),
                reason: Reason::EndpointUnavailable
            },
            Action::OpenFlow {
                flow_id: 1,
                generation: 2,
                candidate: Candidate::Quic,
                channel: 10
            }
        ]
    );
    assert!(!selector.allowed.contains(&Candidate::Tcp));
    assert_eq!(selector.last_good, None);
    // A stale TCP failure must not re-ban a candidate proven healthy since then.
    selector.adopt(Candidate::Tcp, None);
    assert!(
        selector
            .bind_failed(1, 1, Reason::PathTimeout, now)
            .is_empty()
    );
    assert!(selector.allowed.contains(&Candidate::Tcp));
    assert!(selector.bind_succeeded(1, 1, now).is_empty());
    assert!(selector.committed(1, 1).is_empty());
    assert!(selector.take_queue(1).is_none());
    assert_eq!(selector.queued_bytes(), 11);
    selector.bind_succeeded(1, 2, now);
    selector.committed(1, 2);
    assert_eq!(
        selector.take_queue(1).unwrap(),
        [b"first".to_vec(), b"second".to_vec()]
    );
    assert!(selector.take_queue(1).unwrap().is_empty());
    assert_eq!(selector.queued_bytes(), 0);
}

#[test]
fn checking_a_healthy_tcp_binding_does_not_ban_tcp() {
    let mut selector = Selector::new_proactive(Allowed {
        tcp: true,
        ..Allowed::default()
    });
    let now = Instant::now();
    selector.request(1, key(1), b"first", now).unwrap();
    selector.enter_checking(now);
    assert!(selector.banned.is_empty());
    assert!(selector.allowed.contains(&Candidate::Tcp));
    assert!(selector.has_queued(1));
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
                generation: 1
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
            selector.bind_failed(1, 1, Reason::PathTimeout, now),
            vec![Action::ResetBinding {
                flow_id: 1,
                generation: 2,
                from: Some(Candidate::Tcp),
                reason: Reason::PathTimeout
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

// ── ban expiry ──

#[test]
fn ban_expires_after_backoff_and_restores_cold_order_position() {
    let mut selector = Selector::new_proactive(all());
    let now = Instant::now();
    selector
        .request(1, key(1), b"first", now)
        .expect("admission");
    selector.attempt_failed(Candidate::Quic, 1, Reason::PathTimeout, now);
    assert!(!selector.allowed.contains(&Candidate::Quic));

    // 10 min ± 20% jitter: still banned at 7 min, restored by 13 min.
    let actions = selector.poll(now + Duration::from_secs(7 * 60));
    assert!(
        !actions.iter().any(
            |a| matches!(a, Action::BanExpired { candidate } if *candidate == Candidate::Quic)
        )
    );
    let actions = selector.poll(now + Duration::from_secs(13 * 60));
    assert!(
        actions.iter().any(
            |a| matches!(a, Action::BanExpired { candidate } if *candidate == Candidate::Quic)
        )
    );
    // The cold-order position is restored: quic leads again.
    assert_eq!(selector.allowed.first(), Some(&Candidate::Quic));
    // The chronicle keeps the reason for the exhaustion table.
    assert!(
        selector
            .banned
            .contains(&(Candidate::Quic, Reason::PathTimeout))
    );
}

#[test]
fn repeated_bans_double_the_backoff_and_success_resets_it() {
    let mut selector = Selector::new_proactive(all());
    let t0 = Instant::now();
    selector
        .request(1, key(1), b"first", t0)
        .expect("admission");
    selector.attempt_failed(Candidate::Quic, 1, Reason::PathTimeout, t0);
    let t1 = t0 + Duration::from_secs(13 * 60);
    selector.poll(t1);
    assert!(selector.allowed.contains(&Candidate::Quic));

    // Second failure (channel lost before verification): ~20 minutes out.
    selector
        .channels
        .insert(Candidate::Quic, ReadyChannel::new(9, false));
    selector.channel_lost(Candidate::Quic, 9, Reason::ChannelFailed, t1);
    assert!(!selector.allowed.contains(&Candidate::Quic));
    selector.poll(t1 + Duration::from_secs(15 * 60));
    assert!(
        !selector.allowed.contains(&Candidate::Quic),
        "doubled ban holds at 15m"
    );
    let t2 = t1 + Duration::from_secs(25 * 60);
    selector.poll(t2);
    assert!(
        selector.allowed.contains(&Candidate::Quic),
        "doubled ban expired by 25m"
    );

    // Success resets the backoff: the next ban is ~10 minutes again.
    selector.adopt(Candidate::Quic, Some(10));
    selector
        .channels
        .insert(Candidate::Quic, ReadyChannel::new(11, false));
    selector.channel_lost(Candidate::Quic, 11, Reason::ChannelFailed, t2);
    selector.poll(t2 + Duration::from_secs(12 * 60));
    assert!(
        selector.allowed.contains(&Candidate::Quic),
        "reset backoff expires at 12m"
    );
}

// ── e2e hook ──

#[test]
fn ban_backoff_hook_only_shortens_the_first_ban() {
    use std::time::Duration;
    use svpn::selector::ban_backoff_from;
    let start = Duration::from_secs(600);
    assert_eq!(ban_backoff_from(None), start, "unset keeps the default");
    assert_eq!(ban_backoff_from(Some("garbage")), start);
    assert_eq!(ban_backoff_from(Some("0")), start, "zero is not a shrink");
    assert_eq!(ban_backoff_from(Some("3")), Duration::from_secs(3));
    assert_eq!(ban_backoff_from(Some("999999")), start, "never lengthens");
}
