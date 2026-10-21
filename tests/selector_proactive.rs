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

// ── ban expiry (EPIC-016) ──

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
    selector.adopt(Candidate::Quic, Some(10), None);
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

// ── e2e hook (EPIC-016) ──

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
