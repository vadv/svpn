//! Session small units: formatting, strategy maps, heartbeat deadline guard.

use svpn::control::Strategy;
use svpn::session::*;

#[test]
fn prefixed_line_is_unchanged_without_a_tag_and_names_the_server_in_a_pool() {
    assert_eq!(prefixed("", "channel"), "channel:");
    assert_eq!(prefixed("[h1]", "channel"), "channel[h1]:");
    assert_eq!(prefixed("[203.0.113.10]", "flow"), "flow[203.0.113.10]:");
}

#[test]
fn fmt_bytes_is_human_readable() {
    assert_eq!(fmt_bytes(0), "0 B");
    assert_eq!(fmt_bytes(512), "512 B");
    assert_eq!(fmt_bytes(4096), "4.0 KB");
    assert_eq!(fmt_bytes(3 * 1024 * 1024), "3.0 MB");
}

#[test]
fn max_wire_covers_transport_overhead() {
    for strategy in [
        Strategy::Plain,
        Strategy::Mosh,
        Strategy::WebRtc,
        Strategy::Quic,
        Strategy::Obfs,
    ] {
        let cap = strategy_max_wire(strategy);
        assert!(cap >= 576, "{strategy:?} cap {cap}");
        assert!(
            usize::from(cap).saturating_sub(45) >= 512,
            "{strategy:?} fragment budget"
        );
    }
}

#[test]
fn candidate_and_strategy_maps_are_inverse() {
    for strategy in [
        Strategy::Quic,
        Strategy::WebRtc,
        Strategy::Obfs,
        Strategy::Mosh,
    ] {
        let candidate = candidate_strategy_from(strategy);
        assert_eq!(candidate_strategy(candidate), strategy);
    }
}

#[tokio::test]
async fn heartbeat_guard_preserves_readiness_result() {
    let deadline = tokio::time::Instant::now() + HEARTBEAT_TIMEOUT;
    assert!(
        with_heartbeat_deadline(deadline, async { Ok(true) })
            .await
            .unwrap()
    );
    assert!(
        !with_heartbeat_deadline(deadline, async { Ok(false) })
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn ready_work_cannot_revive_an_expired_heartbeat() {
    let mut last_heartbeat = tokio::time::Instant::now() - HEARTBEAT_TIMEOUT * 2;
    let expired = last_heartbeat + HEARTBEAT_TIMEOUT;
    assert!(
        with_heartbeat_deadline(expired, async {
            last_heartbeat = tokio::time::Instant::now();
            Ok(false)
        })
        .await
        .is_err()
    );
    assert!(last_heartbeat > expired);
}
