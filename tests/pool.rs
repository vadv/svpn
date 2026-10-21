//! Server pool: startup, checking state, stop rules, retry backoff, weighted picking.

use std::time::Duration;

use svpn::link_io::Epoch;
use svpn::pool::*;
use tokio::time::Instant;

// ── startup ──

#[test]
fn startup_has_one_attempt_each_and_no_retry_before_first_ready() {
    let now = Instant::now();
    let mut pool = Pool::new([1, 1]);
    assert!(pool.failed(epoch(0), now, "test").unwrap());
    assert_eq!(pool.ready_count(), 0);
    assert_eq!(pool.next_retry(), None);
    assert!(pool.ready(epoch(1), now));
    assert_eq!(pool.retry_at(0), Some(now + Duration::from_secs(1)));
    assert_eq!(pool.pick(), Some(epoch(1)));
    assert_eq!(pool.retry_due(now).unwrap(), []);
}

#[test]
fn all_initial_failures_stop_without_ready() {
    let now = Instant::now();
    let mut pool = Pool::new([1, 1]);
    pool.failed(epoch(0), now, "test").unwrap();
    assert!(
        pool.failed(epoch(1), now, "test")
            .unwrap_err()
            .to_string()
            .contains("no server available")
    );
    assert_eq!(pool.next_retry(), None);
}

#[test]
fn startup_round_failure_stops_despite_failed_peer() {
    let now = Instant::now();
    let mut pool = Pool::new([1, 1]);
    // Server 0 never even established SSH; server 1 got control up but
    // its startup round found no working mimic — the primary wave failed.
    pool.failed(epoch(0), now, "test").unwrap();
    assert!(
        pool.round_failed(epoch(1))
            .unwrap_err()
            .to_string()
            .contains("no server available")
    );
}

// ── checking ──

#[test]
fn checking_keeps_owner_flows_and_excludes_new_ones() {
    let now = Instant::now();
    let mut pool = Pool::new([1, 3]);
    pool.ready(epoch(0), now);
    pool.ready(epoch(1), now);
    assert!(pool.checking(epoch(0)));
    // Not ready, not picked, but its owner flows keep being served.
    assert!(!pool.is_ready(epoch(0)));
    assert!(pool.is_serving(epoch(0)));
    assert!(!pool.is_checking(epoch(1)));
    assert_eq!(pool.checking_count(), 1);
    assert_eq!(pool.ready_count(), 1);
    assert_eq!(pool.pick(), Some(epoch(1)));
    assert_eq!(pool.pick(), Some(epoch(1)));
    // A repeated signal does not demote a Checking link further.
    assert!(!pool.checking(epoch(0)));
    // A successful round brings it back.
    assert!(pool.ready(epoch(0), now));
    assert!(pool.is_ready(epoch(0)));
    assert!(pool.is_serving(epoch(0)));
    assert_eq!(pool.checking_count(), 0);
}

#[test]
fn checking_then_session_death_stops_only_without_other_ready() {
    let now = Instant::now();
    let mut pool = Pool::new([1, 1]);
    pool.ready(epoch(0), now);
    pool.ready(epoch(1), now);
    pool.checking(epoch(0));
    // The session died while checking: the slot fails, the other stays.
    assert!(pool.failed(epoch(0), now, "test").unwrap());
    assert_eq!(pool.ready_count(), 1);
    assert!(!pool.is_serving(epoch(0)));
    // Losing the last one while checking still stops the VPN.
    pool.checking(epoch(1));
    assert!(
        pool.failed(epoch(1), now, "test")
            .unwrap_err()
            .to_string()
            .contains("no server available")
    );
}

// ── stop rules ──

#[test]
fn losing_last_ready_waits_for_another_connecting_round() {
    // superseded: stop-immediately variant — the accepted pool FSM waits
    // for in-flight rounds of Connecting/Checking servers (m12466).
    let now = Instant::now();
    let mut pool = Pool::new([1, 1]);
    pool.ready(epoch(0), now);
    // Slot 1 is still Connecting with its startup round armed: hope stays.
    pool.failed(epoch(0), now, "test").unwrap();
    assert_eq!(pool.ready_count(), 0);
    assert_eq!(pool.retry_at(0), Some(now + Duration::from_secs(1)));
    // Its round fails too — no hope anywhere, the VPN stops.
    assert!(
        pool.round_failed(epoch(1))
            .unwrap_err()
            .to_string()
            .contains("no server available")
    );
}

#[test]
fn round_failure_waits_for_in_flight_rounds_of_other_servers() {
    let now = Instant::now();
    let mut pool = Pool::new([1, 1]);
    pool.ready(epoch(0), now);
    pool.ready(epoch(1), now);
    pool.checking(epoch(1));
    // Server 0 dies outright; server 1 still has its round in flight.
    pool.failed(epoch(0), now, "test").unwrap();
    // That round fails — nothing can reach Ready anymore: stop.
    assert!(
        pool.round_failed(epoch(1))
            .unwrap_err()
            .to_string()
            .contains("no server available, stopping")
    );
}

#[test]
fn retry_round_keeps_hope_when_last_ready_is_lost() {
    let now = Instant::now();
    let mut pool = Pool::new([1, 1]);
    pool.ready(epoch(0), now);
    pool.ready(epoch(1), now);
    pool.checking(epoch(1));
    pool.round_failed(epoch(1)).unwrap();
    // The next round starts while server 0 is still Ready.
    pool.checking(epoch(1));
    assert!(pool.failed(epoch(0), now, "test").is_ok());
    // Only the retry's verdict can exhaust the remaining hope.
    assert!(pool.round_failed(epoch(1)).is_err());
}

#[test]
fn round_failure_with_another_ready_keeps_serving() {
    let now = Instant::now();
    let mut pool = Pool::new([1, 1]);
    pool.ready(epoch(0), now);
    pool.ready(epoch(1), now);
    pool.checking(epoch(1));
    assert!(pool.round_failed(epoch(1)).unwrap());
    // Its owner flows keep being served; new flows go to the Ready one.
    assert!(pool.is_serving(epoch(1)));
    assert_eq!(pool.pick(), Some(epoch(0)));
    // Stale or repeated signals do not retrigger evaluation.
    assert!(!pool.round_failed(epoch(1)).unwrap());
}

// ── retry backoff ──

#[test]
fn retry_caps_at_sixty_and_success_resets_delay() {
    let mut now = Instant::now();
    let mut pool = Pool::new([1, 1]);
    pool.ready(epoch(0), now);
    let mut failed = epoch(1);
    for seconds in [1, 2, 4, 8, 16, 32, 60, 60] {
        pool.failed(failed, now, "test").unwrap();
        now += Duration::from_secs(seconds);
        assert_eq!(pool.retry_at(1), Some(now));
        let retries = pool.retry_due(now).unwrap();
        assert_eq!(retries.len(), 1);
        assert!(!pool.ready(failed, now));
        assert!(!pool.failed(failed, now, "test").unwrap());
        failed = retries[0];
    }
    assert!(pool.ready(failed, now));
    pool.failed(failed, now, "test").unwrap();
    assert_eq!(pool.retry_at(1), Some(now + Duration::from_secs(1)));
}

// ── weighted pick ──

#[test]
fn smooth_weights_preserve_order_and_ignore_failed_servers() {
    let now = Instant::now();
    let mut pool = Pool::new([2, 1]);
    assert_eq!(pool.pick(), None);
    pool.ready(epoch(0), now);
    pool.ready(epoch(1), now);
    let selected: Vec<_> = (0..6).map(|_| pool.pick().unwrap().link).collect();
    assert_eq!(selected, [0, 1, 0, 0, 1, 0]);
    pool.failed(epoch(0), now, "test").unwrap();
    for _ in 0..6 {
        assert_eq!(pool.pick(), Some(epoch(1)));
    }
    let retry = pool.retry_due(now + Duration::from_secs(1)).unwrap()[0];
    pool.ready(retry, now);
    let selected: Vec<_> = (0..3).map(|_| pool.pick().unwrap().link).collect();
    assert_eq!(selected, [0, 1, 0]);
}

fn epoch(link: usize) -> Epoch {
    Epoch {
        link,
        generation: 1,
    }
}
