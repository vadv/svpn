//! Unit tests for the continuous path statistics (EPIC-017):
//! EWMA/MAD smoothing, loss handling, window eviction by count and age.

use std::time::{Duration, Instant};

use svpn::session::stats::{PathStats, WINDOW_LEN};

fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}

#[test]
fn first_push_sets_estimate_and_min() {
    let mut stats = PathStats::default();
    assert!(stats.is_empty());
    stats.push(Instant::now(), Some(ms(40)));
    assert_eq!(stats.ewma_p90(), Some(ms(40)));
    assert_eq!(stats.mad(), Some(Duration::ZERO));
    assert_eq!(stats.min_p90(), Some(ms(40)));
    assert!(!stats.is_empty());
}

#[test]
fn ewma_and_mad_converge_by_rfc9002_alphas() {
    let mut stats = PathStats::default();
    let t0 = Instant::now();
    // alpha = 1/8, beta = 1/4, deviation against the updated EWMA.
    stats.push(t0, Some(ms(100)));
    stats.push(t0, Some(ms(100)));
    stats.push(t0, Some(ms(50)));
    // ewma = (7*100 + 50)/8 = 93.75 ms
    assert_eq!(stats.ewma_p90(), Some(Duration::from_nanos(93_750_000)));
    // dev = |93.75 - 50| = 43.75; mad = 43.75/4 = 10.9375 ms
    assert_eq!(stats.mad(), Some(Duration::from_nanos(10_937_500)));
    assert_eq!(stats.min_p90(), Some(ms(50)));
}

#[test]
fn total_loss_keeps_ewma_and_min() {
    let mut stats = PathStats::default();
    let t0 = Instant::now();
    stats.push(t0, Some(ms(60)));
    stats.push(t0, None);
    // A total loss is a loss event, not an RTT sample.
    assert_eq!(stats.ewma_p90(), Some(ms(60)));
    assert_eq!(stats.mad(), Some(Duration::ZERO));
    assert_eq!(stats.min_p90(), Some(ms(60)));
    // The window keeps growing, so age eviction still applies to it.
    assert!(!stats.is_empty());
}

#[test]
fn slow_drift_keeps_ewma_under_twice_the_window_minimum() {
    // 20 → 40 ms over the window: the minimum climbs with the drift, so
    // the degradation trigger (ewma ≥ 2 × min) must not fire.
    let mut stats = PathStats::default();
    let t0 = Instant::now();
    for sample in [20, 24, 28, 32, 36, 40] {
        stats.push(t0, Some(ms(sample)));
    }
    let (ewma, min) = (stats.ewma_p90().unwrap(), stats.min_p90().unwrap());
    assert!(
        ewma < min * 2,
        "drift is not degradation: {ewma:?} vs 2×{min:?}"
    );
}

#[test]
fn sustained_spike_lifts_ewma_past_twice_the_window_minimum() {
    // A clean 20 ms path that jumps to 60 ms and stays there must trip the
    // degradation trigger while the pre-spike minimum is still in window.
    let mut stats = PathStats::default();
    let t0 = Instant::now();
    for _ in 0..5 {
        stats.push(t0, Some(ms(20)));
    }
    for _ in 0..6 {
        stats.push(t0, Some(ms(60)));
    }
    let (ewma, min) = (stats.ewma_p90().unwrap(), stats.min_p90().unwrap());
    assert!(
        ewma >= min * 2,
        "a sustained spike is degradation: {ewma:?} vs 2×{min:?}"
    );
}

#[test]
fn jitter_stays_inside_bounds_and_converges_to_the_interval() {
    use svpn::session::challenge::jittered;
    let interval = Duration::from_secs(60);
    let mut total = Duration::ZERO;
    for seed in 0..101u64 {
        let value = jittered(interval, seed);
        // ±50% per the cadence spec, both ends inclusive.
        assert!(value >= interval / 2, "seed {seed}: {value:?} too small");
        assert!(
            value <= interval * 3 / 2,
            "seed {seed}: {value:?} too large"
        );
        total += value;
    }
    // The seed sweep is symmetric: the mean is the configured interval.
    assert_eq!(total / 101, interval);
}

#[test]
fn count_eviction_drops_the_oldest_sample() {
    let mut stats = PathStats::default();
    let t0 = Instant::now();
    stats.push(t0, Some(ms(50)));
    for _ in 0..WINDOW_LEN {
        stats.push(t0, Some(ms(100)));
    }
    // WINDOW_LEN samples remain, all 100 ms: the 50 ms left the window.
    assert_eq!(stats.min_p90(), Some(ms(100)));
}

#[test]
fn age_eviction_drops_stale_samples() {
    let mut stats = PathStats::default();
    let t0 = Instant::now();
    stats.push(t0, Some(ms(50)));
    // 31 minutes later the first sample describes a different network.
    let later = t0 + Duration::from_secs(31 * 60);
    stats.push(later, Some(ms(120)));
    assert_eq!(stats.min_p90(), Some(ms(120)));
}
