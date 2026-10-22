//! Continuous path statistics: every burst outcome feeds a per-candidate
//! window; verdicts and the degradation baseline read smoothed values
//! (EWMA and mean deviation, RFC 9002 alphas), never a single burst.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Bursts kept per candidate: ~10 min of samples at the probe cadence.
pub const WINDOW_LEN: usize = 10;
/// Samples older than this describe a different network and are dropped.
pub const WINDOW_AGE: Duration = Duration::from_secs(30 * 60);
/// EWMA weight of a new sample (RFC 9002 smoothed_rtt, alpha = 1/8):
/// ~8 consecutive samples move the estimate — the two-round rule of 0.6.x
/// expressed as a statistic.
const EWMA_ALPHA_DEN: u32 = 8;
/// Mean-deviation weight (RFC 9002 rttvar, beta = 1/4).
const MAD_ALPHA_DEN: u32 = 4;

/// One window entry: when the burst finished, its p90 (None = total loss)
/// and the lost echo count.
struct Sample {
    at: Instant,
    p90: Option<Duration>,
}

/// Smoothed picture of one candidate's path.
#[derive(Default)]
pub struct PathStats {
    window: VecDeque<Sample>,
    ewma: Option<Duration>,
    mad: Option<Duration>,
}

impl PathStats {
    /// Record a finished burst. A total loss keeps the window but does not
    /// pull the EWMA — loss is judged by the burst's own `lost` count.
    pub fn push(&mut self, at: Instant, p90: Option<Duration>) {
        self.window.push_back(Sample { at, p90 });
        self.evict(at);
        if let Some(sample) = p90 {
            // Deviation is taken against the *updated* EWMA, matching
            // RFC 9002's ordering of the two updates.
            let next = self
                .ewma
                .map(|prev| lerp(prev, sample, EWMA_ALPHA_DEN))
                .unwrap_or(sample);
            let dev = next.abs_diff(sample);
            self.mad = Some(
                self.mad
                    .map(|prev| lerp(prev, dev, MAD_ALPHA_DEN))
                    .unwrap_or(dev),
            );
            self.ewma = Some(next);
        }
    }

    fn evict(&mut self, now: Instant) {
        while self.window.len() > WINDOW_LEN {
            self.window.pop_front();
        }
        let cutoff = now.checked_sub(WINDOW_AGE);
        while self
            .window
            .front()
            .is_some_and(|front| cutoff.is_some_and(|cutoff| front.at < cutoff))
        {
            self.window.pop_front();
        }
    }

    /// Minimum p90 over the window — the degradation reference. A path
    /// that drifts slowly raises the EWMA and the minimum together; a
    /// genuine spike does not.
    pub fn min_p90(&self) -> Option<Duration> {
        self.window.iter().filter_map(|s| s.p90).min()
    }

    pub fn ewma_p90(&self) -> Option<Duration> {
        self.ewma
    }

    pub fn mad(&self) -> Option<Duration> {
        self.mad
    }

    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    /// One `34ms±2`-style cell for the per-tick `paths:` log line; a path
    /// with no successful sample yet logs as `-`.
    pub fn summary(&self) -> String {
        match (self.ewma_p90(), self.mad()) {
            (Some(ewma), Some(mad)) => format!("{}ms±{}", ewma.as_millis(), mad.as_millis()),
            _ => "-".to_owned(),
        }
    }
}

/// `(den - 1) * prev + sample) / den` without overflow on long durations.
fn lerp(prev: Duration, sample: Duration, den: u32) -> Duration {
    (prev * (den - 1) + sample) / den
}
