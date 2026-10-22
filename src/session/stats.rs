//! Per-candidate path statistics: EWMA/mean deviation over a bounded
//! sample window.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Bursts kept per candidate.
pub const WINDOW_LEN: usize = 10;
/// Older samples describe a different network.
pub const WINDOW_AGE: Duration = Duration::from_secs(30 * 60);
/// RFC 9002 smoothed_rtt weight, alpha = 1/8.
const EWMA_ALPHA_DEN: u32 = 8;
/// Mean-deviation weight (RFC 9002 rttvar, beta = 1/4).
const MAD_ALPHA_DEN: u32 = 4;

/// One window entry: timestamp and p90 (None = total loss).
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
    /// Record a finished burst; a total loss does not pull the EWMA.
    pub fn push(&mut self, at: Instant, p90: Option<Duration>) {
        self.evict_aged(at);
        if self.window.is_empty() {
            // A fully-expired window must not seed fresh estimates.
            self.ewma = None;
            self.mad = None;
        }
        self.window.push_back(Sample { at, p90 });
        while self.window.len() > WINDOW_LEN {
            self.window.pop_front();
        }
        if let Some(sample) = p90 {
            // Deviation against the updated EWMA (RFC 9002 ordering).
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

    /// Drop samples older than the window age.
    fn evict_aged(&mut self, now: Instant) {
        let cutoff = now.checked_sub(WINDOW_AGE);
        while self
            .window
            .front()
            .is_some_and(|front| cutoff.is_some_and(|cutoff| front.at < cutoff))
        {
            self.window.pop_front();
        }
    }

    /// Minimum p90 over the window — the degradation reference.
    pub fn min_p90(&self) -> Option<Duration> {
        self.window.iter().filter_map(|s| s.p90).min()
    }

    pub fn ewma_p90(&self) -> Option<Duration> {
        self.ewma
    }

    pub fn mad(&self) -> Option<Duration> {
        self.mad
    }

    /// Successful samples behind the estimate.
    pub fn samples(&self) -> usize {
        self.window
            .iter()
            .filter(|sample| sample.p90.is_some())
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }
}

/// `((den - 1) * prev + sample) / den` without overflow on long durations.
fn lerp(prev: Duration, sample: Duration, den: u32) -> Duration {
    (prev * (den - 1) + sample) / den
}
