//! Read-only resource usage of the svpn process itself, for the dashboard.
//!
//! Every value is optional: an OS that cannot report it produces `null` in the
//! JSON snapshot rather than a guess. `getrusage` gives cumulative CPU time and
//! peak RSS on both supported platforms through a safe `nix` wrapper; current
//! RSS comes from `/proc` on Linux. No subprocesses, no new crates, no unsafe.
//!
//! Known limitation: on macOS current RSS is not available without libproc
//! (which needs unsafe, forbidden by the crate lint), so the UI falls back to
//! the peak value and labels it PEAK. Revisit if a safe process-metrics API
//! appears in an already-used dependency.

use serde::Serialize;

/// Resource usage of this process at one snapshot.
#[derive(Serialize, Clone, Copy, Debug, Default, PartialEq)]
pub struct ProcessView {
    /// Current resident set size in bytes, when the OS exposes it.
    pub rss_bytes: Option<u64>,
    /// Peak resident set size in bytes, when `getrusage` succeeded.
    pub peak_rss_bytes: Option<u64>,
    /// Cumulative user + system CPU seconds since process start.
    /// A cumulative counter, not a percentage: the browser derives the live
    /// percentage from two consecutive snapshots.
    pub cpu_seconds: Option<f64>,
    /// Logical CPUs, so a multi-threaded percentage can be scaled.
    pub cpus: Option<usize>,
}

impl ProcessView {
    /// Best RSS value available, with a flag telling the UI whether it is a peak.
    /// Kept as a plain method so the fallback rule has a test of its own.
    pub fn rss(&self) -> (Option<u64>, bool) {
        match self.rss_bytes {
            Some(bytes) => (Some(bytes), false),
            None => (self.peak_rss_bytes, self.peak_rss_bytes.is_some()),
        }
    }
}

/// Parse `VmRSS: <kib> kB` out of `/proc/self/status`.
/// Unknown units, malformed numbers and overflow are all "no value".
pub fn parse_vm_rss(status: &str) -> Option<u64> {
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let mut fields = line.split_whitespace();
    fields.next()?;
    let kib = fields.next()?.parse::<u64>().ok()?;
    if fields.next() != Some("kB") {
        return None;
    }
    kib.checked_mul(1024)
}

/// Convert a raw `ru_maxrss` to bytes. Linux reports KiB, Apple/BSD bytes.
pub fn peak_bytes(raw: i64, kib: bool) -> Option<u64> {
    if raw <= 0 {
        return None;
    }
    let factor = if kib { 1024 } else { 1 };
    u64::try_from(raw).ok()?.checked_mul(factor)
}

/// Sum user and system CPU time, given in microseconds.
/// A negative or overflowing counter means the OS reading is unusable.
pub fn total_cpu_seconds(user_micros: i64, system_micros: i64) -> Option<f64> {
    if user_micros < 0 || system_micros < 0 {
        return None;
    }
    let total = user_micros.checked_add(system_micros)?;
    Some(total as f64 / 1_000_000.0)
}

/// Collect one best-effort sample. Never panics on a missing OS facility.
pub fn sample() -> ProcessView {
    use nix::sys::{
        resource::{UsageWho, getrusage},
        time::TimeValLike,
    };

    let usage = getrusage(UsageWho::RUSAGE_SELF).ok();
    let cpu_seconds = usage.and_then(|usage| {
        total_cpu_seconds(
            usage.user_time().num_microseconds(),
            usage.system_time().num_microseconds(),
        )
    });
    let peak_rss_bytes =
        usage.and_then(|usage| peak_bytes(usage.max_rss(), cfg!(target_os = "linux")));
    ProcessView {
        rss_bytes: current_rss(),
        peak_rss_bytes,
        cpu_seconds,
        cpus: std::thread::available_parallelism()
            .ok()
            .map(|cpus| cpus.get()),
    }
}

#[cfg(target_os = "linux")]
fn current_rss() -> Option<u64> {
    parse_vm_rss(&std::fs::read_to_string("/proc/self/status").ok()?)
}

#[cfg(not(target_os = "linux"))]
fn current_rss() -> Option<u64> {
    None
}
