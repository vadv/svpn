//! Background jobs: transparent scheduled scripts (systemd-style).
//!
//! The job script is trusted user configuration — exactly like hooks. SVPN
//! runs it on a timer, passes an environment contract, logs a capped tail of
//! its output and, on request, reloads the geo tables. All cleverness
//! (staging, validation before rename, platform quirks) belongs to the
//! example templates, not here.

use std::{collections::HashSet, time::Duration};

use anyhow::{Result, bail, ensure};

/// Minimum spacing between runs: a job forks a shell, a resolver does not.
pub const MIN_EVERY: Duration = Duration::from_secs(60);
/// Kill bound when the config says nothing.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
/// A job must not outstay a day even when allowed to.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 3600);

/// What to re-read from disk after a successful run. Closed vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reload {
    Geo,
    Country,
}

impl Reload {
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "geo" => Ok(Reload::Geo),
            "country" => Ok(Reload::Country),
            _ => bail!("reload expects geo or country"),
        }
    }
}

/// One `job "label" {…}` block.
#[derive(Clone, Debug)]
pub struct JobSpec {
    pub label: String,
    /// Interval since the previous run; the first run happens after it.
    pub every: Duration,
    /// SIGKILL bound for the whole process group.
    pub timeout: Duration,
    /// The script, executed as `/bin/sh -c`.
    pub run: String,
    /// Tables to re-read from disk after exit 0.
    pub reload: Vec<Reload>,
}

impl JobSpec {
    /// Cross-block checks: labels are unique.
    pub fn validate_all(jobs: &[JobSpec]) -> Result<()> {
        let mut labels = HashSet::new();
        for job in jobs {
            ensure!(
                labels.insert(&job.label),
                "duplicate job label {}",
                job.label
            );
        }
        Ok(())
    }
}
