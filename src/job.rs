//! Background jobs: transparent scheduled scripts (systemd-style).
//!
//! The job script is trusted user configuration — exactly like hooks. SVPN
//! runs it on a timer, passes an environment contract, logs a capped tail of
//! its output and, on request, reloads the geo tables. All cleverness
//! (staging, validation before rename, platform quirks) belongs to the
//! example templates, not here.

use std::{collections::HashSet, time::Duration};

use anyhow::{Result, bail, ensure};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tokio::{process::Command, time::Instant};

/// Captured output bound: scripts may print secrets, and a runaway log must
/// not grow the process. The tail is what ends up in the log.
const OUTPUT_CAP: usize = 4 * 1024;
const OUTPUT_LINES: usize = 16;

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
    /// Exit 0 of this check skips the attempt (systemd ExecCondition with
    /// freshness polarity). None — every attempt reaches `run`.
    pub skip_if: Option<String>,
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

/// How one run ended. The script is trusted: no interpretation beyond the
/// process status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobStatus {
    Ok,
    /// Nonzero exit; carries the `ExitStatus` display string.
    Failed(String),
    /// Killed at the timeout bound.
    Timeout,
}

/// Execute one job now: `/bin/sh -c`, own process group, SIGKILL at the
/// timeout, stdout+stderr captured into a capped tail. The same discipline
/// as hooks (`process_group(0)`, `killpg`, `kill_on_drop`), adapted for
/// captured output and a per-job deadline.
pub async fn run(spec: &JobSpec, env: &[(String, String)]) -> (JobStatus, String) {
    let started = Instant::now();
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &spec.run])
        .process_group(0)
        .env("SVPN_JOB", &spec.label)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            crate::error!("job {}: spawn failed: {error}", spec.label);
            return (JobStatus::Failed("spawn failed".to_string()), String::new());
        }
    };
    let group = child
        .id()
        .map_or_else(|| Pid::from_raw(-1), |id| Pid::from_raw(id as i32));
    // Drain both pipes concurrently while the child runs, keeping a bounded
    // tail: a full pipe would otherwise block the script forever.
    async fn drain<R: tokio::io::AsyncRead + Unpin>(pipe: Option<R>) -> (Vec<u8>, usize) {
        use tokio::io::AsyncReadExt;
        let mut tail = std::collections::VecDeque::new();
        let mut total = 0usize;
        let mut buffer = [0u8; 2048];
        if let Some(mut pipe) = pipe {
            loop {
                match pipe.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        total += n;
                        for byte in &buffer[..n] {
                            if tail.len() == OUTPUT_CAP {
                                tail.pop_front();
                            }
                            tail.push_back(*byte);
                        }
                    }
                }
            }
        }
        (tail.into_iter().collect(), total)
    }
    let out_handle = tokio::spawn(drain(child.stdout.take()));
    let err_handle = tokio::spawn(drain(child.stderr.take()));
    // Wait with the timeout bound first; kill the whole group on either
    // path, and only then collect the drained tails (closed pipes finish
    // the drains) — awaiting them earlier would block the kill itself.
    let status = tokio::select! {
        status = child.wait() => Some(status),
        _ = tokio::time::sleep_until(started + spec.timeout) => None,
    };
    let _ = killpg(group, Signal::SIGKILL);
    let _ = child.wait().await;
    let (out_pipe, out_total) = out_handle.await.unwrap_or_default();
    let (err_pipe, err_total) = err_handle.await.unwrap_or_default();
    let mut tail = String::from_utf8_lossy(&out_pipe).into_owned();
    tail.push_str(&String::from_utf8_lossy(&err_pipe));
    let status = match status {
        Some(Ok(status)) if status.success() => JobStatus::Ok,
        Some(Ok(status)) => JobStatus::Failed(status.to_string()),
        Some(Err(error)) => JobStatus::Failed(format!("wait failed: {error}")),
        None => JobStatus::Timeout,
    };
    let _ = (out_total, err_total); // size accounting kept for future metrics
    (status, tail)
}

/// Log one finished run: status plus the capped tail, line-prefixed.
pub fn log_run(spec: &JobSpec, status: &JobStatus, tail: &str) {
    match status {
        JobStatus::Ok => crate::info!("job: {} completed", spec.label),
        JobStatus::Failed(reason) => crate::error!("job: {} failed: {reason}", spec.label),
        JobStatus::Timeout => {
            crate::error!(
                "job: {} timed out after {}s",
                spec.label,
                spec.timeout.as_secs()
            )
        }
    }
    let lines: std::collections::VecDeque<&str> = tail.lines().collect();
    let skip = lines.len().saturating_sub(OUTPUT_LINES);
    for line in lines.iter().skip(skip) {
        crate::info!("job[{}]: {line}", spec.label);
    }
}
