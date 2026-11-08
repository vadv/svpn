//! Scheduled jobs and their read-only runtime status. Script output stays out of snapshots.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::{mpsc, watch};

use super::Hub;
use crate::job::{JobSpec, JobStatus, Reload};

/// Scheduler transitions, not script output.
pub enum JobEvent {
    Started {
        label: String,
    },
    Skipped {
        label: String,
        next_at: u64,
        reason: String,
    },
    Finished {
        label: String,
        status: JobStatus,
        reload: Vec<Reload>,
        next_at: u64,
    },
}

/// Everything the scheduler needs: specs, reload paths and the env contract.
#[derive(Default)]
pub struct JobContext {
    pub specs: Vec<crate::job::JobSpec>,
    pub geo_db: Option<std::path::PathBuf>,
    pub country_db: Option<std::path::PathBuf>,
    pub config_dir: Option<std::path::PathBuf>,
}

impl JobContext {
    /// Build the context from parsed client arguments (config-driven parts).
    pub fn from_args(args: &crate::cli::ClientArgs) -> Self {
        Self {
            specs: args.jobs.clone(),
            geo_db: args.geo_db.clone(),
            country_db: args.country_db.clone(),
            config_dir: args.config.as_deref().map(|path| {
                let parent = path.parent().filter(|dir| !dir.as_os_str().is_empty());
                parent.unwrap_or(std::path::Path::new(".")).to_path_buf()
            }),
        }
    }

    /// The documented environment contract; scripts never hardcode paths.
    pub fn env(&self) -> Vec<(String, String)> {
        let mut env = vec![
            (
                "SVPN_OS".to_owned(),
                // The only musl target we ship is OpenWrt; scripts branch on it.
                if cfg!(all(target_os = "linux", target_env = "musl")) {
                    "openwrt".to_owned()
                } else {
                    std::env::consts::OS.to_owned()
                },
            ),
            ("SVPN_JOB".to_owned(), String::new()),
        ];
        if let Some(path) = &self.geo_db {
            env.push(("SVPN_GEO_DB".to_owned(), path.display().to_string()));
        }
        if let Some(path) = &self.country_db {
            env.push(("SVPN_COUNTRY_DB".to_owned(), path.display().to_string()));
        }
        if let Some(dir) = &self.config_dir {
            env.push(("SVPN_CONFIG_DIR".to_owned(), dir.display().to_string()));
        }
        env
    }
}

#[derive(Default, Clone, Serialize)]
pub struct DatabaseStatus {
    pub loaded_at: Option<u64>,
    pub attempted_at: Option<u64>,
    pub error: String,
}

#[derive(Clone, Serialize)]
pub struct JobProgress {
    pub label: String,
    pub every_secs: u64,
    pub timeout_secs: u64,
    pub reload: Vec<&'static str>,
    /// waiting, running (including run_if), skipped, ok, failed, timeout, reload_failed.
    pub state: &'static str,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub success_at: Option<u64>,
    pub next_at: Option<u64>,
    pub reason: String,
}

#[derive(Default, Clone, Serialize)]
pub struct JobStats {
    pub runs: u64,
    pub failures: u64,
    pub timeouts: u64,
    /// Milliseconds since Unix epoch, used to distinguish client runs.
    pub started_at: u64,
    pub details: Vec<JobProgress>,
    pub geo: DatabaseStatus,
    pub country: DatabaseStatus,
}

impl JobStats {
    pub fn new(specs: &[JobSpec], geo_loaded: bool, country_loaded: bool) -> Self {
        let now = unix_time();
        Self {
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |time| time.as_millis().min(u128::from(u64::MAX)) as u64),
            details: specs
                .iter()
                .map(|spec| JobProgress {
                    label: spec.label.clone(),
                    every_secs: spec.every.as_secs(),
                    timeout_secs: spec.timeout.as_secs(),
                    reload: spec
                        .reload
                        .iter()
                        .map(|kind| match kind {
                            Reload::Geo => "geo",
                            Reload::Country => "country",
                        })
                        .collect(),
                    state: "waiting",
                    started_at: None,
                    finished_at: None,
                    success_at: None,
                    next_at: Some(now),
                    reason: String::new(),
                })
                .collect(),
            geo: DatabaseStatus {
                loaded_at: geo_loaded.then_some(now),
                ..Default::default()
            },
            country: DatabaseStatus {
                loaded_at: country_loaded.then_some(now),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

impl Hub {
    pub fn handle_job_event(&mut self, event: JobEvent) {
        let now = unix_time();
        let (label, state, next_at, reason) = match event {
            JobEvent::Started { label } => {
                if let Some(job) = self
                    .job_stats
                    .details
                    .iter_mut()
                    .find(|job| job.label == label)
                {
                    job.state = "running";
                    job.started_at = Some(now);
                    job.next_at = None;
                }
                return;
            }
            JobEvent::Skipped {
                label,
                next_at,
                reason,
            } => (label, "skipped", next_at, reason),
            JobEvent::Finished {
                label,
                status,
                reload,
                next_at,
            } => {
                self.job_stats.runs += 1;
                let (state, reason) = match status {
                    JobStatus::Ok => {
                        let mut ok = true;
                        for kind in reload {
                            // Evaluate every reload even if the previous one failed.
                            ok = self.reload_table(kind, &label) && ok;
                        }
                        if ok {
                            ("ok", String::new())
                        } else {
                            (
                                "reload_failed",
                                "Database reload failed; previous tables retained".to_owned(),
                            )
                        }
                    }
                    JobStatus::Failed(reason) => {
                        self.job_stats.failures += 1;
                        let reason: String = reason.chars().take(256).collect();
                        self.update_failed(&reload, &reason, now);
                        ("failed", reason)
                    }
                    JobStatus::Timeout => {
                        self.job_stats.timeouts += 1;
                        let reason = "Attempt timed out".to_owned();
                        self.update_failed(&reload, &reason, now);
                        ("timeout", reason)
                    }
                };
                (label, state, next_at, reason)
            }
        };
        if let Some(job) = self
            .job_stats
            .details
            .iter_mut()
            .find(|job| job.label == label)
        {
            job.state = state;
            job.finished_at = Some(now);
            job.next_at = Some(next_at);
            if state == "ok" {
                job.success_at = Some(now);
            }
            job.reason = reason;
        }
    }

    fn update_failed(&mut self, reload: &[Reload], reason: &str, now: u64) {
        for kind in reload {
            let status = match kind {
                Reload::Geo => &mut self.job_stats.geo,
                Reload::Country => &mut self.job_stats.country,
            };
            status.attempted_at = Some(now);
            status.error = format!("Update failed: {reason}; previous table retained");
        }
    }

    /// A failed reload never replaces the in-memory table.
    pub fn reload_geo(&mut self, label: &str) -> bool {
        self.reload_table(Reload::Geo, label)
    }

    pub fn reload_country(&mut self, label: &str) -> bool {
        self.reload_table(Reload::Country, label)
    }

    fn reload_table(&mut self, kind: Reload, label: &str) -> bool {
        let name = match kind {
            Reload::Geo => "geo",
            Reload::Country => "country",
        };
        let (path, state) = match kind {
            Reload::Geo => (&self.geo_path, &mut self.job_stats.geo),
            Reload::Country => (&self.country_path, &mut self.job_stats.country),
        };
        let now = unix_time();
        state.attempted_at = Some(now);
        let table = path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("database path not configured"))
            .and_then(|path| match kind {
                Reload::Geo => crate::geo::Geo::load(path),
                Reload::Country => crate::geo::Geo::load_country(path),
            });
        match table {
            Ok(table) => {
                crate::info!(
                    "{name} database reloaded (job {label}): {} IPv4 ranges",
                    table.rows()
                );
                match kind {
                    Reload::Geo => {
                        self.geo = Some(table);
                        self.geo_pending = None;
                    }
                    Reload::Country => {
                        self.country = Some(table);
                        self.country_pending = None;
                    }
                }
                state.loaded_at = Some(now);
                state.error.clear();
                true
            }
            Err(error) => {
                crate::error!("job {label}: {name} reload failed: {error:#}");
                state.error = "Reload failed; previous table retained".to_owned();
                false
            }
        }
    }
}

pub(super) fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs())
}

/// Start the job scheduler when any job is configured. Attempts begin at
/// startup (each one gated by `run_if`) and repeat every `every`; a still
/// running job delays its next attempt instead of stacking.
pub fn spawn_scheduler(
    context: &JobContext,
    shutdown: &mut watch::Receiver<bool>,
) -> (
    Option<mpsc::Receiver<JobEvent>>,
    Option<tokio::task::JoinHandle<()>>,
) {
    if context.specs.is_empty() {
        return (None, None);
    }
    let (tx, rx) = mpsc::channel(16);
    let mut shutdown = shutdown.clone();
    let specs = context.specs.clone();
    let env = context.env();
    let task = tokio::spawn(async move {
        let mut next: Vec<tokio::time::Instant> =
            specs.iter().map(|_| tokio::time::Instant::now()).collect();
        // The whole attempt — run_if gate plus the payload — lives inside the
        // slot's own task: a slow or stuck check delays only its own job and
        // never the scheduler loop or shutdown. Err means run_if skipped.
        type Attempt = Result<(crate::job::JobStatus, String), String>;
        let mut in_flight: Vec<Option<tokio::task::JoinHandle<Attempt>>> =
            specs.iter().map(|_| None).collect();
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                () = tokio::time::sleep_until(next.iter().min().copied().unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(60))) => {
                    let now = tokio::time::Instant::now();
                    for slot in 0..specs.len() {
                        if next[slot] > now {
                            continue;
                        }
                        if let Some(handle) = &mut in_flight[slot] {
                            if !handle.is_finished() {
                                next[slot] = now + Duration::from_secs(1);
                                continue;
                            }
                            let outcome = handle.await.unwrap_or(Ok((
                                crate::job::JobStatus::Failed("scheduler join failed".to_owned()),
                                String::new(),
                            )));
                            in_flight[slot] = None;
                            next[slot] = now + specs[slot].every;
                            let spec = &specs[slot];
                            let next_at = unix_time().saturating_add(spec.every.as_secs());
                            let event = match outcome {
                                Ok((status, tail)) => {
                                    crate::job::log_run(spec, &status, &tail);
                                    JobEvent::Finished {
                                        label: spec.label.clone(), status,
                                        reload: spec.reload.clone(), next_at,
                                    }
                                }
                                Err(reason) => JobEvent::Skipped {
                                    label: spec.label.clone(), next_at, reason,
                                },
                            };
                            if tx.send(event).await.is_err() {
                                return;
                            }
                            continue;
                        }
                        let spec = specs[slot].clone();
                        if tx.send(JobEvent::Started { label: spec.label.clone() }).await.is_err() {
                            return;
                        }
                        let mut slot_env: Vec<(String, String)> = env.clone();
                        for (key, value) in &mut slot_env {
                            if key == "SVPN_JOB" {
                                value.push_str(&spec.label);
                            }
                        }
                        in_flight[slot] = Some(tokio::spawn(async move {
                            // The run_if gate: 0 — there is work, anything
                            // else — a cheap skip; a broken check never
                            // blind-runs the payload.
                            if let Some(check) = &spec.run_if {
                                let check_spec = crate::job::JobSpec {
                                    label: spec.label.clone(),
                                    every: spec.every,
                                    timeout: spec.timeout,
                                    run_if: None,
                                    run: check.clone(),
                                    reload: Vec::new(),
                                };
                                match crate::job::run(&check_spec, &slot_env).await.0 {
                                    crate::job::JobStatus::Ok => {}
                                    crate::job::JobStatus::Failed(reason) => {
                                        if reason.contains("spawn failed") {
                                            crate::error!("job {}: run_if broken: {reason}", spec.label);
                                        } else {
                                            crate::info!("job: {} up-to-date, skipped", spec.label);
                                        }
                                        return Err(format!("run_if did not request work ({reason})"));
                                    }
                                    crate::job::JobStatus::Timeout => {
                                        crate::error!("job {}: run_if timed out", spec.label);
                                        return Err("run_if timed out; payload not run".to_owned());
                                    }
                                }
                            }
                            Ok(crate::job::run(&spec, &slot_env).await)
                        }));
                        next[slot] = now + Duration::from_millis(100);
                    }
                }
            }
        }
    });
    (Some(rx), Some(task))
}
