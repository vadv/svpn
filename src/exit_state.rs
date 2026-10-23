//! Sticky exit owner persistence: failover transitions survive restarts.
//!
//! Only failover reassignments are stored (`group → stable node id`); plain
//! rendezvous assignments reproduce themselves and need no disk. Writes are
//! batched (flash wear) and atomic (tmp + fsync + rename + fsync dir). The
//! file is a hint, not a trust boundary: corruption or a format version
//! mismatch degrades to an empty state, never to an error.

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const VERSION: u32 = 1;
const FLUSH_EVERY: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    owners: HashMap<String, String>,
}

pub struct ExitState {
    owners: HashMap<u64, String>,
    path: Option<PathBuf>,
    dirty: bool,
    last_flush: Instant,
}

impl ExitState {
    /// Missing, unreadable or foreign-version state starts empty.
    pub fn load(path: Option<PathBuf>) -> Self {
        let owners = path
            .as_deref()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|text| serde_json::from_str::<File>(&text).ok())
            .filter(|file| file.version == VERSION)
            .map(|file| {
                file.owners
                    .into_iter()
                    .filter_map(|(group, node)| group.parse::<u64>().ok().map(|g| (g, node)))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            owners,
            path,
            dirty: false,
            last_flush: Instant::now(),
        }
    }

    pub fn owner(&self, group: u64) -> Option<&String> {
        self.owners.get(&group)
    }

    /// Record a failover transition; flushed by `flush_due` / `flush`.
    pub fn assign(&mut self, group: u64, node: &str) {
        if self
            .owners
            .get(&group)
            .is_none_or(|current| current != node)
        {
            self.owners.insert(group, node.to_string());
            self.dirty = true;
        }
    }

    /// Drop groups pinned to nodes that left the configuration.
    pub fn retain_nodes(&mut self, ids: &[String]) {
        let before = self.owners.len();
        self.owners.retain(|_, node| ids.contains(node));
        self.dirty |= self.owners.len() != before;
    }

    pub fn flush_due(&mut self, now: Instant) {
        if self.dirty && now.duration_since(self.last_flush) >= FLUSH_EVERY {
            self.flush();
        }
    }

    pub fn flush(&mut self) {
        if !self.dirty {
            return;
        }
        self.last_flush = Instant::now();
        match self.write() {
            Ok(()) => self.dirty = false,
            // Keep dirty: flush_due retries after FLUSH_EVERY.
            Err(error) => {
                crate::error!("exit state: {error:#} — failover transitions are not persisted")
            }
        }
    }

    fn write(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = File {
            version: VERSION,
            owners: self
                .owners
                .iter()
                .map(|(group, node)| (group.to_string(), node.clone()))
                .collect(),
        };
        let bytes = serde_json::to_vec(&file).context("serialize exit state")?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, &bytes).with_context(|| format!("{}", tmp.display()))?;
        let written = fs::File::open(&tmp)?;
        written.sync_all().context("fsync exit state")?;
        fs::rename(&tmp, path).with_context(|| format!("{}", path.display()))?;
        // A bare relative path has an empty parent: it means the cwd.
        let dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        fs::File::open(dir)
            .and_then(|dir| dir.sync_all())
            .with_context(|| format!("fsync dir {}", dir.display()))?;
        Ok(())
    }

    pub fn owner_indices(&self, ids: &[String]) -> HashMap<u64, usize> {
        self.owners
            .iter()
            .filter_map(|(group, node)| {
                ids.iter()
                    .position(|id| id == node)
                    .map(|link| (*group, link))
            })
            .collect()
    }
}
