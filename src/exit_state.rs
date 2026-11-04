//! Persistent failover owners for sticky routing.
//! Writes are atomic; corrupt or foreign-version state loads empty.
//! Version 1: automatic ASN groups and explicit sticky groups; no legacy
//! migrations (EPIC-021 dropped pre-HCL state formats with the users).

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

/// Typed persistent owner key: one sticky assignment per domain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExitKey {
    /// Automatic sticky-asn group.
    Asn(u32),
    /// Explicit sticky group (canonical `kind:members` selector key).
    Sticky(String),
}

impl ExitKey {
    /// Canonical string key of the map this domain persists to.
    fn key(&self) -> String {
        match self {
            ExitKey::Asn(asn) => asn.to_string(),
            ExitKey::Sticky(canonical) => canonical.clone(),
        }
    }

    /// Parse a stored map key; `None` marks a foreign or corrupt entry.
    fn parse(stored: &str) -> Option<Self> {
        if stored.starts_with("name:")
            || stored.starts_with("cc:")
            || stored.starts_with("ip:")
            || stored.starts_with("asn:")
        {
            return Some(ExitKey::Sticky(stored.to_string()));
        }
        stored.parse::<u32>().ok().map(ExitKey::Asn)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    asn: HashMap<String, String>,
    sticky: HashMap<String, String>,
}

pub struct ExitState {
    asn: HashMap<String, String>,
    sticky: HashMap<String, String>,
    path: Option<PathBuf>,
    dirty: bool,
    last_flush: Instant,
}

impl ExitState {
    /// Missing, unreadable, corrupt or foreign-version state starts empty.
    pub fn load(path: Option<PathBuf>) -> Self {
        let (asn, sticky) = path
            .as_deref()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|text| parse(&text))
            .unwrap_or_default();
        Self {
            asn,
            sticky,
            path,
            dirty: false,
            last_flush: Instant::now(),
        }
    }

    pub fn owner(&self, key: &ExitKey) -> Option<&String> {
        self.map(key).get(&key.key())
    }

    /// Record a failover transition; flushed by `flush_due` / `flush`.
    pub fn assign(&mut self, key: ExitKey, node: &str) {
        let stored = key.key();
        let map = match &key {
            ExitKey::Asn(_) => &mut self.asn,
            ExitKey::Sticky(_) => &mut self.sticky,
        };
        if map.get(&stored).is_none_or(|current| current != node) {
            map.insert(stored, node.to_string());
            self.dirty = true;
        }
    }

    /// Drop entries pinned to nodes that left the configuration.
    pub fn retain_nodes(&mut self, ids: &[String]) {
        let before = self.asn.len() + self.sticky.len();
        self.asn.retain(|_, node| ids.contains(node));
        self.sticky.retain(|_, node| ids.contains(node));
        self.dirty |= self.asn.len() + self.sticky.len() != before;
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

    fn map(&self, key: &ExitKey) -> &HashMap<String, String> {
        match key {
            ExitKey::Asn(_) => &self.asn,
            ExitKey::Sticky(_) => &self.sticky,
        }
    }

    fn write(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = File {
            version: VERSION,
            asn: self.asn.clone(),
            sticky: self.sticky.clone(),
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

    /// Restore link indices per typed key. Stored keys that do not parse and
    /// nodes that left the configuration are skipped.
    pub fn owner_indices(&self, ids: &[String]) -> HashMap<ExitKey, usize> {
        self.asn
            .iter()
            .chain(self.sticky.iter())
            .filter_map(|(stored, node)| {
                let key = ExitKey::parse(stored)?;
                ids.iter().position(|id| id == node).map(|link| (key, link))
            })
            .collect()
    }
}

/// Both maps of a document, or `None` when it is corrupt or foreign version.
fn parse(text: &str) -> Option<(HashMap<String, String>, HashMap<String, String>)> {
    let file = serde_json::from_str::<File>(text).ok()?;
    (file.version == VERSION).then_some((file.asn, file.sticky))
}
