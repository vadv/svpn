//! Sticky exit owner persistence: failover transitions survive restarts.
//!
//! Only failover reassignments are stored; plain rendezvous assignments
//! reproduce themselves and need no disk. Writes are batched (flash wear)
//! and atomic (tmp + fsync + rename + fsync dir). The file is a hint, not a
//! trust boundary: corruption or a format version mismatch degrades to an
//! empty state, never to an error.
//!
//! Version 2 keeps two independent maps in one document: `country` (ISO
//! code → node) and `asn` (numeric global ASN or `CC:ASN` scoped key →
//! node). Both maps are always written, empty or not. A version 1 `owners`
//! map migrates into the global ASN domain only. Queries go through typed
//! [`ExitKey`]s, so the domain is explicit and never inferred from which
//! map happens to be nonempty.

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const VERSION: u32 = 2;
const FLUSH_EVERY: Duration = Duration::from_secs(5);

/// Typed persistent exit key: one sticky assignment per domain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExitKey {
    /// Global ASN (`asn` map, numeric key).
    Asn(u32),
    /// Country-scoped ASN (`asn` map, `CC:ASN` key). The key keeps the
    /// country, so a restored owner can filter candidates before the first
    /// flow.
    ScopedAsn(String, u32),
    /// Country (`country` map, ISO code key).
    Country(String),
}

impl ExitKey {
    /// Canonical string key of the map this domain persists to.
    fn key(&self) -> String {
        match self {
            ExitKey::Asn(asn) => asn.to_string(),
            ExitKey::ScopedAsn(country, asn) => format!("{country}:{asn}"),
            ExitKey::Country(country) => country.clone(),
        }
    }

    /// Parse a stored map key; `None` marks a foreign or corrupt entry.
    fn parse(stored: &str) -> Option<Self> {
        if let Some((country, asn)) = stored.split_once(':') {
            return Some(ExitKey::ScopedAsn(country.to_string(), asn.parse().ok()?));
        }
        if let Ok(asn) = stored.parse() {
            return Some(ExitKey::Asn(asn));
        }
        match stored.as_bytes() {
            [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
                Some(ExitKey::Country(stored.to_ascii_uppercase()))
            }
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    country: HashMap<String, String>,
    asn: HashMap<String, String>,
}

/// A version 1 document carries one `owners` map of numeric group keys.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Legacy {
    version: u32,
    #[serde(default)]
    owners: HashMap<String, String>,
}

pub struct ExitState {
    country: HashMap<String, String>,
    asn: HashMap<String, String>,
    path: Option<PathBuf>,
    dirty: bool,
    last_flush: Instant,
}

impl ExitState {
    /// Missing, unreadable, corrupt or foreign-version state starts empty.
    pub fn load(path: Option<PathBuf>) -> Self {
        let (country, asn) = path
            .as_deref()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|text| parse(&text))
            .unwrap_or_default();
        Self {
            country,
            asn,
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
            ExitKey::Country(_) => &mut self.country,
            _ => &mut self.asn,
        };
        if map.get(&stored).is_none_or(|current| current != node) {
            map.insert(stored, node.to_string());
            self.dirty = true;
        }
    }

    /// Drop entries pinned to nodes that left the configuration.
    pub fn retain_nodes(&mut self, ids: &[String]) {
        let before = self.country.len() + self.asn.len();
        self.country.retain(|_, node| ids.contains(node));
        self.asn.retain(|_, node| ids.contains(node));
        self.dirty |= self.country.len() + self.asn.len() != before;
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
            ExitKey::Country(_) => &self.country,
            _ => &self.asn,
        }
    }

    fn write(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = File {
            version: VERSION,
            country: self.country.clone(),
            asn: self.asn.clone(),
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

    /// Restore link indices per typed key. The originating map is part of
    /// the type: a numeric Country entry or an alphabetic ASN entry is
    /// corrupt, not a key in the other domain. Stored keys that do not
    /// parse and nodes that left the configuration are skipped.
    pub fn owner_indices(&self, ids: &[String]) -> HashMap<ExitKey, usize> {
        let country = self.country.iter().filter_map(|(stored, node)| {
            let key = ExitKey::parse(stored)?;
            if !matches!(key, ExitKey::Country(_)) {
                return None;
            }
            ids.iter().position(|id| id == node).map(|link| (key, link))
        });
        let asn = self.asn.iter().filter_map(|(stored, node)| {
            let key = ExitKey::parse(stored)?;
            if matches!(key, ExitKey::Country(_)) {
                return None;
            }
            ids.iter().position(|id| id == node).map(|link| (key, link))
        });
        country.chain(asn).collect()
    }
}

/// Both maps of a document, or `None` when it is corrupt or foreign.
/// A v1 `owners` map migrates into the global ASN domain only: its keys
/// were numeric group ids, and a v1 file has no country owners.
fn parse(text: &str) -> Option<(HashMap<String, String>, HashMap<String, String>)> {
    if let Ok(file) = serde_json::from_str::<File>(text) {
        return (file.version == VERSION).then_some((file.country, file.asn));
    }
    let legacy = serde_json::from_str::<Legacy>(text).ok()?;
    (legacy.version == 1).then(|| {
        let asn = legacy
            .owners
            .into_iter()
            .filter(|(group, _)| group.parse::<u64>().is_ok())
            .collect();
        (HashMap::new(), asn)
    })
}
