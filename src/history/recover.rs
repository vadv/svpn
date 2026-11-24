//! Opening the database at start: check it, keep what a damaged file still
//! reads, else start from an empty file.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags};

use super::store::{DATA_TABLES, OpenError, Store};

/// A database ready for its first write, and what its file went through.
pub struct Opened {
    pub store: Store,
    pub outcome: Outcome,
}

#[derive(Debug)]
pub enum Outcome {
    Created,
    Opened {
        /// Rows of the minute, hour and day tiers.
        rows: [usize; 3],
    },
    /// A damaged file; this many of its rows still read and were kept.
    Recovered {
        rows: usize,
        reason: String,
    },
    /// A damaged or foreign file that had nothing left to keep.
    Discarded {
        reason: String,
    },
}

/// Open the database for its owner thread. A damaged file never fails the
/// start: it is rebuilt, or replaced by an empty one. Any other error, such
/// as an unwritable directory or a full disk, is returned to be retried.
pub fn open(path: &Path) -> Result<Opened> {
    if !path.exists() {
        // The path is the user's choice; its directory may not exist yet.
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        discard_files(path)?;
        return Ok(Opened {
            store: Store::create(path)?,
            outcome: Outcome::Created,
        });
    }
    let reason = match Store::open_existing(path) {
        Ok(store) => {
            let rows = store.rows()?;
            return Ok(Opened {
                store,
                outcome: Outcome::Opened { rows },
            });
        }
        Err(OpenError::Other(error)) => return Err(error),
        Err(OpenError::Foreign(version)) => {
            let reason = format!(
                "schema version {version}, this build reads {}",
                super::store::SCHEMA_VERSION
            );
            let store = replace_with_empty(path)?;
            return Ok(Opened {
                store,
                outcome: Outcome::Discarded { reason },
            });
        }
        Err(OpenError::Damaged(reason)) => reason,
    };
    rebuild(path, reason)
}

/// No connection may be open on the file while it is read, replaced or
/// deleted: each step closes what it opened before the next one begins.
fn rebuild(path: &Path, reason: String) -> Result<Opened> {
    let temporary = side_file(path, ".rebuild");
    let salvaged = salvage(path, &temporary).and_then(|copied| {
        if copied == 0 {
            bail!("nothing left to read");
        }
        // The copy is held to the same check as any other file.
        let store = Store::open_existing(&temporary).map_err(describe)?;
        store.close()?;
        fs::rename(&temporary, path)?;
        // The WAL of the damaged file would be replayed into the new one.
        remove_if_present(&side_file(path, "-wal"))?;
        remove_if_present(&side_file(path, "-shm"))?;
        let store = Store::open_existing(path).map_err(describe)?;
        Ok((store, copied))
    });
    match salvaged {
        Ok((store, rows)) => Ok(Opened {
            store,
            outcome: Outcome::Recovered { rows, reason },
        }),
        Err(error) => {
            let store = replace_with_empty(path)?;
            Ok(Opened {
                store,
                outcome: Outcome::Discarded {
                    reason: format!("{reason}; {error:#}"),
                },
            })
        }
    }
}

/// Read every data table of a damaged file into a new one, skipping what no
/// longer reads. Returns the rows that were copied.
fn salvage(damaged: &Path, temporary: &Path) -> Result<usize> {
    discard_files(temporary)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let source = Connection::open_with_flags(damaged, flags)
        .with_context(|| format!("opening the damaged history database {}", damaged.display()))?;
    let mut fresh = Store::create(temporary)?;
    let mut copied = 0;
    for (table, key, jump, columns) in DATA_TABLES {
        copied += fresh.salvage_from(&source, table, key, jump, columns)?;
    }
    fresh.close()?;
    Ok(copied)
}

fn replace_with_empty(path: &Path) -> Result<Store> {
    discard_files(&side_file(path, ".rebuild"))?;
    discard_files(path)?;
    Store::create(path)
}

/// The database and its journal; a file that is already gone is fine.
fn discard_files(path: &Path) -> Result<()> {
    for file in [
        path.to_path_buf(),
        side_file(path, "-wal"),
        side_file(path, "-shm"),
        side_file(path, ".rebuild"),
    ] {
        remove_if_present(&file)?;
    }
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(error).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}

fn side_file(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn describe(error: OpenError) -> anyhow::Error {
    match error {
        OpenError::Other(error) => error,
        OpenError::Damaged(reason) => anyhow::anyhow!("the copy failed the check: {reason}"),
        OpenError::Foreign(version) => anyhow::anyhow!("the copy has schema version {version}"),
    }
}
