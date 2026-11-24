//! SQLite schema, minute writes, tiered roll-ups and retention.
//!
//! Every function takes the current time instead of reading the clock, so
//! hours and days can be simulated in tests. Roll-ups follow watermarks: a
//! fine row leaves only after the coarser tier holds its total.

use std::{collections::BTreeMap, path::Path, time::Duration};

use anyhow::Result;
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, Transaction, params};

use super::sample::{Row, Series};

/// Version of the schema this build reads; anything else is rebuilt from scratch.
pub const SCHEMA_VERSION: i64 = 1;
pub(super) const MINUTE: u64 = 60;
pub(super) const HOUR: u64 = 60 * MINUTE;
pub(super) const DAY: u64 = 24 * HOUR;
/// Each tier keeps its rows this long.
pub const MINUTE_TTL: u64 = DAY;
pub const HOUR_TTL: u64 = 7 * DAY;
pub const DAY_TTL: u64 = 30 * DAY;
/// Above this the main file is trimmed: with a WAL of up to 4 MiB it is the
/// 20 MiB budget.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// What an oversized file keeps of each tier.
const TRIM_MINUTE_TTL: u64 = 2 * HOUR;
const TRIM_HOUR_TTL: u64 = 2 * DAY;
const TRIM_DAY_TTL: u64 = 7 * DAY;
/// Rows read from a damaged file per statement.
const SALVAGE_BATCH: usize = 256;
/// Unreadable regions skipped per table before the rest is given up.
const SALVAGE_SKIPS: usize = 64;

/// Data tables in the order a damaged file is read: name, key column, how far
/// to jump past an unreadable region, column count.
pub(super) const DATA_TABLES: [(&str, &str, i64, usize); 4] = [
    ("series", "id", SALVAGE_BATCH as i64, 5),
    ("minute", "ts", HOUR as i64, 11),
    ("hour", "ts", DAY as i64, 13),
    ("day", "ts", 30 * DAY as i64, 13),
];

const SCHEMA: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE series (
    id INTEGER PRIMARY KEY,
    kind INTEGER NOT NULL,
    link TEXT NOT NULL,
    rule TEXT NOT NULL,
    asn INTEGER NOT NULL
);
CREATE UNIQUE INDEX series_key ON series (kind, link, rule, asn);
CREATE TABLE minute (
    ts INTEGER NOT NULL,
    series INTEGER NOT NULL,
    rx_bytes INTEGER NOT NULL,
    tx_bytes INTEGER NOT NULL,
    rx_packets INTEGER NOT NULL,
    tx_packets INTEGER NOT NULL,
    opened INTEGER NOT NULL,
    closed INTEGER NOT NULL,
    failed INTEGER NOT NULL,
    drops INTEGER NOT NULL,
    active INTEGER NOT NULL,
    PRIMARY KEY (ts, series)
) WITHOUT ROWID;
CREATE TABLE hour (
    ts INTEGER NOT NULL,
    series INTEGER NOT NULL,
    rx_bytes INTEGER NOT NULL,
    tx_bytes INTEGER NOT NULL,
    rx_packets INTEGER NOT NULL,
    tx_packets INTEGER NOT NULL,
    opened INTEGER NOT NULL,
    closed INTEGER NOT NULL,
    failed INTEGER NOT NULL,
    drops INTEGER NOT NULL,
    active_avg REAL NOT NULL,
    active_max INTEGER NOT NULL,
    minutes INTEGER NOT NULL,
    PRIMARY KEY (ts, series)
) WITHOUT ROWID;
CREATE TABLE day (
    ts INTEGER NOT NULL,
    series INTEGER NOT NULL,
    rx_bytes INTEGER NOT NULL,
    tx_bytes INTEGER NOT NULL,
    rx_packets INTEGER NOT NULL,
    tx_packets INTEGER NOT NULL,
    opened INTEGER NOT NULL,
    closed INTEGER NOT NULL,
    failed INTEGER NOT NULL,
    drops INTEGER NOT NULL,
    active_avg REAL NOT NULL,
    active_max INTEGER NOT NULL,
    minutes INTEGER NOT NULL,
    PRIMARY KEY (ts, series)
) WITHOUT ROWID;
";

/// Why an existing database cannot be opened as it is. Only `Damaged` may
/// lead to a rebuild; an I/O error says nothing about the file's contents.
#[derive(Debug)]
pub enum OpenError {
    Damaged(String),
    /// Whole, but written by another build: its rows mean nothing here.
    Foreign(i64),
    Other(anyhow::Error),
}

/// The last completely closed hour and day already folded into the coarser
/// tiers; both live in `meta` and survive restarts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tiers {
    pub hour_rolled_to: u64,
    pub day_rolled_to: u64,
}

/// One database file. Owned by a single thread: the connection is never
/// shared, which keeps WAL recovery and roll-ups race-free.
pub struct Store {
    connection: Connection,
    /// Series known to this file, by their stable key.
    series: BTreeMap<Series, i64>,
    tiers: Tiers,
    /// Roll-ups and retention run once per hour of wall time.
    maintained_hour: Option<u64>,
    /// Bytes the main file is kept under.
    cap: u64,
}

impl Store {
    /// A new, empty database file.
    pub fn create(path: &Path) -> Result<Store> {
        let connection = open_file(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        // Trimming shrinks the file page by page, with no temporary copy of
        // it. The mode has to precede the first page, and WAL writes one.
        connection.pragma_update(None, "auto_vacuum", 2)?;
        let auto_vacuum: i64 = connection.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
        anyhow::ensure!(
            auto_vacuum == 2,
            "history database refuses incremental vacuum"
        );
        in_wal(&connection)?;
        connection.execute_batch(SCHEMA)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Store::wrap(connection, BTreeMap::new(), Tiers::default()))
    }

    /// An existing database, checked before use.
    pub fn open_existing(path: &Path) -> std::result::Result<Store, OpenError> {
        let connection = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|error| classify(error, path))?;
        let check: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|error| classify(error, path))?;
        if check != "ok" {
            return Err(OpenError::Damaged(format!("integrity_check: {check}")));
        }
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|error| classify(error, path))?;
        if version != SCHEMA_VERSION {
            return Err(OpenError::Foreign(version));
        }
        let series = registry(&connection).map_err(|error| classify(error, path))?;
        let tiers = Tiers {
            hour_rolled_to: watermark(&connection, "hour_rolled_to")
                .map_err(|error| classify(error, path))?,
            day_rolled_to: watermark(&connection, "day_rolled_to")
                .map_err(|error| classify(error, path))?,
        };
        Ok(Store::wrap(connection, series, tiers))
    }

    fn wrap(connection: Connection, series: BTreeMap<Series, i64>, tiers: Tiers) -> Store {
        Store {
            connection,
            series,
            tiers,
            maintained_hour: None,
            cap: MAX_FILE_BYTES,
        }
    }

    /// Write whole minutes, then fold and age the tiers once per hour.
    /// `oldest` is the first minute of the batch: minutes kept waiting through
    /// write errors may belong to hours the watermarks already passed, and
    /// those hours are folded again.
    pub fn append<'a>(
        &mut self,
        minutes: impl IntoIterator<Item = &'a (u64, Vec<Row>)>,
        oldest: Option<u64>,
        now: u64,
    ) -> Result<Option<&'static str>> {
        // Watermarks and series ids move only once the transaction is on
        // disk: a failed one takes back everything it wrote.
        let mut tiers = self.tiers;
        if let Some(oldest) = oldest {
            tiers.hour_rolled_to = tiers.hour_rolled_to.min(floor(oldest, HOUR));
            tiers.day_rolled_to = tiers.day_rolled_to.min(floor(oldest, DAY));
        }
        let maintained = self.maintained_hour != Some(floor(now, HOUR));
        let written = self.write(minutes, maintained, &mut tiers, now);
        if written.is_err() {
            self.series.clear();
        }
        let trimmed = written?;
        self.tiers = tiers;
        if maintained {
            self.maintained_hour = Some(floor(now, HOUR));
            self.after_maintenance(trimmed)?;
        }
        Ok(trimmed)
    }

    /// The transaction of one flush. `tiers` receives the watermarks it wrote;
    /// a day's gauge is the mean over the minutes its hours hold.
    fn write<'a>(
        &mut self,
        minutes: impl IntoIterator<Item = &'a (u64, Vec<Row>)>,
        maintained: bool,
        tiers: &mut Tiers,
        now: u64,
    ) -> Result<Option<&'static str>> {
        let transaction = self.connection.transaction()?;
        {
            let mut statement = transaction.prepare(
                "INSERT OR REPLACE INTO minute (ts, series, rx_bytes, tx_bytes, rx_packets, tx_packets, \
                 opened, closed, failed, drops, active) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?;
            for (ts, rows) in minutes {
                for row in rows {
                    let id = series_id(&mut self.series, &transaction, &row.series)?;
                    statement.execute(params![
                        sq(*ts),
                        id,
                        sq(row.rx_bytes),
                        sq(row.tx_bytes),
                        sq(row.rx_packets),
                        sq(row.tx_packets),
                        sq(row.opened),
                        sq(row.closed),
                        sq(row.failed),
                        sq(row.drops),
                        sq(row.active),
                    ])?;
                }
            }
        }
        let trimmed = match maintained {
            true => roll_and_age(&transaction, tiers, now, self.cap)?,
            false => None,
        };
        transaction.commit()?;
        Ok(trimmed)
    }

    /// Fold and age the tiers now, whatever the clock.
    pub fn maintain(&mut self, now: u64) -> Result<Option<&'static str>> {
        let mut tiers = self.tiers;
        let transaction = self.connection.transaction()?;
        let trimmed = roll_and_age(&transaction, &mut tiers, now, self.cap)?;
        transaction.commit()?;
        self.tiers = tiers;
        self.maintained_hour = Some(floor(now, HOUR));
        self.after_maintenance(trimmed)?;
        Ok(trimmed)
    }

    /// The size the file is kept under. Tests lower it: the default takes
    /// hundreds of thousands of rows to reach.
    pub fn set_size_cap(&mut self, cap: u64) {
        self.cap = cap;
    }

    /// Series that lost their last row are gone from the file: forget their
    /// ids before one of them is given to a new series. An oversized file
    /// gives its free pages back.
    fn after_maintenance(&mut self, trimmed: Option<&'static str>) -> Result<()> {
        self.series = registry(&self.connection)?;
        if trimmed.is_some() && self.file_bytes() > self.cap {
            // The pragma yields a row per page it gives back: all of them
            // have to be read, or it stops after the first.
            let mut statement = self.connection.prepare("PRAGMA incremental_vacuum")?;
            let mut pages = statement.query([])?;
            while pages.next()?.is_some() {}
            // The file on disk shrinks only once the WAL is folded back into it.
            self.connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        }
        Ok(())
    }

    /// Rows of each tier, for the opening log line.
    pub fn rows(&self) -> Result<[usize; 3]> {
        let mut counts = [0; 3];
        for (count, table) in counts.iter_mut().zip(["minute", "hour", "day"]) {
            let sql = format!("SELECT COUNT(*) FROM {table}");
            let rows: i64 = self.connection.query_row(&sql, [], |row| row.get(0))?;
            *count = usize::try_from(rows).unwrap_or(usize::MAX);
        }
        Ok(counts)
    }

    /// The watermarks as they are in the file.
    pub fn tiers(&self) -> Tiers {
        self.tiers
    }

    /// Bytes of the main database file on disk, the WAL aside.
    pub fn file_bytes(&self) -> u64 {
        file_bytes(&self.connection).unwrap_or(0)
    }

    /// Copy one table of a damaged file into this fresh one, row by row, and
    /// carry on past an unreadable region. Returns the rows copied.
    pub fn salvage_from(
        &mut self,
        source: &Connection,
        table: &str,
        key: &str,
        jump: i64,
        columns: usize,
    ) -> Result<usize> {
        let placeholders = std::iter::repeat_n("?", columns)
            .collect::<Vec<_>>()
            .join(", ");
        let insert = format!("INSERT OR REPLACE INTO {table} VALUES ({placeholders})");
        let select = format!(
            "SELECT * FROM {table} WHERE {key} > COALESCE(?1, -9223372036854775808) ORDER BY {key} LIMIT {SALVAGE_BATCH}"
        );
        let mut resume: Option<i64> = None;
        let mut skips = 0;
        let mut copied = 0;
        loop {
            let (batch, failed) = read_batch(source, &select, resume);
            if !batch.is_empty() {
                let transaction = self.connection.transaction()?;
                for row in &batch {
                    transaction
                        .prepare(&insert)?
                        .execute(rusqlite::params_from_iter(row))?;
                }
                transaction.commit()?;
                copied += batch.len();
                match batch.last().and_then(|row| row.first()) {
                    Some(rusqlite::types::Value::Integer(key)) => resume = Some(*key),
                    _ => return Ok(copied),
                }
            }
            if !failed {
                // Read to the end of the table.
                return Ok(copied);
            }
            // The reader hit damage. What it read before is kept, the rows of
            // the damaged region are lost, and the next read starts past it.
            let Some(last) = resume.filter(|_| skips < SALVAGE_SKIPS) else {
                return Ok(copied);
            };
            skips += 1;
            resume = Some(last.saturating_add(jump));
        }
    }

    /// Checkpoint the WAL and close. A failed checkpoint still closes: the
    /// WAL stays with the file and the next open replays it.
    pub fn close(self) -> Result<()> {
        let _ = self
            .connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
        self.connection
            .close()
            .map_err(|(_, error)| anyhow::Error::from(error))
    }

    pub(super) fn connection(&self) -> &Connection {
        &self.connection
    }
}

/// The modes of every connection this build opens.
fn connect(path: &Path, flags: OpenFlags) -> rusqlite::Result<Connection> {
    let connection = open_file(path, flags)?;
    in_wal(&connection)?;
    Ok(connection)
}

fn open_file(path: &Path, flags: OpenFlags) -> rusqlite::Result<Connection> {
    let connection = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    Ok(connection)
}

fn in_wal(connection: &Connection) -> rusqlite::Result<()> {
    let mode: String =
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    // WAL with NORMAL stays consistent through a power loss; the last minutes may roll back.
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    if !mode.eq_ignore_ascii_case("wal") {
        // rusqlite has no error kind for a refused pragma.
        return Err(rusqlite::Error::InvalidParameterName(mode));
    }
    Ok(())
}

/// Only a corrupt or foreign file may be rebuilt; anything else is reported
/// and left alone.
fn classify(error: rusqlite::Error, path: &Path) -> OpenError {
    let damaged = matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(failure.code, ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase)
    );
    if damaged {
        OpenError::Damaged(error.to_string())
    } else {
        OpenError::Other(
            anyhow::Error::new(error).context(format!("history database {}", path.display())),
        )
    }
}

/// Every series of the file with its id.
fn registry(connection: &Connection) -> rusqlite::Result<BTreeMap<Series, i64>> {
    let mut statement = connection.prepare("SELECT id, kind, link, rule, asn FROM series")?;
    let mut rows = statement.query([])?;
    let mut series = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let key = Series::from_columns(
            row.get(1)?,
            &row.get::<_, String>(2)?,
            &row.get::<_, String>(3)?,
            u32::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
        )
        .ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Integer,
                "unknown series kind".into(),
            )
        })?;
        series.insert(key, row.get(0)?);
    }
    Ok(series)
}

fn watermark(connection: &Connection, key: &str) -> rusqlite::Result<u64> {
    connection
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
            row.get::<_, i64>(0)
        })
        .optional()
        .map(|value| value.map_or(0, |value| u64::try_from(value).unwrap_or(0)))
}

fn set_watermark(transaction: &Transaction<'_>, key: &str, value: u64) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
        params![key, sq(value)],
    )?;
    Ok(())
}

/// The series id in `cache`, inserting the key into `series` on first sight.
fn series_id(
    cache: &mut BTreeMap<Series, i64>,
    transaction: &Transaction<'_>,
    key: &Series,
) -> Result<i64> {
    if let Some(id) = cache.get(key) {
        return Ok(*id);
    }
    let columns = params![key.kind(), key.link(), key.rule(), key.asn()];
    transaction.execute(
        "INSERT OR IGNORE INTO series (kind, link, rule, asn) VALUES (?1, ?2, ?3, ?4)",
        columns,
    )?;
    let id = transaction.query_row(
        "SELECT id FROM series WHERE kind = ?1 AND link = ?2 AND rule = ?3 AND asn = ?4",
        columns,
        |row| row.get(0),
    )?;
    cache.insert(key.clone(), id);
    Ok(id)
}

/// Fold every closed hour and day the watermarks have not seen yet, then age
/// the tiers. Fine rows are deleted only for hours and days the watermarks
/// cover, so nothing leaves a tier before the next one holds its total.
/// Returns what an oversized file lost.
fn roll_and_age(
    transaction: &Transaction<'_>,
    tiers: &mut Tiers,
    now: u64,
    cap: u64,
) -> Result<Option<&'static str>> {
    let hour = floor(now, HOUR).saturating_sub(HOUR);
    // Minute rows older than a day are gone: nothing to fold before that.
    let first = tiers.hour_rolled_to.max(hour.saturating_sub(MINUTE_TTL));
    for start in (first..=hour).step_by(HOUR as usize) {
        transaction.prepare(
            "INSERT OR REPLACE INTO hour SELECT ?1, series, SUM(rx_bytes), SUM(tx_bytes), SUM(rx_packets), \
             SUM(tx_packets), SUM(opened), SUM(closed), SUM(failed), SUM(drops), AVG(active), MAX(active), \
             COUNT(*) FROM minute WHERE ts >= ?1 AND ts < ?2 GROUP BY series",
        )?
        .execute(params![sq(start), sq(start + HOUR)])?;
    }
    set_watermark(transaction, "hour_rolled_to", hour)?;

    let day = floor(now, DAY).saturating_sub(DAY);
    let first = tiers.day_rolled_to.max(day.saturating_sub(HOUR_TTL));
    for start in (first..=day).step_by(DAY as usize) {
        transaction.prepare(
            "INSERT OR REPLACE INTO day SELECT ?1, series, SUM(rx_bytes), SUM(tx_bytes), SUM(rx_packets), \
             SUM(tx_packets), SUM(opened), SUM(closed), SUM(failed), SUM(drops), \
             SUM(active_avg * minutes) / MAX(SUM(minutes), 1), MAX(active_max), SUM(minutes) \
             FROM hour WHERE ts >= ?1 AND ts < ?2 GROUP BY series",
        )?
        .execute(params![sq(start), sq(start + DAY)])?;
    }
    let day_changed = tiers.day_rolled_to != day;
    set_watermark(transaction, "day_rolled_to", day)?;
    tiers.hour_rolled_to = hour;
    tiers.day_rolled_to = day;

    transaction.execute(
        "DELETE FROM minute WHERE ts < ?1 OR ts >= ?2",
        params![sq(now.saturating_sub(MINUTE_TTL)), sq(now)],
    )?;
    transaction.execute(
        "DELETE FROM hour WHERE ts < ?1",
        params![sq(now.saturating_sub(HOUR_TTL))],
    )?;
    transaction.execute(
        "DELETE FROM day WHERE ts < ?1",
        params![sq(now.saturating_sub(DAY_TTL))],
    )?;

    let trimmed = match file_bytes(transaction)? > cap {
        true => Some(trim(transaction, now, cap)?),
        false => None,
    };
    // Once a day, and after a trim: series that lost their last row, e.g. a
    // removed server. Their ids are free for the next series to take.
    if day_changed || trimmed.is_some() {
        transaction.execute(
            "DELETE FROM series WHERE id NOT IN (SELECT series FROM minute) \
             AND id NOT IN (SELECT series FROM hour) AND id NOT IN (SELECT series FROM day)",
            [],
        )?;
    }
    Ok(trimmed)
}

/// Bring an oversized file back under the cap, the finest tier first.
fn trim(transaction: &Transaction<'_>, now: u64, cap: u64) -> Result<&'static str> {
    transaction.execute(
        "DELETE FROM minute WHERE ts < ?1",
        params![sq(now.saturating_sub(TRIM_MINUTE_TTL))],
    )?;
    if used_bytes(transaction)? <= cap {
        return Ok("dropped minute rows older than two hours");
    }
    transaction.execute(
        "DELETE FROM hour WHERE ts < ?1",
        params![sq(now.saturating_sub(TRIM_HOUR_TTL))],
    )?;
    if used_bytes(transaction)? <= cap {
        return Ok("dropped minute rows older than two hours and hour rows older than two days");
    }
    transaction.execute(
        "DELETE FROM day WHERE ts < ?1",
        params![sq(now.saturating_sub(TRIM_DAY_TTL))],
    )?;
    Ok(
        "dropped minute rows older than two hours, hour rows older than two days and day rows older than seven days",
    )
}

/// Bytes of the main database file on disk.
fn file_bytes(connection: &Connection) -> rusqlite::Result<u64> {
    let pages = pragma(connection, "page_count")?;
    let size = pragma(connection, "page_size")?;
    Ok(pages.saturating_mul(size))
}

/// Bytes of the main database file that hold data; the rest is free to reuse.
fn used_bytes(connection: &Connection) -> rusqlite::Result<u64> {
    let pages = pragma(connection, "page_count")?;
    let free = pragma(connection, "freelist_count")?;
    let size = pragma(connection, "page_size")?;
    Ok(pages.saturating_sub(free).saturating_mul(size))
}

fn pragma(connection: &Connection, name: &str) -> rusqlite::Result<u64> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get::<_, i64>(0))
        .map(|value| u64::try_from(value).unwrap_or(0))
}

/// Rows of `select` after `after`, each with all its columns, and whether
/// the reader failed before the end: the rows it did read are still good.
fn read_batch(
    source: &Connection,
    sql: &str,
    after: Option<i64>,
) -> (Vec<Vec<rusqlite::types::Value>>, bool) {
    let mut batch = Vec::new();
    let failed = (|| -> rusqlite::Result<()> {
        let mut statement = source.prepare(sql)?;
        let mut rows = statement.query([after])?;
        while let Some(row) = rows.next()? {
            let mut values = Vec::with_capacity(row.as_ref().column_count());
            for index in 0..values.capacity() {
                values.push(row.get(index)?);
            }
            batch.push(values);
        }
        Ok(())
    })()
    .is_err();
    (batch, failed)
}

/// A counter as SQLite keeps it. One that no longer fits is pinned to the
/// largest value instead of failing the whole minute.
fn sq(value: impl TryInto<i64>) -> i64 {
    value.try_into().unwrap_or(i64::MAX)
}

fn floor(ts: u64, unit: u64) -> u64 {
    ts - ts % unit
}
