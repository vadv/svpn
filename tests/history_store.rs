//! History database: minute rows, roll-ups by watermark, retention and the
//! size cap. Time is passed in, so hours and days are simulated.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, types::Value as Sql};
use svpn::history::{
    Row, Series,
    recover::{self, Outcome},
    store::{DAY_TTL, HOUR_TTL, MINUTE_TTL, SCHEMA_VERSION, Store, Tiers},
};

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
/// Midnight UTC: every tier boundary falls on it.
const START: u64 = 1_792_886_400;
const LINK: &str = "a.example:22";

// ── schema ──

#[test]
fn a_new_file_is_empty_versioned_and_in_wal_mode() {
    let path = database("new");

    let opened = recover::open(&path).unwrap();

    assert!(matches!(opened.outcome, Outcome::Created));
    assert_eq!(opened.store.rows().unwrap(), [0, 0, 0]);
    opened.store.close().unwrap();
    assert_eq!(scalar(&path, "PRAGMA user_version"), SCHEMA_VERSION);
    assert_eq!(text(&path, "PRAGMA journal_mode"), "wal");
    assert_eq!(scalar(&path, "PRAGMA auto_vacuum"), 2);
    assert_eq!(
        read(
            &path,
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ),
        table(["day", "hour", "meta", "minute", "names", "series"])
    );

    let opened = recover::open(&path).unwrap();
    assert!(matches!(
        opened.outcome,
        Outcome::Opened { rows: [0, 0, 0] }
    ));
}

// ── minute rows ──

#[test]
fn minutes_land_in_their_series_and_share_one_id() {
    let path = database("minutes");
    let mut store = open(&path);

    store
        .append(
            &[(START, rows(START)), (START + MINUTE, rows(START + MINUTE))],
            Some(START),
            START + 2 * MINUTE,
        )
        .unwrap();
    store.close().unwrap();

    assert_eq!(scalar(&path, "SELECT COUNT(*) FROM series"), 2);
    assert_eq!(
        read(
            &path,
            "SELECT m.ts, s.link, m.rx_bytes, m.tx_bytes, m.active FROM minute m \
             JOIN series s ON s.id = m.series ORDER BY m.ts, s.link"
        ),
        vec![
            row(START, "", 5, 0, 1),
            row(START, LINK, 1, 2, 0),
            row(START + MINUTE, "", 5, 0, 1),
            row(START + MINUTE, LINK, 1, 2, 1),
        ]
    );
}

#[test]
fn a_resent_minute_replaces_its_row() {
    let (_, mut store) = open_of("resent");

    store
        .append(
            &[(START, vec![traffic(LINK, 7, 7)])],
            Some(START),
            START + MINUTE,
        )
        .unwrap();
    store
        .append(
            &[(START, vec![traffic(LINK, 9, 1)])],
            Some(START),
            START + 2 * MINUTE,
        )
        .unwrap();

    assert_eq!(store.rows().unwrap(), [1, 0, 0]);
    assert_eq!(store.append(&[], None, START + 3 * MINUTE).unwrap(), None);
    assert_eq!(store.rows().unwrap(), [1, 0, 0]);
}

// ── roll-ups ──

#[test]
fn a_closed_hour_holds_its_minutes_and_the_gauge() {
    let path = database("hour");
    let mut store = open(&path);

    write_hours(&mut store, START, 1);
    // The next hour is still running: its minutes stay what they are.
    store
        .append(
            &minutes(START + HOUR, 30),
            Some(START + HOUR),
            START + HOUR + 31 * MINUTE,
        )
        .unwrap();

    assert_eq!(store.rows().unwrap(), [180, 2, 0]);
    assert_eq!(
        store.tiers(),
        Tiers {
            hour_rolled_to: START,
            day_rolled_to: START - DAY
        }
    );
    assert_eq!(
        read(
            &path,
            "SELECT ts, series, rx_bytes, tx_bytes, minutes, active_avg, active_max \
             FROM hour ORDER BY series"
        ),
        vec![
            vec![
                Sql::from(at(START)),
                Sql::from(series_id(&path, &key::link(LINK))),
                Sql::from(60),
                Sql::from(120),
                Sql::from(60),
                Sql::from(1.5),
                Sql::from(3),
            ],
            vec![
                Sql::from(at(START)),
                Sql::from(series_id(&path, &Series::Local)),
                Sql::from(300),
                Sql::from(0),
                Sql::from(60),
                Sql::from(1.0),
                Sql::from(1),
            ],
        ]
    );
}

#[test]
fn a_closed_day_holds_its_hours() {
    let (path, mut store) = open_of("day");

    // The day is folded once the next one is a little under way.
    write_hours(&mut store, START, 25);

    // At START + 25 hours the first hour of minutes is a day old.
    assert_eq!(store.rows().unwrap(), [2880, 50, 2]);
    assert_eq!(store.tiers().day_rolled_to, START);
    assert_eq!(
        read(
            &path,
            "SELECT ts, series, rx_bytes, tx_bytes, active_avg, active_max, minutes \
             FROM day ORDER BY series"
        ),
        vec![
            vec![
                Sql::from(at(START)),
                Sql::from(series_id(&path, &key::link(LINK))),
                Sql::from(1440),
                Sql::from(2880),
                Sql::from(1.5),
                Sql::from(3),
                Sql::from(1440),
            ],
            vec![
                Sql::from(at(START)),
                Sql::from(series_id(&path, &Series::Local)),
                Sql::from(7200),
                Sql::from(0),
                Sql::from(1.0),
                Sql::from(1),
                Sql::from(1440),
            ],
        ]
    );
}

#[test]
fn rolling_again_changes_nothing() {
    let (path, mut store) = open_of("again");

    write_hours(&mut store, START, 2);
    for _ in 0..3 {
        store.maintain(START + 2 * HOUR).unwrap();
    }

    assert_eq!(store.rows().unwrap(), [240, 4, 0]);
    assert_eq!(total(&path, "hour", ""), 2 * 60 * (3 + 5));
}

#[test]
fn minutes_that_arrive_late_fold_at_the_next_hour() {
    let (path, mut store) = open_of("late");

    // The watermark passed two hours, then minutes of an earlier one arrive.
    store
        .append(
            &minutes(START + 2 * HOUR, 60),
            Some(START + 2 * HOUR),
            START + 3 * HOUR,
        )
        .unwrap();
    store
        .append(
            &minutes(START, 60),
            Some(START),
            START + 3 * HOUR + 5 * MINUTE,
        )
        .unwrap();
    assert_eq!(store.rows().unwrap(), [240, 2, 0]);

    store.maintain(START + 4 * HOUR).unwrap();

    assert_eq!(store.rows().unwrap(), [240, 4, 0]);
    assert_eq!(
        read(
            &path,
            "SELECT ts, minutes FROM hour WHERE series = 1 ORDER BY ts"
        ),
        vec![
            vec![Sql::from(at(START)), Sql::from(60)],
            vec![Sql::from(at(START + 2 * HOUR)), Sql::from(60)],
        ]
    );
}

#[test]
fn an_hour_without_rows_leaves_no_aggregate() {
    let (path, mut store) = open_of("gap");

    write_hours(&mut store, START, 1);
    write_hours(&mut store, START + 3 * HOUR, 1);

    assert_eq!(store.rows().unwrap(), [240, 4, 0]);
    assert_eq!(scalar(&path, "SELECT MIN(ts) FROM hour"), at(START));
    assert_eq!(
        scalar(&path, "SELECT MAX(ts) FROM hour"),
        at(START + 3 * HOUR)
    );
}

// ── retention ──

#[test]
fn each_tier_ages_behind_its_watermark() {
    let (path, mut store) = open_of("month");
    let now = START + 32 * DAY;

    write_hours(&mut store, START, 32 * 24);

    let [minute, hour, day] = store.rows().unwrap();
    assert_eq!((minute, hour, day), (2 * 1440, 2 * 168, 2 * 30));
    assert_eq!(scalar(&path, "SELECT MIN(ts) FROM minute"), at(now - DAY));
    assert_eq!(scalar(&path, "SELECT MIN(ts) FROM hour"), at(now - 7 * DAY));
    assert_eq!(scalar(&path, "SELECT MIN(ts) FROM day"), at(now - DAY_TTL));
    // What left a tier lives on in the next one: 32 days were written, the
    // first two are older than the day tier keeps.
    let kept = total(&path, "minute", "")
        + total(&path, "hour", &format!("WHERE ts < {}", at(now - DAY)))
        + total(&path, "day", &format!("WHERE ts < {}", at(now - 7 * DAY)));
    assert_eq!(kept, 30 * 1440 * (3 + 5));
    assert_eq!((MINUTE_TTL, HOUR_TTL, DAY_TTL), (DAY, 7 * DAY, 30 * DAY));
}

#[test]
fn rows_from_the_future_are_dropped() {
    let (_, mut store) = open_of("future");

    store
        .append(&minutes(START, 60), Some(START), START + HOUR)
        .unwrap();
    // The clock went back: what was written "later" than now is not history.
    store.maintain(START - HOUR).unwrap();

    assert_eq!(store.rows().unwrap(), [0, 2, 0]);
}

#[test]
fn watermarks_survive_a_restart() {
    let path = database("restart");

    let mut store = open(&path);
    write_hours(&mut store, START, 2);
    store.close().unwrap();

    let mut store = open(&path);
    assert_eq!(
        store.tiers(),
        Tiers {
            hour_rolled_to: START + HOUR,
            day_rolled_to: START - DAY
        }
    );
    write_hours(&mut store, START + 2 * HOUR, 1);
    store.close().unwrap();

    assert_eq!(scalar(&path, "SELECT COUNT(*) FROM hour"), 6);
}

#[test]
fn a_series_that_lost_its_rows_is_not_confused_with_a_new_one() {
    let path = database("orphans");
    let week = 8 * DAY;

    let mut store = open(&path);
    store
        .append(
            &[(START, vec![traffic("kept", 1, 1), traffic("old", 2, 2)])],
            Some(START),
            START + MINUTE,
        )
        .unwrap();
    // The client was off for a week: what was left of "old" aged out before
    // it was folded, so no tier names it any more and its id is free.
    store
        .append(
            &[(START + week, vec![traffic("kept", 1, 1)])],
            Some(START + week),
            START + week + MINUTE,
        )
        .unwrap();
    assert_eq!(scalar(&path, "SELECT COUNT(*) FROM series"), 1);
    // A new series takes the free id, then "old" returns.
    for (minute, series, bytes) in [(1, "new", 3), (2, "old", 4)] {
        let ts = START + week + minute * MINUTE;
        store
            .append(
                &[(ts, vec![traffic(series, bytes, bytes)])],
                Some(ts),
                ts + MINUTE,
            )
            .unwrap();
    }
    store.close().unwrap();

    let expected = |link: &str, ts, bytes| {
        vec![
            Sql::from(link.to_owned()),
            Sql::from(at(ts)),
            Sql::from(bytes),
        ]
    };
    assert_eq!(
        read(
            &path,
            "SELECT s.link, m.ts, m.rx_bytes FROM minute m JOIN series s ON s.id = m.series \
             ORDER BY m.ts, s.link"
        ),
        vec![
            expected("kept", START + week, 1),
            expected("new", START + week + MINUTE, 3),
            expected("old", START + week + 2 * MINUTE, 4),
        ]
    );
}

// ── size cap ──

#[test]
fn an_oversized_file_is_trimmed_and_gives_its_pages_back() {
    let path = database("cap");
    let mut store = open(&path);
    let cap = 192 * 1024;
    store.set_size_cap(cap);

    // Three hours of forty networks each: more than the file may hold.
    let mut trimmed = None;
    for hour in 0..4 {
        let start = START + hour * HOUR;
        let batch: Vec<(u64, Vec<Row>)> = (0..60)
            .map(|minute| {
                let ts = start + minute * MINUTE;
                let mut batch = vec![traffic(LINK, 1, 1)];
                batch.extend((0..40u32).map(|asn| network(LINK, asn, 1000, 2000)));
                (ts, batch)
            })
            .collect();
        let outcome = store.append(&batch, Some(start), start + HOUR).unwrap();
        if outcome.is_some() {
            trimmed = outcome;
        }
    }

    assert_eq!(trimmed, Some("dropped minute rows older than two hours"));
    assert!(store.file_bytes() <= cap, "{} bytes", store.file_bytes());
    // The two oldest hours survive in their hour rows, the rest as minutes.
    assert_eq!(store.rows().unwrap(), [2 * 60 * 41, 4 * 41, 0]);
    let kept = total(
        &path,
        "hour",
        &format!("WHERE ts < {}", at(START + 2 * HOUR)),
    ) + total(&path, "minute", "");
    assert_eq!(kept, 4 * 60 * (2 + 40 * 3000));
}

// ── size model ──

/// Thirty days of the shape the size model assumes: 3 links, the local
/// exit, 12 rules and the 20 busiest networks a minute.
#[test]
fn thirty_days_stay_within_the_budget() {
    let path = database("model");
    let mut store = open(&path);
    let started = std::time::Instant::now();
    let mut wal = 0;

    for hour in 0..30 * 24u64 {
        let start = START + hour * HOUR;
        let batch: Vec<(u64, Vec<Row>)> = (0..60)
            .map(|minute| (start + minute * MINUTE, model(start + minute * MINUTE)))
            .collect();
        store.append(&batch, Some(start), start + HOUR).unwrap();
        wal = wal.max(std::fs::metadata(side_file(&path, "-wal")).map_or(0, |file| file.len()));
    }
    let bytes = store.file_bytes();
    let rows = store.rows().unwrap();
    store.close().unwrap();

    eprintln!(
        "30 days: {bytes} bytes, peak WAL {wal}, {rows:?} rows in {:.1} s",
        started.elapsed().as_secs_f64()
    );
    assert!(bytes + wal <= 20 * 1024 * 1024, "{bytes} + {wal} bytes");
}

// ── helpers ──

mod key {
    use super::*;

    pub fn link(link: &str) -> Series {
        Series::Link {
            link: link.to_owned(),
        }
    }
}

fn database(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("svpn history {tag} {}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("stats.sqlite")
}

fn open(path: &Path) -> Store {
    recover::open(path).unwrap().store
}

/// A fresh database of its own, already open.
fn open_of(tag: &str) -> (PathBuf, Store) {
    let path = database(tag);
    let store = open(&path);
    (path, store)
}

fn side_file(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn at(ts: u64) -> i64 {
    i64::try_from(ts).unwrap()
}

fn row(ts: u64, link: &str, rx: i64, tx: i64, active: i64) -> Vec<Sql> {
    vec![
        Sql::from(at(ts)),
        Sql::from(link.to_owned()),
        Sql::from(rx),
        Sql::from(tx),
        Sql::from(active),
    ]
}

fn table<const N: usize>(names: [&str; N]) -> Vec<Vec<Sql>> {
    names
        .iter()
        .map(|name| vec![Sql::from((*name).to_owned())])
        .collect()
}

fn traffic(link: &str, rx_bytes: u64, tx_bytes: u64) -> Row {
    Row {
        series: key::link(link),
        rx_bytes,
        tx_bytes,
        ..zero()
    }
}

fn network(link: &str, asn: u32, rx_bytes: u64, tx_bytes: u64) -> Row {
    Row {
        series: Series::Network {
            link: link.to_owned(),
            asn,
        },
        rx_bytes,
        tx_bytes,
        ..zero()
    }
}

fn zero() -> Row {
    Row {
        series: Series::Local,
        rx_bytes: 0,
        tx_bytes: 0,
        rx_packets: 0,
        tx_packets: 0,
        opened: 0,
        closed: 0,
        failed: 0,
        drops: 0,
        active: 0,
    }
}

/// One minute of the fixture: a link row whose gauge cycles 0..3, and the
/// local exit with five received bytes.
fn rows(ts: u64) -> Vec<Row> {
    vec![
        Row {
            active: ((ts / MINUTE) % 4) as usize,
            ..traffic(LINK, 1, 2)
        },
        Row {
            rx_bytes: 5,
            active: 1,
            ..zero()
        },
    ]
}

/// `count` minutes from `start`, as one batch.
fn minutes(start: u64, count: u64) -> Vec<(u64, Vec<Row>)> {
    (0..count)
        .map(|minute| (start + minute * MINUTE, rows(start + minute * MINUTE)))
        .collect()
}

/// Write whole hours the way the writer does: one flush per hour, right
/// after the hour has closed.
fn write_hours(store: &mut Store, start: u64, count: u64) {
    for hour in 0..count {
        let start = start + hour * HOUR;
        store
            .append(&minutes(start, 60), Some(start), start + HOUR)
            .unwrap();
    }
}

/// Thirty-six series of one minute, with counters of a realistic size.
fn model(ts: u64) -> Vec<Row> {
    let tick = (ts / MINUTE) % 997;
    let mut rows: Vec<Row> = (0..3)
        .map(|link| Row {
            rx_bytes: 1_000_000 + tick * 1000,
            tx_bytes: 200_000 + tick * 137,
            active: (tick % 40) as usize,
            ..traffic(&format!("s{link}.example:22"), 0, 0)
        })
        .collect();
    rows.push(Row {
        rx_bytes: 30_000 + tick * 11,
        tx_bytes: 40_000 + tick * 13,
        active: (tick % 6) as usize,
        ..zero()
    });
    for rule in 0..12u64 {
        rows.push(Row {
            series: Series::Rule {
                link: format!("s{}.example:22", rule % 3),
                rule: format!("cc:R{rule}"),
            },
            rx_bytes: 10_000 + tick * (7 + rule),
            tx_bytes: 5_000 + tick * 3,
            active: (tick % 5) as usize,
            ..zero()
        });
    }
    rows.extend((0..20u32).map(|asn| Row {
        series: Series::Network {
            link: format!("s{}.example:22", asn % 3),
            asn: 10_000 + asn,
        },
        rx_bytes: 100_000 + tick * (11 + u64::from(asn)),
        tx_bytes: 20_000 + tick * 5,
        active: (tick % 3) as usize,
        ..zero()
    }));
    rows
}

fn series_id(path: &Path, key: &Series) -> i64 {
    let connection = Connection::open(path).unwrap();
    connection
        .query_row(
            "SELECT id FROM series WHERE kind = ?1 AND link = ?2 AND rule = ?3 AND asn = ?4",
            rusqlite::params![key.kind(), key.link(), key.rule(), key.asn()],
            |row| row.get(0),
        )
        .unwrap()
}

/// The first column of the first row, as an integer.
fn scalar(path: &Path, sql: &str) -> i64 {
    let connection = Connection::open(path).unwrap();
    let value = connection
        .query_row(sql, [], |row| row.get::<_, Sql>(0))
        .unwrap();
    match value {
        Sql::Integer(value) => value,
        Sql::Real(value) => value as i64,
        _ => 0,
    }
}

fn text(path: &Path, sql: &str) -> String {
    let connection = Connection::open(path).unwrap();
    connection.query_row(sql, [], |row| row.get(0)).unwrap()
}

/// Received and sent bytes of a tier, optionally narrowed by `filter`.
fn total(path: &Path, table: &str, filter: &str) -> i64 {
    scalar(
        path,
        &format!("SELECT SUM(rx_bytes + tx_bytes) FROM {table} {filter}"),
    )
}

fn read(path: &Path, sql: &str) -> Vec<Vec<Sql>> {
    let connection = Connection::open(path).unwrap();
    let mut statement = connection.prepare(sql).unwrap();
    let columns = statement.column_count();
    let mut rows = statement.query([]).unwrap();
    let mut all = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        let mut values = Vec::with_capacity(columns);
        for index in 0..columns {
            values.push(row.get(index).unwrap());
        }
        all.push(values);
    }
    all
}
