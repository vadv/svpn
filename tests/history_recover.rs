//! History database at start: a whole file opens, a damaged one keeps what
//! still reads, anything else starts over. An I/O error is never mistaken
//! for damage.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use svpn::history::{
    Row, Series,
    recover::{self, Outcome},
    store::Store,
};

const MINUTE: u64 = 60;
const START: u64 = 1_792_886_400;

// ── whole files ──

#[test]
fn a_missing_file_is_created_and_stale_side_files_are_not_replayed() {
    let dir = temporary_dir("missing");
    let path = dir.join("stats.sqlite");
    // What a crash in the middle of a rebuild could leave behind.
    std::fs::write(side_file(&path, "-wal"), [0xff; 8192]).unwrap();
    std::fs::write(side_file(&path, "-shm"), [0x55; 4096]).unwrap();
    std::fs::write(side_file(&path, ".rebuild"), b"half written").unwrap();

    let opened = recover::open(&path).unwrap();

    assert!(matches!(opened.outcome, Outcome::Created));
    let mut store = opened.store;
    write(&mut store, START, 3);
    store.close().unwrap();

    let opened = recover::open(&path).unwrap();
    assert!(matches!(
        opened.outcome,
        Outcome::Opened { rows: [3, 0, 0] }
    ));
    assert!(!side_file(&path, ".rebuild").exists());
}

#[test]
fn a_file_of_garbage_is_replaced_by_an_empty_one() {
    let path = temporary_dir("garbage").join("stats.sqlite");
    std::fs::write(
        &path,
        (0..4096u32).map(|byte| byte as u8).collect::<Vec<u8>>(),
    )
    .unwrap();

    let opened = recover::open(&path).unwrap();

    let Outcome::Discarded { reason } = opened.outcome else {
        panic!("a file of garbage must be discarded");
    };
    assert!(!reason.is_empty(), "the reason is logged");
    let mut store = opened.store;
    write(&mut store, START, 1);
    assert_eq!(store.rows().unwrap(), [1, 0, 0]);
}

#[test]
fn a_database_of_another_version_is_replaced() {
    let path = filled("version", 5);
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 7)
        .unwrap();

    let opened = recover::open(&path).unwrap();

    let Outcome::Discarded { reason } = opened.outcome else {
        panic!("a foreign version must be discarded");
    };
    assert!(reason.contains("schema version 7"), "{reason}");
    assert_eq!(opened.store.rows().unwrap(), [0, 0, 0]);
}

// ── damaged files ──

#[test]
fn a_leftover_wal_is_replayed() {
    let dir = temporary_dir("wal");
    let path = dir.join("stats.sqlite");
    let mut store = recover::open(&path).unwrap().store;
    write(&mut store, START, 3);
    // A crash: no checkpoint, no close, the WAL stays with the file.
    let before = std::fs::metadata(side_file(&path, "-wal")).unwrap().len();
    std::mem::forget(store);
    assert!(before > 0, "the committed minutes sit in the WAL");

    let opened = recover::open(&path).unwrap();

    assert!(matches!(
        opened.outcome,
        Outcome::Opened { rows: [3, 0, 0] }
    ));
}

#[test]
fn a_truncated_file_starts_over_or_keeps_what_reads() {
    let path = filled("truncated", 400);
    let whole = std::fs::metadata(&path).unwrap().len();
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(whole * 2 / 5).unwrap();
    drop(file);

    let opened = recover::open(&path).unwrap();

    // Which one it is depends on where the cut falls; either way the store works.
    match opened.outcome {
        Outcome::Recovered { rows, .. } => assert!((1..400).contains(&rows), "{rows} rows"),
        Outcome::Discarded { reason } => assert!(!reason.is_empty()),
        other => panic!("a truncated file is not whole: {other:?}"),
    }
    let mut store = opened.store;
    write(&mut store, START + 400 * MINUTE, 2);
    store.close().unwrap();
    assert!(matches!(
        recover::open(&path).unwrap().outcome,
        Outcome::Opened { .. }
    ));
}

#[test]
fn a_corrupt_page_costs_only_its_own_rows() {
    let path = filled("corrupt", 600);
    // The header of the last page of the minute table: the page can no longer
    // be walked, the pages before it can.
    let bytes = std::fs::read(&path).unwrap();
    let page = (1..bytes.len() / 4096)
        .rev()
        .find(|page| bytes[page * 4096] == 10)
        .unwrap();
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    std::os::unix::fs::FileExt::write_all_at(&file, &[0xff; 64], (page * 4096) as u64).unwrap();
    drop(file);

    let opened = recover::open(&path).unwrap();

    let Outcome::Recovered { rows, reason } = opened.outcome else {
        panic!("a corrupt page must be salvaged, not {:#?}", opened.outcome);
    };
    assert!(reason.contains("integrity_check"), "{reason}");
    // SQLite numbers pages from one; the damage is where the test put it.
    assert!(reason.contains(&format!("page {}", page + 1)), "{reason}");
    assert!(rows > 0, "nothing was kept");
    // The rows of the damaged page are gone; the rest of the file came along.
    let [kept, hours, _] = opened.store.rows().unwrap();
    assert!(
        kept > 0 && kept < 600,
        "{kept} of the 600 minute rows are kept"
    );
    assert_eq!(hours, 10);
    let mut store = opened.store;
    write(&mut store, START + 600 * MINUTE, 1);
    store.close().unwrap();
    let check: String = Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(check, "ok");
}

#[test]
fn an_interrupted_rebuild_is_finished_the_next_time() {
    let dir = temporary_dir("interrupted");
    let path = dir.join("stats.sqlite");
    std::fs::write(&path, b"not a database at all").unwrap();
    std::fs::write(side_file(&path, ".rebuild"), b"half of a copy").unwrap();

    let opened = recover::open(&path).unwrap();

    assert!(matches!(opened.outcome, Outcome::Discarded { .. }));
    assert!(!side_file(&path, ".rebuild").exists());
}

// ── I/O errors are not damage ──

#[test]
fn an_unwritable_directory_is_an_error_and_the_file_stays() {
    let path = filled("read-only", 5);
    let before = std::fs::read(&path).unwrap();
    let dir = path.parent().unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    // Root writes wherever it likes: the case cannot be made.
    let writable = std::fs::File::create(dir.join("probe")).is_ok();
    let _ = std::fs::remove_file(dir.join("probe"));
    if !writable {
        let error = recover::open(&path)
            .err()
            .expect("a read-only directory is an error");
        assert!(!error.to_string().is_empty());
    }

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "the file was not touched"
    );
    assert!(matches!(
        recover::open(&path).unwrap().outcome,
        Outcome::Opened { rows: [5, 0, 0] }
    ));
}

#[test]
fn a_missing_directory_is_created_with_the_file() {
    let path = temporary_dir("new-directory").join("var/lib/svpn/stats.sqlite");
    assert!(!path.exists());

    let opened = recover::open(&path).unwrap();

    assert!(matches!(opened.outcome, Outcome::Created));
    assert!(path.is_file());
}

#[test]
fn a_directory_that_cannot_be_made_is_an_error() {
    let dir = temporary_dir("closed-directory");
    let path = dir.join("stats.sqlite");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    // Root writes wherever it likes: the case cannot be made.
    let writable = std::fs::File::create(dir.join("probe")).is_ok();
    let outcome = recover::open(&path).map(|_| ());
    let _ = std::fs::remove_file(dir.join("probe"));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    if writable {
        return;
    }

    let error = outcome.expect_err("no directory can be made, no database");
    assert!(!error.to_string().is_empty());
    assert!(!path.exists());
}

// ── helpers ──

use std::os::unix::fs::PermissionsExt;

fn temporary_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("svpn history recover {tag} {}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A closed database with `count` minutes of one link row each.
fn filled(tag: &str, count: u64) -> PathBuf {
    let path = temporary_dir(tag).join("stats.sqlite");
    let mut store = recover::open(&path).unwrap().store;
    write(&mut store, START, count);
    store.close().unwrap();
    path
}

fn write(store: &mut Store, start: u64, count: u64) {
    let minutes: Vec<(u64, Vec<Row>)> = (0..count)
        .map(|minute| {
            let ts = start + minute * MINUTE;
            (ts, vec![row(ts)])
        })
        .collect();
    store
        .append(&minutes, Some(start), start + count * MINUTE)
        .unwrap();
}

fn row(ts: u64) -> Row {
    Row {
        series: Series::Link {
            link: "a.example:22".to_owned(),
        },
        rx_bytes: ts,
        tx_bytes: 2,
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

fn side_file(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}
