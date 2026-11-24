//! History for the dashboard: the query string, the answer from the tiers,
//! and the thread that owns the database.

use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use svpn::history::{Kind, Query, Range, Recorder, Row, Series, Status, recover, store::Store};

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const START: u64 = 1_792_886_400;
const A: &str = "a.example:22";
const B: &str = "b.example:22";

// ── query string ──

#[test]
fn the_query_string_has_defaults_and_takes_its_four_fields() {
    assert_eq!(
        Query::parse("").unwrap(),
        Query {
            range: Range::Day,
            kind: Kind::Link,
            link: None,
            top: 8,
        }
    );
    assert_eq!(
        Query::parse("range=7d&kind=network&top=32&link=s1.example:22").unwrap(),
        Query {
            range: Range::Week,
            kind: Kind::Network,
            link: Some("s1.example:22".to_owned()),
            top: 32,
        }
    );
}

#[test]
fn the_query_string_rejects_what_it_does_not_know() {
    let long = "x".repeat(129);
    for query in [
        "range=1y",
        "kind=country",
        "top=0",
        "top=33",
        "top=-1",
        "top=x",
        "link=a%20b",
        "link=../etc",
        "link=",
        "range=1h&range=24h",
        "range",
        "=1h",
        "limit=5",
    ] {
        assert!(Query::parse(query).is_err(), "{query:?}");
    }
    assert!(Query::parse(&format!("link={long}")).is_err());
}

// ── answers ──

#[test]
fn series_come_busiest_first_up_to_top() {
    let (_, store) = history("rank", DAY / HOUR);
    let query = Query {
        range: Range::Day,
        kind: Kind::Link,
        link: None,
        top: 8,
    };

    let answer = store.query(&query, START + DAY).unwrap();

    let links: Vec<&str> = answer
        .series
        .iter()
        .map(|series| series.link.as_str())
        .collect();
    assert_eq!(links, vec!["", B, A]);
    assert_eq!(answer.series[0].kind, "local");
    assert_eq!(answer.series[0].rx_bytes, 3000 * 1440);
    assert_eq!(answer.series[0].tx_bytes, 1440);
    assert_eq!(answer.series[0].active_avg, 2.0);
    // A day comes in four-minute buckets: never more than 400 points a series.
    assert_eq!(
        (answer.range, answer.kind, answer.step),
        ("24h", "link", 4 * MINUTE)
    );
    assert_eq!((answer.from, answer.to), (START, START + DAY));

    let top = Query { top: 2, ..query };
    assert_eq!(store.query(&top, START + DAY).unwrap().series.len(), 2);
}

#[test]
fn the_breakdown_selects_its_series_and_the_link_narrows_them() {
    let (_, store) = history("kinds", DAY / HOUR);
    let now = START + DAY;
    // Kind, link, rule and network of every series the answer names.
    let names = |query: &Query| {
        store
            .query(query, now)
            .unwrap()
            .series
            .iter()
            .map(|series| {
                format!(
                    "{} {} {} {:?}",
                    series.kind,
                    series.link,
                    series.rule.as_deref().unwrap_or("-"),
                    series.asn
                )
            })
            .collect::<Vec<_>>()
    };
    let mut query = Query {
        range: Range::Day,
        kind: Kind::Rule,
        link: None,
        top: 8,
    };

    assert_eq!(
        names(&query),
        ["rule local fallback None", "rule a.example:22 cc:RU None"]
    );
    query.kind = Kind::Network;
    assert_eq!(
        names(&query),
        [
            "network a.example:22 - Some(4134)",
            "network b.example:22 - Some(31133)",
            "network a.example:22 - Some(15169)",
        ]
    );
    query.link = Some(A.to_owned());
    assert_eq!(
        names(&query),
        [
            "network a.example:22 - Some(4134)",
            "network a.example:22 - Some(15169)",
        ]
    );
    query.kind = Kind::Link;
    assert_eq!(names(&query), ["link a.example:22 - None"]);
}

#[test]
fn points_are_minutes_summing_to_the_totals() {
    let (_, store) = history("points", 2 * DAY / HOUR);
    let query = Query {
        range: Range::Hour,
        kind: Kind::Link,
        link: Some(B.to_owned()),
        top: 8,
    };

    let answer = store.query(&query, START + 2 * DAY - 7 * MINUTE).unwrap();

    let series = &answer.series[0];
    assert_eq!(
        (answer.from, answer.to),
        (
            START + 2 * DAY - 7 * MINUTE - HOUR,
            START + 2 * DAY - 7 * MINUTE
        )
    );
    assert_eq!(series.points.len(), 60);
    assert_eq!(series.points[0], [answer.from, 2000, 1]);
    assert_eq!(series.points[59], [answer.to - MINUTE, 2000, 1]);
    assert_eq!(
        series.points.iter().map(|point| point[1]).sum::<u64>(),
        series.rx_bytes
    );
}

#[test]
fn long_ranges_come_from_the_coarse_tiers_in_thinned_buckets() {
    let (_, store) = history("ranges", 8 * DAY / HOUR);
    let now = START + 8 * DAY;

    let week = store
        .query(
            &Query {
                range: Range::Week,
                kind: Kind::Link,
                link: Some(A.to_owned()),
                top: 8,
            },
            now,
        )
        .unwrap();
    assert_eq!((week.step, week.from, week.to), (HOUR, now - 7 * DAY, now));
    assert_eq!(week.series[0].points.len(), 168);
    assert_eq!(week.series[0].points[0], [now - 7 * DAY, 1000 * 60, 60]);
    assert_eq!(week.series[0].rx_bytes, 1000 * 60 * 168);

    let month = store
        .query(
            &Query {
                range: Range::Month,
                kind: Kind::Link,
                link: Some(A.to_owned()),
                top: 8,
            },
            now,
        )
        .unwrap();
    assert_eq!(
        (month.step, month.from, month.to),
        (DAY, now - 30 * DAY, now)
    );
    // Eight days were written; the window reaches thirty.
    assert_eq!(month.series[0].points.len(), 8);
    assert_eq!(month.series[0].points[7], [now - DAY, 1000 * 1440, 1440]);
}

#[test]
fn a_range_without_history_answers_with_no_series() {
    let path = database("empty");
    let store = recover::open(&path).unwrap().store;

    let answer = store
        .query(
            &Query {
                range: Range::Month,
                kind: Kind::Network,
                link: None,
                top: 8,
            },
            START + 40 * DAY,
        )
        .unwrap();

    assert!(answer.series.is_empty());
    drop(store);
}

// ── the owner thread ──

#[tokio::test]
async fn the_thread_opens_the_database_and_answers_through_the_hub() {
    let path = database("thread");
    let recorder = Recorder::spawn(path.clone());
    assert_eq!(recorder.status().state, "checking");

    let status = settled(&recorder).await;
    assert_eq!((status.state, status.error.as_str()), ("ok", ""));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    recorder.record(
        now / MINUTE * MINUTE - 2 * MINUTE,
        vec![traffic(A, 500, 100)],
    );
    recorder.record(now / MINUTE * MINUTE - MINUTE, vec![traffic(A, 700, 100)]);
    assert_eq!(recorder.status().state, "ok");

    let answer = answered(&recorder, Kind::Link, 1).await;
    assert_eq!(answer.series.len(), 1);
    assert_eq!(answer.series[0].link, A);
    assert_eq!(answer.series[0].rx_bytes, 1200);

    recorder.close();
    let error = recorder.query(query(Kind::Link)).expect_err("closed");
    assert!(error.to_string().contains("not running"), "{error}");
}

#[tokio::test]
async fn a_database_that_cannot_open_is_an_error_in_the_status_and_nothing_else() {
    // A directory where the file should be: no build can open that.
    let path = database("not-a-file");
    std::fs::create_dir_all(&path).unwrap();
    let recorder = Recorder::spawn(path);

    let status = settled(&recorder).await;
    assert_eq!(status.state, "error");
    assert!(!status.error.is_empty());

    // The hub hands minutes over as before, and does not wait for anything.
    let started = std::time::Instant::now();
    recorder.record(START, vec![traffic(A, 1, 1)]);
    assert!(started.elapsed() < Duration::from_millis(50));
    // A query comes back with the reason the dashboard shows.
    let answer = recorder
        .query(query(Kind::Link))
        .expect("the thread is running");
    let error = tokio::time::timeout(Duration::from_secs(5), answer)
        .await
        .unwrap()
        .unwrap()
        .expect_err("no database, no answer");
    assert_eq!(error.to_string(), status.error);

    recorder.close();
}

// ── helpers ──

fn traffic(link: &str, rx_bytes: u64, tx_bytes: u64) -> Row {
    Row {
        series: Series::Link {
            link: link.to_owned(),
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

fn query(kind: Kind) -> Query {
    Query {
        range: Range::Day,
        kind,
        link: None,
        top: 8,
    }
}

/// The status once the thread has tried the database.
async fn settled(recorder: &Recorder) -> Status {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let status = recorder.status();
        if status.state != "checking" || std::time::Instant::now() > deadline {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Wait until the history holds `series` series of `kind`.
async fn answered(recorder: &Recorder, kind: Kind, series: usize) -> svpn::history::History {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let answer = recorder.query(query(kind)).unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(5), answer)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if answer.series.len() >= series || std::time::Instant::now() > deadline {
            return answer;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn database(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("svpn history api {tag} {}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("stats.sqlite")
}

/// Two links, the local exit, two rules and three networks, written hour by
/// hour. A series carries `(its place + 1) * 1000` bytes a minute, so the
/// ranking is known.
fn history(tag: &str, hours: u64) -> (PathBuf, Store) {
    let path = database(tag);
    let mut store = recover::open(&path).unwrap().store;
    for hour in 0..hours {
        let start = START + hour * HOUR;
        let minutes: Vec<(u64, Vec<Row>)> = (0..60)
            .map(|minute| (start + minute * MINUTE, rows()))
            .collect();
        store.append(&minutes, Some(start), start + HOUR).unwrap();
    }
    (path, store)
}

fn rows() -> Vec<Row> {
    [
        (Series::Link { link: A.to_owned() }, 1000),
        (Series::Link { link: B.to_owned() }, 2000),
        (Series::Local, 3000),
        (
            Series::Rule {
                link: A.to_owned(),
                rule: "cc:RU".to_owned(),
            },
            4000,
        ),
        (
            Series::Rule {
                link: "local".to_owned(),
                rule: "fallback".to_owned(),
            },
            5000,
        ),
        (
            Series::Network {
                link: A.to_owned(),
                asn: 15169,
            },
            6000,
        ),
        (
            Series::Network {
                link: B.to_owned(),
                asn: 31133,
            },
            7000,
        ),
        (
            Series::Network {
                link: A.to_owned(),
                asn: 4134,
            },
            8000,
        ),
    ]
    .into_iter()
    .map(|(series, rx_bytes)| Row {
        series,
        rx_bytes,
        tx_bytes: 1,
        active: 2,
        ..zero()
    })
    .collect()
}
