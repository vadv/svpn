//! History minute rows: the counters of two snapshots become one minute.

use std::collections::BTreeMap;

use svpn::history::{
    Bytes, Counters, FALLBACK, LOCAL, LinkCounters, LocalCounters, Row, Series, TOP_NETWORKS,
    minute,
};

// ── links and the local exit: counters since start ──

#[test]
fn first_minute_counts_from_zero() {
    let rows = minute(
        None,
        &Counters {
            links: vec![("a.example:22".to_owned(), link(500, 300))],
            local: LocalCounters {
                rx_bytes: 70,
                tx_bytes: 30,
                opened: 4,
                closed: 2,
                failed: 1,
                active: 2,
            },
            ..Counters::default()
        },
    );

    assert_eq!(
        rows[0],
        Row {
            series: key::link("a.example:22"),
            rx_bytes: 500,
            tx_bytes: 300,
            active: 1,
            ..zero()
        }
    );
    assert_eq!(
        rows[1],
        Row {
            series: Series::Local,
            rx_bytes: 70,
            tx_bytes: 30,
            opened: 4,
            closed: 2,
            failed: 1,
            active: 2,
            ..zero()
        }
    );
}

#[test]
fn later_minutes_are_the_difference() {
    let before = links([("a.example:22", 500, 300)]);
    let now = links([("a.example:22", 900, 1000)]);

    let rows = minute(Some(&before), &now);

    assert_eq!(rows[0].rx_bytes, 400);
    assert_eq!(rows[0].tx_bytes, 700);
    assert_eq!(rows.len(), 2);
}

#[test]
fn reset_counter_counts_its_new_value() {
    // The server restarted: every counter is below its last snapshot.
    let before = Counters {
        links: vec![(
            "a.example:22".to_owned(),
            LinkCounters {
                rx_bytes: 9000,
                tx_bytes: 9000,
                opened: 50,
                closed: 50,
                failed: 9,
                drops: 9,
                active: 3,
                ..LinkCounters::default()
            },
        )],
        local: LocalCounters {
            rx_bytes: 8000,
            tx_bytes: 8000,
            opened: 40,
            failed: 8,
            ..LocalCounters::default()
        },
        ..Counters::default()
    };
    let now = Counters {
        links: vec![(
            "a.example:22".to_owned(),
            LinkCounters {
                rx_bytes: 10,
                tx_bytes: 20,
                opened: 2,
                closed: 1,
                failed: 1,
                drops: 2,
                active: 1,
                ..LinkCounters::default()
            },
        )],
        local: LocalCounters {
            rx_bytes: 5,
            tx_bytes: 6,
            opened: 3,
            failed: 2,
            ..LocalCounters::default()
        },
        ..Counters::default()
    };

    let rows = minute(Some(&before), &now);

    assert_eq!(
        rows[0],
        Row {
            series: key::link("a.example:22"),
            rx_bytes: 10,
            tx_bytes: 20,
            opened: 2,
            closed: 1,
            failed: 1,
            drops: 2,
            active: 1,
            ..zero()
        }
    );
    assert_eq!(
        rows[1],
        Row {
            series: Series::Local,
            rx_bytes: 5,
            tx_bytes: 6,
            opened: 3,
            failed: 2,
            ..zero()
        }
    );
}

#[test]
fn link_added_or_removed_keeps_the_others_honest() {
    let before = links([("a.example:22", 100, 100), ("old.example:22", 900, 900)]);
    let now = links([("a.example:22", 150, 130), ("new.example:22", 40, 60)]);

    let rows = minute(Some(&before), &now);

    // Every link in hub order, then the local exit.
    let keys: Vec<Series> = rows.iter().map(|row| row.series.clone()).collect();
    assert_eq!(
        keys,
        vec![
            key::link("a.example:22"),
            key::link("new.example:22"),
            Series::Local,
        ]
    );
    assert_eq!((rows[0].rx_bytes, rows[0].tx_bytes), (50, 30));
    // A link without a previous snapshot counts from zero, like the first minute.
    assert_eq!((rows[1].rx_bytes, rows[1].tx_bytes), (40, 60));
}

#[test]
fn the_local_exit_is_always_recorded() {
    let rows = minute(None, &Counters::default());

    assert_eq!(rows, vec![zero_of(Series::Local)]);
}

// ── rules and networks: the minute as measured ──

#[test]
fn rules_carry_bytes_and_open_flows_under_stable_keys() {
    let now = Counters {
        rules: [
            (
                ("a.example:22".to_owned(), "cc:RU".to_owned()),
                (Bytes { rx: 10, tx: 20 }, 3),
            ),
            (
                (LOCAL.to_owned(), FALLBACK.to_owned()),
                (Bytes { rx: 1, tx: 2 }, 1),
            ),
            // Open flows without bytes still count as activity.
            (
                ("a.example:22".to_owned(), "asn:1".to_owned()),
                (Bytes::default(), 5),
            ),
            (
                ("a.example:22".to_owned(), "asn:2".to_owned()),
                (Bytes::default(), 0),
            ),
        ]
        .into_iter()
        .collect(),
        ..Counters::default()
    };

    let rows = minute(None, &now);

    // An idle key gets no row, whoever is listening on it.
    let got: Vec<(Series, u64, u64, usize)> = rows
        .iter()
        .filter(|row| matches!(row.series, Series::Rule { .. }))
        .map(|row| (row.series.clone(), row.rx_bytes, row.tx_bytes, row.active))
        .collect();
    assert_eq!(
        got,
        vec![
            (key::rule("a.example:22", "asn:1"), 0, 0, 5),
            (key::rule("a.example:22", "cc:RU"), 10, 20, 3),
            (key::rule(LOCAL, FALLBACK), 1, 2, 1),
        ]
    );
    assert!(
        rows.iter()
            .all(|row| row.opened == 0 && row.rx_packets == 0)
    );
}

#[test]
fn networks_are_the_busiest_with_ties_by_key() {
    // Twenty-five networks share one link, five of them with equal bytes.
    let mut networks = BTreeMap::new();
    for asn in 1..=18u32 {
        networks.insert(
            ("a.example:22".to_owned(), asn),
            (
                Bytes {
                    rx: u64::from(100 - asn),
                    tx: 0,
                },
                0,
            ),
        );
    }
    for asn in 101..=105u32 {
        networks.insert(
            ("a.example:22".to_owned(), asn),
            (Bytes { rx: 60, tx: 0 }, 0),
        );
        networks.insert(
            ("b.example:22".to_owned(), asn),
            (Bytes { rx: 60, tx: 0 }, 0),
        );
    }
    // A network with an open flow and no bytes still gets a row.
    networks.insert(("a.example:22".to_owned(), 999), (Bytes::default(), 2));

    let rows = minute(
        None,
        &Counters {
            networks,
            ..Counters::default()
        },
    );
    let got: Vec<Series> = rows
        .iter()
        .filter(|row| matches!(row.series, Series::Network { .. }))
        .map(|row| row.series.clone())
        .collect();

    assert_eq!(got.len(), TOP_NETWORKS);
    // The most bytes first, then the ties sorted by link and ASN.
    let top: Vec<Series> = (1..=18u32)
        .map(|asn| key::network("a.example:22", asn))
        .collect();
    assert_eq!(&got[..18], top.as_slice());
    assert_eq!(got[18], key::network("a.example:22", 101));
    assert_eq!(got[19], key::network("a.example:22", 102));
    // The idle network ranks last and falls off the twenty.
    assert!(!got.contains(&key::network("a.example:22", 999)));
}

#[test]
fn a_quiet_minute_has_no_rule_or_network_rows() {
    let now = Counters {
        rules: [(
            ("a.example:22".to_owned(), "cc:RU".to_owned()),
            (Bytes::default(), 0),
        )]
        .into_iter()
        .collect(),
        networks: [(("a.example:22".to_owned(), 7), (Bytes::default(), 0))]
            .into_iter()
            .collect(),
        ..Counters::default()
    };

    assert_eq!(minute(None, &now), vec![zero_of(Series::Local)]);
}

// ── series columns ──

#[test]
fn series_survive_their_table_columns() {
    let all = [
        key::link("a.example:22"),
        key::rule("a.example:22", "cc:RU,BY"),
        Series::Local,
        key::network(LOCAL, 4321),
    ];
    for series in all {
        let back = Series::from_columns(series.kind(), series.link(), series.rule(), series.asn());
        assert_eq!(back.as_ref(), Some(&series));
    }
    assert_eq!(Series::from_columns(4, "", "", 0), None);
    assert_eq!(Series::Local.link(), "");
    assert_eq!(key::rule("a.example:22", "cc:RU").asn(), 0);
    assert_eq!(
        [
            key::link("a").kind(),
            key::rule("a", "r").kind(),
            Series::Local.kind(),
            key::network("a", 1).kind()
        ],
        [0, 1, 2, 3]
    );
}

// ── helpers ──

mod key {
    use super::Series;

    pub fn link(link: &str) -> Series {
        Series::Link {
            link: link.to_owned(),
        }
    }

    pub fn rule(link: &str, rule: &str) -> Series {
        Series::Rule {
            link: link.to_owned(),
            rule: rule.to_owned(),
        }
    }

    pub fn network(link: &str, asn: u32) -> Series {
        Series::Network {
            link: link.to_owned(),
            asn,
        }
    }
}

fn link(rx_bytes: u64, tx_bytes: u64) -> LinkCounters {
    LinkCounters {
        rx_bytes,
        tx_bytes,
        active: 1,
        ..LinkCounters::default()
    }
}

fn links<const N: usize>(counters: [(&str, u64, u64); N]) -> Counters {
    Counters {
        links: counters
            .iter()
            .map(|(name, rx, tx)| (name.to_string(), link(*rx, *tx)))
            .collect(),
        ..Counters::default()
    }
}

fn zero() -> Row {
    zero_of(Series::Local)
}

fn zero_of(series: Series) -> Row {
    Row {
        series,
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
