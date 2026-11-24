//! The hub's history minute: when it is cut and what it takes along.

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use svpn::{
    history::{History, Kind, Query, Range, Recorder},
    hub::{Hub, UsageMeter, history::delay},
    packet,
};
use tokio::sync::{mpsc, watch};

const MINUTE: u64 = 60;
/// Two seconds past the end of a minute, when the hub cuts it.
const MARGIN: u64 = 2;

// ── when ──

#[test]
fn the_minute_is_cut_two_seconds_after_it_ended() {
    assert_eq!(delay(0), Duration::from_secs(62));
    assert_eq!(delay(58), Duration::from_secs(4));
    assert_eq!(delay(59), Duration::from_secs(3));
    assert_eq!(delay(1_792_886_460), Duration::from_secs(62));
}

// ── what ──

#[tokio::test]
async fn every_link_and_the_local_exit_are_recorded_once_a_minute() {
    let mut hub = recording_hub("links").await;
    // Two minutes ago ended the minute that started `base`.
    let base = real_minute() - 2 * MINUTE;
    let tick = base + MINUTE + MARGIN;

    hub.record_history_at(tick);
    hub.record_history_at(tick + 1);

    assert_eq!(hub.history_ts, Some(base));
    let answer = answered(&hub, window(Kind::Link), 3).await;
    hub.history.as_ref().unwrap().close();
    let series: Vec<(&str, u64, f64)> = answer
        .series
        .iter()
        .map(|series| (series.link.as_str(), series.rx_bytes, series.active_avg))
        .collect();
    assert_eq!(
        series,
        // The live counters of the first link count from zero; the rest idled.
        vec![("192.0.2.1", 4242, 3.0), ("192.0.2.2", 0, 0.), ("", 0, 0.)]
    );
    assert_eq!(answer.series[0].kind, "link");
    assert_eq!(answer.series[2].kind, "local");
}

#[tokio::test]
async fn the_next_minute_records_the_difference() {
    let mut hub = recording_hub("difference").await;
    let base = real_minute() - 2 * MINUTE;
    hub.record_history_at(base + MINUTE + MARGIN);
    // A later report of the first link, one minute later.
    let (_, latest) = watch::channel(svpn::control::Stats {
        inner_rx_bytes: 5000,
        inner_rx_packets: 9,
        active_flows: 1,
        ..Default::default()
    });
    hub.links[0].latest = Some(latest);
    hub.record_history_at(base + 2 * MINUTE + MARGIN);

    let answer = answered(&hub, window(Kind::Link), 3).await;
    hub.history.as_ref().unwrap().close();
    let first = answer
        .series
        .iter()
        .find(|series| series.link == "192.0.2.1")
        .unwrap();
    assert_eq!(
        first
            .points
            .iter()
            .map(|point| point[1])
            .collect::<Vec<_>>(),
        vec![4242, 758]
    );
    assert_eq!(first.active_avg, 2.0);
}

#[tokio::test]
async fn rules_and_networks_carry_what_flowed_over_them() {
    let mut hub = recording_hub("flows").await;
    let bytes = common::udp_packet(false);
    let key = packet::parse(&bytes, true).unwrap().flow;
    let ip = u32::from(key.destination);
    hub.geo = Some(svpn::geo::Geo::from_ranges(vec![(ip, ip, 64512)]));
    let (tx, _rx) = mpsc::channel(1);
    hub.links[0].outgoing = Some(tx);
    hub.dispatch(&bytes, key.source).unwrap();

    hub.record_history();

    let rule = answered(&hub, window(Kind::Rule), 1).await;
    assert_eq!(rule.series.len(), 1);
    assert_eq!(
        (rule.series[0].link.as_str(), rule.series[0].rule.as_deref()),
        ("192.0.2.1", Some("fallback"))
    );
    assert_eq!(rule.series[0].tx_bytes, bytes.len() as u64);
    assert_eq!(rule.series[0].active_avg, 1.0);
    let network = answered(&hub, window(Kind::Network), 1).await;
    assert_eq!(network.series[0].asn, Some(64512));
    assert_eq!(network.series[0].tx_bytes, bytes.len() as u64);

    // The next minute carries nothing: it adds no rule row.
    hub.record_history_at(real_minute() + MINUTE + MARGIN);
    let rules = answered(&hub, window(Kind::Rule), 1).await;
    hub.history.as_ref().unwrap().close();
    assert_eq!(rules.series[0].points.len(), 1);
}

#[tokio::test]
async fn without_history_the_minute_is_not_cut() {
    let mut hub = common::hub::dashboard_hub();

    hub.record_history();

    assert_eq!(hub.history_ts, None);
    assert!(hub.history_prev.is_none());
}

// ── helpers ──

/// The minute that runs now, as its first second.
fn real_minute() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / MINUTE
        * MINUTE
}

fn window(kind: Kind) -> Query {
    Query {
        range: Range::Hour,
        kind,
        link: None,
        top: 8,
    }
}

/// A dashboard hub that records history into a database of its own, once
/// the history thread has opened it.
async fn recording_hub(tag: &str) -> Hub {
    let mut hub = common::hub::dashboard_hub();
    let dir = std::env::temp_dir().join(format!("svpn hub history {tag} {}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    hub.routes.usage = Some(UsageMeter::default());
    std::fs::create_dir_all(&dir).unwrap();
    let recorder = Recorder::spawn(dir.join("stats.sqlite"));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while recorder.status().state == "checking" && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(recorder.status().state, "ok", "{}", recorder.status().error);
    hub.history = Some(recorder);
    hub
}

/// Wait until the history holds `count` series: the thread writes on its own.
async fn answered(hub: &Hub, query: Query, count: usize) -> History {
    let recorder = hub.history.as_ref().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let answer = recorder.query(query.clone()).unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(5), answer)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if answer.series.len() >= count || std::time::Instant::now() > deadline {
            return answer;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
