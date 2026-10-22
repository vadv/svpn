//! Stats reports: snapshot deltas, reconnect totals, saturation safety, formatting.

use std::time::Duration;

use svpn::control::Stats;
use svpn::stats::*;

fn counters(value: u64, active: usize) -> Stats {
    Stats {
        inner_tx_packets: value,
        inner_rx_packets: value,
        inner_tx_bytes: value,
        inner_rx_bytes: value,
        dropped_packets: value,
        opened_flows: value,
        open_failed_flows: value,
        closed_flows: value,
        active_flows: active,
        active_candidate: None,
        transport_failures: Default::default(),
    }
}

// ── snapshot deltas ──

#[test]
fn snapshots_count_deltas_not_repeated_heartbeats() {
    let mut snapshot = Snapshot::default();
    snapshot.observe(counters(10, 3));
    snapshot.observe(counters(10, 3));
    snapshot.observe(counters(25, 2));
    let (delta, total) = snapshot.sample();
    assert_eq!(delta, counters(25, 2));
    assert_eq!(total, counters(25, 2));
    assert_eq!(snapshot.sample().0, counters(0, 2));
    snapshot.observe(counters(30, 1));
    let (delta, total) = snapshot.sample();
    assert_eq!(delta, counters(5, 1));
    assert_eq!(total, counters(30, 1));
}

#[test]
fn reconnect_keeps_totals_and_unreported_traffic() {
    let mut snapshot = Snapshot::default();
    snapshot.observe(counters(10, 3));
    snapshot.sample();
    snapshot.observe(counters(15, 4));
    snapshot.reset();
    let (delta, total) = snapshot.sample();
    assert_eq!(delta, counters(5, 0));
    assert_eq!(total, counters(15, 0));
    snapshot.observe(counters(2, 1));
    let (delta, total) = snapshot.sample();
    assert_eq!(delta, counters(2, 1));
    assert_eq!(total, counters(17, 1));
}

// ── unseen links and saturation ──

#[test]
fn unseen_links_zero_elapsed_and_saturation_are_safe() {
    let (delta, total) = Snapshot::default().sample();
    let output = format("[server] connecting", &delta, &total, Duration::ZERO);
    assert!(output.contains("0.00 Mbit/s"));
    assert!(output.contains("flows 0 active"));
    assert!(!output.contains("NaN") && !output.contains("inf"));
    assert_eq!(difference(&counters(1, 0), &counters(2, 1)), counters(0, 0));
    let mut sum = counters(u64::MAX, usize::MAX);
    add(&mut sum, &counters(1, 1));
    assert_eq!(sum, counters(u64::MAX, usize::MAX));
}

// ── report formatting ──

#[test]
fn report_labels_rates_interval_counters_and_totals() {
    let delta = Stats {
        inner_rx_bytes: 12_000_000,
        inner_tx_bytes: 3_000_000,
        inner_rx_packets: 8000,
        inner_tx_packets: 2000,
        dropped_packets: 2,
        opened_flows: 4,
        open_failed_flows: 1,
        closed_flows: 2,
        active_flows: 3,
        active_candidate: None,
        transport_failures: Default::default(),
    };
    let total = Stats {
        inner_rx_bytes: 64 * 1_048_576,
        active_candidate: None,
        transport_failures: Default::default(),
        ..delta.clone()
    };
    assert_eq!(
        format(
            "[203.0.113.10] ready",
            &delta,
            &total,
            Duration::from_secs(30)
        ),
        "stats: [203.0.113.10] ready | RX     3.20 Mbit/s (    8000 packets) | TX     0.80 Mbit/s (    2000 packets)\n\
         stats: [203.0.113.10] ready | total RX 64.00 MiB / TX 2.86 MiB | drops +2 (total 2)\n\
         stats: [203.0.113.10] ready | flows 3 active | +4 opened / +1 failed / +2 closed"
    );
}

// ── transport failures ──

#[test]
fn difference_and_add_carry_per_transport_failures() {
    let mut before = counters(0, 0);
    before.transport_failures.insert("quic".into(), 2);
    let mut now = counters(0, 0);
    now.transport_failures.insert("quic".into(), 5);
    now.transport_failures.insert("tcp-ssh".into(), 1);
    let delta = difference(&now, &before);
    assert_eq!(delta.transport_failures.get("quic"), Some(&3));
    assert_eq!(delta.transport_failures.get("tcp-ssh"), Some(&1));
    let mut total = Stats::default();
    add(&mut total, &delta);
    add(&mut total, &delta);
    assert_eq!(total.transport_failures.get("quic"), Some(&6));
}

#[test]
fn report_lists_transport_failures_only_when_present() {
    let mut delta = counters(0, 0);
    assert!(!format("x", &delta, &delta, Duration::from_secs(1)).contains("failures"));
    delta.transport_failures.insert("quic".into(), 3);
    let report = format("x", &delta, &delta, Duration::from_secs(1));
    assert!(
        report.contains("stats: x | failures (packet-level): quic=3"),
        "{report}"
    );
}
