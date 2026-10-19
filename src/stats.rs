//! Client reports from cumulative link snapshots; no packet-path accounting.

use std::time::Duration;

use crate::control::Stats;

#[derive(Default)]
pub struct Snapshot {
    latest: Stats,
    total: Stats,
    reported: Stats,
}

impl Snapshot {
    pub fn observe(&mut self, stats: Stats) {
        add(&mut self.total, &difference(&stats, &self.latest));
        self.total.active_flows = stats.active_flows;
        self.latest = stats;
    }

    /// Keep session totals, but a new link generation starts its counters at zero.
    pub fn reset(&mut self) {
        self.latest = Stats::default();
        self.total.active_flows = 0;
    }

    pub fn sample(&mut self) -> (Stats, Stats) {
        let delta = difference(&self.total, &self.reported);
        self.reported = self.total.clone();
        (delta, self.total.clone())
    }
}

pub fn difference(now: &Stats, before: &Stats) -> Stats {
    Stats {
        inner_tx_packets: now.inner_tx_packets.saturating_sub(before.inner_tx_packets),
        inner_rx_packets: now.inner_rx_packets.saturating_sub(before.inner_rx_packets),
        inner_tx_bytes: now.inner_tx_bytes.saturating_sub(before.inner_tx_bytes),
        inner_rx_bytes: now.inner_rx_bytes.saturating_sub(before.inner_rx_bytes),
        dropped_packets: now.dropped_packets.saturating_sub(before.dropped_packets),
        opened_flows: now.opened_flows.saturating_sub(before.opened_flows),
        open_failed_flows: now
            .open_failed_flows
            .saturating_sub(before.open_failed_flows),
        closed_flows: now.closed_flows.saturating_sub(before.closed_flows),
        active_flows: now.active_flows,
        active_candidate: None,
    }
}

pub fn add(total: &mut Stats, stats: &Stats) {
    total.inner_tx_packets = total
        .inner_tx_packets
        .saturating_add(stats.inner_tx_packets);
    total.inner_rx_packets = total
        .inner_rx_packets
        .saturating_add(stats.inner_rx_packets);
    total.inner_tx_bytes = total.inner_tx_bytes.saturating_add(stats.inner_tx_bytes);
    total.inner_rx_bytes = total.inner_rx_bytes.saturating_add(stats.inner_rx_bytes);
    total.dropped_packets = total.dropped_packets.saturating_add(stats.dropped_packets);
    total.opened_flows = total.opened_flows.saturating_add(stats.opened_flows);
    total.open_failed_flows = total
        .open_failed_flows
        .saturating_add(stats.open_failed_flows);
    total.closed_flows = total.closed_flows.saturating_add(stats.closed_flows);
    total.active_flows = total.active_flows.saturating_add(stats.active_flows);
}

pub fn format(label: &str, delta: &Stats, total: &Stats, elapsed: Duration) -> String {
    let rate = |bytes: u64| {
        if elapsed.is_zero() {
            0.0
        } else {
            bytes as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0
        }
    };
    let mib = |bytes: u64| bytes as f64 / 1_048_576.0;
    format!(
        "stats: {label} | RX {:>8.2} Mbit/s ({:>8} packets) | TX {:>8.2} Mbit/s ({:>8} packets)\n\
         stats: {label} | total RX {:.2} MiB / TX {:.2} MiB | drops +{} (total {})\n\
         stats: {label} | flows {} active | +{} opened / +{} failed / +{} closed",
        rate(delta.inner_rx_bytes),
        delta.inner_rx_packets,
        rate(delta.inner_tx_bytes),
        delta.inner_tx_packets,
        mib(total.inner_rx_bytes),
        mib(total.inner_tx_bytes),
        delta.dropped_packets,
        total.dropped_packets,
        total.active_flows,
        delta.opened_flows,
        delta.open_failed_flows,
        delta.closed_flows,
    )
}
