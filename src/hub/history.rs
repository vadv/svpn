//! One history minute: at each UTC minute boundary the hub's counters
//! become rows for the history thread.

use std::{
    collections::HashMap,
    pin::Pin,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::time::Sleep;

use super::{Hub, Target};
use crate::{
    control::Stats,
    history::{Bytes, Counters, FALLBACK, LOCAL, LinkCounters, LocalCounters},
};

/// Seconds past the boundary when the ended minute is cut: the timer never
/// fires early, and the wall clock is read after the boundary, not before.
const MARGIN: u64 = 2;

/// When the minute running now has ended. Built from the wall clock every
/// time, so it does not drift away from the boundary.
pub(super) fn deadline() -> Pin<Box<Sleep>> {
    Box::pin(tokio::time::sleep(delay(unix())))
}

/// How long until the minute that contains `now` has been cut.
pub fn delay(now: u64) -> Duration {
    Duration::from_secs(60 + MARGIN - now % 60)
}

impl Hub {
    /// The minute that just ended: cut it from the counters and hand it
    /// over. The hub never waits for the history thread.
    pub fn record_history(&mut self) {
        self.record_history_at(unix());
    }

    /// `record_history` for a hub that hears the clock from its caller.
    pub fn record_history_at(&mut self, now: u64) {
        let Some(recorder) = self.history.clone() else {
            return;
        };
        // A clock that went back, or a minute already recorded: what was
        // measured joins the next minute instead of overwriting history.
        let ts = (now / 60).saturating_sub(1) * 60;
        if self.history_ts.is_some_and(|last| ts <= last) {
            return;
        }
        self.history_ts = Some(ts);
        let counters = self.history_counters();
        let rows = crate::history::minute(self.history_prev.as_ref(), &counters);
        self.history_prev = Some(counters);
        recorder.record(ts, rows);
    }

    /// The hub's counters of this moment, keyed by the names history keeps.
    fn history_counters(&mut self) -> Counters {
        let links: Vec<String> = (0..self.links.len())
            .map(|link| crate::web::node_id(self, link))
            .collect();
        let rules: Vec<String> = self
            .stickies
            .iter()
            .map(|rule| rule.block.canonical_key())
            .collect();
        let mut counters = Counters {
            links: self
                .links
                .iter()
                .zip(&links)
                .map(|(link, id)| (id.clone(), link_counters(&crate::web::link_counters(link))))
                .collect(),
            local: LocalCounters {
                opened: self.local_stats.opened,
                failed: self.local_stats.failed,
                closed: self.local_stats.closed,
                active: self
                    .local
                    .as_ref()
                    .map_or(0, |local| local.latest.borrow().active_flows),
                ..LocalCounters::default()
            },
            ..Counters::default()
        };
        let Some(meter) = self.routes.usage.as_mut() else {
            return counters;
        };
        // Open flows at this moment, by the meter's own keys.
        let mut open_rules: HashMap<(Option<usize>, Option<usize>), usize> = HashMap::new();
        let mut open_networks: HashMap<(u32, Option<usize>), usize> = HashMap::new();
        for flow in self.routes.by_key.values().filter(|flow| !flow.closing) {
            let link = match flow.target {
                Target::Remote(owner) => Some(owner.epoch.link),
                Target::Direct(_) => None,
            };
            *open_rules.entry((link, flow.rule)).or_default() += 1;
            if let Some(asn) = flow.asn {
                *open_networks.entry((asn, link)).or_default() += 1;
            }
        }
        for (key, flow) in &mut self.routes.by_key {
            meter.pending.collect(key.destination, flow);
        }
        let sample = meter.sample(Instant::now());
        counters.local.rx_bytes = sample.session.local.rx_bytes;
        counters.local.tx_bytes = sample.session.local.tx_bytes;
        let window = meter.take_window();
        let link_name = |link: Option<usize>| link.map_or(LOCAL, |link| links[link].as_str());
        let rule_name = |rule: Option<usize>| rule.map_or(FALLBACK, |rule| rules[rule].as_str());
        let as_bytes = |bytes: &super::Traffic| Bytes {
            rx: bytes.rx_bytes,
            tx: bytes.tx_bytes,
        };
        counters.rules = window
            .rules
            .iter()
            .filter(|(_, bytes)| bytes.rx_bytes + bytes.tx_bytes > 0)
            .map(|(&(link, rule), bytes)| {
                (
                    (link_name(link).to_owned(), rule_name(rule).to_owned()),
                    (
                        as_bytes(bytes),
                        open_rules.get(&(link, rule)).copied().unwrap_or(0),
                    ),
                )
            })
            .collect();
        counters.networks = window
            .networks
            .iter()
            .filter(|(_, bytes)| bytes.rx_bytes + bytes.tx_bytes > 0)
            .map(|(&(asn, link), bytes)| {
                (
                    (link_name(link).to_owned(), asn),
                    (
                        as_bytes(bytes),
                        open_networks.get(&(asn, link)).copied().unwrap_or(0),
                    ),
                )
            })
            .collect();
        counters
    }
}

/// The counters of one link as history keeps them.
fn link_counters(stats: &Stats) -> LinkCounters {
    LinkCounters {
        rx_bytes: stats.inner_rx_bytes,
        tx_bytes: stats.inner_tx_bytes,
        rx_packets: stats.inner_rx_packets,
        tx_packets: stats.inner_tx_packets,
        opened: stats.opened_flows,
        closed: stats.closed_flows,
        failed: stats.open_failed_flows,
        drops: stats.dropped_packets,
        active: stats.active_flows,
    }
}

fn unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |passed| passed.as_secs())
}
