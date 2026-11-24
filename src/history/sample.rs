//! Cumulative hub counters and their difference into one minute row.
//!
//! Pure: the hub snapshots its counters at each UTC minute, this module
//! differences two snapshots and ranks the networks. Counter deltas are
//! honest across restarts and resets: a first snapshot counts from zero, a
//! counter that went down counts its new value.

use std::collections::BTreeMap;

/// Networks kept per minute, ranked by bytes: the busiest ones become
/// history, the rest stay in the per-link totals.
pub const TOP_NETWORKS: usize = 20;
/// Rule key of the traffic that no sticky block matched.
pub const FALLBACK: &str = "fallback";
/// Link key of the local exit.
pub const LOCAL: &str = "local";

/// One recorded dimension. Keys are stable node ids and canonical rule keys,
/// so a reordered config keeps its history.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Series {
    Link { link: String },
    Rule { link: String, rule: String },
    Local,
    Network { link: String, asn: u32 },
}

/// Bytes in both directions since client start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bytes {
    pub rx: u64,
    pub tx: u64,
}

/// Counters of one link since client start; `active` is a gauge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub opened: u64,
    pub closed: u64,
    pub failed: u64,
    pub drops: u64,
    pub active: usize,
}

/// Counters of the local exit since client start.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub opened: u64,
    pub closed: u64,
    pub failed: u64,
    pub active: usize,
}

/// One snapshot of the hub's counters. Links and the local exit count
/// since client start and are differenced against the previous snapshot;
/// rules and networks carry the minute as the hub measured it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Every configured link, in hub order.
    pub links: Vec<(String, LinkCounters)>,
    /// Bytes per link × rule, and the open flows of the minute's last moment.
    pub rules: BTreeMap<(String, String), (Bytes, usize)>,
    pub local: LocalCounters,
    /// Bytes per network (ASN) × link, with open flows.
    pub networks: BTreeMap<(String, u32), (Bytes, usize)>,
}

/// One minute of one series: counter deltas over the minute and the gauge at
/// its end. Rows of rules and networks carry bytes and the gauge only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub series: Series,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub opened: u64,
    pub closed: u64,
    pub failed: u64,
    pub drops: u64,
    pub active: usize,
}

impl Row {
    /// A row of a series that counts bytes and active flows only.
    fn of_bytes(series: Series, bytes: Bytes, active: usize) -> Row {
        Row {
            series,
            rx_bytes: bytes.rx,
            tx_bytes: bytes.tx,
            active,
            rx_packets: 0,
            tx_packets: 0,
            opened: 0,
            closed: 0,
            failed: 0,
            drops: 0,
        }
    }
}

impl Series {
    /// Kind code of the `series` table.
    pub fn kind(&self) -> i64 {
        match self {
            Series::Link { .. } => 0,
            Series::Rule { .. } => 1,
            Series::Local => 2,
            Series::Network { .. } => 3,
        }
    }

    pub fn link(&self) -> &str {
        match self {
            Series::Link { link } | Series::Rule { link, .. } | Series::Network { link, .. } => {
                link
            }
            Series::Local => "",
        }
    }

    pub fn rule(&self) -> &str {
        match self {
            Series::Rule { rule, .. } => rule,
            _ => "",
        }
    }

    pub fn asn(&self) -> u32 {
        match self {
            Series::Network { asn, .. } => *asn,
            _ => 0,
        }
    }

    /// The series stored under these `series` table columns.
    pub fn from_columns(kind: i64, link: &str, rule: &str, asn: u32) -> Option<Series> {
        let link = link.to_owned();
        match kind {
            0 => Some(Series::Link { link }),
            1 => Some(Series::Rule {
                link,
                rule: rule.to_owned(),
            }),
            2 => Some(Series::Local),
            3 => Some(Series::Network { link, asn }),
            _ => None,
        }
    }
}

/// The minute rows between two snapshots. `previous` is `None` for the first
/// minute after a start: links and the local exit then count from zero.
pub fn minute(previous: Option<&Counters>, now: &Counters) -> Vec<Row> {
    let empty = Counters::default();
    let before = previous.unwrap_or(&empty);
    let zero = LinkCounters::default();
    let mut rows = Vec::with_capacity(now.links.len() + now.rules.len() + 1 + TOP_NETWORKS);

    for (link, counters) in &now.links {
        let old = before
            .links
            .iter()
            .find(|(id, _)| id == link)
            .map_or(&zero, |(_, counters)| counters);
        rows.push(Row {
            series: Series::Link { link: link.clone() },
            rx_bytes: delta(counters.rx_bytes, old.rx_bytes),
            tx_bytes: delta(counters.tx_bytes, old.tx_bytes),
            rx_packets: delta(counters.rx_packets, old.rx_packets),
            tx_packets: delta(counters.tx_packets, old.tx_packets),
            opened: delta(counters.opened, old.opened),
            closed: delta(counters.closed, old.closed),
            failed: delta(counters.failed, old.failed),
            drops: delta(counters.drops, old.drops),
            active: counters.active,
        });
    }

    rows.extend(carried(&now.rules).map(|((link, rule), bytes, active)| {
        Row::of_bytes(Series::Rule { link, rule }, bytes, active)
    }));

    let old = &before.local;
    let local = &now.local;
    rows.push(Row {
        series: Series::Local,
        rx_bytes: delta(local.rx_bytes, old.rx_bytes),
        tx_bytes: delta(local.tx_bytes, old.tx_bytes),
        opened: delta(local.opened, old.opened),
        closed: delta(local.closed, old.closed),
        failed: delta(local.failed, old.failed),
        active: local.active,
        rx_packets: 0,
        tx_packets: 0,
        drops: 0,
    });

    // The busiest networks first; ties break by series key, never by map order.
    let mut networks: Vec<(u128, Row)> = carried(&now.networks)
        .map(|((link, asn), bytes, active)| {
            let row = Row::of_bytes(Series::Network { link, asn }, bytes, active);
            (u128::from(row.rx_bytes) + u128::from(row.tx_bytes), row)
        })
        .collect();
    networks.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.series.cmp(&b.1.series)));
    rows.extend(networks.into_iter().take(TOP_NETWORKS).map(|(_, row)| row));
    rows
}

/// The keys of a minute that carried bytes or held an open flow. An idle key
/// gets no row: history stays as small as the traffic it describes.
fn carried<'a, K: Clone + 'a>(
    minute: &'a BTreeMap<K, (Bytes, usize)>,
) -> impl Iterator<Item = (K, Bytes, usize)> + 'a {
    minute
        .iter()
        .filter(|(_, (bytes, active))| bytes.rx + bytes.tx > 0 || *active > 0)
        .map(|(key, (bytes, active))| (key.clone(), *bytes, *active))
}

/// Growth of a counter. A counter that went down was reset: its new value is
/// everything counted since, so it becomes the row instead of a fake zero.
fn delta(now: u64, before: u64) -> u64 {
    if now >= before { now - before } else { now }
}
