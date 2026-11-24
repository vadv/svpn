//! Dashboard-only inner-IP accounting. Fold flow deltas at snapshot/retirement,
//! not on the packet path. Each axis counts the same bytes independently.

use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
    net::Ipv4Addr,
    time::Instant,
};

use serde::Serialize;

use super::{RoutedFlow, Target, Traffic};

/// Retain the largest buckets, with staging room for newly busy destinations.
const NAMED: usize = 256;

#[derive(Clone, Serialize)]
pub struct Breakdown<K> {
    pub named: HashMap<K, Traffic>,
    pub other: Traffic,
}

impl<K> Default for Breakdown<K> {
    fn default() -> Self {
        Self {
            named: HashMap::new(),
            other: Traffic::default(),
        }
    }
}

impl<K: Eq + Hash + Ord + Copy> Breakdown<K> {
    fn add(&mut self, key: K, traffic: Traffic) {
        self.named.entry(key).or_default().add(traffic);
        if self.named.len() >= 2 * NAMED {
            self.compact();
        }
    }

    fn compact(&mut self) {
        if self.named.len() <= NAMED {
            return;
        }
        let mut ranks: Vec<_> = self
            .named
            .iter()
            .map(|(&key, t)| (u128::from(t.rx_bytes) + u128::from(t.tx_bytes), key))
            .collect();
        ranks.select_nth_unstable_by(NAMED, |a, b| b.cmp(a));
        for (_, key) in &ranks[NAMED..] {
            if let Some(t) = self.named.remove(key) {
                self.other.add(t);
            }
        }
    }

    fn merge(&mut self, delta: &Self) {
        self.other.add(delta.other);
        // Compact once after merging: admission does not depend on hash iteration order.
        for (&key, &t) in &delta.named {
            self.named.entry(key).or_default().add(t);
        }
        self.compact();
    }
}

#[derive(Default, Clone, Serialize)]
pub struct Usage {
    pub exits: HashMap<usize, Traffic>,
    pub local: Traffic,
    pub destinations: Breakdown<Ipv4Addr>,
    pub networks: Breakdown<u32>,
    pub unknown_asn: Traffic,
    /// What the history rows are cut from; never part of the dashboard API.
    #[serde(skip)]
    pub split: Split,
}

/// Bytes by sticky rule and by network, each with its link; a link of `None`
/// is the local exit.
#[derive(Clone, Default, Serialize)]
pub struct Split {
    /// Sticky rule index (None: fallback) by link.
    pub rules: BTreeMap<(Option<usize>, Option<usize>), Traffic>,
    /// Network by link.
    pub networks: BTreeMap<(u32, Option<usize>), Traffic>,
}

impl Usage {
    pub(super) fn collect(&mut self, ip: Ipv4Addr, flow: &mut RoutedFlow) {
        let t = Traffic {
            tx_bytes: flow.traffic.tx_bytes - flow.reported.tx_bytes,
            rx_bytes: flow.traffic.rx_bytes - flow.reported.rx_bytes,
        };
        if t.tx_bytes == 0 && t.rx_bytes == 0 {
            return;
        }
        flow.reported = flow.traffic;
        let link = match flow.target {
            Target::Remote(owner) => Some(owner.epoch.link),
            Target::Direct(_) => None,
        };
        match link {
            Some(link) => self.exits.entry(link).or_default().add(t),
            None => self.local.add(t),
        }
        self.split
            .rules
            .entry((link, flow.rule))
            .or_default()
            .add(t);
        self.destinations.add(ip, t);
        match flow.asn {
            Some(asn) => {
                self.networks.add(asn, t);
                self.split.networks.entry((asn, link)).or_default().add(t);
            }
            None => self.unknown_asn.add(t),
        }
    }
}

#[derive(Clone, Serialize)]
pub struct UsageSample {
    pub session: Usage,
    pub interval: Usage,
    pub seconds: Option<f64>,
}

#[derive(Default)]
pub struct UsageMeter {
    pub(super) pending: Usage,
    session: Usage,
    last: Option<Instant>,
    /// Rule and network bytes since the last history minute took them.
    window: Split,
}

impl UsageMeter {
    pub(super) fn sample(&mut self, now: Instant) -> UsageSample {
        let mut interval = std::mem::take(&mut self.pending);
        interval.destinations.compact();
        interval.networks.compact();
        self.session.destinations.merge(&interval.destinations);
        self.session.networks.merge(&interval.networks);
        self.session.unknown_asn.add(interval.unknown_asn);
        self.session.local.add(interval.local);
        for (&link, &t) in &interval.exits {
            self.session.exits.entry(link).or_default().add(t);
        }
        // Sampled once a minute, not once a second: the intervals pile up.
        for (&key, &t) in &interval.split.rules {
            self.window.rules.entry(key).or_default().add(t);
        }
        for (&key, &t) in &interval.split.networks {
            self.window.networks.entry(key).or_default().add(t);
        }
        let seconds = self
            .last
            .replace(now)
            .map(|last| now.saturating_duration_since(last).as_secs_f64());
        UsageSample {
            session: self.session.clone(),
            interval,
            seconds,
        }
    }
}

impl UsageMeter {
    /// The rule and network bytes since the last call: one history minute.
    pub fn take_window(&mut self) -> Split {
        std::mem::take(&mut self.window)
    }
}

impl Traffic {
    fn add(&mut self, t: Traffic) {
        self.tx_bytes = self.tx_bytes.saturating_add(t.tx_bytes);
        self.rx_bytes = self.rx_bytes.saturating_add(t.rx_bytes);
    }
}
