//! Explicit sticky routing: ordered first-match groups (names/countries/ips/asn).

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::Ipv4Addr,
    time::Duration,
};

use anyhow::{Result, bail, ensure};

/// Default re-resolve interval for name selectors.
pub const DEFAULT_EVERY: Duration = Duration::from_secs(300);
/// Lower bound keeps a misconfigured file from turning into a resolve storm.
pub const MIN_EVERY: Duration = Duration::from_secs(5);

/// IPv4 network: an exact address is a /32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpNet {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl IpNet {
    pub fn parse(text: &str) -> Result<Self> {
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => {
                let prefix: u8 = prefix.parse().map_err(|_| bad_net())?;
                (addr, Some(prefix))
            }
            None => (text, None),
        };
        let addr: Ipv4Addr = addr.parse().map_err(|_| bad_net())?;
        let prefix = prefix.unwrap_or(32);
        ensure!(prefix <= 32, "prefix length exceeds 32");
        let host = u32::from(addr) & !mask(prefix);
        ensure!(host == 0, "host bits must be zero");
        Ok(IpNet { addr, prefix })
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask(self.prefix) == u32::from(self.addr)
    }

    fn canon(self) -> String {
        if self.prefix == 32 {
            self.addr.to_string()
        } else {
            format!("{}/{}", self.addr, self.prefix)
        }
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn bad_net() -> anyhow::Error {
    anyhow::anyhow!("invalid IPv4 address or network")
}

impl std::fmt::Display for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Selector::Names(names) => write!(f, "name: {}", names.join(", ")),
            Selector::Countries(codes) => write!(f, "cc: {}", codes.join(", ")),
            Selector::Ips(nets) => {
                let nets: Vec<String> = nets.iter().map(|net| net.canon()).collect();
                write!(f, "ip: {}", nets.join(", "))
            }
            Selector::Asn(asns) => {
                let asns: Vec<String> = asns.iter().map(u32::to_string).collect();
                write!(f, "asn: {}", asns.join(", "))
            }
        }
    }
}

impl std::fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Via::Servers(servers) => write!(f, "servers: {}", servers.join(", ")),
            Via::Local => f.write_str("local"),
        }
    }
}

/// Group membership selector; exactly one per sticky block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    Names(Vec<String>),
    Countries(Vec<String>),
    Ips(Vec<IpNet>),
    Asn(Vec<u32>),
}

/// Where matched destinations go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Via {
    Servers(Vec<String>),
    Local,
}

/// `via` resolved against the configured pool: labels → link indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedVia {
    Links(Vec<usize>),
    Local,
}

/// One `sticky "label" {…}` block.
#[derive(Clone, Debug)]
pub struct StickyBlock {
    pub label: String,
    pub selector: Selector,
    pub via: Via,
    pub every: Duration,
}

impl StickyBlock {
    /// Canonical persistence key; stable under config reorder.
    pub fn canonical_key(&self) -> String {
        let (kind, mut members): (&str, Vec<String>) = match &self.selector {
            Selector::Names(names) => ("name", names.to_vec()),
            Selector::Countries(codes) => ("cc", codes.iter().map(|c| c.to_uppercase()).collect()),
            Selector::Ips(nets) => ("ip", nets.iter().map(|n| n.canon()).collect()),
            Selector::Asn(asns) => ("asn", asns.iter().map(u32::to_string).collect()),
        };
        members.sort();
        members.dedup();
        format!("{kind}:{}", members.join(","))
    }

    /// Cross-block checks: labels unique, canonical keys unique, via labels known.
    pub fn validate_all(blocks: &[StickyBlock], server_labels: &HashSet<&str>) -> Result<()> {
        let mut labels = HashSet::new();
        let mut keys = HashSet::new();
        for block in blocks {
            ensure!(
                labels.insert(&block.label),
                "duplicate sticky label {}",
                block.label
            );
            ensure!(
                keys.insert(block.canonical_key()),
                "duplicate sticky selector {}",
                block.canonical_key()
            );
            if let Via::Servers(via) = &block.via {
                for label in via {
                    ensure!(
                        server_labels.contains(label.as_str()),
                        "sticky {}: unknown server label {label}",
                        block.label
                    );
                }
            }
        }
        Ok(())
    }
}

/// Runtime view of a sticky block: config plus the resolver-maintained IP
/// set for name selectors.
pub struct RuntimeSticky {
    pub block: StickyBlock,
    /// Resolved name IPs (H6 resolver); selectors other than names ignore it.
    pub resolved: HashSet<Ipv4Addr>,
}

impl RuntimeSticky {
    pub fn new(block: StickyBlock) -> Self {
        Self {
            block,
            resolved: HashSet::new(),
        }
    }

    /// First-match membership test for one destination.
    pub fn matches(
        &self,
        ip: Ipv4Addr,
        country: Option<&crate::geo::Geo>,
        geo: Option<&crate::geo::Geo>,
    ) -> bool {
        match &self.block.selector {
            Selector::Names(_) => self.resolved.contains(&ip),
            Selector::Countries(codes) => country
                .and_then(|table| table.lookup(ip))
                .is_some_and(|packed| codes.contains(&unpack(packed))),
            Selector::Ips(nets) => nets.iter().any(|net| net.contains(ip)),
            Selector::Asn(asns) => geo
                .and_then(|table| table.lookup(ip))
                .is_some_and(|asn| asns.contains(&asn)),
        }
    }
}

fn unpack(packed: u32) -> String {
    crate::geo::unpack_country(packed)
}

/// Stable u64 rendezvous group id for a canonical sticky key (FNV-1a).
pub fn group_key(canonical: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in canonical.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Duration `N(s|m|h)`; the single duration syntax for the whole config.
/// Untrusted input never panics: non-UTF-8-safe slicing is avoided and the
/// product is checked.
pub fn parse_duration(text: &str) -> Result<Duration> {
    let (digits, scale) = if let Some(digits) = text.strip_suffix('s') {
        (digits, 1u64)
    } else if let Some(digits) = text.strip_suffix('m') {
        (digits, 60)
    } else if let Some(digits) = text.strip_suffix('h') {
        (digits, 3600)
    } else {
        bail!("invalid duration, expected Ns/Nm/Nh")
    };
    let secs: u64 = digits
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration"))?;
    let total = secs
        .checked_mul(scale)
        .ok_or_else(|| anyhow::anyhow!("duration exceeds the supported range"))?;
    Ok(Duration::from_secs(total))
}

/// Validate a DNS name: ASCII lowercase host, ≤253 chars, 1..=8 per block.
pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 253,
        "invalid DNS name length"
    );
    ensure!(
        name.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'),
        "DNS names must be lowercase ASCII letters, digits, '-' or '.'"
    );
    for label in name.split('.') {
        ensure!(!label.is_empty() && label.len() <= 63, "invalid DNS label");
        ensure!(
            !label.starts_with('-') && !label.ends_with('-'),
            "DNS labels must not start or end with '-'"
        );
    }
    Ok(())
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canon())
    }
}

/// Resolver → hub delivery: one refresh of one name block.
pub struct Update {
    pub index: usize,
    /// Surviving set after this refresh; empty on a failed lookup.
    pub ips: HashSet<Ipv4Addr>,
    pub purged: usize,
    pub ok: bool,
}

/// Two-miss purge cache for one name block: an IP not seen in the last two
/// refreshes leaves the pinned set (it may have been re-leased to a CDN).
#[derive(Default)]
pub struct ResolveCache {
    seq: u64,
    seen: HashMap<Ipv4Addr, u64>,
}

impl ResolveCache {
    /// Record one refresh; returns the surviving set and the purge count.
    pub fn refresh(&mut self, ips: &[Ipv4Addr]) -> (HashSet<Ipv4Addr>, usize) {
        self.seq += 1;
        for ip in ips {
            self.seen.insert(*ip, self.seq);
        }
        let before = self.seen.len();
        self.seen.retain(|_, seen| self.seq - *seen < 2);
        (
            self.seen.keys().copied().collect(),
            before - self.seen.len(),
        )
    }
}
