//! Sticky exit grouping: IPv4 destination → ASN, weighted rendezvous order.
//!
//! The parsed table is a sorted array of `(start, end, asn)` — ~4.8 MB of RAM
//! for DB-IP ASN Lite. Parsed once at startup (~0.4 s measured on the target
//! router); lookup runs only for a new flow, never per packet.
//!
//! shortcut: IPv4 only — IPv6 traffic keeps the balance behavior until real
//! v6 traffic appears in the pool.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::Ipv4Addr,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

/// Sanity floor: a complete DB-IP ASN Lite holds ~400k IPv4 rows.
const MIN_ROWS: usize = 100_000;

/// Sorted, non-overlapping `(start, end, asn)` ranges.
pub struct Geo {
    ranges: Vec<(u32, u32, u32)>,
}

impl Geo {
    /// Streaming parse of DB-IP ASN Lite CSV (`"first","last",asn,"org"`).
    /// Non-IPv4 and malformed rows are skipped; overlaps and truncation fail.
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("geo database: {}", path.display()))?;
        let mut ranges = Vec::with_capacity(410_000);
        for line in BufReader::new(file).lines() {
            let line = line.context("geo database: read")?;
            let mut fields = line.split(',');
            let (Some(first), Some(last), Some(asn)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let (Some(start), Some(end), Ok(asn)) = (
                parse_v4(unquote(first)),
                parse_v4(unquote(last)),
                unquote(asn).parse::<u32>(),
            ) else {
                continue; // IPv6 and garbage rows
            };
            ensure!(start <= end, "geo database: start > end in {line:?}");
            ranges.push((start, end, asn));
        }
        ranges.sort_unstable();
        ensure!(
            ranges.len() >= MIN_ROWS,
            "geo database: {} IPv4 rows, the file looks truncated",
            ranges.len()
        );
        for pair in ranges.windows(2) {
            ensure!(
                pair[0].1 < pair[1].0,
                "geo database: overlapping ranges at {:#010x}",
                pair[1].0
            );
        }
        Ok(Self { ranges })
    }

    /// The ASN owning `ip`, if the database covers it.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<u32> {
        let ip = u32::from(ip);
        self.ranges
            .binary_search_by(|&(start, end, _)| {
                if ip < start {
                    std::cmp::Ordering::Greater
                } else if ip > end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()
            .map(|index| self.ranges[index].2)
    }

    pub fn rows(&self) -> usize {
        self.ranges.len()
    }

    /// Direct construction for tests and synthetic e2e databases.
    #[doc(hidden)]
    pub fn from_ranges(mut ranges: Vec<(u32, u32, u32)>) -> Self {
        ranges.sort_unstable();
        Self { ranges }
    }
}

/// Rendezvous key for a database group.
pub fn asn_key(asn: u32) -> u64 {
    u64::from(asn)
}

/// Rendezvous key for an uncovered destination: stable per-address stickiness
/// without any persistence, in a separate domain from ASN keys.
pub fn ip_key(ip: Ipv4Addr) -> u64 {
    (1 << 32) | u64::from(u32::from(ip))
}

/// Weighted rendezvous order: node indices, most preferred first.
/// Efraimidis–Spirakis key `u^(1/w)` gives shares proportional to weights;
/// equal weights degenerate to plain rendezvous hashing.
pub fn rendezvous(key: u64, nodes: &[(String, u32)]) -> Vec<usize> {
    let mut scored: Vec<(f64, usize)> = nodes
        .iter()
        .enumerate()
        .map(|(index, (id, weight))| (score(key, id, *weight), index))
        .collect();
    scored.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, index)| index).collect()
}

fn score(key: u64, node: &str, weight: u32) -> f64 {
    let mut hasher = Sha256::new();
    hasher.update(key.to_be_bytes());
    hasher.update(node.as_bytes());
    let hash = u64::from_be_bytes(hasher.finalize()[..8].try_into().expect("sha256 prefix"));
    // (0,1]: the zero hash must not reach powf with exponent 0 log-domain edge.
    let u = ((hash >> 11) as f64 / 2f64.powi(53)).max(f64::MIN_POSITIVE);
    u.powf(1.0 / f64::from(weight))
}

fn unquote(field: &str) -> &str {
    field
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(field)
}

fn parse_v4(text: &str) -> Option<u32> {
    let mut value: u32 = 0;
    let mut octets = 0u8;
    let mut octet: u32 = 0;
    let mut digits = false;
    for &byte in text.as_bytes() {
        match byte {
            b'0'..=b'9' => {
                octet = octet * 10 + u32::from(byte - b'0');
                if octet > 255 {
                    return None;
                }
                digits = true;
            }
            b'.' if digits && octets < 3 => {
                value = (value << 8) | octet;
                octet = 0;
                digits = false;
                octets += 1;
            }
            _ => return None,
        }
    }
    if digits && octets == 3 {
        Some((value << 8) | octet)
    } else {
        None
    }
}
