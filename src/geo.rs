//! IPv4 destination → ASN/country grouping with weighted rendezvous order.
//! Rows are parsed once into sorted ranges; lookup happens only for new flows.
//! Country rows are strict because malformed mappings misroute traffic.
//!
//! shortcut: IPv4 only — IPv6 keeps balance behavior until real v6 traffic appears.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::Ipv4Addr,
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

/// Sanity floor for a complete DB-IP Lite database; ASN Lite holds ~400k
/// IPv4 rows, Country Lite is in the same range.
const MIN_ROWS: usize = 100_000;

/// Sorted, non-overlapping `(start, end, payload)` ranges; the payload is an
/// ASN for [`Geo::load`] and a packed country code for [`Geo::load_country`].
pub struct Geo {
    ranges: Vec<(u32, u32, u32)>,
}

impl Geo {
    /// Streaming parse of DB-IP ASN Lite CSV (`"first","last",asn,"org"`).
    /// Non-IPv4 and malformed rows are skipped; overlaps and truncation fail.
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_ranges(path, asn_row)
    }

    /// Load strict Country Lite IPv4 ranges (`ip_start,ip_end,country`).
    /// Reject malformed, inverted or overlapping rows with their row number.
    /// Skip IPv6 rows, which this IPv4-only table cannot use.
    pub fn load_country(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("country database: {}", path.display()))?;
        let mut rows: Vec<(u32, u32, u32, usize)> = Vec::with_capacity(410_000);
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = line.context("country database: read")?;
            let number = index + 1;
            match country_row(&line) {
                CountryRow::Range(start, end, payload) => {
                    ensure!(
                        start <= end,
                        "country database: row {number}: inverted range"
                    );
                    rows.push((start, end, payload, number));
                }
                CountryRow::Ipv6 => {}
                CountryRow::Invalid(category) => {
                    bail!("country database: row {number}: {category}")
                }
            }
        }
        rows.sort_unstable();
        ensure!(
            rows.len() >= MIN_ROWS,
            "country database: {} IPv4 rows, the file looks truncated",
            rows.len()
        );
        for pair in rows.windows(2) {
            ensure!(
                pair[0].1 < pair[1].0,
                "country database: overlapping ranges: rows {} and {}",
                pair[0].3,
                pair[1].3
            );
        }
        let ranges = rows
            .into_iter()
            .map(|(start, end, payload, _)| (start, end, payload))
            .collect();
        Ok(Self { ranges })
    }

    fn load_ranges(path: &Path, row: fn(&str) -> Option<(u32, u32, u32)>) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("geo database: {}", path.display()))?;
        let mut ranges = Vec::with_capacity(410_000);
        for line in BufReader::new(file).lines() {
            let line = line.context("geo database: read")?;
            let Some((start, end, payload)) = row(&line) else {
                continue; // IPv6 and garbage rows
            };
            ensure!(start <= end, "geo database: start > end in {line:?}");
            ranges.push((start, end, payload));
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

    /// The ASN or packed country code owning `ip`, if the database covers it.
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

/// Stable per-address key, disjoint from ASN and country keys.
pub fn ip_key(ip: Ipv4Addr) -> u64 {
    (1 << 32) | u64::from(u32::from(ip))
}

/// Country key in a separate rendezvous domain.
pub fn country_key(packed: u32) -> u64 {
    (1 << 33) | u64::from(packed)
}

/// `(country, asn)` key; the high tag prevents country aliases.
pub fn scoped_asn_key(packed: u32, asn: u32) -> u64 {
    (1 << 48) | (u64::from(packed) << 32) | u64::from(asn)
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
    let hash = rendezvous_hash(key, node);
    // (0,1]: the zero hash must not reach powf with exponent 0 log-domain edge.
    let u = ((hash >> 11) as f64 / 2f64.powi(53)).max(f64::MIN_POSITIVE);
    u.powf(1.0 / f64::from(weight))
}

/// The raw rendezvous hash: the u64 key big-endian bytes, then the node id.
/// Frozen by golden tests — the numeric group encodings above are hashed,
/// never the persisted string keys, so restored owners keep their groups.
#[doc(hidden)]
pub fn rendezvous_hash(key: u64, node: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(key.to_be_bytes());
    hasher.update(node.as_bytes());
    u64::from_be_bytes(hasher.finalize()[..8].try_into().expect("sha256 prefix"))
}

/// ASN Lite row `"first","last",asn,"org"`; trailing fields are ignored.
fn asn_row(line: &str) -> Option<(u32, u32, u32)> {
    let mut fields = line.split(',');
    let first = unquote(fields.next()?);
    let last = unquote(fields.next()?);
    let asn = unquote(fields.next()?);
    Some((parse_v4(first)?, parse_v4(last)?, asn.parse::<u32>().ok()?))
}

/// Country Lite row `ip_start,ip_end,country`; trailing fields are ignored.
enum CountryRow {
    Range(u32, u32, u32),
    /// Both address fields contain `:` — a valid IPv6 row, skipped because
    /// the table is IPv4-only.
    Ipv6,
    /// Corruption category for the row-numbered startup error.
    Invalid(&'static str),
}

fn country_row(line: &str) -> CountryRow {
    let mut fields = line.split(',');
    let (Some(first), Some(last), Some(country)) = (fields.next(), fields.next(), fields.next())
    else {
        return CountryRow::Invalid("malformed row");
    };
    let (first, last, country) = (unquote(first), unquote(last), unquote(country));
    if first.contains(':') && last.contains(':') {
        return CountryRow::Ipv6;
    }
    let (Some(start), Some(end)) = (parse_v4(first), parse_v4(last)) else {
        return CountryRow::Invalid("malformed IPv4 address");
    };
    match pack_country(country) {
        Some(payload) => CountryRow::Range(start, end, payload),
        None => CountryRow::Invalid("invalid country code"),
    }
}

/// Uppercased two-letter code packed into 16 bits: `"US"` and `"us"` → 0x5553;
/// [`unpack_country`] reverses it.
pub fn pack_country(code: &str) -> Option<u32> {
    match code.as_bytes() {
        [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
            Some(u32::from(a.to_ascii_uppercase()) << 8 | u32::from(b.to_ascii_uppercase()))
        }
        _ => None,
    }
}

/// Convert a packed country payload back to its two-letter code.
pub fn unpack_country(packed: u32) -> String {
    format!("{}{}", (packed >> 8) as u8 as char, packed as u8 as char)
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
