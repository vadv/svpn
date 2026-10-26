//! Geo table: CSV parsing, lookup boundaries, rendezvous distribution.

use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use svpn::geo::{
    Geo, asn_key, country_key, ip_key, pack_country, rendezvous, scoped_asn_key, unpack_country,
};

struct Csv(PathBuf);

impl Csv {
    fn of(rows: &[String]) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "svpn-geo-test-{}-{}.csv",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = std::fs::File::create(&path).unwrap();
        for row in rows {
            writeln!(file, "{row}").unwrap();
        }
        Self(path)
    }
}

impl Drop for Csv {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// MIN_ROWS is 100k; fill with distinct /24s inside 10/8.
fn full_rows(extra: &[String]) -> Vec<String> {
    let mut rows: Vec<String> = (0..100_000u32)
        .map(|i| {
            let base = 0x0A00_0000u32 + i * 256;
            format!(
                "\"{}\",\"{}\",{},\"X\"",
                Ipv4Addr::from(base),
                Ipv4Addr::from(base + 255),
                100 + i % 500
            )
        })
        .collect();
    rows.extend(extra.iter().cloned());
    rows
}

/// The same fill in Country Lite format `ip_start,ip_end,country`.
fn full_country_rows(extra: &[String]) -> Vec<String> {
    let mut rows: Vec<String> = (0..100_000u32)
        .map(|i| {
            let base = 0x0A00_0000u32 + i * 256;
            format!("{},{},US", Ipv4Addr::from(base), Ipv4Addr::from(base + 255))
        })
        .collect();
    rows.extend(extra.iter().cloned());
    rows
}

// ── parsing ──

#[test]
fn skips_garbage_v6_and_bad_asn_rows() {
    let extra = vec![
        "garbage line without commas".to_string(),
        "\"2607:6bc0::\",\"2607:6bc0::ffff\",399358,\"v6 skipped\"".to_string(),
        "\"1.2.3.4\",\"1.2.3.4\",\"not-a-number\",\"bad asn skipped\"".to_string(),
        "\"300.1.1.1\",\"300.1.1.2\",7,\"bad ip skipped\"".to_string(),
        // More than three separators: must be skipped, not wrap the octet
        // counter (regression: u8 overflow panicked debug / wrapped release).
        format!(
            "\"{}1.2.3.4\",\"1.2.3.5\",7,\"overflow skipped\"",
            "0.".repeat(256)
        ),
    ];
    let csv = Csv::of(&full_rows(&extra));
    let geo = Geo::load(csv.0.as_path()).unwrap();
    assert_eq!(geo.rows(), 100_000);
}

#[test]
fn rejects_truncated_database() {
    let csv = Csv::of(&["\"1.0.0.0\",\"1.0.0.255\",13335,\"Cloudflare\"".to_string()]);
    assert!(Geo::load(csv.0.as_path()).is_err());
}

#[test]
fn rejects_overlapping_ranges() {
    let rows = full_rows(&["\"10.0.0.1\",\"10.0.0.2\",2,\"overlap\"".to_string()]);
    let csv = Csv::of(&rows);
    assert!(Geo::load(csv.0.as_path()).is_err());
}

#[test]
fn rejects_inverted_ranges() {
    let mut rows = full_rows(&[]);
    rows[0] = "\"10.0.0.255\",\"10.0.0.0\",100,\"inverted\"".to_string();
    let csv = Csv::of(&rows);
    assert!(Geo::load(csv.0.as_path()).is_err());
}

// ── country database ──

#[test]
fn country_rejects_malformed_row_in_large_db() {
    // 100k valid rows satisfy the floor; corruption must still fail startup.
    let rows = full_country_rows(&["garbage line without commas".to_string()]);
    let message = country_error(&rows);
    assert!(message.contains("row 100001"), "{message}");
    assert!(message.contains("malformed row"), "{message}");
}

#[test]
fn country_rejects_malformed_ipv4_address() {
    for row in [
        "300.1.1.1,300.1.1.2,US", // octet out of range
        "1.2.3,1.2.4,US",         // missing octet
        "::1,1.2.3.4,US",         // mixed families is corruption, not a v6 row
    ] {
        let message = country_error(&full_country_rows(&[row.to_string()]));
        assert!(
            message.contains("malformed IPv4 address"),
            "{row}: {message}"
        );
    }
}

#[test]
fn country_rejects_invalid_country_code() {
    for row in [
        "11.0.0.0,11.0.0.255,USA", // three letters
        "12.0.0.0,12.0.0.255,",    // empty code
        "13.0.0.0,13.0.0.255,u5",  // non-letter
    ] {
        let message = country_error(&full_country_rows(&[row.to_string()]));
        assert!(message.contains("invalid country code"), "{row}: {message}");
    }
}

#[test]
fn country_rejects_inverted_country_range() {
    let mut rows = full_country_rows(&[]);
    rows[0] = "10.0.0.255,10.0.0.0,US".to_string();
    let message = country_error(&rows);
    assert!(message.contains("row 1"), "{message}");
    assert!(message.contains("inverted range"), "{message}");
}

#[test]
fn country_rejects_overlapping_country_ranges() {
    let rows = full_country_rows(&["10.0.0.64,10.0.0.128,DE".to_string()]);
    let message = country_error(&rows);
    assert!(message.contains("rows 1 and 100001"), "{message}");
}

#[test]
fn country_skips_ipv6_rows() {
    let extra = vec![
        "2001:db8::,2001:db8::ffff:ffff:ffff:ffff:ffff:ffff,JP".to_string(),
        "::ffff:1.0.0.0,::ffff:1.0.0.255,US".to_string(),
    ];
    let csv = Csv::of(&full_country_rows(&extra));
    let geo = Geo::load_country(csv.0.as_path()).unwrap();
    assert_eq!(geo.rows(), 100_000);
    // The skipped v6-mapped row does not cover the IPv4 address.
    assert_eq!(geo.lookup(Ipv4Addr::new(1, 0, 0, 5)), None);
}

#[test]
fn country_lookup_hits_ipv4_boundaries() {
    let extra = vec![
        "0.0.0.0,0.0.0.0,DE".to_string(),
        "255.255.255.255,255.255.255.255,JP".to_string(),
    ];
    let csv = Csv::of(&full_country_rows(&extra));
    let geo = Geo::load_country(csv.0.as_path()).unwrap();
    let us = pack_country("US");
    assert_eq!(geo.lookup(Ipv4Addr::new(0, 0, 0, 0)), pack_country("DE"));
    assert_eq!(geo.lookup(Ipv4Addr::new(0, 0, 0, 1)), None, "gap after /32");
    let first = 0x0A00_0000u32;
    assert_eq!(geo.lookup(Ipv4Addr::from(first)), us, "range start");
    assert_eq!(geo.lookup(Ipv4Addr::from(first + 255)), us, "range end");
    assert_eq!(
        geo.lookup(Ipv4Addr::new(255, 255, 255, 254)),
        None,
        "gap before the last /32"
    );
    assert_eq!(
        geo.lookup(Ipv4Addr::new(255, 255, 255, 255)),
        pack_country("JP")
    );
}

#[test]
fn country_errors_never_include_row_contents() {
    let cases = [
        ("9.9.9.9,SECRETFIELD", "malformed row"),
        ("9.9.9.300,9.9.9.301,US", "malformed IPv4 address"),
        ("9.9.9.0,9.9.9.255,SECRETCC", "invalid country code"),
        ("9.9.9.9,9.9.9.8,US", "inverted range"),
    ];
    for (row, category) in cases {
        let message = country_error(&full_country_rows(&[row.to_string()]));
        assert!(message.contains(category), "{row}: {message}");
        assert!(message.contains("row 100001"), "{row}: {message}");
        assert!(!message.contains(row), "{row}: {message}");
        assert!(!message.contains("SECRET"), "{row}: {message}");
    }
    // The overlap diagnostic names rows, never addresses or codes.
    let rows = full_country_rows(&["10.0.0.64,10.0.0.128,DE".to_string()]);
    let message = country_error(&rows);
    assert!(message.contains("overlapping ranges"), "{message}");
    assert!(message.contains("rows 1 and 100001"), "{message}");
    assert!(!message.contains("10.0.0.64"), "{message}");
    assert!(!message.contains("10.0.0.128"), "{message}");
}

#[test]
fn country_codes_pack_roundtrip_and_key_domains_stay_disjoint() {
    assert_eq!(pack_country("us"), Some(0x5553));
    assert_eq!(pack_country("US"), Some(0x5553));
    for bad in ["", "U", "USA", "U5", "US "] {
        assert_eq!(pack_country(bad), None, "{bad:?}");
    }
    assert_eq!(unpack_country(0x5553), "US");
    assert_eq!(unpack_country(0x5255), "RU");
    // ASN keys live in [0, 2^32), bare IPs above them, then country and
    // scoped-ASN keys — no rendezvous collisions across group kinds.
    assert!(asn_key(u32::MAX) < ip_key(Ipv4Addr::new(0, 0, 0, 0)));
    assert!(ip_key(Ipv4Addr::new(255, 255, 255, 255)) < country_key(0));
    assert!(country_key(0xFFFF) < scoped_asn_key(0, 0));
    assert_ne!(asn_key(0x5553), country_key(0x5553));
    assert_ne!(
        scoped_asn_key(pack_country("CH").unwrap(), 64500),
        scoped_asn_key(pack_country("CL").unwrap(), 64500),
        "country bits must not be overwritten by the scoped domain tag"
    );
}

// ── lookup ──

#[test]
fn lookup_hits_boundaries_and_misses_gaps() {
    let csv = Csv::of(&full_rows(&[]));
    let geo = Geo::load(csv.0.as_path()).unwrap();
    let first = 0x0A00_0000u32;
    assert_eq!(geo.lookup(Ipv4Addr::from(first)), Some(100), "range start");
    assert_eq!(
        geo.lookup(Ipv4Addr::from(first + 255)),
        Some(100),
        "range end"
    );
    assert_eq!(geo.lookup(Ipv4Addr::from(first - 1)), None, "gap before");
    assert_eq!(
        geo.lookup(Ipv4Addr::new(8, 8, 8, 8)),
        None,
        "outside the table"
    );
}

// ── rendezvous ──

fn nodes(weights: &[u32]) -> Vec<(String, u32)> {
    weights
        .iter()
        .enumerate()
        .map(|(i, w)| (format!("node-{i}.example:22"), *w))
        .collect()
}

#[test]
fn rendezvous_is_deterministic_and_complete() {
    let first = rendezvous(asn_key(13335), &nodes(&[1, 1, 1]));
    assert_eq!(first, rendezvous(asn_key(13335), &nodes(&[1, 1, 1])));
    let mut sorted = first.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, vec![0, 1, 2], "a full permutation");
}

#[test]
fn rendezvous_equal_weights_are_uniform() {
    let nodes = nodes(&[1, 1, 1]);
    let mut wins = [0usize; 3];
    for asn in 1..10_000u32 {
        wins[rendezvous(asn_key(asn), &nodes)[0]] += 1;
    }
    for (i, w) in wins.iter().enumerate() {
        let share = *w as f64 / 9999.0;
        assert!(
            (share - 1.0 / 3.0).abs() < 0.05,
            "node {i} share {share:.2} far from 0.33"
        );
    }
}

#[test]
fn rendezvous_weights_scale_shares() {
    let nodes = nodes(&[3, 1, 1]);
    let mut wins = [0usize; 3];
    for asn in 1..10_000u32 {
        wins[rendezvous(asn_key(asn), &nodes)[0]] += 1;
    }
    let share = |i: usize| wins[i] as f64 / 9999.0;
    assert!(
        (0.45..=0.75).contains(&share(0)),
        "weight 3 → ~0.60, got {:.2}",
        share(0)
    );
    assert!(
        (0.10..=0.30).contains(&share(1)),
        "weight 1 → ~0.20, got {:.2}",
        share(1)
    );
    assert!(
        (0.10..=0.30).contains(&share(2)),
        "weight 1 → ~0.20, got {:.2}",
        share(2)
    );
}

#[test]
fn rendezvous_resilient_to_node_addition() {
    let three = nodes(&[1, 1, 1]);
    let four = nodes(&[1, 1, 1, 1]);
    let mut moved = 0usize;
    let mut moved_to_new = 0usize;
    for asn in 1..5_000u32 {
        let before = rendezvous(asn_key(asn), &three)[0];
        let after = rendezvous(asn_key(asn), &four)[0];
        if before != after {
            moved += 1;
            if after == 3 {
                moved_to_new += 1;
            }
        }
    }
    assert_eq!(
        moved, moved_to_new,
        "existing nodes must not swap groups between themselves"
    );
    assert!(moved < 5_000 / 2, "~1/4 expected, got {moved}");
}

#[test]
fn ip_key_domain_differs_from_asn() {
    assert_ne!(ip_key(Ipv4Addr::new(1, 2, 3, 4)), asn_key(0x0102_0304));
}

#[test]
fn legacy_group_hashing_is_frozen() {
    // Golden values freeze the legacy hash inputs (spec §4): the u64 key
    // big-endian bytes, then the node id — numeric group encodings only,
    // never the persisted string keys. A change here reshuffles every
    // restored owner's group.
    let node = "192.0.2.1:22";
    assert_eq!(
        svpn::geo::rendezvous_hash(asn_key(100), node),
        0x32a1_35d0_0e96_49a6,
        "global ASN: u64 ASN big-endian + node"
    );
    assert_eq!(
        svpn::geo::rendezvous_hash(ip_key(Ipv4Addr::new(1, 2, 3, 4)), node),
        0x2ad0_5776_bbeb_5ba4,
        "uncovered IP: 1 << 32 | u32 address + node"
    );
}

/// The strict Country loader's startup error text.
fn country_error(rows: &[String]) -> String {
    let csv = Csv::of(rows);
    match Geo::load_country(csv.0.as_path()) {
        Err(error) => error.to_string(),
        Ok(geo) => panic!("country database unexpectedly loaded: {} rows", geo.rows()),
    }
}
