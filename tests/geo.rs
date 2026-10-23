//! Geo table: CSV parsing, lookup boundaries, rendezvous distribution.

use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use svpn::geo::{Geo, asn_key, ip_key, rendezvous};

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

// ── parsing ──

#[test]
fn skips_garbage_v6_and_bad_asn_rows() {
    let extra = vec![
        "garbage line without commas".to_string(),
        "\"2607:6bc0::\",\"2607:6bc0::ffff\",399358,\"v6 skipped\"".to_string(),
        "\"1.2.3.4\",\"1.2.3.4\",\"not-a-number\",\"bad asn skipped\"".to_string(),
        "\"300.1.1.1\",\"300.1.1.2\",7,\"bad ip skipped\"".to_string(),
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
