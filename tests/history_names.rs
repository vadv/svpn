//! Organization names of networks from the ASN CSV: one pass, whatever is asked.

use std::{collections::BTreeSet, path::PathBuf};

use svpn::history::names;

// ── rows ──

#[test]
fn names_come_from_quoted_and_plain_rows_and_skip_what_is_no_network() {
    let path = csv(
        "names",
        "first,last,asn,org\n\
         \"1.0.0.0\",\"1.0.0.255\",\"13335\",\"Cloudflare, Inc.\"\n\
         \"2.0.0.0\",\"2.0.0.255\",15169,Google LLC\n\
         \"2001:db8::\",\"2001:db8::ff\",\"64512\",\"An IPv6 row\"\n\
         \"3.0.0.0\",\"3.0.0.255\",\"14061\",\"DigitalOcean, LLC\"\n\
         \"4.0.0.0\",\"4.0.0.255\",\"14061\",\"DigitalOcean, LLC\",\"more, fields\"\n\
         \"5.0.0.0\",\"5.0.0.255\",\"16509\",\"Amazon.com, Inc. \"\"Amazon\"\"\"\n\
         \"6.0.0.0\",\"6.0.0.255\",\"6762\",\"\"\n\
         \"7.0.0.0\",\"7.0.0.255\",\"12345,67890\",\"Two networks in one field\"\n",
    );
    let wanted: BTreeSet<u32> = [16509, 14061, 15169, 6762, 12345, 13335]
        .into_iter()
        .collect();

    let found = names::lookup(&path, &wanted).unwrap();

    // The first row of a network names it; later ones repeat it.
    assert_eq!(
        found,
        vec![
            (13335, "Cloudflare, Inc.".to_owned()),
            (15169, "Google LLC".to_owned()),
            (14061, "DigitalOcean, LLC".to_owned()),
            (16509, "Amazon.com, Inc. \"Amazon\"".to_owned()),
        ]
    );
}

#[test]
fn what_is_not_asked_for_is_not_read_twice_and_a_missing_file_is_an_error() {
    let path = csv(
        "wanted",
        "\"1.0.0.0\",\"1.0.0.255\",\"1\",\"One\"\n\"2.0.0.0\",\"2.0.0.255\",\"2\",\"Two\"\n",
    );
    let only_two: BTreeSet<u32> = [2].into_iter().collect();
    assert_eq!(
        names::lookup(&path, &only_two).unwrap(),
        [(2, "Two".to_owned())]
    );
    assert_eq!(
        names::lookup(&path, &BTreeSet::new()).unwrap(),
        Vec::<(u32, String)>::new()
    );
    assert!(names::lookup(&PathBuf::from("/nowhere/asn.csv"), &only_two).is_err());
}

// ── helpers ──

fn csv(tag: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("svpn history names {tag} {}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("asn.csv");
    std::fs::write(&path, body).unwrap();
    path
}
