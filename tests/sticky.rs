//! Sticky block units: networks, durations, canonical keys, group ids.

use std::net::Ipv4Addr;
use std::time::Duration;

use svpn::sticky::{IpNet, Selector, StickyBlock, Via, group_key, parse_duration, validate_name};

// ── IpNet ──

#[test]
fn ip_net_parses_exact_and_prefixes() {
    let exact = IpNet::parse("1.2.3.4").unwrap();
    assert_eq!(
        (exact.addr, exact.prefix),
        ("1.2.3.4".parse::<Ipv4Addr>().unwrap(), 32)
    );
    assert!(exact.contains(Ipv4Addr::new(1, 2, 3, 4)));
    assert!(!exact.contains(Ipv4Addr::new(1, 2, 3, 5)));

    let net = IpNet::parse("5.6.0.0/16").unwrap();
    assert!(net.contains(Ipv4Addr::new(5, 6, 255, 255)));
    assert!(!net.contains(Ipv4Addr::new(5, 7, 0, 0)));
    let zero = IpNet::parse("0.0.0.0/0").unwrap();
    assert!(zero.contains(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn ip_net_rejects_garbage_and_host_bits() {
    for text in [
        "x",
        "1.2.3.4/33",
        "1.2.3.4/-1",
        "5.6.7.8/16",
        "1.2.3.256",
        "1.2.3.4/",
    ] {
        assert!(IpNet::parse(text).is_err(), "{text}");
    }
}

// ── durations ──

#[test]
fn durations_accept_seconds_minutes_hours() {
    assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
    assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
    assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
    assert_eq!(parse_duration("0s").unwrap(), Duration::ZERO);
    for text in ["", "5", "m", "1d", "-5s", "1.5h"] {
        assert!(parse_duration(text).is_err(), "{text}");
    }
}

// ── names ──

#[test]
fn dns_names_are_strictly_validated() {
    for name in ["a.example", "claude.ai", "printer.lan", "a-b.c-d.e"] {
        assert!(validate_name(name).is_ok(), "{name}");
    }
    for name in [
        "",
        "A.example",
        "a..b",
        "-a",
        "a-.",
        &"a".repeat(254),
        &format!("{}.example", "a".repeat(64)),
    ] {
        assert!(validate_name(name).is_err(), "{name}");
    }
}

// ── canonical keys and group ids ──

fn block(selector: Selector) -> StickyBlock {
    StickyBlock {
        label: "x".into(),
        selector,
        via: Via::Servers(vec!["nl1".into()]),
        every: Duration::from_secs(300),
    }
}

#[test]
fn canonical_keys_are_sorted_and_stable() {
    assert_eq!(
        block(Selector::Names(vec![
            "claude.ai".into(),
            "anthropic.com".into()
        ]))
        .canonical_key(),
        "name:anthropic.com,claude.ai"
    );
    assert_eq!(
        block(Selector::Countries(vec!["NL".into(), "DE".into()])).canonical_key(),
        "cc:DE,NL"
    );
    assert_eq!(
        block(Selector::Ips(vec![
            IpNet::parse("5.6.0.0/16").unwrap(),
            IpNet::parse("1.2.3.4").unwrap(),
        ]))
        .canonical_key(),
        "ip:1.2.3.4,5.6.0.0/16"
    );
    assert_eq!(
        block(Selector::Asn(vec![13335])).canonical_key(),
        "asn:13335"
    );
}

#[test]
fn group_keys_are_stable_and_disjoint() {
    let a = group_key("name:anthropic.com,claude.ai");
    let b = group_key("name:claude.ai,anthropic.com");
    assert_ne!(a, b, "canonical sorting prevents key collisions");
    assert_eq!(
        a,
        group_key("name:anthropic.com,claude.ai"),
        "stable across runs"
    );
    assert_ne!(group_key("asn:13335"), group_key("cc:DE,NL"));
}

// ── resolve cache (two-miss purge) ──

#[test]
fn resolve_cache_purges_after_two_misses() {
    let mut cache = svpn::sticky::ResolveCache::default();
    let a = Ipv4Addr::new(1, 1, 1, 1);
    let b = Ipv4Addr::new(2, 2, 2, 2);
    let (set, purged) = cache.refresh(&[a, b]);
    assert_eq!(set.len(), 2);
    assert_eq!(purged, 0);

    // One miss: the disappeared IP survives.
    let (set, purged) = cache.refresh(&[b]);
    assert!(set.contains(&a), "a single miss keeps the IP pinned");
    assert_eq!(purged, 0);

    // Two misses: it leaves the set.
    let (set, purged) = cache.refresh(&[b]);
    assert!(!set.contains(&a), "a second miss purges the IP");
    assert_eq!(purged, 1);
    assert_eq!(set.len(), 1);

    // A returning IP re-enters and survives again.
    let (set, _) = cache.refresh(&[a, b]);
    assert_eq!(set.len(), 2);
}

#[test]
fn resolve_cache_dedups_and_keeps_order_irrelevant() {
    let mut cache = svpn::sticky::ResolveCache::default();
    let ip = Ipv4Addr::new(9, 9, 9, 9);
    let (set, _) = cache.refresh(&[ip, ip]);
    assert_eq!(set.len(), 1);
}
