//! Address pair pool: flock allocation semantics (#181).

use std::net::Ipv4Addr;
use std::path::PathBuf;

use svpn::addrpool::*;

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("svpn-addrpool-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn pool_pairs_and_index_round_trip() {
    for n in [0, 1, 254] {
        let (server, client) = pair_of(n);
        assert_eq!(server, Ipv4Addr::new(10, 77, n, 1));
        assert_eq!(client, Ipv4Addr::new(10, 77, n, 2));
        assert_eq!(pool_index(server, client), Some(n));
    }
    assert_eq!(
        pool_index(Ipv4Addr::new(10, 77, 0, 1), Ipv4Addr::new(10, 77, 1, 2)),
        None
    );
    assert_eq!(
        pool_index(Ipv4Addr::new(192, 168, 5, 1), Ipv4Addr::new(192, 168, 5, 2)),
        None
    );
}

#[test]
fn claim_takes_first_free_skips_held_and_reuses_stale_files() {
    let dir = tempdir("reuse");
    let (_a, s0, _) = claim(dir.as_path(), 0).unwrap();
    assert_eq!(s0, Ipv4Addr::new(10, 77, 0, 1));
    // A stale file without a lock holder (dead process) is reused, not skipped.
    std::fs::write(dir.join("net-1"), b"").unwrap();
    let (_b, s1, _) = claim(dir.as_path(), 0).unwrap();
    assert_eq!(s1, Ipv4Addr::new(10, 77, 1, 1));
    // Held pairs are skipped: next free is 2.
    let (_c, s2, _) = claim(dir.as_path(), 0).unwrap();
    assert_eq!(s2, Ipv4Addr::new(10, 77, 2, 1));
    // The start offset scans past already-offered pairs.
    let (_d, s3, _) = claim(dir.as_path(), 3).unwrap();
    assert_eq!(s3, Ipv4Addr::new(10, 77, 3, 1));
    // A dropped guard frees the pair for the next claim.
    drop(_a);
    let (_e, s0_back, _) = claim(dir.as_path(), 0).unwrap();
    assert_eq!(s0_back, Ipv4Addr::new(10, 77, 0, 1));
}

#[test]
fn claim_scans_from_start_and_wraps() {
    let dir = tempdir("wrap");
    let (_a, s254, _) = claim(dir.as_path(), 254).unwrap();
    assert_eq!(s254, Ipv4Addr::new(10, 77, 254, 1));
    // 254 held: scanning wraps to the beginning of the pool.
    let (_b, s0, _) = claim(dir.as_path(), 254).unwrap();
    assert_eq!(s0, Ipv4Addr::new(10, 77, 0, 1));
}

#[test]
fn server_claim_modes() {
    let dir = tempdir("modes");
    // Auto claims the first free pair.
    let (guard, pair) = server_claim(
        dir.as_path(),
        true,
        (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED),
        0,
    )
    .unwrap();
    assert!(guard.is_some());
    assert_eq!(pair, pair_of(0));
    // Explicit pool pair: locked, and busy for a second session.
    let (g1, p1) = server_claim(dir.as_path(), false, pair_of(7), 0).unwrap();
    assert!(g1.is_some());
    assert_eq!(p1, pair_of(7));
    match server_claim(dir.as_path(), false, pair_of(7), 0) {
        Err(error) => assert!(error.to_string().contains("already used")),
        Ok(_) => panic!("busy pair must fail"),
    }
    // Explicit pair outside the pool subnet: honored without a lock.
    let custom = (Ipv4Addr::new(192, 168, 5, 1), Ipv4Addr::new(192, 168, 5, 2));
    let (g2, p2) = server_claim(dir.as_path(), false, custom, 0).unwrap();
    assert!(g2.is_none());
    assert_eq!(p2, custom);
    // Auto with start skips the busy explicit pair.
    let (_g3, p3) = server_claim(dir.as_path(), true, pair, 7).unwrap();
    assert_eq!(p3, pair_of(8));
}

#[test]
fn client_claim_dedupes_within_process_and_rejects_other_process_pair() {
    // Pool pair: second in-process claim of the same pair reuses the guard.
    let (server, client) = pair_of(200);
    let first = client_claim(server, client).unwrap().unwrap();
    let second = client_claim(server, client).unwrap().unwrap();
    assert!(std::sync::Arc::ptr_eq(&first, &second));
    // A pair locked by a real file holder (simulating another process) is busy.
    let (server, client) = pair_of(201);
    let _foreign = claim(std::path::Path::new(CLIENT_POOL_DIR), 201).unwrap();
    assert!(client_claim(server, client).unwrap().is_none());
    drop(_foreign);
    assert!(client_claim(server, client).unwrap().is_some());
    // Non-pool pairs are rejected (explicit non-pool pairs never reach here).
    assert!(client_claim(Ipv4Addr::new(192, 168, 5, 1), Ipv4Addr::new(192, 168, 5, 2)).is_err());
}
