//! Address pair pool: port-token allocation semantics (#181).
//!
//! One sequential test: the token port space is host-global, so parallel
//! tests scanning the pool would divert each other's claims.

use std::net::Ipv4Addr;

use svpn::addrpool::*;
use svpn::portlock::PortLock;

#[test]
fn pool_allocation_lifecycle() {
    // ── pair arithmetic ──
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

    // ── claim: first free, skip held, start offset, reuse after drop ──
    let (a, s0, _) = claim(0).unwrap();
    assert_eq!(s0, Ipv4Addr::new(10, 77, 0, 1));
    let (_b, s1, _) = claim(0).unwrap();
    assert_eq!(s1, Ipv4Addr::new(10, 77, 1, 1));
    let (_c, s2, _) = claim(0).unwrap();
    assert_eq!(s2, Ipv4Addr::new(10, 77, 2, 1));
    let (_d, s3, _) = claim(3).unwrap();
    assert_eq!(s3, Ipv4Addr::new(10, 77, 3, 1));
    drop(a);
    let (_e, s0_back, _) = claim(0).unwrap();
    assert_eq!(s0_back, Ipv4Addr::new(10, 77, 0, 1));

    // ── claim: scanning from start wraps around the pool ──
    let (_f, s254, _) = claim(254).unwrap();
    assert_eq!(s254, Ipv4Addr::new(10, 77, 254, 1));
    let (_g, s_wrap, _) = claim(254).unwrap();
    assert_eq!(s_wrap, Ipv4Addr::new(10, 77, 4, 1), "wraps to first free");

    // ── server_claim modes ──
    let custom = (Ipv4Addr::new(192, 168, 5, 1), Ipv4Addr::new(192, 168, 5, 2));
    let (g_unlocked, p_custom) = server_claim(false, custom, 0).unwrap();
    assert!(
        g_unlocked.is_none() && p_custom == custom,
        "off-pool pair unlocked"
    );
    let (g7, p7) = server_claim(false, pair_of(7), 0).unwrap();
    assert!(g7.is_some() && p7 == pair_of(7));
    match server_claim(false, pair_of(7), 0) {
        Err(error) => assert!(error.to_string().contains("already used")),
        Ok(_) => panic!("busy pair must fail"),
    }
    drop(g7);
    let (g7_back, _) = server_claim(false, pair_of(7), 0).unwrap();
    assert!(g7_back.is_some(), "dropped pair is lockable again");

    // ── server_claim auto honors the proposed pool pair (#181) ──
    let (g5, p5) = server_claim(true, pair_of(5), 0).unwrap();
    assert!(g5.is_some() && p5 == pair_of(5), "free proposal is taken");
    let (_g6, p6) = server_claim(true, pair_of(5), 0).unwrap();
    assert_eq!(p6, pair_of(6), "busy proposal falls back to first free");
    let (_g8, p8) = server_claim(true, pair_of(1), 8).unwrap();
    assert_eq!(p8, pair_of(8), "a retry after decline scans from start");

    // ── client_claim: in-process sharing, foreign holder rejection ──
    let (server, client) = pair_of(200);
    let first = client_claim(server, client).unwrap().unwrap();
    let second = client_claim(server, client).unwrap().unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&first, &second),
        "same process shares"
    );
    let (server, client) = pair_of(201);
    let foreign = PortLock::try_acquire(LOCK_PORT_BASE + 201)
        .unwrap()
        .unwrap();
    assert!(
        client_claim(server, client).unwrap().is_none(),
        "foreign holder wins"
    );
    drop(foreign);
    assert!(client_claim(server, client).unwrap().is_some());
    assert!(
        client_claim(custom.0, custom.1).is_err(),
        "non-pool pair rejected"
    );

    // ── exhaustion: every token held → clean error, no panic ──
    let mut held = Vec::new();
    for n in 0..POOL_SIZE {
        if let Some(guard) = PortLock::try_acquire(LOCK_PORT_BASE + u16::from(n)).unwrap() {
            held.push(guard);
        }
    }
    match claim(0) {
        Err(error) => assert!(error.to_string().contains("no free tunnel address pair")),
        Ok(_) => panic!("a fully held pool must fail"),
    }
    drop(held);
}
