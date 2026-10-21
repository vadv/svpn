//! Tunnel address pair allocation via loopback port tokens (#181).
//!
//! A pair is (server 10.77.<n>.1, client 10.77.<n>.2), n in 0..POOL_SIZE.
//! Ownership of pair n on a host is the portlock token LOCK_PORT_BASE + n:
//! atomic in the kernel, released on process death, even SIGKILL. The port
//! carries no traffic; it only names the pair. The kernel cannot arbitrate
//! the addresses themselves: duplicate p2p addresses on different TUNs are
//! legal on Linux and macOS and silently misroute instead of failing.

use std::{
    collections::HashMap,
    io,
    net::Ipv4Addr,
    sync::{Arc, Mutex, OnceLock},
};

use anyhow::{Context, Result, bail};

use crate::portlock::PortLock;

/// Pair count: third octets 0..=254 of 10.77.0.0/16, hosts .1/.2.
pub const POOL_SIZE: u8 = 255;

/// Token port for pair n is LOCK_PORT_BASE + n; below the ephemeral ranges
/// of Linux (32768+) and macOS (49152+), so outbound connections never take
/// it.
pub const LOCK_PORT_BASE: u16 = 29700;

/// RAII hold on the pair token; dropping releases the port.
pub type PairGuard = PortLock;

pub fn pair_of(n: u8) -> (Ipv4Addr, Ipv4Addr) {
    (Ipv4Addr::new(10, 77, n, 1), Ipv4Addr::new(10, 77, n, 2))
}

/// Pool index of a pair, None when outside the pool subnet (an explicit pair
/// in the admin's own addressing is honored without a lock).
pub fn pool_index(server: Ipv4Addr, client: Ipv4Addr) -> Option<u8> {
    match (server.octets(), client.octets()) {
        ([10, 77, n, 1], [10, 77, m, 2]) if n == m => Some(n),
        _ => None,
    }
}

fn lock(n: u8) -> io::Result<Option<PairGuard>> {
    PortLock::try_acquire(LOCK_PORT_BASE + u16::from(n))
}

/// Server side, auto mode: the first free pair, scanning from `start` so a
/// declined pair is not offered again.
pub fn claim(start: u8) -> Result<(PairGuard, Ipv4Addr, Ipv4Addr)> {
    for n in (start..POOL_SIZE).chain(0..start) {
        if let Some(guard) = lock(n)? {
            let (server, client) = pair_of(n);
            return Ok((guard, server, client));
        }
    }
    bail!("no free tunnel address pair in the pool")
}

/// Server side: auto → first free pair; explicit pool pair → lock it or fail;
/// an explicit pair outside the pool subnet is honored unlocked.
pub fn server_claim(
    auto: bool,
    pair: (Ipv4Addr, Ipv4Addr),
    start: u8,
) -> Result<(Option<PairGuard>, (Ipv4Addr, Ipv4Addr))> {
    if auto {
        // Honor the client's proposed pool pair first (a pinned pool pair on
        // reconnect, #181); busy or off-pool — fall back to the first free.
        if start == 0
            && let Some(n) = pool_index(pair.0, pair.1)
            && let Some(guard) = lock(n)?
        {
            return Ok((Some(guard), pair));
        }
        let (guard, server, client) = claim(start)?;
        return Ok((Some(guard), (server, client)));
    }
    match pool_index(pair.0, pair.1) {
        Some(n) => Ok((
            Some(lock(n)?.context("address pair already used by another svpn session")?),
            pair,
        )),
        None => Ok((None, pair)),
    }
}

/// Client side: process-wide registry, so pool members sharing one pair do
/// not collide with themselves; distinct processes contend via port tokens.
/// The claim is held until process exit, so reconnects keep the pair.
/// Ok(None) — the pair is held by another local svpn process.
pub fn client_claim(server: Ipv4Addr, client: Ipv4Addr) -> Result<Option<Arc<PairGuard>>> {
    type Claims = Mutex<HashMap<(Ipv4Addr, Ipv4Addr), Arc<PairGuard>>>;
    static CLAIMS: OnceLock<Claims> = OnceLock::new();
    let mut claims = CLAIMS
        .get_or_init(Claims::default)
        .lock()
        .map_err(|_| anyhow::anyhow!("address claims registry poisoned"))?;
    if let Some(guard) = claims.get(&(server, client)) {
        return Ok(Some(guard.clone()));
    }
    let n = pool_index(server, client).context("client_claim requires a pool pair")?;
    let Some(guard) = lock(n)? else {
        return Ok(None);
    };
    let guard = Arc::new(guard);
    claims.insert((server, client), guard.clone());
    Ok(Some(guard))
}
