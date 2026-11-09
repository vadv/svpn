//! LAN sources of the flow table: the router NATs every LAN device into the
//! tunnel, so the hub only ever sees its own TUN address as the source.
//! Conntrack keeps the original tuple and the DHCP leases the device name —
//! read here for the dashboard only, never on the hub's packet path.

use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    net::Ipv4Addr,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crate::web::FlowView;

/// Kernel conntrack table and dnsmasq lease file of an OpenWrt router.
pub const CONNTRACK: &str = "/proc/net/nf_conntrack";
pub const LEASES: &str = "/tmp/dhcp.leases";

/// Re-read at most this often: the dashboard polls once per second.
const REFRESH: Duration = Duration::from_secs(1);
/// Hard bounds on the bytes one poll may read; the rest of a table is
/// dropped whole rather than read.
const MAX_CONNTRACK: u64 = 4 * 1024 * 1024;
const MAX_LEASES: u64 = 64 * 1024;

/// One flow as the hub keys it: protocol, TUN address and port, remote peer.
pub type Tuple = (u8, Ipv4Addr, u16, Ipv4Addr, u16);
/// LAN source of each masqueraded flow, with its DHCP hostname if leased.
pub type Sources = HashMap<Tuple, (Ipv4Addr, Option<String>)>;

/// Masqueraded conntrack entries keyed by the flow as the hub sees it: the
/// reply tuple of a NATed entry is the tunnel flow (its `dst` is the TUN
/// address), the original tuple names the LAN device. Router-originated
/// traffic starts at the TUN address already and stays out.
pub fn parse_conntrack(text: &str) -> HashMap<Tuple, Ipv4Addr> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        if tokens.next() != Some("ipv4") {
            continue; // IPv6 neighbours never match an IPv4 tunnel flow
        }
        let protocol = match tokens.nth(1) {
            Some("tcp") => 6,
            Some("udp") => 17,
            Some("icmp") => 1,
            _ => continue,
        };
        // Each confirmed entry has two tuples, original first, reply second;
        // an unconfirmed one has none to map yet.
        let mut tuples = line.split(" src=").skip(1);
        let Some(original) = tuples.next().and_then(tuple) else {
            continue;
        };
        let Some(reply) = tuples.next().and_then(tuple) else {
            continue;
        };
        let (lan, _, _, _) = original;
        let (remote, tunnel, remote_port, tunnel_port) = reply;
        // A hub ICMP flow carries the echo id as its source port and no
        // destination port, so the reply's sport does not key it.
        let remote_port = if protocol == 1 { 0 } else { remote_port };
        if lan == tunnel {
            continue; // the router itself, not a device behind it
        }
        map.insert((protocol, tunnel, tunnel_port, remote, remote_port), lan);
    }
    map
}

/// One conntrack tuple, split after its `src=`: the source address, then
/// `dst=` and the ports (`sport=`/`dport=`, or the echo `id=` for ICMP).
/// Returns (source, destination, source port, destination port).
fn tuple(half: &str) -> Option<(Ipv4Addr, Ipv4Addr, u16, u16)> {
    let mut fields = half.split_whitespace();
    let source = fields.next()?.parse().ok()?;
    let mut destination = None;
    let mut source_port = None;
    let mut destination_port = None;
    for token in fields {
        let field = |prefix: &str| token.strip_prefix(prefix);
        if let Some(value) = field("dst=") {
            destination.get_or_insert(value.parse().ok()?);
        } else if let Some(value) = field("sport=") {
            source_port.get_or_insert(value.parse().ok()?);
        } else if let Some(value) = field("dport=") {
            destination_port.get_or_insert(value.parse().ok()?);
        } else if let Some(value) = field("id=") {
            // An echo carries one id for both directions of the flow.
            source_port.get_or_insert(value.parse().ok()?);
            destination_port.get_or_insert(value.parse().ok()?);
        }
    }
    Some((source, destination?, source_port?, destination_port?))
}

/// DHCP leases keyed by IPv4 address; `*` and absent hostnames stay out.
pub fn parse_leases(text: &str) -> HashMap<Ipv4Addr, String> {
    let mut names = HashMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(_) = fields.next() else { continue }; // expiry
        let Some(_) = fields.next() else { continue }; // mac
        let Some(address) = fields.next().and_then(|field| field.parse().ok()) else {
            continue; // the IPv6 leases of the same file
        };
        let Some(host) = fields.next() else { continue };
        if host != "*" && !host.is_empty() {
            names.insert(address, host.to_owned());
        }
    }
    names
}

/// Join conntrack sources with lease names into one lookup table.
pub fn resolve(conntrack: &str, leases: &str) -> Sources {
    let names = parse_leases(leases);
    parse_conntrack(conntrack)
        .into_iter()
        .map(|(key, lan)| (key, (lan, names.get(&lan).cloned())))
        .collect()
}

/// Set `client`/`client_name` on flows the table resolves to a LAN device;
/// everything else (the router's own flows, no conntrack entry) keeps nulls.
pub fn apply(sources: &Sources, flows: &mut [FlowView]) {
    for flow in flows {
        let protocol = match flow.protocol {
            "tcp" => 6,
            "udp" => 17,
            "icmp" => 1,
            _ => continue,
        };
        let Some((tunnel, tunnel_port)) = endpoint(&flow.source) else {
            continue;
        };
        let Some((remote, remote_port)) = endpoint(&flow.destination) else {
            continue;
        };
        if let Some((lan, name)) =
            sources.get(&(protocol, tunnel, tunnel_port, remote, remote_port))
        {
            flow.client = Some(lan.to_string());
            flow.client_name = name.clone();
        }
    }
}

/// `address:port` of one flow-view endpoint.
fn endpoint(text: &str) -> Option<(Ipv4Addr, u16)> {
    let (address, port) = text.rsplit_once(':')?;
    Some((address.parse().ok()?, port.parse().ok()?))
}

/// Conntrack/lease view shared by dashboard requests, parsed at most once
/// per [`REFRESH`] and off the async runtime.
#[derive(Default)]
pub struct Cache {
    table: Mutex<Option<(Instant, Sources)>>,
    missing_logged: AtomicBool,
}

impl Cache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enrich flow sources with LAN devices; called from the HTTP handler.
    pub async fn enrich(&self, flows: &mut [FlowView]) {
        {
            let table = self.lock();
            if let Some((at, sources)) = &*table
                && at.elapsed() < REFRESH
            {
                apply(sources, flows);
                return;
            }
        } // The lock is never held across an await.
        let Ok((sources, missing)) = tokio::task::spawn_blocking(read_tables).await else {
            return; // the runtime is shutting down; the next request retries
        };
        // A missing table is normal off-router: say so once, never per poll.
        if missing && !self.missing_logged.swap(true, Ordering::Relaxed) {
            crate::debug!("dashboard: {CONNTRACK} unavailable, flow sources stay the TUN address");
        }
        apply(&sources, flows);
        *self.lock() = Some((Instant::now(), sources));
    }

    /// A poisoned lock only loses a cache; the next request rebuilds it.
    fn lock(&self) -> MutexGuard<'_, Option<(Instant, Sources)>> {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Read both tables within their byte bounds; a missing table reads empty.
fn read_tables() -> (Sources, bool) {
    let conntrack = read_bounded(CONNTRACK, MAX_CONNTRACK);
    let leases = read_bounded(LEASES, MAX_LEASES);
    let sources = resolve(
        conntrack.as_deref().unwrap_or_default(),
        leases.as_deref().unwrap_or_default(),
    );
    (sources, conntrack.is_none())
}

fn read_bounded(path: &str, limit: u64) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(limit)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}
