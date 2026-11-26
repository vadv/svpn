//! One DNS query against a list of resolvers: every resolver is asked at
//! once over UDP, the first well-formed answer inside the budget wins. The
//! server passes its `/etc/resolv.conf` nameservers with no device; the hub's
//! local exit passes the WAN resolvers and binds the socket to the WAN
//! device, or the query would be routed back into the TUN.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, LazyLock, Once},
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore},
};

use crate::dns::{self, wire};
use crate::local_proxy::egress;

pub const RESOLV_CONF: &str = "/etc/resolv.conf";
/// OpenWrt keeps the DHCP resolvers here: its `/etc/resolv.conf` is dnsmasq.
pub const OPENWRT_RESOLV: &str = "/tmp/resolv.conf.d/resolv.conf.auto";
/// Total time one query waits for every resolver together.
pub const BUDGET: Duration = Duration::from_secs(2);
/// resolv.conf's own maximum (`MAXNS`).
pub const MAX_NAMESERVERS: usize = 3;
/// Relays in flight per process: a query storm must not become a socket storm.
const RELAYS: usize = 64;

static PERMITS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(RELAYS)));
static NO_RESOLVERS: Once = Once::new();

/// A free relay slot; `None` when every one is busy.
pub fn acquire() -> Option<OwnedSemaphorePermit> {
    PERMITS.clone().try_acquire_owned().ok()
}

/// IPv4 `nameserver` lines of a resolv.conf, in file order, as many as
/// there are: the resolvers of one query are cut by `resolve`.
pub fn nameservers(text: &str) -> Vec<Ipv4Addr> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| fields.next())
                .flatten()
        })
        .filter_map(|address| address.parse().ok())
        .collect()
}

/// Resolvers of the hub's local exit. Loopback is left out on purpose: it is
/// a forwarder (dnsmasq, systemd-resolved) whose own upstream may be the
/// hub, which would ask it again.
pub fn local_nameservers(configured: &[Ipv4Addr], files: &[&str]) -> Vec<Ipv4Addr> {
    let discovered = || {
        files.iter().find_map(|path| {
            std::fs::read_to_string(path)
                .ok()
                .map(|text| external(&text))
                .filter(|found| !found.is_empty())
        })
    };
    match configured.is_empty() {
        false => configured.to_vec(),
        true => discovered().unwrap_or_default(),
    }
}

/// Non-loopback nameservers of a resolv.conf.
pub fn external(text: &str) -> Vec<Ipv4Addr> {
    nameservers(text)
        .into_iter()
        .filter(|address| !address.is_loopback())
        .collect()
}

/// The server's own resolvers, reached over an ordinary socket.
pub async fn resolve_system(query: &[u8]) -> Option<Vec<u8>> {
    let text = std::fs::read_to_string(RESOLV_CONF).ok()?;
    let nameservers = nameservers(&text);
    if nameservers.is_empty() {
        NO_RESOLVERS.call_once(|| {
            crate::error!("dns relay: no IPv4 nameserver in {RESOLV_CONF} — answers SERVFAIL")
        });
        return None;
    }
    exchange(&sockets(&nameservers), None, query, BUDGET).await
}

/// Resolver addresses as the sockets they are asked on: the DNS port, and
/// no more of them than resolv.conf allows.
pub fn sockets(nameservers: &[Ipv4Addr]) -> Vec<SocketAddr> {
    nameservers
        .iter()
        .take(MAX_NAMESERVERS)
        .map(|&nameserver| SocketAddr::from((nameserver, dns::PORT)))
        .collect()
}

/// Ask every resolver at once; `None` when none answered within `budget`.
/// A `device` binds every socket to that interface.
pub async fn exchange(
    targets: &[SocketAddr],
    device: Option<&str>,
    query: &[u8],
    budget: Duration,
) -> Option<Vec<u8>> {
    let mut asks = tokio::task::JoinSet::new();
    for &target in targets.iter().take(MAX_NAMESERVERS) {
        let bind = match device {
            None => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await,
            Some(device) => egress::udp_socket(Some(device), target),
        };
        if let Ok(socket) = bind {
            let query = query.to_vec();
            asks.spawn(async move { ask(socket, target, &query).await.ok() });
        }
    }
    // A task's None is a socket error: the others may still answer.
    let first = tokio::time::timeout(budget, async {
        while let Some(ask) = asks.join_next().await {
            if let Ok(Some(answer)) = ask {
                return Some(answer);
            }
        }
        None
    })
    .await;
    asks.abort_all();
    while asks.join_next().await.is_some() {}
    first.ok().flatten()
}

/// Send once and take the first datagram from the resolver that answers
/// `query`; anything else on the socket is ignored.
async fn ask(socket: UdpSocket, target: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    socket.send_to(query, target).await?;
    // The DNS limit; pages are touched only as far as the answer fills them.
    let mut buffer = vec![0u8; 65536];
    loop {
        let (length, from) = socket.recv_from(&mut buffer).await?;
        if from.ip() == target.ip()
            && let Some(answer) = wire::answers(&buffer[..length], query)
        {
            return Ok(answer);
        }
    }
}
