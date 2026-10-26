//! Direct System Stack engine (spec §5.2-5.3; the ICMP sibling of spec
//! §5.4 lives in the `icmp` submodule): home-country TCP/UDP flows
//! leave through the host stack on the physical uplink instead of the VPN.
//!
//! TCP turns the client kernel into the local endpoint: the original tuple
//! `client:c → dst:d` is NATed to `peer:nat → client:listen`, where a real
//! kernel listener terminates the connection; an independent outbound
//! `TcpStream` to the original destination relays bytes with
//! `copy_bidirectional` (segments preserved byte for byte, no seq offsets,
//! no synthetic SYN-ACK). UDP gets one connected, uplink-bound socket per
//! flow; replies are rebuilt with the original tuple.
//!
//! Shared state: the mapping tables are touched by this synchronous Hub
//! entry path (`open_*`/`forward_*`/`rewrite_reverse`) and by the engine's
//! own tasks (accept loop, relays, UDP flows, expiry timer). `Mutex` guards
//! short map operations only and is never held across an `.await`; the flow
//! tasks report back through the packet/event channels instead.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex as AsyncMutex, mpsc},
    task::{AbortHandle, JoinSet},
    time::Instant,
};

use crate::packet::{self, FlowKey, Packet, internet_checksum};
#[cfg(target_os = "macos")]
use std::num::NonZeroU32;

pub mod icmp;

/// Whole direct table across every stage (spec §5.5).
pub const MAX_FLOWS: usize = 4096;
/// Simultaneous unanswered-SYN reservations (accepts/connects in flight).
pub const MAX_PENDING: usize = 64;
/// Lossy outbound packet queue bound: MTU-sized packets only, so the queue
/// holds at most `PACKET_QUEUE * MTU` bytes.
pub const PACKET_QUEUE: usize = 1024;
/// Reliable lifecycle events (close/reconciliation), backpressured.
const EVENT_QUEUE: usize = 1024;
/// Unanswered SYN frees its reservation after this budget.
pub const PENDING_TIMEOUT: Duration = Duration::from_secs(30);
/// Outbound connect budget per flow.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Idle budget of a UDP flow; refreshed by requests and replies.
pub const UDP_IDLE: Duration = Duration::from_secs(60);
/// Idle budget of a relaying TCP flow, refreshed by packets in both
/// directions (client side and kernel-listener side).
pub const TCP_IDLE: Duration = Duration::from_secs(2 * 3600 + 4 * 60);
/// Mapping dwell after copy/teardown: the local kernel may still emit the
/// delayed final ACK and FIN retransmissions.
pub const FIN_DWELL: Duration = Duration::from_secs(4 * 60);
/// A retired nat port stays out of rotation so stale kernel segments of a
/// previous connection cannot be rewritten into a new mapping.
pub const PORT_RETIRE: Duration = Duration::from_secs(4 * 60);
/// Expiry runs on its own timer so idle flows die without new traffic.
const EXPIRY_TICK: Duration = Duration::from_secs(1);
/// One-time join budget of the bounded shutdown.
const SHUTDOWN_JOIN: Duration = Duration::from_secs(1);

/// Physical IPv4 default-route interface, captured before user hooks run
/// (spec §5.1). Every outbound direct socket binds to it before connect or
/// send; there is no unbound fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uplink {
    pub name: String,
    pub index: u32,
}

/// Discovers the interface of the IPv4 default route — the physical uplink
/// the direct engine must pin its sockets to. Call it before `hooks.start`
/// replaces the routing view. `find_route(0.0.0.0)` is a longest-prefix
/// match and would happily pick a tunnel's `0.0.0.0/1`, so the default
/// route itself is selected — the kernel's preference is the lowest
/// metric, ties keep the first listed.
pub fn discover_uplink() -> Result<Uplink> {
    let mut manager = route_manager::RouteManager::new().context("route manager")?;
    let routes = manager.list().context("list routes")?;
    select_uplink(&routes)
}

/// Select the preferred main-table IPv4 default route. Linux omits a zero
/// metric in netlink, so an absent metric is the highest priority (zero),
/// not a reason to prefer a backup with an explicit positive metric.
pub fn select_uplink(routes: &[route_manager::Route]) -> Result<Uplink> {
    let route = routes
        .iter()
        .filter(|route| {
            route.destination() == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                && route.prefix() == 0
                && table_is_main(route)
        })
        .min_by_key(|route| route_metric(route).unwrap_or(0))
        .context("no IPv4 default route — cannot capture the physical uplink")?;
    let uplink = match (route.if_name().cloned(), route.if_index()) {
        (Some(name), Some(index @ 1..)) => Uplink { name, index },
        _ => bail!("IPv4 default route has no usable interface identity"),
    };
    Ok(uplink)
}

/// Negotiated identity the engine operates on: the tunnel pair confirmed by
/// the server, the live TUN (name + if index for the return route), its MTU
/// and the pinned physical uplink. Test configurations may use loopback
/// addresses so the kernel paths stay drivable without a real TUN.
#[derive(Clone, Debug)]
pub struct DirectConfig {
    pub client: Ipv4Addr,
    pub peer: Ipv4Addr,
    pub tun_name: String,
    pub tun_index: u32,
    pub mtu: u16,
    pub uplink: Uplink,
}

/// Engine output for the Hub. `Packet` rides the lossy queue (dropped under
/// pressure, never blocks a flow); terminal events ride the reliable channel
/// and are never lost to packet-queue pressure. Both are tagged with the flow id.
#[derive(Debug)]
pub enum DirectEvent {
    /// Outbound packet to write into the TUN, e.g. a rebuilt UDP reply.
    Packet { id: u64, bytes: Vec<u8> },
    /// Flow finished normally (relay done, idle or pending timeout).
    /// `key` names the original tuple so the Hub reconciles exactly this
    /// owner; a late close of a replaced generation must not affect it.
    Closed { id: u64, key: FlowKey },
    /// A background socket/connect/relay failure terminated this flow.
    Failed { id: u64, key: FlowKey },
}

#[derive(Debug)]
enum TcpStage {
    /// Reservation for a rewritten SYN, waiting for the local accept.
    Pending { deadline: Instant },
    /// Accepted locally, the outbound connect still unresolved: keeps its
    /// slot in the MAX_PENDING budget until the connect resolves (spec
    /// §5.5 counts accepts and connects).
    Connecting {
        abort: Option<AbortHandle>,
        deadline: Instant,
    },
    /// Accepted and connected; relays bytes in both directions. The abort
    /// handle is attached right after the task spawn; the idle sweep uses
    /// it.
    Relay { abort: Option<AbortHandle> },
    /// Copy finished; both forward and reverse mappings live on so kernel
    /// FIN/ACK/retransmissions keep flowing to the application.
    Dwell { until: Instant },
}

struct TcpFlow {
    id: u64,
    /// Local NAT port of the rewritten `peer:nat` source.
    nat_port: u16,
    /// Original tuple; drives the reverse rewrite.
    flow: FlowKey,
    stage: TcpStage,
    last_seen: Instant,
}

struct UdpFlow {
    id: u64,
    socket: Option<Arc<UdpSocket>>,
    abort: Option<AbortHandle>,
    last_seen: Instant,
}

#[derive(Default)]
struct DirectState {
    tcp: HashMap<FlowKey, TcpFlow>,
    udp: HashMap<FlowKey, UdpFlow>,
    /// Nat ports kept out of rotation after teardown until their deadline.
    retired: VecDeque<(u16, Instant)>,
    port_cursor: u16,
}

struct Shared {
    cfg: DirectConfig,
    listener_port: u16,
    // Lock poisoning is unreachable: a panicking task aborts the process
    // (see the panic hook in main_entry). The guard covers map operations
    // only and is never held across an await.
    state: Mutex<DirectState>,
    tasks: AsyncMutex<JoinSet<()>>,
    packets: mpsc::Sender<DirectEvent>,
    events: mpsc::Sender<DirectEvent>,
}

impl Shared {
    /// A failed outbound connect/relay still owns an accepted kernel socket:
    /// retain its NAT mapping through FIN_DWELL so the resulting FIN/RST can
    /// be rewritten, but notify the Hub promptly with a failure outcome.
    async fn fail_tcp(&self, flow: FlowKey, id: u64) {
        {
            let mut state = self.state.lock().unwrap();
            let Some(entry) = state.tcp.get_mut(&flow) else {
                return;
            };
            if entry.id != id
                || !matches!(
                    entry.stage,
                    TcpStage::Connecting { .. } | TcpStage::Relay { .. }
                )
            {
                return;
            }
            entry.stage = TcpStage::Dwell {
                until: Instant::now() + FIN_DWELL,
            };
        }
        let _ = self
            .events
            .send(DirectEvent::Failed { id, key: flow })
            .await;
    }

    /// Relay teardown enters FIN_DWELL without retiring the Hub owner.
    /// The expiry sweep emits the one terminal Closed event when both NAT
    /// mappings are actually removed; delayed ACK/FIN segments can therefore
    /// still use forward_tcp during the dwell.
    async fn finish_tcp(&self, flow: FlowKey, id: u64) {
        let mut state = self.state.lock().unwrap();
        if let Some(entry) = state.tcp.get_mut(&flow)
            && entry.id == id
            && matches!(
                entry.stage,
                TcpStage::Connecting { .. } | TcpStage::Relay { .. }
            )
        {
            entry.stage = TcpStage::Dwell {
                until: Instant::now() + FIN_DWELL,
            };
        }
    }

    fn remove_udp(&self, flow: FlowKey, id: u64) -> Option<UdpFlow> {
        let mut state = self.state.lock().unwrap();
        match state.udp.get(&flow) {
            Some(entry) if entry.id == id => state.udp.remove(&flow),
            _ => None,
        }
    }

    /// Background UDP failure reports through the reliable channel. The
    /// Hub-originated send-error path uses forget_udp instead: awaiting this
    /// channel from Hub dispatch could deadlock while the Hub is the drain.
    async fn finish_udp(&self, flow: FlowKey, id: u64) {
        let Some(entry) = self.remove_udp(flow, id) else {
            return;
        };
        let _ = self
            .events
            .send(DirectEvent::Failed { id, key: flow })
            .await;
        if let Some(abort) = entry.abort {
            abort.abort();
        }
    }

    fn forget_udp(&self, flow: FlowKey, id: u64) {
        if let Some(entry) = self.remove_udp(flow, id)
            && let Some(abort) = entry.abort
        {
            abort.abort();
        }
    }
}

/// How the `peer/32` return route came to exist (spec §5.2). Only the
/// engine-installed variant is ever deleted: a preexisting route — created
/// by the TUN bring-up or an operator hook, or installed concurrently while
/// our own add raced to EEXIST — is foreign property for the whole run.
#[derive(Debug)]
enum RouteBinding {
    /// Present before the engine ensured it: never removed by us.
    Preinstalled,
    /// Installed and verified by this engine: removed on shutdown.
    Owned(route_manager::Route),
}

/// Standalone direct TCP+UDP engine. The Hub owns it, feeds client packets
/// in, polls events out and writes returned packets into the TUN.
pub struct DirectEngine {
    shared: Arc<Shared>,
    accept: tokio::task::JoinHandle<()>,
    expiry: tokio::task::JoinHandle<()>,
    packets_rx: mpsc::Receiver<DirectEvent>,
    events_rx: mpsc::Receiver<DirectEvent>,
    /// Ownership state of the `peer/32` return route.
    route: Option<RouteBinding>,
}

impl DirectEngine {
    /// Binds the kernel TCP listener on the negotiated client address (OS
    /// port) and starts the accept and expiry tasks. A bind failure stops
    /// SVPN startup (spec §2); uplink binding is applied per outbound socket
    /// and surfaces as a per-flow error instead.
    pub async fn new(config: DirectConfig) -> Result<Self> {
        validate(&config)?;
        let listener = TcpListener::bind(SocketAddr::from(SocketAddrV4::new(config.client, 0)))
            .await
            .with_context(|| {
                format!(
                    "direct TCP listener bind on the TUN client address {} \
                     (AddrNotAvailable: the negotiated client address is not on the TUN)",
                    config.client
                )
            })?;
        let listener_port = listener
            .local_addr()
            .context("direct TCP listener address")?
            .port();
        let (packets_tx, packets_rx) = mpsc::channel(PACKET_QUEUE);
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
        let shared = Arc::new(Shared {
            cfg: config,
            listener_port,
            state: Mutex::default(),
            tasks: AsyncMutex::new(JoinSet::new()),
            packets: packets_tx,
            events: events_tx,
        });
        let accept = tokio::spawn(accept_loop(shared.clone(), listener));
        let expiry = tokio::spawn(expiry_loop(shared.clone()));
        Ok(Self {
            shared,
            accept,
            expiry,
            packets_rx,
            events_rx,
            route: None,
        })
    }

    /// Local port the kernel listener actually got.
    pub fn listen_port(&self) -> u16 {
        self.shared.listener_port
    }

    /// Mapping count across every stage — the capacity gauge.
    pub fn flow_count(&self) -> usize {
        let state = self.shared.state.lock().unwrap();
        state.tcp.len() + state.udp.len()
    }

    /// Whether this exact generation still owns an engine mapping. Hub
    /// dispatch uses this to distinguish a rejected packet from a terminal
    /// socket failure without desynchronizing the two tables.
    pub(crate) fn owns(&self, flow: FlowKey, id: u64) -> bool {
        let state = self.shared.state.lock().unwrap();
        match flow.protocol {
            6 => state.tcp.get(&flow).is_some_and(|entry| entry.id == id),
            17 => state.udp.get(&flow).is_some_and(|entry| entry.id == id),
            _ => false,
        }
    }

    /// Whether a TCP mapping is retaining its NAT state after socket relay
    /// completion. The Hub must keep its owner until this becomes false.
    pub fn tcp_in_dwell(&self, flow: FlowKey) -> bool {
        let state = self.shared.state.lock().unwrap();
        matches!(
            state.tcp.get(&flow).map(|entry| &entry.stage),
            Some(TcpStage::Dwell { .. })
        )
    }

    /// First packet (SYN) of a new direct TCP flow: installs the reservation
    /// before the Hub writes anything into the TUN, and returns the rewritten
    /// `peer:nat → client:listen` segment. A retransmitted SYN reuses the
    /// existing reservation.
    pub fn open_tcp(&mut self, id: u64, packet: &Packet, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
        let cfg = &self.shared.cfg;
        ensure!(packet.flow.protocol == 6, "direct open: not a TCP flow");
        ensure!(packet.can_open, "direct open: only a SYN opens a flow");
        ensure!(
            client_flow(&packet.flow, cfg.client),
            "direct open: flow does not originate from the client address"
        );
        let mut state = self.shared.state.lock().unwrap();
        if let Some(entry) = state.tcp.get_mut(&packet.flow) {
            ensure!(entry.id == id, "direct open: stale flow id");
            ensure!(
                matches!(entry.stage, TcpStage::Pending { .. }),
                "direct open: original tuple reuse before retirement"
            );
            entry.last_seen = Instant::now();
            let nat_port = entry.nat_port;
            return rewrite_tuple(
                bytes,
                cfg.peer,
                cfg.client,
                nat_port,
                self.shared.listener_port,
            )
            .map(Some)
            .context("direct open: rewrite");
        }
        ensure!(
            state.tcp.len() + state.udp.len() < MAX_FLOWS,
            "direct flow capacity exhausted ({MAX_FLOWS})"
        );
        let pending = state
            .tcp
            .values()
            .filter(|entry| {
                matches!(
                    entry.stage,
                    TcpStage::Pending { .. } | TcpStage::Connecting { .. }
                )
            })
            .count();
        ensure!(pending < MAX_PENDING, "direct pending capacity exhausted");
        let nat_port = state
            .allocate_port(self.shared.listener_port)
            .context("direct nat port space exhausted")?;
        let rewritten = rewrite_tuple(
            bytes,
            cfg.peer,
            cfg.client,
            nat_port,
            self.shared.listener_port,
        )
        .context("direct open: rewrite")?;
        state.tcp.insert(
            packet.flow,
            TcpFlow {
                id,
                nat_port,
                flow: packet.flow,
                stage: TcpStage::Pending {
                    deadline: Instant::now() + PENDING_TIMEOUT,
                },
                last_seen: Instant::now(),
            },
        );
        Ok(Some(rewritten))
    }

    /// Any later client→destination TCP segment of an open direct flow.
    /// Returns the rewritten segment for the TUN; activity refreshes the
    /// idle clock of this direction.
    pub fn forward_tcp(&self, id: u64, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
        let cfg = &self.shared.cfg;
        let parsed = packet::parse(bytes, true).context("direct tcp forward: bad packet")?;
        let mut state = self.shared.state.lock().unwrap();
        let entry = state
            .tcp
            .get_mut(&parsed.flow)
            .context("direct tcp forward: no mapping for the flow")?;
        ensure!(entry.id == id, "direct tcp forward: stale flow id");
        entry.last_seen = Instant::now();
        rewrite_tuple(
            bytes,
            cfg.peer,
            cfg.client,
            entry.nat_port,
            self.shared.listener_port,
        )
        .map(Some)
        .context("direct tcp forward: rewrite")
    }

    /// Reverse direction: a kernel listener packet `client:listen →
    /// peer:nat` read from the TUN, rewritten back to the original
    /// `dst:d → client:c` tuple. Synchronous on purpose — the Hub checks
    /// this before any new-flow classification (spec §5.5), so a reverse
    /// SYN-ACK never passes unowned admission.
    pub fn rewrite_reverse(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let cfg = &self.shared.cfg;
        let parsed = packet::parse(bytes, true)?;
        if parsed.flow.protocol != 6
            || parsed.flow.source != cfg.client
            || parsed.flow.destination != cfg.peer
            || parsed.flow.source_port != self.shared.listener_port
        {
            return None;
        }
        let mut state = self.shared.state.lock().unwrap();
        let entry = state
            .tcp
            .values_mut()
            .find(|entry| entry.nat_port == parsed.flow.destination_port)?;
        entry.last_seen = Instant::now();
        let original = entry.flow;
        rewrite_tuple(
            bytes,
            original.destination,
            original.source,
            original.destination_port,
            original.source_port,
        )
    }

    /// First datagram of a new direct UDP flow: allocates the mapping and
    /// hands the payload to the flow task, which dials the bound, connected
    /// socket and sends it.
    pub async fn open_udp(&mut self, id: u64, packet: &Packet, bytes: &[u8]) -> Result<()> {
        let cfg = &self.shared.cfg;
        ensure!(
            packet.flow.protocol == 17,
            "direct open: not a UDP flow (ICMP is a separate engine)"
        );
        ensure!(
            client_flow(&packet.flow, cfg.client),
            "direct open: flow does not originate from the client address"
        );
        let payload = udp_payload(bytes).context("direct udp open: bad packet")?;
        let destination = SocketAddrV4::new(packet.flow.destination, packet.flow.destination_port);
        let first = payload.to_vec();
        let flow = packet.flow;
        {
            let state = self.shared.state.lock().unwrap();
            if let Some(entry) = state.udp.get(&packet.flow) {
                ensure!(entry.id == id, "direct open: stale flow id");
                return Ok(()); // the dial task carries this datagram
            }
            ensure!(
                state.tcp.len() + state.udp.len() < MAX_FLOWS,
                "direct flow capacity exhausted ({MAX_FLOWS})"
            );
        }
        // Insert before spawning: dial failure may finish the task before
        // its abort handle can be registered.
        self.shared.state.lock().unwrap().udp.insert(
            flow,
            UdpFlow {
                id,
                socket: None,
                abort: None,
                last_seen: Instant::now(),
            },
        );
        let handle = self.shared.tasks.lock().await.spawn(udp_flow(
            self.shared.clone(),
            id,
            flow,
            destination,
            first,
        ));
        let mut state = self.shared.state.lock().unwrap();
        if let Some(entry) = state.udp.get_mut(&flow)
            && entry.id == id
        {
            entry.abort = Some(handle);
        }
        // Gone or replaced: the task is either exiting after reporting its
        // own close or has no mapping to serve — aborting it could cancel an
        // in-flight close report, so it runs out on its own socket error.
        Ok(())
    }

    /// Later client→destination datagrams of an open UDP flow: sent through
    /// the flow's connected socket. A missing socket means the dial is still
    /// in flight — the datagram is dropped, as UDP may be.
    pub async fn forward_udp(&self, id: u64, bytes: &[u8]) -> Result<()> {
        let parsed = packet::parse(bytes, true).context("direct udp forward: bad packet")?;
        ensure!(
            parsed.flow.protocol == 17,
            "direct udp forward: not a UDP flow"
        );
        let payload = udp_payload(bytes).context("direct udp forward: bad packet")?;
        let socket = {
            let mut state = self.shared.state.lock().unwrap();
            let entry = state
                .udp
                .get_mut(&parsed.flow)
                .context("direct udp forward: no mapping for the flow")?;
            ensure!(entry.id == id, "direct udp forward: stale flow id");
            entry.last_seen = Instant::now();
            entry.socket.clone()
        };
        if let Some(socket) = socket
            && let Err(error) = socket.send(payload).await
        {
            // Hub dispatch reconciles the close synchronously; never await
            // the reliable queue while the Hub itself is its drain.
            self.shared.forget_udp(parsed.flow, id);
            return Err(error).context("direct udp send");
        }
        Ok(())
    }

    /// Non-blocking event poll: reliable events first, then packets.
    pub fn poll_event(&mut self) -> Option<DirectEvent> {
        if let Ok(event) = self.events_rx.try_recv() {
            return Some(event);
        }
        self.packets_rx.try_recv().ok()
    }

    /// Blocking event receive for a Hub select loop.
    pub async fn recv_event(&mut self) -> DirectEvent {
        if let Some(event) = self.poll_event() {
            return event;
        }
        // The engine keeps its own senders alive, so neither channel closes.
        tokio::select! {
            event = self.events_rx.recv() => event.expect("engine event senders alive"),
            event = self.packets_rx.recv() => event.expect("engine packet senders alive"),
        }
    }

    /// Installs the one `peer/32 → TUN` return route unless the TUN or a
    /// hook already provides it (then it is not ours and never deleted).
    /// Linux: unicast route in the main table (254). Ownership is recorded
    /// the moment our add succeeds — a failed verification rolls the route
    /// back instead of orphaning it, and a failed rollback keeps the
    /// binding so shutdown retries. An EEXIST race converts to preinstalled
    /// (the route is not ours) but never overwrites a foreign route.
    pub fn ensure_peer_route(&mut self) -> Result<()> {
        if self.route.is_some() {
            return Ok(());
        }
        let cfg = &self.shared.cfg;
        let mut manager = route_manager::RouteManager::new().context("route manager")?;
        if route_present(&mut manager, cfg.peer, cfg.tun_index)? {
            self.route = Some(RouteBinding::Preinstalled);
            return Ok(());
        }
        let desired = peer_route(cfg.peer, cfg.tun_index);
        match manager.add(&desired) {
            Ok(()) => {
                // Ownership first: a failing verification must not orphan
                // the route this engine just installed.
                self.route = Some(RouteBinding::Owned(desired.clone()));
                let verified = route_present(&mut manager, cfg.peer, cfg.tun_index);
                if let Ok(true) = verified {
                    return Ok(());
                }
                // Roll our own route back, then fail startup.
                let rollback = remove_route(&mut manager, &desired);
                if let Err(error) = &rollback {
                    // Deleting failed: keep the binding — shutdown retries
                    // the removal instead of leaking the route.
                    crate::warn!("direct return route rollback failed — {error:#}");
                } else {
                    self.route = None;
                }
                match verified {
                    Err(error) => Err(error.context("verify direct return route")),
                    // Ok(false): a successful add the listing never shows.
                    Ok(_) => bail!(
                        "direct return route peer {}/32 via {} did not install",
                        cfg.peer,
                        cfg.tun_name
                    ),
                }
            }
            // Someone else (TUN bring-up, operator hook) installed the exact
            // route between our check and add: theirs, never deleted. A
            // foreign peer/32 via another interface is a startup error — it
            // would break the direct return path, and we never delete it.
            Err(error) if error.raw_os_error() == Some(17) => {
                if route_present(&mut manager, cfg.peer, cfg.tun_index)? {
                    self.route = Some(RouteBinding::Preinstalled);
                    return Ok(());
                }
                Err(error).with_context(|| {
                    format!(
                        "foreign route blocks the direct return route peer {}/32 via {}",
                        cfg.peer, cfg.tun_name
                    )
                })
            }
            Err(error) => Err(error).with_context(|| {
                format!(
                    "add direct return route peer {}/32 via {}",
                    cfg.peer, cfg.tun_name
                )
            }),
        }
    }

    /// Bounded teardown: the listener, all flow tasks and the expiry timer
    /// stop within the join budget; the owned return route is deleted even
    /// when a join times out — and only the one this engine installed.
    pub async fn shutdown(mut self) -> Result<()> {
        self.accept.abort();
        self.expiry.abort();
        // Reaping both tasks also drops the listener before the caller can
        // reuse the port or remove the TUN.
        let _ = tokio::time::timeout(SHUTDOWN_JOIN, &mut self.accept).await;
        let _ = tokio::time::timeout(SHUTDOWN_JOIN, &mut self.expiry).await;
        let mut tasks = self.shared.tasks.lock().await;
        tasks.abort_all();
        if tokio::time::timeout(SHUTDOWN_JOIN, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            crate::warn!("direct engine: tasks did not stop within 1 s");
        }
        drop(tasks);
        if let Some(RouteBinding::Owned(route)) = self.route.take() {
            let mut manager = route_manager::RouteManager::new().context("route manager")?;
            remove_route(&mut manager, &route).context("delete owned direct return route")?;
        }
        Ok(())
    }
}

impl TcpFlow {
    /// The outbound connect resolved: the flow leaves the pending budget
    /// and becomes a relaying connection.
    fn connected(&mut self) {
        if let TcpStage::Connecting { abort, .. } = &self.stage {
            self.stage = TcpStage::Relay {
                abort: abort.clone(),
            };
        }
    }
}

impl DirectState {
    /// Next free nat port: rotates the whole space from the end of the
    /// privileged range upward, skipping the listener port, live mappings
    /// and retired ports.
    fn allocate_port(&mut self, listener_port: u16) -> Option<u16> {
        for _ in 0..u16::MAX {
            let next = u32::from(self.port_cursor) + 1;
            self.port_cursor = if next > u32::from(u16::MAX) {
                1024
            } else {
                next as u16
            };
            if self.port_cursor < 1024 {
                self.port_cursor = 1024;
            }
            let port = self.port_cursor;
            if port == listener_port
                || self.tcp.values().any(|entry| entry.nat_port == port)
                || self.retired.iter().any(|&(retired, _)| retired == port)
            {
                continue;
            }
            return Some(port);
        }
        None
    }
}

/// Kernel listener loop: every accepted connection must be the tunnel peer
/// on a port reserved by a pending SYN; anything else is dropped.
async fn accept_loop(shared: Arc<Shared>, listener: TcpListener) {
    loop {
        let (stream, remote) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // A persistent accept error must not spin the core.
                crate::warn!("direct tcp listener: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let SocketAddr::V4(remote) = remote else {
            continue;
        };
        if *remote.ip() != shared.cfg.peer {
            crate::debug!("direct tcp: accept from {remote} is not the tunnel peer — dropped");
            continue;
        }
        let claim = {
            let mut state = shared.state.lock().unwrap();
            state.tcp.values_mut().find_map(|entry| {
                if entry.nat_port != remote.port()
                    || !matches!(entry.stage, TcpStage::Pending { .. })
                {
                    return None;
                }
                // Mark Connecting before spawning: a refused outbound
                // connection can finish before the task handle is registered
                // below. The stage keeps the pending budget until the
                // outbound connect resolves.
                entry.stage = TcpStage::Connecting {
                    abort: None,
                    deadline: Instant::now() + PENDING_TIMEOUT,
                };
                entry.last_seen = Instant::now();
                Some((entry.id, entry.flow))
            })
        };
        let Some((id, flow)) = claim else {
            crate::debug!(
                "direct tcp: accept from {remote} matches no pending reservation — dropped"
            );
            continue;
        };
        let handle = shared
            .tasks
            .lock()
            .await
            .spawn(relay(shared.clone(), id, flow, stream));
        let mut state = shared.state.lock().unwrap();
        match state.tcp.get_mut(&flow) {
            Some(entry) if entry.id == id => match &mut entry.stage {
                TcpStage::Connecting { abort, .. } | TcpStage::Relay { abort } => {
                    *abort = Some(handle)
                }
                // The relay already finished: its close report may still be
                // in flight — aborting here could cancel it, so the task
                // runs out on its own.
                TcpStage::Dwell { .. } => {}
                // A replaced reservation has nothing to serve.
                TcpStage::Pending { .. } => handle.abort(),
            },
            // Gone: the sweeper removed it and reported the close itself.
            _ => handle.abort(),
        }
    }
}

/// Dials the original destination through the bound uplink and relays bytes
/// in both directions with independent half-close. Whatever the outcome,
/// the mapping moves to dwell so the local kernel can finish its side.
async fn relay(shared: Arc<Shared>, id: u64, flow: FlowKey, mut accepted: TcpStream) {
    let destination = SocketAddrV4::new(flow.destination, flow.destination_port);
    let mut outbound = match tcp_connect(&shared.cfg, destination).await {
        Ok(stream) => stream,
        Err(error) => {
            crate::debug!("direct tcp {flow:?}: connect {destination} — {error:#}");
            return shared.fail_tcp(flow, id).await;
        }
    };
    // The connect resolved: the flow leaves the pending budget and
    // refreshes its relay idle clock.
    {
        let mut state = shared.state.lock().unwrap();
        if let Some(entry) = state.tcp.get_mut(&flow)
            && entry.id == id
        {
            entry.connected();
            entry.last_seen = Instant::now();
        }
    }
    if let Err(error) = copy_bidirectional(&mut accepted, &mut outbound).await {
        crate::debug!("direct tcp {flow:?}: relay — {error}");
        shared.fail_tcp(flow, id).await;
    } else {
        shared.finish_tcp(flow, id).await;
    }
}

/// One connected UDP socket per flow; sends the first datagram after the
/// dial, then pumps replies into the lossy packet queue with the original
/// tuple rebuilt. Oversized replies are rejected whole, never truncated.
async fn udp_flow(
    shared: Arc<Shared>,
    id: u64,
    flow: FlowKey,
    destination: SocketAddrV4,
    first: Vec<u8>,
) {
    let socket = match udp_dial(&shared.cfg, destination) {
        Ok(socket) => Arc::new(socket),
        Err(error) => {
            crate::debug!("direct udp {flow:?}: dial {destination} — {error:#}");
            return shared.finish_udp(flow, id).await;
        }
    };
    if let Err(error) = socket.send(&first).await {
        crate::debug!("direct udp {flow:?}: send — {error:#}");
        return shared.finish_udp(flow, id).await;
    }
    {
        let mut state = shared.state.lock().unwrap();
        match state.udp.get_mut(&flow) {
            Some(entry) if entry.id == id => entry.socket = Some(socket.clone()),
            // Expired mid-dial: the sweep already reported the close.
            _ => return,
        }
    }
    let origin = SocketAddrV4::new(flow.source, flow.source_port);
    // A read window one byte past the MTU-28 payload limit: anything longer
    // (including a datagram the kernel truncated to fill the window) is
    // rejected, so no reply is ever forwarded looking valid but cut short.
    let max_payload = shared.cfg.mtu as usize - 28;
    let mut buf = vec![0u8; max_payload + 1];
    loop {
        let len = match socket.recv(&mut buf).await {
            Ok(len) => len,
            Err(error) => {
                crate::debug!("direct udp {flow:?}: recv — {error:#}");
                break;
            }
        };
        {
            let mut state = shared.state.lock().unwrap();
            match state.udp.get_mut(&flow) {
                Some(entry) if entry.id == id => entry.last_seen = Instant::now(),
                _ => return,
            }
        }
        if len > max_payload {
            crate::debug!("direct udp {flow:?}: reply of {len} B exceeds MTU-28 — dropped");
            continue;
        }
        let bytes = udp_packet(destination, origin, &buf[..len]);
        let _ = shared.packets.try_send(DirectEvent::Packet { id, bytes });
    }
    shared.finish_udp(flow, id).await;
}

/// Timer-driven expiry: pending reservations and unresolved connects,
/// dwell ends, idle relays and idle UDP flows; retired ports age out. Works
/// without incoming traffic. Completed flow tasks are reaped every cycle:
/// an unreaped JoinSet grows with total historical flows, not the live
/// table.
async fn expiry_loop(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(EXPIRY_TICK);
    loop {
        tick.tick().await;
        {
            let mut tasks = shared.tasks.lock().await;
            while tasks.try_join_next().is_some() {}
        }
        let closed = {
            let mut state = shared.state.lock().unwrap();
            sweep(&mut state, Instant::now())
        };
        for (key, id) in closed {
            let _ = shared.events.send(DirectEvent::Closed { id, key }).await;
        }
    }
}

fn sweep(state: &mut DirectState, now: Instant) -> Vec<(FlowKey, u64)> {
    let mut closed = Vec::new();
    let mut retired = std::mem::take(&mut state.retired);
    state.tcp.retain(|key, entry| match entry.stage {
        // A reservation or an accepted-but-unresolved connect that never
        // resolved: both hold a pending budget slot (spec §5.5). The
        // connect's own budget resolves it earlier in every healthy path.
        TcpStage::Pending { deadline } | TcpStage::Connecting { deadline, .. }
            if deadline <= now =>
        {
            if let TcpStage::Connecting {
                abort: Some(handle),
                ..
            } = &entry.stage
            {
                handle.abort();
            }
            retired.push_back((entry.nat_port, now + PORT_RETIRE));
            closed.push((*key, entry.id));
            false
        }
        TcpStage::Dwell { until } if until <= now => {
            retired.push_back((entry.nat_port, now + PORT_RETIRE));
            closed.push((*key, entry.id));
            false
        }
        TcpStage::Relay { .. } if entry.last_seen + TCP_IDLE <= now => {
            if let TcpStage::Relay {
                abort: Some(handle),
            } = &entry.stage
            {
                handle.abort();
            }
            entry.stage = TcpStage::Dwell {
                until: now + FIN_DWELL,
            };
            true
        }
        _ => true,
    });
    state.udp.retain(|key, entry| {
        if entry.last_seen + UDP_IDLE <= now {
            if let Some(abort) = &entry.abort {
                abort.abort();
            }
            closed.push((*key, entry.id));
            false
        } else {
            true
        }
    });
    while retired.front().is_some_and(|&(_, until)| until <= now) {
        retired.pop_front();
    }
    state.retired = retired;
    closed
}

/// Outbound TCP connect: binds the physical uplink first — an unbound socket
/// could loop back into the TUN default (spec §5.1) — then connects with a
/// bounded budget. The in-progress error surfaces later via SO_ERROR.
async fn tcp_connect(config: &DirectConfig, destination: SocketAddrV4) -> Result<TcpStream> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .context("direct tcp socket")?;
    socket
        .set_nonblocking(true)
        .context("direct tcp nonblocking")?;
    bind_uplink(&socket, &config.uplink)?;
    let _ = socket.connect(&socket2::SockAddr::from(destination));
    let stream = TcpStream::from_std(socket.into()).context("direct tcp register")?;
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        stream.writable().await.context("direct tcp connect wait")?;
        match stream.take_error().context("direct tcp so_error")? {
            Some(error) => Err(anyhow::Error::new(error).context("direct tcp connect")),
            None => Ok(stream),
        }
    })
    .await
    .context("direct tcp connect timeout")?
}

/// Outbound UDP dial: same uplink binding, connected to the original
/// destination so replies are scoped to this flow.
fn udp_dial(config: &DirectConfig, destination: SocketAddrV4) -> Result<UdpSocket> {
    let socket =
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).context("direct udp socket")?;
    socket
        .set_nonblocking(true)
        .context("direct udp nonblocking")?;
    bind_uplink(&socket, &config.uplink)?;
    socket
        .connect(&socket2::SockAddr::from(destination))
        .context("direct udp connect")?;
    UdpSocket::from_std(socket.into()).context("direct udp register")
}

/// Binds `socket` to the captured physical uplink before any connect or
/// send. A failed binding is the only fallback: the flow errors out, it is
/// never sent unbound. Linux `SO_BINDTODEVICE`, macOS `IP_BOUND_IF`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn bind_uplink(socket: &Socket, uplink: &Uplink) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        socket
            .bind_device(Some(uplink.name.as_bytes()))
            .context("bind direct socket to the uplink (SO_BINDTODEVICE, needs CAP_NET_RAW)")
    }
    #[cfg(target_os = "macos")]
    {
        let index = NonZeroU32::new(uplink.index).context("uplink interface index")?;
        socket
            .bind_device_by_index_v4(Some(index))
            .context("bind direct socket to the uplink (IP_BOUND_IF)")
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn bind_uplink(socket: &Socket, uplink: &Uplink) -> Result<()> {
    let _ = (socket, uplink);
    bail!("direct uplink binding is not supported on this platform")
}

fn validate(config: &DirectConfig) -> Result<()> {
    // Loopback stays allowed: integration tests drive the kernel paths over
    // loopback without a real TUN (packet::unicast would reject it).
    let usable = |ip: Ipv4Addr| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast();
    ensure!(
        usable(config.client) && usable(config.peer) && config.client != config.peer,
        "invalid direct tunnel pair"
    );
    ensure!(
        (576..=1400).contains(&config.mtu),
        "MTU must be between 576 and 1400"
    );
    ensure!(
        !config.tun_name.is_empty() && config.tun_index != 0,
        "direct requires the negotiated TUN identity"
    );
    ensure!(
        !config.uplink.name.is_empty() && config.uplink.index != 0,
        "direct requires the captured physical uplink"
    );
    Ok(())
}

/// The Hub validated the packet on admission; the engine asserts the tuple
/// belongs to its own client so a NAT mapping is never created for a foreign
/// source. Unlike `FlowKey::valid_for`, loopback addresses stay usable.
fn client_flow(flow: &FlowKey, client: Ipv4Addr) -> bool {
    flow.source == client
        && matches!(flow.protocol, 6 | 17)
        && flow.source_port != 0
        && flow.destination_port != 0
        && !flow.destination.is_unspecified()
}

/// Rewrites the tuple of a parsed IPv4 packet: addresses and ports change,
/// everything else — IHL, options, TTL, seq/ack, window, flags, payload — is
/// preserved byte for byte, with the IPv4 header and transport checksums
/// recomputed. UDP checksums are always computed (a computed zero is sent as
/// 0xFFFF per RFC 768).
fn rewrite_tuple(
    bytes: &[u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> Option<Vec<u8>> {
    if bytes.len() < 28 || bytes[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if ihl < 20 || total != bytes.len() || total < ihl + 8 {
        return None;
    }
    let protocol = bytes[9];
    if !matches!(protocol, 6 | 17) {
        return None;
    }
    let mut out = bytes.to_vec();
    out[12..16].copy_from_slice(&source.octets());
    out[16..20].copy_from_slice(&destination.octets());
    out[ihl..ihl + 2].copy_from_slice(&source_port.to_be_bytes());
    out[ihl + 2..ihl + 4].copy_from_slice(&destination_port.to_be_bytes());
    let checksum_at = match protocol {
        6 => ihl + 16,
        _ => ihl + 6,
    };
    out[checksum_at..checksum_at + 2].fill(0);
    let mut checksum = transport_checksum(source, destination, protocol, &out[ihl..]);
    if protocol == 17 && checksum == 0 {
        checksum = u16::MAX;
    }
    out[checksum_at..checksum_at + 2].copy_from_slice(&checksum.to_be_bytes());
    out[10..12].fill(0);
    let header = internet_checksum(&out[..ihl]);
    out[10..12].copy_from_slice(&header.to_be_bytes());
    Some(out)
}

/// Payload of a parsed UDP packet (the caller checked it parses).
fn udp_payload(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 28 || bytes[0] >> 4 != 4 || bytes[9] != 17 {
        return None;
    }
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    (ihl >= 20 && total == bytes.len() && total >= ihl + 8).then(|| &bytes[ihl + 8..total])
}

/// IPv4+UDP reply `source → destination` (the original flow tuple): the
/// packet an application expects to read from the TUN.
fn udp_packet(source: SocketAddrV4, destination: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut bytes = vec![0u8; total];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&0x534eu16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&source.ip().octets());
    bytes[16..20].copy_from_slice(&destination.ip().octets());
    bytes[20..22].copy_from_slice(&source.port().to_be_bytes());
    bytes[22..24].copy_from_slice(&destination.port().to_be_bytes());
    bytes[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes[28..].copy_from_slice(payload);
    let mut checksum = transport_checksum(*source.ip(), *destination.ip(), 17, &bytes[20..]);
    if checksum == 0 {
        checksum = u16::MAX;
    }
    bytes[26..28].copy_from_slice(&checksum.to_be_bytes());
    let header = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&header.to_be_bytes());
    bytes
}

/// RFC 1071 checksum over the IPv4 pseudo-header plus the transport segment.
fn transport_checksum(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    let mut buf = Vec::with_capacity(12 + segment.len());
    buf.extend_from_slice(&source.octets());
    buf.extend_from_slice(&destination.octets());
    buf.push(0);
    buf.push(protocol);
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(segment);
    internet_checksum(&buf)
}

/// The `peer/32` unicast route via this TUN; main table (254) on Linux.
fn peer_route(peer: Ipv4Addr, tun_index: u32) -> route_manager::Route {
    #[cfg(target_os = "linux")]
    {
        route_manager::Route::new(IpAddr::V4(peer), 32)
            .with_if_index(tun_index)
            .with_table(254)
    }
    #[cfg(not(target_os = "linux"))]
    {
        route_manager::Route::new(IpAddr::V4(peer), 32).with_if_index(tun_index)
    }
}

/// Whether the exact `peer/32` route via this TUN interface is present.
fn route_present(
    manager: &mut route_manager::RouteManager,
    peer: Ipv4Addr,
    tun_index: u32,
) -> Result<bool> {
    let routes = manager.list().context("list routes")?;
    Ok(routes
        .iter()
        .any(|route| peer_route_matches(route, peer, tun_index)))
}

/// The kernel's preference between equal default routes: the lower
/// metric wins. An absent metric is zero on Linux/Windows; on macOS/BSD
/// every listed default is equivalent.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn route_metric(route: &route_manager::Route) -> Option<u32> {
    route.metric()
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn route_metric(_route: &route_manager::Route) -> Option<u32> {
    None
}

/// Whether `route` is exactly the `peer/32` return route via this TUN
/// interface (main table on Linux). The ownership notion of spec §5.2.
pub fn peer_route_matches(route: &route_manager::Route, peer: Ipv4Addr, tun_index: u32) -> bool {
    route.destination() == IpAddr::V4(peer)
        && route.prefix() == 32
        && route.if_index() == Some(tun_index)
        && table_is_main(route)
}

/// Deletes a route this engine owns. A route that already vanished — the
/// TUN interface was removed first, taking its routes with it — is
/// success, not an error.
fn remove_route(
    manager: &mut route_manager::RouteManager,
    route: &route_manager::Route,
) -> Result<()> {
    match manager.delete(route) {
        Ok(()) => Ok(()),
        Err(error) if route_error_is_missing(&error) => Ok(()),
        Err(error) => Err(anyhow::Error::new(error)),
    }
}

/// Deletion is idempotent after a down-hook or interface removal. Linux
/// reports ENOENT; macOS route(4) reports ESRCH for a missing route.
pub fn route_error_is_missing(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(2 | 3))
}

#[cfg(target_os = "linux")]
fn table_is_main(route: &route_manager::Route) -> bool {
    route.table() == 254
}

#[cfg(not(target_os = "linux"))]
fn table_is_main(_route: &route_manager::Route) -> bool {
    true
}
