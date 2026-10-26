//! Home-country TCP/UDP flows use the host stack on the physical uplink.
//! TCP is terminated by a local listener and relayed; UDP uses one bound
//! socket per flow. Shared maps are locked only for short operations, never
//! across `.await`.

use std::{
    collections::{HashMap, VecDeque},
    io,
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

/// Maximum simultaneous TCP and UDP mappings.
pub const MAX_FLOWS: usize = 4096;
/// Maximum unanswered-SYN reservations.
pub const MAX_PENDING: usize = 64;
/// Lossy packet queue capacity.
pub const PACKET_QUEUE: usize = 1024;
/// Reliable lifecycle event queue capacity.
const EVENT_QUEUE: usize = 1024;
/// Reservation lifetime for an unanswered SYN.
pub const PENDING_TIMEOUT: Duration = Duration::from_secs(30);
/// Outbound connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// UDP idle timeout.
pub const UDP_IDLE: Duration = Duration::from_secs(60);
/// TCP relay idle timeout.
pub const TCP_IDLE: Duration = Duration::from_secs(2 * 3600 + 4 * 60);
/// Keep NAT mappings briefly for delayed FIN/ACK packets.
pub const FIN_DWELL: Duration = Duration::from_secs(4 * 60);
/// Keep retired NAT ports out of rotation while old segments may arrive.
pub const PORT_RETIRE: Duration = Duration::from_secs(4 * 60);
/// Expiry timer interval.
const EXPIRY_TICK: Duration = Duration::from_secs(1);
/// Shutdown join timeout.
const SHUTDOWN_JOIN: Duration = Duration::from_secs(1);

/// Physical uplink captured before hooks can change routing.
/// Every direct socket must bind to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uplink {
    pub name: String,
    pub index: u32,
}

/// Find the physical interface of the lowest-metric IPv4 default route.
/// Call before hooks replace the routing view; a longest-prefix lookup
/// could otherwise select the tunnel's `0.0.0.0/1`.
pub fn discover_uplink() -> Result<Uplink> {
    let mut manager = route_manager::RouteManager::new().context("route manager")?;
    let routes = manager.list().context("list routes")?;
    select_uplink(&routes)
}

/// Select the preferred main-table default route.
/// Linux omits a zero metric in netlink; treat an absent metric as zero.
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

/// Live tunnel identity, MTU and physical uplink for a direct engine.
/// Tests may use loopback instead of a real TUN.
#[derive(Clone, Debug)]
pub struct DirectConfig {
    pub client: Ipv4Addr,
    pub peer: Ipv4Addr,
    pub tun_name: String,
    pub tun_index: u32,
    pub mtu: u16,
    pub uplink: Uplink,
}

/// Engine output for the Hub. Packets are lossy; terminal events are
/// reliable and tagged with the flow id.
#[derive(Debug)]
pub enum DirectEvent {
    /// Packet to write into the TUN.
    Packet { id: u64, bytes: Vec<u8> },
    /// Flow finished normally. The original key prevents a late close from
    /// removing a replacement owner.
    Closed { id: u64, key: FlowKey },
    /// Background socket failure terminated this flow.
    Failed { id: u64, key: FlowKey },
}

#[derive(Debug)]
enum TcpStage {
    /// Rewritten SYN waiting for local accept.
    Pending { deadline: Instant },
    /// Locally accepted, with outbound connect still pending.
    Connecting {
        abort: Option<AbortHandle>,
        deadline: Instant,
    },
    /// Connected relay; the idle sweep uses its abort handle.
    Relay { abort: Option<AbortHandle> },
    /// Relay finished; mappings remain for delayed kernel FIN/ACK packets.
    Dwell { until: Instant },
}

struct TcpFlow {
    id: u64,
    /// NAT port used for the rewritten peer source.
    nat_port: u16,
    /// Original flow tuple used for reverse rewriting.
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
    /// Retired NAT ports and their reuse deadlines.
    retired: VecDeque<(u16, Instant)>,
    port_cursor: u16,
}

struct Shared {
    cfg: DirectConfig,
    listener_port: u16,
    // The process aborts on panic; never hold this lock across an await.
    state: Mutex<DirectState>,
    tasks: AsyncMutex<JoinSet<()>>,
    packets: mpsc::Sender<DirectEvent>,
    events: mpsc::Sender<DirectEvent>,
}

impl Shared {
    /// Keep an accepted socket's NAT mapping through FIN_DWELL after failure,
    /// but report the flow failure to the Hub immediately.
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

    /// Relay completion enters FIN_DWELL without retiring the Hub owner.
    /// Expiry emits Closed only after both mappings are removed.
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

    /// Background UDP failures use the reliable channel. Hub-originated
    /// send errors remove the mapping synchronously to avoid a queue deadlock.
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

/// Ownership of the peer return route. Only routes installed by this
/// engine are removed; preexisting or concurrently added routes are foreign.
#[derive(Debug)]
enum RouteBinding {
    /// Preexisting route; never removed by this engine.
    Preinstalled,
    /// Installed by this engine; removed on shutdown.
    Owned(route_manager::Route),
}

/// Direct TCP/UDP engine driven by the Hub.
pub struct DirectEngine {
    shared: Arc<Shared>,
    accept: tokio::task::JoinHandle<()>,
    expiry: tokio::task::JoinHandle<()>,
    packets_rx: mpsc::Receiver<DirectEvent>,
    events_rx: mpsc::Receiver<DirectEvent>,
    /// Return-route ownership.
    route: Option<RouteBinding>,
}

impl DirectEngine {
    /// Bind the local listener and start accept/expiry tasks.
    /// Listener bind failure is fatal; outbound bind failure is per-flow.
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

    /// Actual local listener port.
    pub fn listen_port(&self) -> u16 {
        self.shared.listener_port
    }

    /// Number of live mappings.
    pub fn flow_count(&self) -> usize {
        let state = self.shared.state.lock().unwrap();
        state.tcp.len() + state.udp.len()
    }

    /// Whether this flow generation still owns a mapping.
    pub(crate) fn owns(&self, flow: FlowKey, id: u64) -> bool {
        let state = self.shared.state.lock().unwrap();
        match flow.protocol {
            6 => state.tcp.get(&flow).is_some_and(|entry| entry.id == id),
            17 => state.udp.get(&flow).is_some_and(|entry| entry.id == id),
            _ => false,
        }
    }

    /// Whether TCP NAT state is still retained after relay completion.
    pub fn tcp_in_dwell(&self, flow: FlowKey) -> bool {
        let state = self.shared.state.lock().unwrap();
        matches!(
            state.tcp.get(&flow).map(|entry| &entry.stage),
            Some(TcpStage::Dwell { .. })
        )
    }

    /// Install a TCP reservation and rewrite its first SYN.
    /// Retransmitted SYNs reuse the reservation.
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

    /// Rewrite a later client TCP segment and refresh its idle timer.
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

    /// Rewrite a listener packet back to the original flow tuple.
    /// This runs before new-flow admission so SYN-ACKs cannot be misclassified.
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

    /// Allocate a UDP mapping and start its connected-socket task.
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

    /// Send a later UDP datagram; datagrams arriving before connect are dropped.
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
            // An ICMP error reply is destination feedback, not a broken
            // local socket. Keep the mapping so the application can see the
            // error and continue using the original tuple.
            if is_icmp_feedback(&error) {
                crate::debug!("direct udp {:?}: ICMP error reply — {error}", parsed.flow);
                return Ok(());
            }
            // Hub dispatch reconciles the close synchronously; never await
            // the reliable queue while the Hub itself is its drain.
            self.shared.forget_udp(parsed.flow, id);
            return Err(error).context("direct udp send");
        }
        Ok(())
    }

    /// Poll events without blocking, reliable events first.
    pub fn poll_event(&mut self) -> Option<DirectEvent> {
        if let Ok(event) = self.events_rx.try_recv() {
            return Some(event);
        }
        self.packets_rx.try_recv().ok()
    }

    /// Receive the next event for a Hub select loop.
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

    /// Ensure the peer/32 return route and record its ownership.
    /// Roll back failed verification; never delete or overwrite foreign routes.
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

    /// Stop tasks within the join budget and delete only our return route.
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
    /// Move a connected flow out of the pending budget.
    fn connected(&mut self) {
        if let TcpStage::Connecting { abort, .. } = &self.stage {
            self.stage = TcpStage::Relay {
                abort: abort.clone(),
            };
        }
    }
}

impl DirectState {
    /// Allocate a NAT port, skipping live, retired and listener ports.
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

/// Accept only the tunnel peer on ports reserved by pending SYNs.
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

/// Connect through the uplink and relay with independent half-close.
/// Always leave the mapping in dwell afterward.
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

/// Run one connected UDP socket per flow.
/// Rebuild replies with the original tuple and reject oversized replies.
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
        if !is_icmp_feedback(&error) {
            crate::debug!("direct udp {flow:?}: send — {error:#}");
            return shared.finish_udp(flow, id).await;
        }
        crate::debug!("direct udp {flow:?}: ICMP error reply — {error}");
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
            Err(error) if is_icmp_feedback(&error) => {
                // Unreachable/refused is an ICMP response for the app, not
                // a reason to tear down this flow's mapping.
                crate::debug!("direct udp {flow:?}: ICMP error reply — {error}");
                continue;
            }
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

/// Expire pending, idle and dwell flows without incoming traffic.
/// Reap completed tasks and retired ports on every pass.
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

/// Bind to the uplink before a bounded TCP connect.
/// An in-progress error is read later from SO_ERROR.
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

/// Bind and connect a UDP socket to the original destination.
fn udp_dial(config: &DirectConfig, destination: SocketAddrV4) -> Result<UdpSocket> {
    let socket =
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).context("direct udp socket")?;
    socket
        .set_nonblocking(true)
        .context("direct udp nonblocking")?;
    bind_uplink(&socket, &config.uplink)?;
    // A fresh socket has sent no request, so a connect error is local and
    // must still fail the flow; only established send/recv errors can be
    // asynchronous ICMP feedback.
    socket
        .connect(&socket2::SockAddr::from(destination))
        .context("direct udp connect")?;
    UdpSocket::from_std(socket.into()).context("direct udp register")
}

/// ICMP errors report destination feedback, not a dead local mapping.
/// Do not classify permission, descriptor or socket-state errors as ICMP.
pub fn is_icmp_feedback(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::TimedOut
    )
}

/// Bind a socket to the uplink before connect/send.
/// Failure is per-flow; never send unbound. Linux uses SO_BINDTODEVICE,
/// macOS uses IP_BOUND_IF.
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

/// Assert that the admitted tuple belongs to this client.
/// Loopback remains allowed for integration tests.
fn client_flow(flow: &FlowKey, client: Ipv4Addr) -> bool {
    flow.source == client
        && matches!(flow.protocol, 6 | 17)
        && flow.source_port != 0
        && flow.destination_port != 0
        && !flow.destination.is_unspecified()
}

/// Rewrite addresses and ports, preserving the remaining packet fields.
/// Recompute IPv4/transport checksums; encode a zero UDP checksum as 0xFFFF.
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

/// Return the payload of an already validated UDP packet.
fn udp_payload(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 28 || bytes[0] >> 4 != 4 || bytes[9] != 17 {
        return None;
    }
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    (ihl >= 20 && total == bytes.len() && total >= ihl + 8).then(|| &bytes[ihl + 8..total])
}

/// Build a UDP reply using the original flow tuple.
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

/// Compute the transport checksum with the IPv4 pseudo-header.
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

/// Build the peer/32 unicast route via this TUN.
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

/// Check for the exact peer/32 route via this TUN.
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

/// Compare default-route metrics; an absent metric is zero on Linux/Windows.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn route_metric(route: &route_manager::Route) -> Option<u32> {
    route.metric()
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn route_metric(_route: &route_manager::Route) -> Option<u32> {
    None
}

/// Check whether a route is our exact peer/32 TUN route.
pub fn peer_route_matches(route: &route_manager::Route, peer: Ipv4Addr, tun_index: u32) -> bool {
    route.destination() == IpAddr::V4(peer)
        && route.prefix() == 32
        && route.if_index() == Some(tun_index)
        && table_is_main(route)
}

/// Delete an owned route; an already vanished route is success.
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

/// Treat Linux ENOENT and macOS ESRCH as an already deleted route.
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
