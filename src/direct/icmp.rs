//! Home-country ICMP echo flows use raw sockets on the physical uplink.
//! Each flow preserves the original id/seq/payload and rewrites replies
//! (including quoted ICMP errors) back to the client tuple. Raw sockets
//! require CAP_NET_RAW/root; failure affects ICMP only, never VPN fallback.

use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail, ensure};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::UdpSocket,
    sync::{Mutex as AsyncMutex, mpsc},
    task::{AbortHandle, JoinSet},
    time::Instant,
};

use crate::packet::{self, FlowKey, Packet, internet_checksum};

use super::{
    DirectConfig, DirectEvent, EVENT_QUEUE, EXPIRY_TICK, MAX_FLOWS, PACKET_QUEUE, SHUTDOWN_JOIN,
    UDP_IDLE, Uplink, bind_uplink, is_icmp_feedback, validate,
};

fn is_icmp_feedback_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(is_icmp_feedback)
    })
}

// UdpSocket drives send/recv on the raw ICMP socket; std has no ICMP type.

/// Echo fields preserved by a direct flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Echo {
    pub id: u16,
    pub seq: u16,
    pub payload: Vec<u8>,
}

/// Validate a complete, unfragmented ICMP echo request and its checksum.
pub fn parse_echo_request(bytes: &[u8]) -> Option<Echo> {
    let (header, total) = ipv4_header(bytes)?;
    if total != bytes.len() || bytes[9] != 1 || fragmented(bytes) {
        return None;
    }
    echo_message(&bytes[header..total], 8)
}

/// Validate a raw echo reply and return its source, TTL and echo fields.
/// Reject packets beyond the TUN MTU, including truncated packets.
pub fn parse_echo_reply_ip(bytes: &[u8], mtu: usize) -> Option<(Ipv4Addr, u8, Echo)> {
    let (header, total) = ipv4_header(bytes)?;
    if bytes[9] != 1 {
        return None;
    }
    if total > bytes.len() {
        return None;
    }
    let end = total;
    if end > mtu {
        return None;
    }
    let echo = echo_message(&bytes[header..end], 0)?;
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    Some((source, bytes[8], echo))
}

/// Convert Darwin's host-order outer ip_len/ip_off to wire order.
/// Quoted headers in ICMP errors remain untouched.
pub fn normalize_darwin_raw_ip(bytes: &mut [u8]) {
    if bytes.len() < 20 {
        return;
    }
    let total = u16::from_ne_bytes([bytes[2], bytes[3]]);
    bytes[2..4].copy_from_slice(&total.to_be_bytes());
    let offset = u16::from_ne_bytes([bytes[6], bytes[7]]);
    bytes[6..8].copy_from_slice(&offset.to_be_bytes());
}

/// Rewrite an ICMP error quoting our request for delivery to the client.
/// Match the physical source and recompute all affected checksums.
/// Return None for malformed, unrelated or non-error packets.
pub fn rewrite_icmp_error(
    bytes: &[u8],
    client: Ipv4Addr,
    physical: Ipv4Addr,
) -> Option<(FlowKey, Vec<u8>)> {
    let (header, total) = ipv4_header(bytes)?;
    if bytes[9] != 1 || total > bytes.len() {
        return None;
    }
    let icmp = &bytes[header..total];
    if !matches!(icmp.first()?, 3 | 11 | 12) || icmp.len() < 8 {
        return None;
    }
    if internet_checksum(icmp) != 0 {
        return None;
    }
    let quote = icmp.get(8..)?;
    let (quote_header, quote_total) = ipv4_header(quote)?;
    if quote[9] != 1 || quote_total < quote_header + 8 {
        return None;
    }
    // RFC 792 quotes only the IP header and 8 bytes; the full checksum
    // cannot be validated from this prefix.
    let quoted = quote.get(quote_header..quote_header + 8)?;
    if quoted[0] != 8 || quoted[1] != 0 {
        return None;
    }
    if quote[12..16] != physical.octets() {
        return None;
    }
    let mut out = bytes[..total].to_vec();
    let at = header + 8; // offset of the quoted IPv4 header inside `out`
    out[at + 12..at + 16].copy_from_slice(&client.octets());
    out[at + 10..at + 12].fill(0);
    let checksum = internet_checksum(&out[at..at + quote_header]);
    out[at + 10..at + 12].copy_from_slice(&checksum.to_be_bytes());
    out[16..20].copy_from_slice(&client.octets());
    out[header + 2..header + 4].fill(0);
    let checksum = internet_checksum(&out[header..total]);
    out[header + 2..header + 4].copy_from_slice(&checksum.to_be_bytes());
    out[10..12].fill(0);
    let checksum = internet_checksum(&out[..header]);
    out[10..12].copy_from_slice(&checksum.to_be_bytes());
    let flow = FlowKey {
        protocol: 1,
        source: client,
        destination: Ipv4Addr::new(quote[16], quote[17], quote[18], quote[19]),
        source_port: u16::from_be_bytes([quoted[4], quoted[5]]),
        destination_port: 0,
    };
    Some((flow, out))
}

/// Build an echo request with a fresh checksum.
fn echo_request_message(echo: &Echo) -> Vec<u8> {
    let mut icmp = vec![0u8; 8 + echo.payload.len()];
    icmp[0] = 8;
    icmp[4..6].copy_from_slice(&echo.id.to_be_bytes());
    icmp[6..8].copy_from_slice(&echo.seq.to_be_bytes());
    icmp[8..].copy_from_slice(&echo.payload);
    let checksum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    icmp
}

/// Build an echo reply with the original tuple and valid checksums.
pub fn echo_reply_packet(source: Ipv4Addr, destination: Ipv4Addr, ttl: u8, echo: &Echo) -> Vec<u8> {
    let icmp_len = 8 + echo.payload.len();
    let total = 20 + icmp_len;
    let mut bytes = vec![0u8; total];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[8] = ttl;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&source.octets());
    bytes[16..20].copy_from_slice(&destination.octets());
    bytes[20] = 0;
    bytes[24..26].copy_from_slice(&echo.id.to_be_bytes());
    bytes[26..28].copy_from_slice(&echo.seq.to_be_bytes());
    bytes[28..].copy_from_slice(&echo.payload);
    let checksum = internet_checksum(&bytes[20..]);
    bytes[22..24].copy_from_slice(&checksum.to_be_bytes());
    let checksum = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

/// Validate an IPv4 header and return its header and total lengths.
fn ipv4_header(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return None;
    }
    let header = usize::from(bytes[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    (header >= 20 && header <= total).then_some((header, total))
}

fn fragmented(bytes: &[u8]) -> bool {
    u16::from_be_bytes([bytes[6], bytes[7]]) & 0xbfff != 0
}

/// Validate an echo message of the expected type, code and checksum.
fn echo_message(icmp: &[u8], expected_type: u8) -> Option<Echo> {
    if icmp.len() < 8 || icmp[0] != expected_type || icmp[1] != 0 {
        return None;
    }
    if internet_checksum(icmp) != 0 {
        return None;
    }
    Some(Echo {
        id: u16::from_be_bytes([icmp[4], icmp[5]]),
        seq: u16::from_be_bytes([icmp[6], icmp[7]]),
        payload: icmp[8..].to_vec(),
    })
}

struct IcmpFlow {
    id: u64,
    socket: Arc<UdpSocket>,
    abort: Option<AbortHandle>,
    last_seen: Instant,
}

#[derive(Default)]
struct IcmpState {
    flows: HashMap<FlowKey, IcmpFlow>,
}

struct Shared {
    cfg: DirectConfig,
    /// Physical source address for requests.
    source: Ipv4Addr,
    // The process aborts on panic; never hold this lock across an await.
    state: Mutex<IcmpState>,
    tasks: AsyncMutex<JoinSet<()>>,
    packets: mpsc::Sender<DirectEvent>,
    events: mpsc::Sender<DirectEvent>,
}

impl Shared {
    fn remove_icmp(&self, flow: &FlowKey, id: u64) -> Option<IcmpFlow> {
        let mut state = self.state.lock().unwrap();
        match state.flows.get(flow) {
            Some(entry) if entry.id == id => state.flows.remove(flow),
            _ => None,
        }
    }

    async fn finish_icmp(&self, flow: &FlowKey, id: u64) {
        let Some(entry) = self.remove_icmp(flow, id) else {
            return;
        };
        let _ = self
            .events
            .send(DirectEvent::Failed { id, key: *flow })
            .await;
        if let Some(abort) = entry.abort {
            abort.abort();
        }
    }

    fn forget_icmp(&self, flow: &FlowKey, id: u64) {
        if let Some(entry) = self.remove_icmp(flow, id)
            && let Some(abort) = entry.abort
        {
            abort.abort();
        }
    }
}

/// Direct ICMP engine driven by the Hub.
/// The TCP/UDP engine owns the shared return route.
pub struct IcmpEngine {
    shared: Arc<Shared>,
    expiry: tokio::task::JoinHandle<()>,
    packets_rx: mpsc::Receiver<DirectEvent>,
    events_rx: mpsc::Receiver<DirectEvent>,
}

impl IcmpEngine {
    /// Derive the uplink source and start expiry.
    /// Initialization failure disables ICMP only; it never enables VPN fallback.
    pub async fn new(config: DirectConfig) -> Result<Self> {
        validate(&config)?;
        let source = uplink_source(&config.uplink)?;
        let (packets_tx, packets_rx) = mpsc::channel(PACKET_QUEUE);
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
        let shared = Arc::new(Shared {
            cfg: config,
            source,
            state: Mutex::default(),
            tasks: AsyncMutex::new(JoinSet::new()),
            packets: packets_tx,
            events: events_tx,
        });
        let expiry = tokio::spawn(icmp_expiry_loop(shared.clone()));
        Ok(Self {
            shared,
            expiry,
            packets_rx,
            events_rx,
        })
    }

    /// Physical source address used for requests.
    pub fn uplink_source(&self) -> Ipv4Addr {
        self.shared.source
    }

    /// Number of live mappings.
    pub fn flow_count(&self) -> usize {
        self.shared.state.lock().unwrap().flows.len()
    }

    /// Whether this flow generation still owns a mapping.
    pub(crate) fn owns(&self, flow: FlowKey, id: u64) -> bool {
        self.shared
            .state
            .lock()
            .unwrap()
            .flows
            .get(&flow)
            .is_some_and(|entry| entry.id == id)
    }

    /// Validate and send the first echo request, creating its socket first.
    /// Repeated requests reuse the socket; failed setup creates no mapping.
    pub async fn open_icmp(&mut self, id: u64, packet: &Packet, bytes: &[u8]) -> Result<()> {
        let cfg = &self.shared.cfg;
        ensure!(packet.flow.protocol == 1, "direct open: not an ICMP flow");
        ensure!(
            packet.can_open,
            "direct open: only an echo request opens a flow"
        );
        ensure!(
            packet.flow.source == cfg.client,
            "direct open: flow does not originate from the client address"
        );
        ensure!(
            !packet.flow.destination.is_unspecified()
                && !packet.flow.destination.is_multicast()
                && !packet.flow.destination.is_broadcast(),
            "direct open: unusable echo destination"
        );
        let echo = parse_echo_request(bytes).context("direct icmp open: bad echo request")?;
        ensure!(
            echo.id == packet.flow.source_port,
            "direct icmp open: echo id disagrees with the flow key"
        );
        let flow = packet.flow;
        let ttl = bytes[8];
        let existing = {
            let state = self.shared.state.lock().unwrap();
            match state.flows.get(&flow) {
                Some(entry) => {
                    ensure!(entry.id == id, "direct open: stale flow id");
                    Some(entry.socket.clone())
                }
                None => {
                    ensure!(
                        state.flows.len() < MAX_FLOWS,
                        "direct flow capacity exhausted ({MAX_FLOWS})"
                    );
                    None
                }
            }
        };
        let socket = match &existing {
            Some(socket) => socket.clone(),
            None => Arc::new(icmp_socket(&cfg.uplink, self.shared.source)?),
        };
        let message = echo_request_message(&echo);
        if let Err(error) = send_request(&socket, flow.destination, ttl, &message).await {
            if !is_icmp_feedback_error(&error) {
                return Err(error);
            }
            crate::debug!("direct icmp {flow:?}: ICMP error reply — {error:#}");
        }
        if existing.is_none() {
            // Register the task before it can finish and report failure.
            self.shared.state.lock().unwrap().flows.insert(
                flow,
                IcmpFlow {
                    id,
                    socket: socket.clone(),
                    abort: None,
                    last_seen: Instant::now(),
                },
            );
            let handle = self.shared.tasks.lock().await.spawn(icmp_flow(
                self.shared.clone(),
                id,
                flow,
                socket,
            ));
            let mut state = self.shared.state.lock().unwrap();
            if let Some(entry) = state.flows.get_mut(&flow)
                && entry.id == id
            {
                entry.abort = Some(handle);
            }
            // Do not abort a task that may still be reporting its close.
        }
        Ok(())
    }

    /// Send a later echo request with its TTL.
    pub async fn forward_icmp(&self, id: u64, bytes: &[u8]) -> Result<()> {
        let parsed = packet::parse(bytes, true).context("direct icmp forward: bad packet")?;
        ensure!(
            parsed.flow.protocol == 1,
            "direct icmp forward: not an ICMP flow"
        );
        let echo = parse_echo_request(bytes).context("direct icmp forward: bad echo request")?;
        let ttl = bytes[8];
        let socket = {
            let mut state = self.shared.state.lock().unwrap();
            let entry = state
                .flows
                .get_mut(&parsed.flow)
                .context("direct icmp forward: no mapping for the flow")?;
            ensure!(entry.id == id, "direct icmp forward: stale flow id");
            entry.last_seen = Instant::now();
            entry.socket.clone()
        };
        let message = echo_request_message(&echo);
        if let Err(error) = send_request(&socket, parsed.flow.destination, ttl, &message).await {
            if is_icmp_feedback_error(&error) {
                crate::debug!(
                    "direct icmp {:?}: ICMP error reply — {error:#}",
                    parsed.flow
                );
                return Ok(());
            }
            // The Hub reconciles this close synchronously; do not await its queue.
            self.shared.forget_icmp(&parsed.flow, id);
            return Err(error).context("direct icmp send");
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
        // The engine retains senders, so both channels stay open.
        tokio::select! {
            event = self.events_rx.recv() => event.expect("engine event senders alive"),
            event = self.packets_rx.recv() => event.expect("engine packet senders alive"),
        }
    }

    /// Stop tasks within the join budget; the TCP/UDP engine owns the route.
    pub async fn shutdown(mut self) -> Result<()> {
        self.expiry.abort();
        let _ = tokio::time::timeout(SHUTDOWN_JOIN, &mut self.expiry).await;
        let mut tasks = self.shared.tasks.lock().await;
        tasks.abort_all();
        if tokio::time::timeout(SHUTDOWN_JOIN, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            crate::warn!("direct icmp engine: tasks did not stop within 1 s");
        }
        Ok(())
    }
}

/// The uplink's own IPv4 address comes from the interface, not from a
/// UDP route probe: Linux can report another interface's source for a
/// device-bound socket when the probed destination has no route. Every
/// direct ICMP request is sent from this address — the client's tunnel
/// address must never appear on the physical network.
fn uplink_source(uplink: &Uplink) -> Result<Ipv4Addr> {
    let interfaces = nix::ifaddrs::getifaddrs().context("enumerate direct uplink addresses")?;
    for interface in interfaces.filter(|interface| interface.interface_name == uplink.name) {
        let Some(address) = interface.address else {
            continue;
        };
        let Some(address) = address.as_sockaddr_in() else {
            continue;
        };
        let ip = address.ip();
        if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() {
            return Ok(ip);
        }
    }
    bail!("the direct uplink has no usable IPv4 source address")
}

/// One raw ICMP socket per flow: pinned to the uplink and its physical
/// source. Raw mode preserves the echo id and the IPv4 header on both
/// supported systems; direct already requires network privileges.
fn icmp_socket(uplink: &Uplink, source: Ipv4Addr) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .context("direct icmp raw socket (SOCK_RAW needs CAP_NET_RAW/root)")?;
    socket
        .set_nonblocking(true)
        .context("direct icmp nonblocking")?;
    bind_uplink(&socket, uplink)?;
    socket
        .bind(&socket2::SockAddr::from(SocketAddrV4::new(source, 0)))
        .context("bind direct icmp socket to the uplink source address")?;
    UdpSocket::from_std(socket.into()).context("register direct icmp socket")
}

/// Sends one request message with the client's TTL. Both calls are
/// non-blocking syscalls on the flow's private socket; the Hub dispatcher
/// awaits this to completion, so they are never interleaved with another
/// request of the same socket.
async fn send_request(
    socket: &UdpSocket,
    destination: Ipv4Addr,
    ttl: u8,
    message: &[u8],
) -> Result<()> {
    socket.set_ttl(u32::from(ttl)).context("direct icmp ttl")?;
    let sent = socket
        .send_to(message, SocketAddr::from(SocketAddrV4::new(destination, 0)))
        .await;
    let written = sent.context("direct icmp send")?;
    ensure!(
        written == message.len(),
        "direct icmp send wrote {written}/{} bytes",
        message.len()
    );
    Ok(())
}

/// One flow's receive loop: hands every received datagram to the matcher
/// and ends on a socket error; idle expiry aborts it.
async fn icmp_flow(shared: Arc<Shared>, id: u64, flow: FlowKey, socket: Arc<UdpSocket>) {
    // Raw sockets include the IPv4 header, whose total length exposes
    // truncation of a full-MTU reply. The window is one byte past the MTU:
    // anything longer — including a datagram the kernel truncated to fill
    // it — is rejected whole rather than forwarded looking valid.
    let mut buf = vec![0u8; shared.cfg.mtu as usize + 1];
    loop {
        let received = socket.recv_from(&mut buf).await.map(|(len, _)| len);
        let len = match received {
            Ok(len) => len,
            Err(error) if is_icmp_feedback(&error) => {
                crate::debug!("direct icmp {flow:?}: ICMP error reply — {error}");
                continue;
            }
            Err(error) => {
                crate::debug!("direct icmp {flow:?}: recv — {error}");
                break;
            }
        };
        if len > shared.cfg.mtu as usize {
            crate::debug!("direct icmp {flow:?}: reply of {len} B exceeds the TUN MTU — dropped");
            continue;
        }
        let bytes = &mut buf[..len];
        #[cfg(target_os = "macos")]
        normalize_darwin_raw_ip(bytes);
        handle_receive(&shared, &flow, id, bytes);
    }
    shared.finish_icmp(&flow, id).await;
}

/// Accept a matching echo reply or an ICMP error quoting this flow.
/// Rebuild it for the client; drop malformed or unrelated datagrams.
fn handle_receive(shared: &Shared, flow: &FlowKey, id: u64, bytes: &[u8]) {
    if let Some((source, ttl, echo)) = parse_echo_reply_ip(bytes, shared.cfg.mtu as usize)
        && source == flow.destination
        && echo.id == flow.source_port
    {
        let packet = echo_reply_packet(source, flow.source, ttl, &echo);
        deliver(shared, flow, id, packet);
        return;
    }
    if let Some((error_flow, packet)) = rewrite_icmp_error(bytes, shared.cfg.client, shared.source)
        && error_flow == *flow
    {
        deliver(shared, flow, id, packet);
    }
}

/// Forwards one rebuilt packet for a still-current flow; a late reply of a
/// closed or replaced flow is dropped instead.
fn deliver(shared: &Shared, flow: &FlowKey, id: u64, bytes: Vec<u8>) {
    let mut state = shared.state.lock().unwrap();
    match state.flows.get_mut(flow) {
        Some(entry) if entry.id == id => entry.last_seen = Instant::now(),
        _ => return,
    }
    drop(state);
    let _ = shared.packets.try_send(DirectEvent::Packet { id, bytes });
}

/// Expire idle flows after `UDP_IDLE` and report their close reliably.
/// Reap completed tasks on every timer pass.
async fn icmp_expiry_loop(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(EXPIRY_TICK);
    loop {
        tick.tick().await;
        {
            let mut tasks = shared.tasks.lock().await;
            while tasks.try_join_next().is_some() {}
        }
        let closed = {
            let mut state = shared.state.lock().unwrap();
            let now = Instant::now();
            let mut closed = Vec::new();
            state.flows.retain(|key, entry| {
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
            closed
        };
        for (key, id) in closed {
            let _ = shared.events.send(DirectEvent::Closed { id, key }).await;
        }
    }
}
