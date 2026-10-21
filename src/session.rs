//! VPN session v2 (EPIC-005 I08). Data plane — shared UDP channels
//! (mosh/webrtc/quic/obfs) driven by the candidate selector; the EPIC-003
//! TCP mode is kept unchanged (`TransportConfig::Tcp`).
//!
//! One channel per strategy: the server opens the strategy socket on
//! `channel_prepare`, the client connects and verifies the channel with
//! probes (probe A/AB/B + size). The channel task (`channel_task`) owns the
//! driver and the AEAD state; the session sends commands and receives
//! events. Flow:
//! `flow_open` → `flow_opened` + FLOW_PROBE/ECHO → `commit`/`committed`;
//! DATA is only sent after committed.
//!
//! Layout: `state` holds the planes and flow records, `pump` the channel
//! task, `round` the N3 liveness rounds, `control` the control dispatch and
//! channel handshake, `flow` the flow lifecycle, `event` task events and
//! selector actions, `tun` the packet path, `tcp` the EPIC-003 mode.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant as StdInstant},
};

use anyhow::{Context, Result, bail, ensure};
use tokio::{sync::mpsc, task::JoinSet, time::MissedTickBehavior};
use tun_rs::AsyncDevice;

use crate::control::{Control, Message, Stats, Strategy};
use crate::link_io::LinkIo;
use crate::selector::{Allowed, Candidate, Reason, Selector};
use crate::udp::Incoming;
use crate::{channel, quic};

pub mod burst;
mod control;
mod event;
mod flow;
mod pump;
mod round;
mod state;
mod tcp;
mod tun;

pub use pump::{ChannelCtx, ChannelHandle, ChannelReadyParams, TaskCommand, TaskEvent, pump};
pub use round::{Round, RoundCandidate, pick_verified, unanswered};

pub use state::{
    ChannelsPlane, Flow, FlowTcp, PacketIo, Plane, Readiness, TcpFlow, TcpPlane, Tombstone,
    Tombstones, TransportConfig,
};

// ────────────────────────── Timeouts and budgets ──────────────────────────

/// Control-channel heartbeat period.
pub const HEARTBEAT: Duration = Duration::from_secs(2);
/// Control-channel silence after which the session stops.
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(5);
/// Data-plane channel keepalive and silence budget (consent freshness).
pub const KEEPALIVE: Duration = Duration::from_secs(1);
pub const CONSENT_TIMEOUT: Duration = Duration::from_secs(5);
/// An active flow without traffic is closed (idle timeout).
pub const FLOW_IDLE: Duration = Duration::from_secs(60);
/// FIN from the target with no data for this long — the server closes the flow (server decides).
pub const FIN_DWELL: Duration = Duration::from_secs(15);
/// Per-channel outgoing IP-packet queue and binding wait.
pub const CHANNEL_QUEUE: usize = 1024;
/// How long a lost link's tuples stay refused before normal admission
/// resumes: a new-ISN SYN then becomes a new flow (EPIC-010 §5.3).
pub const TOMBSTONE_TTL: Duration = Duration::from_secs(30);
/// Maximum remembered tombstones; the oldest entry is evicted on overflow.
pub const TOMBSTONE_CAP: usize = 4096;

// ────────────────────────── Session ──────────────────────────

pub struct Session {
    pub control: Control,
    pub io: PacketIo,
    /// Hub IDs increase within an epoch, including rejected admissions.
    pub last_link_id: u64,
    pub readiness: Option<Readiness>,
    pub client_ip: Ipv4Addr,
    pub mtu: u16,
    pub plane: Plane,
    /// Listener and owned TCP/QUIC tasks live outside `plane` so
    /// `select!` arms borrow different struct fields.
    pub tcp_listener: Option<tokio::net::TcpListener>,
    pub tasks: JoinSet<()>,
    /// Shared event stream of channel tasks.
    pub task_events: (mpsc::Sender<TaskEvent>, mpsc::Receiver<TaskEvent>),
    /// Assembled IP packets from channels.
    pub incoming: (mpsc::Sender<Incoming>, mpsc::Receiver<Incoming>),
    /// Legacy-mode TCP events.
    pub tcp_events: (
        mpsc::Sender<crate::tcp::Event>,
        mpsc::Receiver<crate::tcp::Event>,
    ),
    /// Retired flows of lost links (EPIC-010 §5.3).
    pub tombstones: Tombstones,
    /// N3 liveness round; None once the link is Ready.
    pub round: Option<Round>,
    /// N3 round attempt ids start above the selector's space.
    pub next_round_attempt: u64,
    pub stats: Stats,
    /// Precomputed `drop[host]:` prefix — every loss logs its reason (#124).
    pub drop_prefix: String,
    /// EPIC-016: next health burst at; armed on Ready, re-armed per burst.
    pub health_at: Option<tokio::time::Instant>,
    /// EPIC-016: in-flight probe burst over the live channel.
    pub burst: Option<burst::Burst>,
}

impl Session {
    pub(crate) fn tag(&self) -> &str {
        match &self.io {
            PacketIo::Link(io) => &io.tag,
            PacketIo::Device(_) => "",
        }
    }
    pub(crate) fn client(&self) -> bool {
        match &self.plane {
            Plane::Channels(p) if p.selector.is_some() => true,
            Plane::Tcp(p) if p.server_ip.is_some() => true,
            _ => false,
        }
    }

    pub fn active_candidate(&self) -> Option<String> {
        match &self.plane {
            Plane::Channels(plane) => plane
                .selector
                .as_ref()
                .and_then(|selector| selector.last_good)
                .map(|candidate| match candidate {
                    Candidate::Tcp => plane
                        .tcp_camouflage
                        .map(|c| format!("tcp-{c}"))
                        .unwrap_or_else(|| candidate.to_string()),
                    _ => candidate.to_string(),
                }),
            Plane::Tcp(plane) => plane
                .server_ip
                .map(|_| format!("tcp-{}", plane.mode.camouflage)),
        }
    }

    pub(crate) fn accepts_packets(&self) -> bool {
        self.readiness.is_none_or(|state| state == Readiness::Ready)
    }

    async fn event_loop(mut self) -> Result<()> {
        let started = tokio::time::Instant::now();
        // None after the first Ready: later Checking rounds have no startup
        // budget — the link retries while the control channel lives (N3).
        let mut startup_deadline = Some(started + crate::selector::FLOW_BUDGET + HEARTBEAT_TIMEOUT);
        with_heartbeat_deadline(started + HEARTBEAT_TIMEOUT, async {
            self.begin_preflight().await?;
            Ok(false)
        })
        .await?;
        let mut last_heartbeat = None;
        let mut buffer = vec![0u8; self.mtu as usize];
        let mut ticks: u64 = 0;
        let mut tick = tokio::time::interval(HEARTBEAT);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            let accepts_packets = self.accepts_packets();
            let mut deadline = last_heartbeat.unwrap_or(started) + HEARTBEAT_TIMEOUT;
            if !accepts_packets && let Some(sd) = startup_deadline {
                deadline = deadline.min(sd);
            }
            let round_wake = self.round.as_ref().and_then(|round| round.decide_at);
            let health_wake = self.health_wake();
            let result = with_heartbeat_deadline(deadline, async {
                tokio::select! {
                    message = self.control.recv() => {
                        let message = message?;
                        if matches!(message, Message::Heartbeat { .. }) {
                            last_heartbeat = Some(tokio::time::Instant::now());
                        }
                        self.dispatch_control(message).await?
                    }
                    result = self.io.recv(&mut buffer, self.mtu) => {
                        self.handle_tun_packet(&buffer, result?).await?;
                    }
                    event = self.task_events.1.recv() => {
                        let event = event.context("channel tasks stopped")?;
                        self.dispatch_task_event(event).await?;
                    }
                    incoming = self.incoming.1.recv() => {
                        let incoming = incoming.context("channel pump stopped")?;
                        self.deliver_to_tun(incoming).await?;
                    }
                    event = self.tcp_events.1.recv() => {
                        if let Some(event) = event {
                            match event {
                                crate::tcp::Event::Packet(incoming) => {
                                    self.deliver_to_tun(incoming).await?;
                                }
                                crate::tcp::Event::Connected { id } => self.tcp_connected(id).await?,
                                crate::tcp::Event::Failed { id } => self.tcp_failed(id).await?,
                                crate::tcp::Event::Closed { id } => self.tcp_closed(id).await?,
                                crate::tcp::Event::Bound { token, conn } => {
                                    conn.send(self.resolve_binding(&token)).ok();
                                }
                            }
                        }
                    }
                    accepted = crate::tcp::accept(self.tcp_listener.as_mut()),
                            if self.tcp_listener.is_some() => {
                        let (stream, peer) = accepted.context("accept TCP flow connection")?;
                        crate::debug!("tcp_accept peer={peer}");
                        let events = self.tcp_events.0.clone();
                        let tag = self.tag().to_owned();
                        let camouflage = match &self.plane {
                            Plane::Tcp(plane) => plane.mode.camouflage,
                            // The channel-mode TCP candidate always uses SSH camouflage.
                            Plane::Channels(_) => crate::framing::Camouflage::Ssh,
                        };
                        self.tasks.spawn(async move {
                            if let Err(error) = crate::tcp::serve(stream, camouflage, events).await {
                                crate::error!(
                                    "{} tcp accept from {peer} failed — {error:#}",
                                    prefixed(&tag, "flow")
                                );
                            }
                        });
                    }
                    Some(result) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                        if let Err(error) = result {
                            if error.is_cancelled() {
                                crate::debug!("session task cancelled — {error}");
                            } else {
                                crate::error!("session task failed — {error}");
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(round_wake.unwrap_or(deadline)), if round_wake.is_some() => {
                        // The grace window closed: bring the verdict without
                        // waiting for the heartbeat tick.
                        self.poll_round(tokio::time::Instant::now()).await?;
                    }
                    _ = tokio::time::sleep_until(health_wake.unwrap_or(deadline)), if health_wake.is_some() => {
                        // Health burst due or in flight (EPIC-016).
                        self.poll_burst(tokio::time::Instant::now()).await?;
                    }
                    _ = tick.tick() => {
                        let now = tokio::time::Instant::now();
                        self.expire_flows(now).await?;
                        self.stats.active_flows = self.flow_count();
                        self.stats.active_candidate = self.active_candidate();
                        if let PacketIo::Link(io) = &self.io {
                            io.delivery.apply(&mut self.stats);
                        }
                        self.control.send(Message::Heartbeat { stats: self.stats.clone() }).await?;
                        if let PacketIo::Link(io) = &self.io {
                            io.stats.send_replace(self.stats.clone());
                        }
                        crate::debug!("heartbeat sent");
                        ticks += 1;
                        // In a pool the hub logs one aggregated line instead.
                        if ticks.is_multiple_of(5) && self.tag().is_empty() {
                            crate::debug!("stats: tx_packets={} rx_packets={} tx_bytes={} rx_bytes={} dropped={} flows_opened={} flows_closed={}",
                        self.stats.inner_tx_packets, self.stats.inner_rx_packets, self.stats.inner_tx_bytes,
                        self.stats.inner_rx_bytes, self.stats.dropped_packets, self.stats.opened_flows,
                        self.stats.closed_flows);
                        }
                        if let Plane::Channels(plane) = &mut self.plane
                            && let Some(selector) = plane.selector.as_mut()
                        {
                            let actions = selector.poll(StdInstant::now());
                            self.execute_actions(actions).await?;
                        }
                        self.poll_round(now).await?;
                        self.poll_burst(now).await?;
                    }
                }
                if !self.accepts_packets()
                    && let Some(sd) = startup_deadline
                {
                    ensure!(tokio::time::Instant::now() < sd, "link readiness timed out");
                }
                self.announce_ready(last_heartbeat, startup_deadline).await
            })
            .await;
            if !self.accepts_packets()
                && let Some(sd) = startup_deadline
                && tokio::time::Instant::now() >= sd
            {
                bail!("link readiness timed out");
            }
            match result {
                // First Ready clears the startup budget: Checking retries
                // run on heartbeat deadlines alone (N3).
                Ok(true) => startup_deadline = None,
                Ok(false) => {}
                Err(error) => {
                    // Link loss (EPIC-010 §5.3): reset the link's client TCP
                    // flows toward the client kernel before the error unwinds.
                    self.emit_retired_resets();
                    return Err(error);
                }
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let PacketIo::Link(io) = &self.io {
            io.delivery.apply(&mut self.stats);
        }
        let remaining = self.flow_count();
        match &mut self.plane {
            Plane::Channels(plane) => {
                plane.channels.clear();
                plane.flows.clear();
                if let Some((endpoint, _)) = &plane.quic {
                    endpoint.close(0u32.into(), b"session stopped");
                }
            }
            Plane::Tcp(plane) => plane.flows.clear(),
        }
        self.tasks.abort_all();
        self.stats.closed_flows += remaining as u64;
        self.stats.active_flows = 0;
        crate::info!(
            "{} stopped after {:.0} s — received {}, sent {}, flows {}, dropped {}",
            prefixed(self.tag(), "vpn"),
            crate::logging::elapsed_secs(),
            fmt_bytes(self.stats.inner_rx_bytes),
            fmt_bytes(self.stats.inner_tx_bytes),
            self.stats.opened_flows,
            self.stats.dropped_packets
        );
    }
}

// ────────────────────────── Setup ──────────────────────────

pub async fn run(
    control: Control,
    tun: AsyncDevice,
    server: Option<Ipv4Addr>,
    client_ip: Ipv4Addr,
    mtu: u16,
    config: TransportConfig,
) -> Result<()> {
    run_io(
        control,
        PacketIo::Device(tun),
        server,
        client_ip,
        mtu,
        config,
    )
    .await
}

pub async fn run_link(
    control: Control,
    server: Ipv4Addr,
    client_ip: Ipv4Addr,
    mtu: u16,
    config: TransportConfig,
    io: LinkIo,
) -> Result<()> {
    run_io(
        control,
        PacketIo::Link(io),
        Some(server),
        client_ip,
        mtu,
        config,
    )
    .await
}

async fn run_io(
    control: Control,
    io: PacketIo,
    server: Option<Ipv4Addr>,
    client_ip: Ipv4Addr,
    mtu: u16,
    config: TransportConfig,
) -> Result<()> {
    let mut server_listener: Option<tokio::net::TcpListener> = None;
    let plane = match config {
        TransportConfig::Client {
            strategies,
            endpoints,
            pin,
            tcp,
            tcp_camouflage,
        } => {
            let mut allowed = Allowed::default();
            let offer: Vec<Strategy> = endpoints.iter().map(|e| e.strategy).collect();
            let wanted: &[Strategy] = if strategies.is_empty() {
                // auto: everything the server offered except diagnostic plain.
                &offer
            } else {
                &strategies
            };
            for strategy in wanted {
                if !offer.contains(strategy) {
                    continue;
                }
                match strategy_allowed(*strategy) {
                    Some(Candidate::Quic) => allowed.quic = true,
                    Some(Candidate::WebRtc) => allowed.webrtc = true,
                    Some(Candidate::Obfs) => allowed.obfs = true,
                    Some(Candidate::Mosh) => allowed.mosh = true,
                    _ => {}
                }
            }
            // The TCP candidate is not part of the UDP strategies: only via the announced port.
            allowed.tcp = tcp.is_some();
            if allowed.webrtc {
                // The first webrtc peer pays the one-time crypto init; hide
                // it behind the SSH bootstrap instead of the first round.
                drop(crate::webrtc::prewarm());
            }
            ensure!(
                allowed.quic || allowed.webrtc || allowed.obfs || allowed.mosh || allowed.tcp,
                "no available strategy: server offered {offer:?}, client allows {strategies:?}"
            );
            // auto (empty strategies) runs proactively: a candidate failure
            // bans it for the rest of the session; exhaustion stops the client (m06456).
            let selector = if strategies.is_empty() {
                Selector::new_proactive(allowed)
            } else {
                Selector::new(allowed)
            };
            Plane::Channels(Box::new(ChannelsPlane {
                prepared: HashMap::new(),
                selector: Some(selector),
                server_ip: server,
                quic_pin: pin,
                tcp_port: tcp,
                tcp_camouflage,
                token_index: HashMap::new(),
                ports: HashMap::new(),
                bind: Ipv4Addr::UNSPECIFIED,
                quic: None,
                channels: HashMap::new(),
                next_channel_id: 0,
                attempt: None,
                flows: HashMap::new(),
                by_key: HashMap::new(),
                next_client_flow_id: 1,
            }))
        }
        TransportConfig::Server {
            ports,
            bind,
            quic,
            tcp,
        } => {
            let tcp_port = tcp.as_ref().map(|(_, port)| *port);
            server_listener = tcp.map(|(listener, _)| listener);
            Plane::Channels(Box::new(ChannelsPlane {
                prepared: HashMap::new(),
                selector: None,
                server_ip: None,
                quic_pin: None,
                tcp_port,
                tcp_camouflage: None,
                token_index: HashMap::new(),
                ports: ports.iter().map(|e| (e.strategy, e.port)).collect(),
                bind,
                quic,
                channels: HashMap::new(),
                next_channel_id: 0,
                attempt: None,
                flows: HashMap::new(),
                by_key: HashMap::new(),
                next_client_flow_id: 1,
            }))
        }
        TransportConfig::Tcp { mode, listener } => {
            server_listener = listener;
            Plane::Tcp(TcpPlane {
                mode,
                server_ip: server,
                token_index: HashMap::new(),
                flows: HashMap::new(),
                by_key: HashMap::new(),
                next_flow_id: 1,
            })
        }
    };
    let tcp_listener = match (&plane, server) {
        // TCP-mode server: serve already raised the listener (ephemeral-aware).
        (Plane::Tcp(_), None) => server_listener,
        // Channel-mode TCP candidate: serve already raised the listener (ephemeral-aware).
        (Plane::Channels(_), None) => server_listener,
        _ => None,
    };
    let drop_prefix = format!(
        "drop{}:",
        match &io {
            PacketIo::Link(io) => io.tag.as_str(),
            PacketIo::Device(_) => "",
        }
    );
    Session {
        control,
        io,
        last_link_id: 0,
        readiness: None,
        client_ip,
        mtu,
        plane,
        tcp_listener,
        tasks: JoinSet::new(),
        task_events: mpsc::channel(64),
        incoming: mpsc::channel(CHANNEL_QUEUE),
        tcp_events: mpsc::channel(CHANNEL_QUEUE),
        tombstones: Tombstones::default(),
        stats: Stats::default(),
        round: None,
        next_round_attempt: u64::MAX / 2,
        health_at: None,
        burst: None,
        drop_prefix,
    }
    .event_loop()
    .await
}

// ────────────────────────── Helpers ──────────────────────────

pub fn probe_payload_len(mtu: u16, sample: u16) -> Result<usize> {
    let max = usize::from(mtu).saturating_sub(28).min(1400);
    ensure!(max >= 32, "MTU is too small for an ICMP liveness probe");
    Ok(32 + usize::from(sample) % (max - 31))
}

/// Strategy wire budget: maximum sealed record on the transport.
pub fn strategy_max_wire(strategy: Strategy) -> u16 {
    match strategy {
        Strategy::Quic => quic::FRAGMENT_BUDGET as u16,
        Strategy::WebRtc => (channel::MAX_PACKET + 45) as u16,
        Strategy::Mosh | Strategy::Plain => crate::profile::MAX_WIRE as u16,
        Strategy::Obfs => (crate::profile::MAX_WIRE - 32) as u16,
    }
}

pub(crate) fn strategy_profile(strategy: Strategy) -> crate::profile::Profile {
    match strategy {
        Strategy::Mosh => crate::profile::Profile::Mosh,
        Strategy::Obfs => crate::profile::Profile::Obfs,
        _ => crate::profile::Profile::Plain,
    }
}

pub fn candidate_strategy(candidate: Candidate) -> Strategy {
    match candidate {
        Candidate::Quic => Strategy::Quic,
        Candidate::WebRtc => Strategy::WebRtc,
        Candidate::Obfs => Strategy::Obfs,
        Candidate::Mosh | Candidate::Tcp => Strategy::Mosh,
    }
}

fn strategy_allowed(strategy: Strategy) -> Option<Candidate> {
    match strategy {
        Strategy::Quic => Some(Candidate::Quic),
        Strategy::WebRtc => Some(Candidate::WebRtc),
        Strategy::Obfs => Some(Candidate::Obfs),
        Strategy::Mosh => Some(Candidate::Mosh),
        Strategy::Plain => None, // diagnostic U-L0, not an auto candidate
    }
}

/// English rendering of a strategy failure reason for the log (the wire
/// format is `Reason::as_str`; we don't change it).
pub(crate) fn reason_en(reason: Reason) -> &'static str {
    match reason {
        Reason::PathTimeout => "probe timeout",
        Reason::OneWay => "one-way channel",
        Reason::SizeProbeFailed => "size probe failed",
        Reason::Unsupported => "strategy unsupported",
        Reason::EndpointUnavailable => "server port unavailable",
        Reason::ResourceExhausted => "resources exhausted",
        Reason::ChannelFailed => "channel not verified",
    }
}

/// Human-readable size: 512 B, 12.3 MB.
pub fn fmt_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// Log-prefix rendering for pool links: `channel:` stays single-server,
/// `channel[host]:` names the server inside a pool.
pub fn prefixed(tag: &str, name: &str) -> String {
    format!("{name}{tag}:")
}

pub fn candidate_strategy_from(strategy: Strategy) -> Candidate {
    match strategy {
        Strategy::Quic => Candidate::Quic,
        Strategy::WebRtc => Candidate::WebRtc,
        Strategy::Obfs => Candidate::Obfs,
        Strategy::Mosh | Strategy::Plain => Candidate::Mosh,
    }
}

pub async fn with_heartbeat_deadline(
    deadline: tokio::time::Instant,
    work: impl std::future::Future<Output = Result<bool>>,
) -> Result<bool> {
    let ready = tokio::time::timeout_at(deadline, work)
        .await
        .context("control heartbeat timeout")??;
    // Tokio can complete ready work after the deadline without polling the timer.
    ensure!(
        tokio::time::Instant::now() < deadline,
        "control heartbeat timeout"
    );
    Ok(ready)
}
