//! Session state: data-plane modes, per-flow records, readiness, and the
//! tombstone table of retired flows.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::Ipv4Addr,
    time::{Duration, Instant as StdInstant},
};

use anyhow::{Context, Result, ensure};
use tokio::sync::{mpsc, oneshot};
use tun_rs::AsyncDevice;

use crate::control::{Endpoint, Strategy};
use crate::framing::Camouflage;
use crate::link_io::LinkIo;
use crate::packet::{self, FlowKey};
use crate::selector::{Action, Candidate, Reason, Selector};
use crate::webrtc;

use super::{ChannelHandle, FIN_DWELL, FLOW_IDLE, TCP_IDLE, TOMBSTONE_CAP, TOMBSTONE_TTL};

// ────────────────────────── Tombstones ──────────────────────────

/// Minimum spacing between two synthesized responses for one tombstone.
const TOMBSTONE_MIN_INTERVAL: Duration = Duration::from_millis(200);

pub struct Tombstone {
    retired_at: StdInstant,
    /// Last CLOSED-endpoint response; None — never answered.
    responded_at: Option<StdInstant>,
}

/// Retired flows of lost links: their tuples never re-enter admission
/// while the tombstone lives; a matching client packet is answered as a
/// CLOSED endpoint (RFC 9293 §3.10.7.1) instead.
#[derive(Default)]
pub struct Tombstones {
    pub entries: HashMap<FlowKey, Tombstone>,
    /// Insertion order for oldest-eviction; compacted when stale.
    order: VecDeque<FlowKey>,
}

impl Tombstones {
    pub fn insert(&mut self, key: FlowKey, now: StdInstant) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.retired_at = now;
            return;
        }
        if self.entries.len() >= TOMBSTONE_CAP {
            while let Some(oldest) = self.order.pop_front() {
                if self.entries.remove(&oldest).is_some() {
                    break;
                }
            }
            crate::error!(
                "tombstone table full ({TOMBSTONE_CAP}), evicting the oldest retired flow"
            );
        }
        if self.order.len() > self.entries.len() * 2 {
            self.order.retain(|key| self.entries.contains_key(key));
        }
        self.entries.insert(
            key,
            Tombstone {
                retired_at: now,
                responded_at: None,
            },
        );
        self.order.push_back(key);
    }

    /// Active until the TTL expires; expiry frees the tuple for admission.
    pub fn active(&mut self, key: &FlowKey, now: StdInstant) -> bool {
        match self.entries.get(key) {
            Some(entry) if now.saturating_duration_since(entry.retired_at) >= TOMBSTONE_TTL => {
                self.entries.remove(key);
                false
            }
            Some(_) => true,
            None => false,
        }
    }

    /// CLOSED-endpoint response for a client packet in a tombstoned flow.
    /// None when rate-limited, when the packet is itself an RST (a reset is
    /// never answered), or when the key is not tombstoned — the caller
    /// checks `active` first and treats None as a silent drop.
    pub fn respond(
        &mut self,
        key: &FlowKey,
        packet: &packet::Packet,
        now: StdInstant,
    ) -> Option<[u8; 40]> {
        if packet.is_rst {
            return None;
        }
        let entry = self.entries.get_mut(key)?;
        if entry
            .responded_at
            .is_some_and(|at| now.saturating_duration_since(at) < TOMBSTONE_MIN_INTERVAL)
        {
            return None;
        }
        let reset = packet::tcp_reset_for(packet)?;
        entry.responded_at = Some(now);
        Some(reset)
    }
}

// ────────────────────────── Data-plane modes ──────────────────────────

/// Session data-plane mode.
pub enum TransportConfig {
    /// UDP-channel client: allowed strategies (empty — all from endpoints)
    /// and the server's actual endpoints from `Endpoints`.
    Client {
        strategies: Vec<Strategy>,
        endpoints: Vec<Endpoint>,
        pin: Option<[u8; 32]>,
        /// TCP-candidate port from endpoints, if fallback is allowed.
        tcp: Option<u16>,
        /// TCP fallback camouflage agreed with the server; None when TCP is off.
        tcp_camouflage: Option<Camouflage>,
        /// Re-selection cadence; None keeps the first winner (auto only).
        remeasure: Option<std::time::Duration>,
    },
    /// UDP-channel server: public port of each strategy, bind address
    /// and the shared QUIC endpoint with certificate pin.
    Server {
        ports: Vec<Endpoint>,
        bind: Ipv4Addr,
        quic: Option<(quinn::Endpoint, [u8; 32])>,
        /// TCP candidate: listener and actual port.
        tcp: Option<(tokio::net::TcpListener, u16)>,
    },
    /// TCP mode: per-flow connections; the server passes its bound
    /// listener so Endpoints/Opened carry the actual (possibly ephemeral) port.
    Tcp {
        mode: crate::tcp::Mode,
        listener: Option<tokio::net::TcpListener>,
    },
}

// ────────────────────────── Flows and planes ──────────────────────────

/// Per-flow TCP connection of the Tcp candidate (SSH camouflage), both sides.
pub struct FlowTcp {
    pub key: [u8; 16],
    /// Server: binding-frame token.
    pub token: Option<[u8; 16]>,
    /// Client: outgoing IP packets to the pump task.
    pub out: Option<mpsc::Sender<Vec<u8>>>,
    /// Server: outgoing-packet channel after binding resolution.
    pub receiver: Option<mpsc::Receiver<Vec<u8>>>,
    pub task: Option<tokio::task::JoinHandle<()>>,
    pub cancel: Option<oneshot::Sender<()>>,
}

impl Drop for FlowTcp {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[derive(Default)]
pub struct TcpClose {
    fin_end: [Option<u32>; 2],
    acknowledged: [bool; 2],
    acked_until: [Option<u32>; 2],
    pub deadline: Option<tokio::time::Instant>,
}

impl TcpClose {
    pub fn observe(
        &mut self,
        packet: &packet::Packet,
        from_client: bool,
        now: tokio::time::Instant,
    ) {
        let Some(tcp) = packet.tcp else { return };
        if from_client && tcp.flags & 0x17 == 0x02 {
            *self = Self::default();
            return;
        }
        if self.finished() || tcp.flags & 0x04 != 0 {
            return;
        }
        let direction = usize::from(from_client);
        if packet.fin && tcp.flags & 0x02 == 0 {
            let end = tcp.seq.wrapping_add(tcp.payload_len as u32).wrapping_add(1);
            // A duplicate ACK of earlier data does not acknowledge this FIN.
            if self.acked_until[direction].is_none_or(|ack| (end.wrapping_sub(ack) as i32) > 0)
                && self.fin_end[direction] != Some(end)
            {
                self.fin_end[direction] = Some(end);
                self.acknowledged[direction] = false;
            }
        }
        if tcp.flags & 0x10 != 0 {
            let peer = 1 - direction;
            if self.acked_until[peer].is_none_or(|ack| (tcp.ack.wrapping_sub(ack) as i32) >= 0) {
                self.acked_until[peer] = Some(tcp.ack);
            }
            if self.fin_end[peer] == Some(tcp.ack) {
                self.acknowledged[peer] = true;
            }
        }
        if self.finished() {
            self.deadline = Some(now + FIN_DWELL);
        }
    }

    pub fn finished(&self) -> bool {
        self.acknowledged == [true; 2]
    }
}

pub struct Recovery {
    pub started: tokio::time::Instant,
    pub from: Option<Candidate>,
    pub attempts: u32,
}

pub struct Flow {
    pub key: FlowKey,
    pub generation: u64,
    /// Sticky: a transport has accepted user data; its delivery is uncertain.
    pub data_started: bool,
    pub recovery: Option<Recovery>,
    /// Binding channel; None until `flow_channel`/`flow_opened` agrees.
    pub channel: Option<u64>,
    /// Server awaits an echo to its FLOW_PROBE.
    pub echo_pending: Option<[u8; 16]>,
    /// DATA allowed: commit barrier passed.
    pub active: bool,
    /// Server: Commit and authenticated TCP binding may arrive in either order.
    pub commit_pending: bool,
    pub tcp_connected: bool,
    /// The client kernel requested reset; a subsequent transport close is expected.
    pub reset_requested: bool,
    /// Pre-active queue of complete IP packets (server) until commit.
    pub pending: VecDeque<Vec<u8>>,
    /// Tcp candidate: a dedicated connection instead of a shared channel.
    pub tcp: Option<FlowTcp>,
    pub tcp_close: TcpClose,
    /// Newest client ACK (TCP flows): seeds the link-loss reset.
    pub last_ack: Option<u32>,
    /// Last packet time (idle timeout) and creation time (budget).
    pub last_seen: tokio::time::Instant,
    pub created: tokio::time::Instant,
}

impl Flow {
    pub fn new(key: FlowKey, now: tokio::time::Instant) -> Self {
        Self {
            key,
            generation: 1,
            data_started: false,
            recovery: None,
            channel: None,
            echo_pending: None,
            active: false,
            commit_pending: false,
            tcp_connected: false,
            reset_requested: false,
            pending: VecDeque::new(),
            tcp: None,
            tcp_close: TcpClose::default(),
            last_ack: None,
            last_seen: now,
            created: now,
        }
    }
}

/// UDP-channel mode.
pub struct ChannelsPlane {
    /// Client: candidate selector; server: None.
    pub selector: Option<Selector>,
    pub server_ip: Option<Ipv4Addr>,
    pub quic_pin: Option<[u8; 32]>,
    /// Server: TCP-candidate port (SSH camouflage), if enabled.
    pub tcp_port: Option<u16>,
    /// Client: TCP fallback camouflage, for stats labeling.
    pub tcp_camouflage: Option<Camouflage>,
    /// Server: binding-frame token → (flow, generation).
    pub token_index: HashMap<[u8; 16], (u64, u64)>,
    /// Server: public ports, bind address, and QUIC endpoint.
    pub ports: HashMap<Strategy, u16>,
    pub bind: Ipv4Addr,
    pub quic: Option<(quinn::Endpoint, [u8; 32])>,
    pub channels: HashMap<u64, ChannelHandle>,
    /// Channels of a replaced incumbent: no new flows, not
    /// probed; torn down once the last bound flow closes.
    pub draining: HashSet<u64>,
    /// Channel ids this side no longer holds; a late reuse reply
    /// naming one is rejected (its cipher key is used up).
    pub retired: HashSet<u64>,
    pub prepared: HashMap<u64, u64>,
    pub next_channel_id: u64,
    /// Client: preparation in flight (attempt, candidate, channel, webrtc peer).
    pub attempt: Option<(u64, Candidate, Option<u64>, Option<webrtc::Peer>)>,
    pub flows: HashMap<u64, Flow>,
    pub by_key: HashMap<FlowKey, u64>,
    /// Client allocates these increasing from 1.
    pub next_client_flow_id: u64,
}

impl ChannelsPlane {
    pub fn channel_failed(
        &mut self,
        attempt: Option<u64>,
        channel: Option<u64>,
        reason: Reason,
        now: StdInstant,
    ) -> Vec<Action> {
        let channel = channel.or_else(|| attempt.and_then(|id| self.prepared.get(&id).copied()));
        if let Some(channel_id) = channel {
            self.prepared.retain(|_, id| *id != channel_id);
            if let Some(handle) = self.retire(channel_id) {
                if let Some(selector) = self.selector.as_mut() {
                    // Remove the channel from the selector too: otherwise it
                    // waits for its probes forever.
                    return selector.channel_lost(handle.candidate, channel_id, reason, now);
                }
                return Vec::new();
            }
            return Vec::new();
        }
        let Some(selector) = self.selector.as_mut() else {
            return Vec::new();
        };
        if self
            .attempt
            .as_ref()
            .is_some_and(|pending| Some(pending.0) == attempt)
            && let Some((pending_attempt, candidate, ..)) = self.attempt.take()
        {
            return selector.attempt_failed(candidate, pending_attempt, reason, now);
        }
        Vec::new()
    }

    /// Remove a channel and remember its id: reuse replies naming it
    /// are rejected.
    pub fn retire(&mut self, id: u64) -> Option<ChannelHandle> {
        self.retired.insert(id);
        self.channels.remove(&id)
    }
}

/// TCP mode: per-flow connections with binding tokens.
pub struct TcpFlow {
    pub key: FlowKey,
    pub generation: u64,
    pub data_started: bool,
    pub recovery: Option<Recovery>,
    pub retry_at: Option<tokio::time::Instant>,
    pub binding_deadline: Option<tokio::time::Instant>,
    pub active: bool,
    pub commit_pending: bool,
    pub tcp_connected: bool,
    pub reset_requested: bool,
    pub outgoing: Option<mpsc::Sender<Vec<u8>>>,
    pub pending: VecDeque<Vec<u8>>,
    pub tcp_key: Option<[u8; 16]>,
    pub tcp_token: Option<[u8; 16]>,
    pub tcp_receiver: Option<mpsc::Receiver<Vec<u8>>>,
    pub task: Option<tokio::task::JoinHandle<()>>,
    pub cancel: Option<oneshot::Sender<()>>,
    pub tcp_close: TcpClose,
    /// Newest client ACK: seeds the link-loss reset.
    pub last_ack: Option<u32>,
    pub last_seen: tokio::time::Instant,
    pub created: tokio::time::Instant,
}

impl TcpFlow {
    pub fn new(key: FlowKey, now: tokio::time::Instant) -> Self {
        Self {
            key,
            generation: 1,
            data_started: false,
            recovery: None,
            retry_at: None,
            binding_deadline: None,
            active: false,
            commit_pending: false,
            tcp_connected: false,
            reset_requested: false,
            outgoing: None,
            pending: VecDeque::new(),
            tcp_key: None,
            tcp_token: None,
            tcp_receiver: None,
            task: None,
            cancel: None,
            tcp_close: TcpClose::default(),
            last_ack: None,
            last_seen: now,
            created: now,
        }
    }
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub struct TcpPlane {
    pub mode: crate::tcp::Mode,
    pub server_ip: Option<Ipv4Addr>,
    pub token_index: HashMap<[u8; 16], (u64, u64)>,
    pub flows: HashMap<u64, TcpFlow>,
    pub by_key: HashMap<FlowKey, u64>,
    pub next_flow_id: u64,
}

pub enum Plane {
    Channels(Box<ChannelsPlane>),
    Tcp(TcpPlane),
}

// ────────────────────────── Packet I/O ──────────────────────────

pub enum PacketIo {
    Device(AsyncDevice),
    Link(LinkIo),
}

impl PacketIo {
    pub(crate) async fn recv(&mut self, buffer: &mut Vec<u8>, mtu: u16) -> Result<Option<u64>> {
        match self {
            Self::Device(tun) => {
                buffer.resize(usize::from(mtu), 0);
                let length = tun.recv(buffer).await.context("read TUN")?;
                ensure!(length != 0, "TUN closed");
                buffer.truncate(length);
                Ok(None)
            }
            Self::Link(io) => {
                let packet = io.packets.recv().await.context("packet port closed")?;
                // The shared ingress validation rejects packets larger than MTU.
                *buffer = packet.bytes;
                Ok(Some(packet.id))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readiness {
    Probing,
    /// The technical flow is retired; retain the verified UDP channel until Ready.
    Verified(Option<u64>),
    Ready,
}

pub(super) fn idle_timeout(protocol: u8) -> Duration {
    if protocol == 6 { TCP_IDLE } else { FLOW_IDLE }
}
