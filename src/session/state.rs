//! Session state: data-plane modes, per-flow records, readiness, and the
//! tombstone table of retired flows.

use std::{
    collections::{HashMap, VecDeque},
    net::Ipv4Addr,
    time::{Duration, Instant as StdInstant},
};

use anyhow::{Context, Result, ensure};
use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

use crate::control::{Endpoint, Strategy};
use crate::link_io::LinkIo;
use crate::packet::{self, FlowKey};
use crate::selector::{Action, Candidate, Reason, Selector};
use crate::webrtc;

use super::{ChannelHandle, TOMBSTONE_CAP, TOMBSTONE_TTL};

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
    /// EPIC-003 TCP mode: per-flow connections; the server passes its bound
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
}

impl Drop for FlowTcp {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub struct Flow {
    pub key: FlowKey,
    /// Binding channel; None until `flow_channel`/`flow_opened` agrees.
    pub channel: Option<u64>,
    /// Server awaits an echo to its FLOW_PROBE.
    pub echo_pending: Option<[u8; 16]>,
    /// DATA allowed: commit barrier passed.
    pub active: bool,
    /// The client kernel requested reset; a subsequent transport close is expected.
    pub reset_requested: bool,
    /// Pre-active queue of complete IP packets (server) until commit.
    pub pending: VecDeque<Vec<u8>>,
    /// Tcp candidate: a dedicated connection instead of a shared channel.
    pub tcp: Option<FlowTcp>,
    /// Server saw FIN from the target: close the flow if no data for 15s
    /// (half-close keeps sending data and resets the timer).
    pub fin_dwell: Option<tokio::time::Instant>,
    /// Newest client ACK (TCP flows): seeds the link-loss reset (§5.3).
    pub last_ack: Option<u32>,
    /// Last packet time (idle timeout) and creation time (budget).
    pub last_seen: tokio::time::Instant,
    pub created: tokio::time::Instant,
}

impl Flow {
    pub fn new(key: FlowKey, now: tokio::time::Instant) -> Self {
        Self {
            key,
            channel: None,
            echo_pending: None,
            active: false,
            reset_requested: false,
            pending: VecDeque::new(),
            tcp: None,
            fin_dwell: None,
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
    /// Server: binding-frame token → flow.
    pub token_index: HashMap<[u8; 16], u64>,
    /// Server: public ports, bind address, and QUIC endpoint.
    pub ports: HashMap<Strategy, u16>,
    pub bind: Ipv4Addr,
    pub quic: Option<(quinn::Endpoint, [u8; 32])>,
    pub channels: HashMap<u64, ChannelHandle>,
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
            if let Some(handle) = self.channels.remove(&channel_id) {
                if let Some(selector) = self.selector.as_mut() {
                    // Remove the channel from the selector too: otherwise it
                    // waits for its probes forever.
                    return selector.channel_lost(handle.candidate, channel_id, reason, now);
                }
                return self
                    .flows
                    .iter()
                    .filter(|(_, flow)| flow.channel == Some(channel_id))
                    .map(|(&flow_id, _)| Action::CloseFlow { flow_id })
                    .collect();
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
}

/// EPIC-003 TCP mode: per-flow connections with binding tokens.
pub struct TcpFlow {
    pub key: FlowKey,
    pub active: bool,
    pub reset_requested: bool,
    pub outgoing: Option<mpsc::Sender<Vec<u8>>>,
    pub pending: VecDeque<Vec<u8>>,
    pub tcp_key: Option<[u8; 16]>,
    pub tcp_token: Option<[u8; 16]>,
    pub tcp_receiver: Option<mpsc::Receiver<Vec<u8>>>,
    pub task: Option<tokio::task::JoinHandle<()>>,
    pub fin_dwell: Option<tokio::time::Instant>,
    /// Newest client ACK: seeds the link-loss reset (§5.3).
    pub last_ack: Option<u32>,
    pub last_seen: tokio::time::Instant,
    pub created: tokio::time::Instant,
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
    pub token_index: HashMap<[u8; 16], u64>,
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
