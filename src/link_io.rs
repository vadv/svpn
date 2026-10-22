//! Bounded packet port between a client session and its flow owner.

use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::sync::{mpsc, watch};

use crate::{control::Stats, packet::FlowKey};

/// Reserve the upper half for session-owned probes; Hub IDs stay below it.
pub const FIRST_PROBE_ID: u64 = u64::MAX / 2;
pub const PREFLIGHT_ID: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Epoch {
    pub link: usize,
    pub generation: u64,
}

#[derive(Debug)]
pub struct Packet {
    /// Native flow ID; new flows use increasing, nonzero IDs within an epoch.
    pub id: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum Event {
    Ready,
    /// Confirmed data-path loss with the control channel still alive.
    Checking,
    /// A liveness round finished with every candidate failing; the server
    /// stays in Checking and retries after backoff.
    RoundFailed,
    Packet(Packet),
    Closed {
        id: u64,
        key: FlowKey,
    },
}

/// Shared delivery counters: enqueueing a packet is not a successful TUN write.
/// Relaxed snapshots are sufficient for telemetry; only the session drains drops.
#[derive(Default)]
pub struct Delivery {
    packets: AtomicU64,
    bytes: AtomicU64,
    drops: AtomicU64,
}

impl Delivery {
    pub fn received(&self, bytes: usize) {
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dropped(&self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn apply(&self, stats: &mut Stats) {
        stats.inner_rx_packets = self.packets.load(Ordering::Relaxed);
        stats.inner_rx_bytes = self.bytes.load(Ordering::Relaxed);
        stats.dropped_packets += self.drops.swap(0, Ordering::Relaxed);
    }
}

pub struct LinkIo {
    pub epoch: Epoch,
    /// Virtual server address used only by the technical readiness flow.
    pub peer_ip: Ipv4Addr,
    /// Pool log tag: empty for a single server, `[host]` inside a pool.
    pub tag: String,
    pub packets: mpsc::Receiver<Packet>,
    pub events: mpsc::Sender<(Epoch, Event)>,
    /// Latest heartbeat snapshot cannot be lost behind packet traffic.
    pub stats: watch::Sender<Stats>,
    pub delivery: Arc<Delivery>,
}

pub fn is_probe_flow(id: u64) -> bool {
    id >= FIRST_PROBE_ID
}
