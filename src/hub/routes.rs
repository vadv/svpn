//! Flow ownership and first-match traffic attribution across link generations.

use std::{collections::HashMap, net::Ipv4Addr};

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::{
    link_io::{Delivery, Epoch, FIRST_PROBE_ID, Packet},
    packet::{self, FlowKey},
};

use super::{Link, drop_note};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub epoch: Epoch,
    pub id: u64,
}

/// A remote generation or local-exit flow id; both share one id space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Remote(Owner),
    Direct(u64),
}

/// Rule attribution is pinned with ownership, never re-evaluated on DNS refresh.
pub struct RoutedFlow {
    pub target: Target,
    /// Config-order sticky index; None is the automatic fallback.
    pub rule: Option<usize>,
}

/// Inner IP bytes: TX accepted by the hub queue, RX delivered to the client TUN.
#[derive(Default, Clone, Copy, Serialize)]
pub struct Traffic {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Default)]
pub struct Routes {
    pub by_key: HashMap<FlowKey, RoutedFlow>,
    /// Bounded by configured rules plus fallback; survives flow retirement.
    pub traffic: HashMap<Option<usize>, Traffic>,
    pub next: u64,
}

impl Routes {
    pub fn allocate(&mut self) -> Result<u64> {
        self.next = self
            .next
            .checked_add(1)
            .filter(|id| *id < FIRST_PROBE_ID)
            .context("flow id space exhausted")?;
        Ok(self.next)
    }

    pub fn target(&self, key: &FlowKey) -> Option<&Target> {
        self.by_key.get(key).map(|flow| &flow.target)
    }

    pub fn insert(&mut self, key: FlowKey, target: Target, rule: Option<usize>) {
        self.by_key.insert(key, RoutedFlow { target, rule });
    }

    /// Call only after the queue/TUN accepted the full packet.
    pub fn record(&mut self, key: FlowKey, tx: usize, rx: usize) {
        if let Some(flow) = self.by_key.get(&key) {
            let traffic = self.traffic.entry(flow.rule).or_default();
            traffic.tx_bytes = traffic.tx_bytes.saturating_add(tx as u64);
            traffic.rx_bytes = traffic.rx_bytes.saturating_add(rx as u64);
        }
    }

    /// True only when the packet was accepted by the link queue.
    pub fn enqueue(
        &mut self,
        bytes: &[u8],
        client_ip: Ipv4Addr,
        epoch: Epoch,
        outgoing: &mpsc::Sender<Packet>,
        delivery: &Delivery,
        links: &[Link],
    ) -> Result<bool> {
        let parsed = match packet::parse(bytes, true) {
            Some(parsed) if parsed.flow.valid_for(client_ip) => parsed,
            Some(_) => {
                drop_note(
                    delivery,
                    links,
                    Some(epoch.link),
                    "foreign source in client TUN packet",
                );
                return Ok(false);
            }
            None => {
                drop_note(
                    delivery,
                    links,
                    Some(epoch.link),
                    "unparseable packet from client TUN",
                );
                return Ok(false);
            }
        };
        let (owner, fresh) = match self.target(&parsed.flow) {
            Some(Target::Remote(owner)) if owner.epoch == epoch => (*owner, false),
            // A local-exit-owned flow never spills onto a server link.
            Some(Target::Direct(_)) | Some(Target::Remote(_)) => {
                drop_note(
                    delivery,
                    links,
                    Some(epoch.link),
                    "flow owned by another link or not openable",
                );
                return Ok(false);
            }
            None if parsed.can_open => (
                Owner {
                    epoch,
                    id: self.allocate()?,
                },
                true,
            ),
            None => {
                drop_note(
                    delivery,
                    links,
                    Some(epoch.link),
                    "flow owned by another link or not openable",
                );
                return Ok(false);
            }
        };
        match outgoing.try_send(Packet {
            id: owner.id,
            bytes: bytes.to_vec(),
        }) {
            Ok(()) => {
                if fresh {
                    self.insert(parsed.flow, Target::Remote(owner), None);
                }
                Ok(true)
            }
            // A closed receiver is reported by its task; never fail other links here.
            Err(_) => {
                drop_note(delivery, links, Some(epoch.link), "link packet queue full");
                Ok(false)
            }
        }
    }

    pub fn accepts(&self, epoch: Epoch, packet: &Packet) -> bool {
        packet::parse(&packet.bytes, false).is_some_and(|p| {
            self.target(&p.flow)
                == Some(&Target::Remote(Owner {
                    epoch,
                    id: packet.id,
                }))
        })
    }

    pub fn forget(&mut self, key: FlowKey, owner: Owner) {
        if self.target(&key) == Some(&Target::Remote(owner)) {
            self.by_key.remove(&key);
        }
    }

    /// Remove a local-exit owner only if its generation is still current.
    /// The caller may tombstone the tuple only when removal succeeds.
    pub fn forget_direct(&mut self, key: FlowKey, id: u64) -> bool {
        if self.target(&key) == Some(&Target::Direct(id)) {
            self.by_key.remove(&key);
            true
        } else {
            false
        }
    }

    /// Drops every remote owner of the epoch and returns the retired keys
    /// so the caller can tombstone the TCP ones. local-exit owners survive
    /// failure of an unrelated link.
    pub fn remove_epoch(&mut self, epoch: Epoch) -> Vec<FlowKey> {
        let mut retired = Vec::new();
        self.by_key.retain(|key, flow| {
            if matches!(flow.target, Target::Remote(owner) if owner.epoch == epoch) {
                retired.push(*key);
                false
            } else {
                true
            }
        });
        retired
    }
}
