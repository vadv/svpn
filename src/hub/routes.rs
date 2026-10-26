//! Flow ownership: which owner serves which client flow.

use std::{collections::HashMap, net::Ipv4Addr};

use anyhow::{Context, Result};
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

#[derive(Default)]
pub struct Routes {
    pub by_key: HashMap<FlowKey, Target>,
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

    pub fn enqueue(
        &mut self,
        bytes: &[u8],
        client_ip: Ipv4Addr,
        epoch: Epoch,
        outgoing: &mpsc::Sender<Packet>,
        delivery: &Delivery,
        links: &[Link],
    ) -> Result<()> {
        let parsed = match packet::parse(bytes, true) {
            Some(parsed) if parsed.flow.valid_for(client_ip) => parsed,
            Some(_) => {
                drop_note(
                    delivery,
                    links,
                    Some(epoch.link),
                    "foreign source in client TUN packet",
                );
                return Ok(());
            }
            None => {
                drop_note(
                    delivery,
                    links,
                    Some(epoch.link),
                    "unparseable packet from client TUN",
                );
                return Ok(());
            }
        };
        let (owner, fresh) = match self.by_key.get(&parsed.flow) {
            Some(Target::Remote(owner)) if owner.epoch == epoch => (*owner, false),
            // A local-exit-owned flow never spills onto a server link.
            Some(Target::Direct(_)) | Some(Target::Remote(_)) => {
                drop_note(
                    delivery,
                    links,
                    Some(epoch.link),
                    "flow owned by another link or not openable",
                );
                return Ok(());
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
                return Ok(());
            }
        };
        match outgoing.try_send(Packet {
            id: owner.id,
            bytes: bytes.to_vec(),
        }) {
            Ok(()) if fresh => {
                self.by_key.insert(parsed.flow, Target::Remote(owner));
            }
            Ok(()) => {}
            // A closed receiver is reported by its task; never fail other links here.
            Err(_) => drop_note(delivery, links, Some(epoch.link), "link packet queue full"),
        }
        Ok(())
    }

    pub fn accepts(&self, epoch: Epoch, packet: &Packet) -> bool {
        packet::parse(&packet.bytes, false).is_some_and(|p| {
            self.by_key.get(&p.flow)
                == Some(&Target::Remote(Owner {
                    epoch,
                    id: packet.id,
                }))
        })
    }

    pub fn forget(&mut self, key: FlowKey, owner: Owner) {
        if self.by_key.get(&key) == Some(&Target::Remote(owner)) {
            self.by_key.remove(&key);
        }
    }

    /// Remove a local-exit owner only if its generation is still current.
    /// The caller may tombstone the tuple only when removal succeeds.
    pub fn forget_direct(&mut self, key: FlowKey, id: u64) -> bool {
        if self.by_key.get(&key) == Some(&Target::Direct(id)) {
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
        self.by_key.retain(|key, target| {
            if matches!(target, Target::Remote(owner) if owner.epoch == epoch) {
                retired.push(*key);
                false
            } else {
                true
            }
        });
        retired
    }
}
