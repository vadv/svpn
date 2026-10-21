//! Flow ownership: which link generation serves which client flow.

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

#[derive(Default)]
pub struct Routes {
    pub by_key: HashMap<FlowKey, Owner>,
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
            Some(&owner) if owner.epoch == epoch => (owner, false),
            None if parsed.can_open => (
                Owner {
                    epoch,
                    id: self.allocate()?,
                },
                true,
            ),
            _ => {
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
                self.by_key.insert(parsed.flow, owner);
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
                == Some(&Owner {
                    epoch,
                    id: packet.id,
                })
        })
    }

    pub fn forget(&mut self, key: FlowKey, owner: Owner) {
        if self.by_key.get(&key) == Some(&owner) {
            self.by_key.remove(&key);
        }
    }

    /// Drops every owner of the epoch and returns the retired keys so the
    /// caller can tombstone the TCP ones.
    pub fn remove_epoch(&mut self, epoch: Epoch) -> Vec<FlowKey> {
        let mut retired = Vec::new();
        self.by_key.retain(|key, owner| {
            if owner.epoch == epoch {
                retired.push(*key);
                false
            } else {
                true
            }
        });
        retired
    }
}
