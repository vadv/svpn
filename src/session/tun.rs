//! TUN-side packet path: admission of local packets, forwarding to flows,
//! delivery from channels, and flow expiry.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant as StdInstant},
};

use anyhow::{Context, Result, ensure};

use crate::control::{Message, Stats};
use crate::link_io::{self, FIRST_PROBE_ID, PREFLIGHT_ID, is_probe_flow};
use crate::packet::{self, FlowKey};
use crate::udp::Incoming;

use super::{
    ChannelHandle, FIN_DWELL, FLOW_IDLE, Flow, PacketIo, Plane, Session, TaskCommand, TcpFlow,
};

const FLOW_PENDING: usize = 64;

impl Session {
    pub(crate) async fn notify_closed(&self, id: u64, key: FlowKey) -> Result<()> {
        if !is_probe_flow(id)
            && let PacketIo::Link(io) = &self.io
        {
            // The event loop's heartbeat deadline also bounds reliable close delivery.
            io.events
                .send((io.epoch, link_io::Event::Closed { id, key }))
                .await
                .context("packet event port closed")?;
        }
        Ok(())
    }

    async fn reject_unowned_tun_packet(
        &mut self,
        bytes: &[u8],
        packet: &packet::Packet,
        explicit_id: Option<u64>,
    ) -> Result<()> {
        if !self.client() && packet.tcp.is_some() {
            self.stats.dropped_packets += 1;
            crate::debug!("{} packet for closed TCP flow", self.drop_prefix);
            // The server's parsed tuple is normalized; a reply needs the wire direction.
            if let Some(reset) =
                packet::parse(bytes, true).and_then(|packet| packet::tcp_reset_for(&packet))
            {
                self.write_tun_packet(0, reset.to_vec()).await?;
            }
        } else {
            self.stats
                .count_drop(&self.drop_prefix, "flow not openable");
        }
        if let Some(id) = explicit_id {
            self.notify_closed(id, packet.flow).await?;
        }
        Ok(())
    }

    pub async fn handle_tun_packet(
        &mut self,
        bytes: &[u8],
        explicit_id: Option<u64>,
    ) -> Result<()> {
        ensure!(
            explicit_id.is_none_or(|id| id < FIRST_PROBE_ID),
            "reserved Hub flow ID"
        );
        if !self.accepts_packets() && !explicit_id.is_some_and(|id| self.has_flow(id)) {
            if let Some(id) = explicit_id {
                self.last_link_id = self.last_link_id.max(id);
                if let Some(packet) = packet::parse(bytes, self.client()) {
                    self.notify_closed(id, packet.flow).await?;
                }
            }
            return Ok(());
        }
        let parsed = packet::parse(bytes, self.client());
        let Some(packet) = parsed.as_ref().filter(|packet| {
            bytes.len() <= self.mtu as usize && packet.flow.valid_for(self.client_ip)
        }) else {
            self.stats.count_drop(
                &self.drop_prefix,
                &format!(
                    "unparseable or oversized packet from TUN ({} B)",
                    bytes.len()
                ),
            );
            if let Some(id) = explicit_id
                && !self.has_flow(id)
            {
                self.last_link_id = self.last_link_id.max(id);
                // An unparseable packet has no tuple to release at the owner.
                if let Some(packet) = parsed {
                    self.notify_closed(id, packet.flow).await?;
                }
            }
            return Ok(());
        };
        let is_client = self.client();
        // A retired flow never re-enters admission (EPIC-010 §5.3): answer
        // as a CLOSED endpoint, rate-limited; a client RST is just dropped.
        // Device sessions never tombstone, so there is no local write path.
        if is_client && self.tombstones.active(&packet.flow, StdInstant::now()) {
            if let Some(reset) = self
                .tombstones
                .respond(&packet.flow, packet, StdInstant::now())
                && let PacketIo::Link(io) = &self.io
                && io
                    .events
                    .try_send((
                        io.epoch,
                        link_io::Event::Packet(link_io::Packet {
                            id: explicit_id.unwrap_or(0),
                            bytes: reset.to_vec(),
                        }),
                    ))
                    .is_err()
            {
                self.stats
                    .count_drop(&self.drop_prefix, "tombstone reset not delivered");
            }
            self.stats
                .count_drop(&self.drop_prefix, "flow closed (tombstone)");
            return Ok(());
        }
        // Newest client ACK per TCP flow seeds the link-loss reset (§5.3).
        if is_client
            && let Some(ack) = packet
                .tcp
                .as_ref()
                .filter(|tcp| tcp.flags & 0x10 != 0)
                .map(|tcp| tcp.ack)
        {
            match &mut self.plane {
                Plane::Channels(plane) => {
                    if let Some(&id) = plane.by_key.get(&packet.flow)
                        && let Some(flow) = plane.flows.get_mut(&id)
                    {
                        flow.last_ack = Some(ack);
                    }
                }
                Plane::Tcp(plane) => {
                    if let Some(&id) = plane.by_key.get(&packet.flow)
                        && let Some(flow) = plane.flows.get_mut(&id)
                    {
                        flow.last_ack = Some(ack);
                    }
                }
            }
        }
        if let Some(id) = explicit_id {
            let known = match &self.plane {
                Plane::Channels(plane) => plane.by_key.get(&packet.flow),
                Plane::Tcp(plane) => plane.by_key.get(&packet.flow),
            };
            // Check before RST handling: a stale packet cannot close a new tuple owner.
            if known.is_some_and(|&known| known != id) {
                self.stats
                    .count_drop(&self.drop_prefix, &format!("stale packet for flow id {id}"));
                return Ok(());
            }
            if known.is_none() {
                let reused = id <= self.last_link_id || self.has_flow(id);
                self.last_link_id = self.last_link_id.max(id);
                if reused {
                    if id != 0 && !self.has_flow(id) {
                        // Hub can queue packets before it consumes our Closed event.
                        self.stats.dropped_packets += 1;
                        crate::debug!(
                            "{} stale packet for inactive flow id {id}",
                            self.drop_prefix
                        );
                    } else {
                        self.stats
                            .count_drop(&self.drop_prefix, &format!("reused flow id {id}"));
                    }
                    return self.notify_closed(id, packet.flow).await;
                }
            }
        }
        let is_client = self.client();
        match &mut self.plane {
            Plane::Channels(plane) => {
                let now = tokio::time::Instant::now();
                let known = plane.by_key.get(&packet.flow).copied();
                let mut open_actions = Vec::new();
                // fresh: the packet is already queued in selector.request; the enqueue below would duplicate it.
                let mut fresh = false;
                let flow_id = match known {
                    Some(id) => id,
                    None => {
                        let from_client = plane.selector.is_some();
                        if !from_client || !packet.can_open {
                            return self
                                .reject_unowned_tun_packet(bytes, packet, explicit_id)
                                .await;
                        }
                        let flow_id = explicit_id.unwrap_or_else(|| {
                            let id = plane.next_client_flow_id;
                            plane.next_client_flow_id += 1;
                            id
                        });
                        plane.flows.insert(flow_id, Flow::new(packet.flow, now));
                        plane.by_key.insert(packet.flow, flow_id);
                        self.stats.opened_flows += 1;
                        crate::debug!("flow_request id={flow_id} key={:?}", packet.flow);
                        let Some(selector) = plane.selector.as_mut() else {
                            unreachable!("client plane always has selector");
                        };
                        match selector.request(flow_id, packet.flow, bytes, StdInstant::now()) {
                            Ok(actions) => {
                                open_actions = actions;
                                fresh = true;
                                flow_id
                            }
                            Err(_) => {
                                self.stats.open_failed_flows += 1;
                                plane.flows.remove(&flow_id);
                                plane.by_key.remove(&packet.flow);
                                self.notify_closed(flow_id, packet.flow).await?;
                                return Ok(());
                            }
                        }
                    }
                };
                let Some(flow_state) = plane.flows.get_mut(&flow_id) else {
                    return Ok(());
                };
                flow_state.last_seen = now;
                flow_state.reset_requested |= is_client && packet.is_rst;
                // FIN from the target (server TUN): schedule a dwell close;
                // half-close data resets it — keep forwarding while data flows.
                if packet.fin && !is_client {
                    flow_state.fin_dwell.get_or_insert(now + FIN_DWELL);
                } else if packet.tcp.is_some_and(|tcp| tcp.payload_len > 0) {
                    flow_state.fin_dwell = None;
                }
                // Pre-active: the server buffers locally, the client hands to the selector.
                if flow_state.active {
                    forward_active(
                        &mut self.stats,
                        &self.drop_prefix,
                        flow_id,
                        flow_state,
                        &plane.channels,
                        bytes,
                    );
                } else if fresh {
                    // The flow's first packet is already queued in selector.request().
                } else if let Some(selector) = plane.selector.as_mut() {
                    if selector.enqueue(flow_id, bytes).is_err() {
                        self.stats.count_drop(
                            &self.drop_prefix,
                            &format!("flow {flow_id} selector queue full"),
                        );
                    }
                } else if flow_state.pending.len() < FLOW_PENDING {
                    flow_state.pending.push_back(bytes.to_vec());
                } else {
                    self.stats.count_drop(
                        &self.drop_prefix,
                        &format!("flow {flow_id} pending buffer full"),
                    );
                }
                self.execute_actions(open_actions).await?;
            }
            Plane::Tcp(plane) => {
                let now = tokio::time::Instant::now();
                let known = plane.by_key.get(&packet.flow).copied();
                let id = match known {
                    Some(id) => id,
                    None => {
                        if !is_client || !packet.can_open {
                            return self
                                .reject_unowned_tun_packet(bytes, packet, explicit_id)
                                .await;
                        }
                        let id = explicit_id.unwrap_or_else(|| {
                            let id = plane.next_flow_id;
                            plane.next_flow_id += 1;
                            id
                        });
                        self.control
                            .send(Message::Open {
                                id,
                                flow: packet.flow,
                            })
                            .await?;
                        plane.flows.insert(
                            id,
                            TcpFlow {
                                key: packet.flow,
                                active: false,
                                reset_requested: false,
                                outgoing: None,
                                pending: VecDeque::from([bytes.to_vec()]),
                                tcp_key: None,
                                tcp_token: None,
                                tcp_receiver: None,
                                task: None,
                                fin_dwell: None,
                                last_ack: None,
                                last_seen: now,
                                created: now,
                            },
                        );
                        plane.by_key.insert(packet.flow, id);
                        self.stats.opened_flows += 1;
                        // The first packet is already in the new flow's pending;
                        // a failure below would duplicate it in the queue.
                        return Ok(());
                    }
                };
                if let Some(flow_state) = plane.flows.get_mut(&id) {
                    flow_state.last_seen = now;
                    flow_state.reset_requested |= is_client && packet.is_rst;
                    if packet.fin && !is_client {
                        flow_state.fin_dwell.get_or_insert(now + FIN_DWELL);
                    } else if packet.tcp.is_some_and(|tcp| tcp.payload_len > 0) {
                        flow_state.fin_dwell = None;
                    }
                }
                let Some(flow_state) = plane.flows.get_mut(&id) else {
                    return Ok(());
                };
                if let Some(send) = &flow_state.outgoing {
                    match send.try_send(bytes.to_vec()) {
                        Ok(()) => self.stats.record_tx(bytes.len(), true),
                        Err(_) => self.stats.count_drop(
                            &self.drop_prefix,
                            &format!("flow {id} transport queue full"),
                        ),
                    }
                } else if flow_state.pending.len() < FLOW_PENDING {
                    flow_state.pending.push_back(bytes.to_vec());
                } else {
                    self.stats
                        .count_drop(&self.drop_prefix, &format!("flow {id} pending buffer full"));
                }
            }
        }
        Ok(())
    }

    async fn write_tun_packet(&mut self, id: u64, bytes: Vec<u8>) -> Result<bool> {
        let sent = bytes.len();
        match &self.io {
            PacketIo::Device(tun) => {
                let written = match tokio::time::timeout(
                    Duration::from_millis(100),
                    tun.send(&bytes),
                )
                .await
                {
                    Ok(result) => result.context("write TUN")?,
                    Err(_) => {
                        self.stats
                            .count_drop(&self.drop_prefix, "TUN write timeout");
                        return Ok(false);
                    }
                };
                ensure!(written == sent, "short TUN write");
                self.stats.inner_rx_packets += 1;
                self.stats.inner_rx_bytes += sent as u64;
            }
            PacketIo::Link(io) => {
                if io
                    .events
                    .try_send((
                        io.epoch,
                        link_io::Event::Packet(link_io::Packet { id, bytes }),
                    ))
                    .is_err()
                {
                    self.stats
                        .count_drop(&self.drop_prefix, "hub event queue full");
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    pub async fn deliver_to_tun(&mut self, incoming: Incoming) -> Result<()> {
        let from_client = !self.client();
        let Some(packet) = packet::parse(&incoming.packet, from_client) else {
            self.stats.count_drop(
                &self.drop_prefix,
                &format!("unparseable packet from link id {}", incoming.id),
            );
            return Ok(());
        };
        let client_address = if from_client {
            &incoming.packet[12..16]
        } else {
            &incoming.packet[16..20]
        };
        let (key, channel, active, flow_exists) = match &self.plane {
            Plane::Channels(plane) => plane
                .flows
                .get(&incoming.id)
                .map_or((None, None, false, false), |flow| {
                    (Some(flow.key), flow.channel, flow.active, true)
                }),
            Plane::Tcp(plane) => plane
                .flows
                .get(&incoming.id)
                .map_or((None, None, false, false), |flow| {
                    (Some(flow.key), None, flow.active, true)
                }),
        };
        // A packet that overtook committed never reaches the TUN.
        if !flow_exists
            || key != Some(packet.flow)
            || !active
            || client_address != self.client_ip.octets()
        {
            self.stats.count_drop(
                &self.drop_prefix,
                &format!("stale or unowned packet from link id {}", incoming.id),
            );
            return Ok(());
        }
        if is_probe_flow(incoming.id) && self.client() {
            if incoming.channel != channel {
                return Ok(());
            }
            let verdict = self.round.as_ref().is_some_and(|round| {
                let expected_id = if round.tcp_id == Some(incoming.id) {
                    Some(round.id)
                } else {
                    round.pending.get(&incoming.id).map(|rc| rc.icmp_id)
                };
                expected_id.is_some_and(|id| {
                    packet::icmp_echo_reply_matches(&incoming.packet, id, round.seq, &round.payload)
                })
            });
            if verdict {
                self.round_won(channel).await?;
            }
            return Ok(());
        }
        if !self.write_tun_packet(incoming.id, incoming.packet).await? {
            return Ok(());
        }
        let from_target = self.client();
        let now = tokio::time::Instant::now();
        if let Plane::Channels(plane) = &mut self.plane
            && let Some(flow_state) = plane.flows.get_mut(&incoming.id)
        {
            flow_state.last_seen = now;
            if packet.fin && from_target {
                flow_state.fin_dwell.get_or_insert(now + FIN_DWELL);
            } else if packet.tcp.is_some_and(|tcp| tcp.payload_len > 0) {
                flow_state.fin_dwell = None;
            }
        }
        if let Plane::Tcp(plane) = &mut self.plane
            && let Some(flow_state) = plane.flows.get_mut(&incoming.id)
        {
            flow_state.last_seen = now;
            if packet.fin && from_target {
                flow_state.fin_dwell.get_or_insert(now + FIN_DWELL);
            } else if packet.tcp.is_some_and(|tcp| tcp.payload_len > 0) {
                flow_state.fin_dwell = None;
            }
        }
        // Only authenticated client resets retire a flow, after successful TUN delivery.
        if from_client && packet.is_rst {
            self.close_flow(incoming.id, true).await?;
        }
        Ok(())
    }

    pub async fn expire_flows(&mut self, now: tokio::time::Instant) -> Result<()> {
        match &mut self.plane {
            Plane::Channels(plane) => {
                let budget = crate::selector::FLOW_BUDGET;
                let dwell_expired: Vec<u64> = plane
                    .flows
                    .iter()
                    .filter_map(|(&id, flow)| Some((id, flow.fin_dwell?)))
                    .filter(|(_, at)| now >= *at)
                    .map(|(id, _)| id)
                    .collect();
                let expired: Vec<u64> = plane
                    .flows
                    .iter()
                    .filter(|(id, flow)| {
                        **id != PREFLIGHT_ID
                            && ((flow.active && now.duration_since(flow.last_seen) > FLOW_IDLE)
                                || (!flow.active && now.duration_since(flow.created) > budget))
                    })
                    .map(|(&id, _)| id)
                    .collect();
                for id in dwell_expired {
                    if id != PREFLIGHT_ID {
                        crate::debug!("flow_close id={id} fin dwell");
                    }
                    self.close_flow(id, true).await?;
                }
                for id in expired {
                    if id != PREFLIGHT_ID {
                        crate::debug!("flow_close id={id} budget={budget:?} idle={FLOW_IDLE:?}");
                    }
                    self.close_flow(id, true).await?;
                }
            }
            Plane::Tcp(plane) => {
                let expired: Vec<u64> = plane
                    .flows
                    .iter()
                    .filter(|(id, flow)| {
                        **id != PREFLIGHT_ID
                            && now.duration_since(flow.created) > FLOW_IDLE
                            && now.duration_since(flow.last_seen) > FLOW_IDLE
                    })
                    .map(|(&id, _)| id)
                    .collect();
                for id in expired {
                    self.tcp_close(id).await?;
                }
            }
        }
        Ok(())
    }
}

fn forward_active(
    stats: &mut Stats,
    drop_prefix: &str,
    flow_id: u64,
    flow_state: &mut Flow,
    channels: &HashMap<u64, ChannelHandle>,
    bytes: &[u8],
) {
    if let Some(tcp_out) = flow_state.tcp.as_ref().and_then(|tcp| tcp.out.clone()) {
        if tcp_out.try_send(bytes.to_vec()).is_ok() {
            stats.inner_tx_packets += 1;
            stats.inner_tx_bytes += bytes.len() as u64;
        } else {
            stats.count_drop(drop_prefix, &format!("flow {flow_id} output queue full"));
        }
    } else if let Some(channel_id) = flow_state.channel
        && let Some(handle) = channels.get(&channel_id)
    {
        if handle
            .command
            .try_send(TaskCommand::Data(flow_id, bytes.to_vec()))
            .is_ok()
        {
            stats.inner_tx_packets += 1;
            stats.inner_tx_bytes += bytes.len() as u64;
        } else {
            stats.count_drop(drop_prefix, &format!("flow {flow_id} channel queue full"));
        }
    } else {
        stats.count_drop(
            drop_prefix,
            &format!("flow {flow_id} active without output"),
        );
    }
}
