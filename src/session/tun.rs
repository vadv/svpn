//! TUN-side packet path: admission of local packets, forwarding to flows,
//! delivery from channels, and flow expiry.

use std::time::{Duration, Instant as StdInstant};

use anyhow::{Context, Result, ensure};

use crate::control::Message;
use crate::link_io::{self, FIRST_PROBE_ID, PREFLIGHT_ID, is_probe_flow};
use crate::packet::{self, FlowKey};
use crate::udp::Incoming;

use super::state::idle_timeout;
use super::{Flow, PacketIo, Plane, Session, TcpFlow};

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
            match packet::unsupported(bytes).filter(|_| bytes.len() <= self.mtu as usize) {
                Some(reason) => self.stats.count_drop_expected(&self.drop_prefix, &reason),
                None => self.stats.count_drop(
                    &self.drop_prefix,
                    &format!(
                        "unparseable or oversized packet from TUN ({} B)",
                        bytes.len()
                    ),
                ),
            }
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
        // A retired flow never re-enters admission: answer
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
        // Newest client ACK per TCP flow seeds the link-loss reset.
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
        let known = match &self.plane {
            Plane::Channels(plane) => plane.by_key.contains_key(&packet.flow),
            Plane::Tcp(plane) => plane.by_key.contains_key(&packet.flow),
        };
        if is_client && packet.can_open && !known && self.flow_limit_reached(0) {
            self.stats.opened_flows += 1;
            self.stats.open_failed_flows += 1;
            self.stats
                .count_drop(&self.drop_prefix, "flow limit reached");
            if let Some(id) = explicit_id {
                self.notify_closed(id, packet.flow).await?;
            }
            return Ok(());
        }
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
                flow_state.tcp_close.observe(packet, is_client, now);
                if !fresh {
                    if let Some(selector) = plane.selector.as_mut() {
                        if selector.enqueue(flow_id, bytes).is_err() {
                            self.stats
                                .count_drop(&self.drop_prefix, "flow pending queue full");
                        }
                    } else if !flow_state.active && flow_state.data_started {
                        self.stats
                            .count_drop_expected(&self.drop_prefix, "TCP binding recovering");
                    } else if flow_state.pending.len()
                        < if flow_state.data_started {
                            1
                        } else {
                            FLOW_PENDING
                        }
                    {
                        flow_state.pending.push_back(bytes.to_vec());
                    } else {
                        self.stats
                            .count_drop(&self.drop_prefix, "flow pending queue full");
                    }
                }
                self.execute_actions(open_actions).await?;
                self.flush_flow(flow_id).await?;
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
                        if plane.flows.keys().filter(|id| !is_probe_flow(**id)).count()
                            >= super::FLOW_CAP
                            || plane
                                .flows
                                .iter()
                                .filter(|(id, flow)| !is_probe_flow(**id) && !flow.active)
                                .count()
                                >= crate::selector::PENDING_FLOWS
                        {
                            self.stats.open_failed_flows += 1;
                            if let Some(id) = explicit_id {
                                self.notify_closed(id, packet.flow).await?;
                            }
                            return Ok(());
                        }
                        let id = explicit_id.unwrap_or_else(|| {
                            let id = plane.next_flow_id;
                            plane.next_flow_id += 1;
                            id
                        });
                        self.control
                            .send(Message::Open {
                                id,
                                generation: 1,
                                flow: packet.flow,
                            })
                            .await?;
                        let mut flow = TcpFlow::new(packet.flow, now);
                        flow.pending.push_back(bytes.to_vec());
                        flow.binding_deadline = Some(now + crate::selector::ATTEMPT_BUDGET);
                        plane.flows.insert(id, flow);
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
                    flow_state.tcp_close.observe(packet, is_client, now);
                }
                let Some(flow_state) = plane.flows.get_mut(&id) else {
                    return Ok(());
                };
                if flow_state.pending.len()
                    < if flow_state.data_started {
                        1
                    } else {
                        FLOW_PENDING
                    }
                {
                    flow_state.pending.push_back(bytes.to_vec());
                } else {
                    self.stats
                        .count_drop(&self.drop_prefix, "flow pending queue full");
                }
                self.flush_flow(id).await?;
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
            || !self.binding_current(incoming.id, incoming.generation)
            || channel != incoming.channel
            || key != Some(packet.flow)
            || !active
            || client_address != self.client_ip.octets()
        {
            // The control handshake and the data raced (a channel backlog
            // drained after FlowClose): expected, the kernel retransmits.
            self.stats.count_drop_expected(
                &self.drop_prefix,
                &format!("stale or unowned packet from link id {}", incoming.id),
            );
            return Ok(());
        }
        let now = tokio::time::Instant::now();
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
                self.round_verified(channel, incoming.id).await?;
            } else if let Some(burst) = self.burst.as_mut()
                && incoming.channel == Some(burst.channel)
                && let Some(seq) =
                    packet::icmp_echo_reply_seq(&incoming.packet, burst.icmp_id, &burst.payload)
                && burst.record_echo(seq, now)
                && burst.finished(now)
            {
                self.finish_burst(now).await?;
            } else {
                // A challenge burst owns this probe flow: record the echo and
                // collect the burst right here when it completed.
                let finished = if let Some(challenge) = self.challenge.as_mut()
                    && let Some(challenger) = challenge.attempts.get_mut(&incoming.id)
                    && let Some(burst) = challenger.burst.as_mut()
                    && incoming.channel == Some(burst.channel)
                    && let Some(seq) =
                        packet::icmp_echo_reply_seq(&incoming.packet, burst.icmp_id, &burst.payload)
                {
                    burst.record_echo(seq, now);
                    burst.finished(now)
                } else {
                    false
                };
                if finished {
                    self.finish_probe(incoming.id).await?;
                }
            }
            return Ok(());
        }
        // Data counts only once a packet actually reached the TUN; a failed write
        // must not lift the pre-data FLOW_BUDGET bound.
        if !self.write_tun_packet(incoming.id, incoming.packet).await? {
            return Ok(());
        }
        match &mut self.plane {
            Plane::Channels(plane) => {
                if let Some(flow) = plane.flows.get_mut(&incoming.id) {
                    flow.data_started = true;
                }
            }
            Plane::Tcp(plane) => {
                if let Some(flow) = plane.flows.get_mut(&incoming.id) {
                    flow.data_started = true;
                }
            }
        }
        self.recovery_delivered(incoming.id, "peer_packet");
        if let Plane::Channels(plane) = &mut self.plane
            && let Some(flow_state) = plane.flows.get_mut(&incoming.id)
        {
            flow_state.last_seen = now;
            flow_state.tcp_close.observe(&packet, from_client, now);
        }
        if let Plane::Tcp(plane) = &mut self.plane
            && let Some(flow_state) = plane.flows.get_mut(&incoming.id)
        {
            flow_state.last_seen = now;
            flow_state.tcp_close.observe(&packet, from_client, now);
        }
        // The client TCP stack owns reset decisions; a target RST may be out of window.
        if from_client && packet.is_rst {
            self.close_flow(incoming.id, true).await?;
        }
        Ok(())
    }

    pub async fn expire_flows(&mut self, now: tokio::time::Instant) -> Result<()> {
        let expired: Vec<_> = match &self.plane {
            Plane::Channels(plane) => plane
                .flows
                .iter()
                .filter(|(id, flow)| {
                    **id != PREFLIGHT_ID
                        && ((!flow.data_started
                            && now.duration_since(flow.created) >= crate::selector::FLOW_BUDGET)
                            || (flow.data_started
                                && super::recovery::recovery_expired(&flow.recovery, now))
                            || (flow.active
                                && (flow.tcp_close.deadline.is_some_and(|at| now >= at)
                                    || now.duration_since(flow.last_seen)
                                        >= idle_timeout(flow.key.protocol))))
                })
                .map(|(&id, _)| id)
                .collect(),
            Plane::Tcp(plane) => plane
                .flows
                .iter()
                .filter(|(id, flow)| {
                    **id != PREFLIGHT_ID
                        && ((!flow.data_started
                            && now.duration_since(flow.created) >= crate::selector::FLOW_BUDGET)
                            || (flow.data_started
                                && super::recovery::recovery_expired(&flow.recovery, now))
                            || (flow.active
                                && (flow.tcp_close.deadline.is_some_and(|at| now >= at)
                                    || now.duration_since(flow.last_seen)
                                        >= idle_timeout(flow.key.protocol))))
                })
                .map(|(&id, _)| id)
                .collect(),
        };
        for id in expired {
            crate::debug!("flow_close id={id} lifetime expired");
            self.close_flow(id, true).await?;
        }
        let timed_out: Vec<_> = match &self.plane {
            Plane::Tcp(plane) if plane.server_ip.is_some() => plane
                .flows
                .iter()
                .filter(|(id, flow)| {
                    !is_probe_flow(**id)
                        && !flow.active
                        && flow.binding_deadline.is_some_and(|at| now >= at)
                })
                .map(|(&id, flow)| (id, flow.generation))
                .collect(),
            _ => Vec::new(),
        };
        for (id, generation) in timed_out {
            if let Plane::Tcp(plane) = &mut self.plane {
                plane
                    .flows
                    .get_mut(&id)
                    .expect("flow collected above")
                    .binding_deadline = None;
            }
            if !self
                .retry_flow(id, generation, crate::selector::Reason::PathTimeout)
                .await?
            {
                self.close_flow(id, true).await?;
            }
        }
        Ok(())
    }
}
