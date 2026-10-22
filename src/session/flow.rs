//! Flow lifecycle: admission and binding, the commit barrier, teardown, and
//! link-loss retirement.

use std::{collections::VecDeque, time::Instant as StdInstant};

use anyhow::{Context, Result, bail, ensure};

use crate::channel;
use crate::control::Message;
use crate::link_io::{self, PREFLIGHT_ID, is_probe_flow};
use crate::packet::{self, FlowKey};
use crate::selector::{Candidate, Reason};

use super::burst::Burst;
use super::round::{ROUND_RESEND, unanswered};
use super::{FLOW_IDLE, Flow, PacketIo, Plane, Readiness, Session, TaskCommand};

impl Session {
    // ────────────────────────── TCP transport events ──────────────────────────

    pub async fn tcp_connected(&mut self, id: u64) -> Result<()> {
        if is_probe_flow(id) {
            if !self.has_flow(id)
                || (self.client()
                    && self
                        .round
                        .as_ref()
                        .is_none_or(|round| round.tcp_id != Some(id) || round.retry_at.is_some()))
            {
                return Ok(());
            }
            if self.client() {
                let connecting = match &self.plane {
                    Plane::Channels(plane) => plane
                        .flows
                        .get(&id)
                        .and_then(|flow| flow.tcp.as_ref())
                        .is_some_and(|tcp| tcp.task.is_some()),
                    Plane::Tcp(plane) => {
                        plane.flows.get(&id).is_some_and(|flow| flow.task.is_some())
                    }
                };
                ensure!(connecting, "unexpected TCP preflight success");
            }
            // The binding is authenticated; only its ICMP reply can win the round.
            // The probe left inside the transport handshake and `Connected`
            // fires right after — this is the RTT baseline.
            if let Some(round) = self.round.as_mut() {
                round.tcp_started.get_or_insert(tokio::time::Instant::now());
            }
            match &mut self.plane {
                Plane::Channels(plane) => {
                    if let Some(flow) = plane.flows.get_mut(&id) {
                        flow.active = true;
                    }
                }
                Plane::Tcp(plane) => {
                    if let Some(flow) = plane.flows.get_mut(&id) {
                        flow.active = true;
                    }
                }
            }
            return Ok(());
        }
        if let Plane::Channels(plane) = &mut self.plane
            && let Some(selector) = plane.selector.as_mut()
        {
            let actions = selector.bind_succeeded(id, StdInstant::now());
            self.execute_actions(actions).await?;
        } else if let Plane::Tcp(plane) = &mut self.plane
            && let Some(flow) = plane.flows.get_mut(&id)
        {
            flow.active = true;
        }
        Ok(())
    }

    pub async fn tcp_closed(&mut self, id: u64) -> Result<()> {
        if is_probe_flow(id) {
            return self.tcp_failed(id).await;
        }
        let now = tokio::time::Instant::now();
        let expected = match &self.plane {
            Plane::Channels(plane) => plane.flows.get(&id).is_none_or(|flow| {
                flow.fin_dwell.is_some() || now.duration_since(flow.last_seen) >= FLOW_IDLE
            }),
            Plane::Tcp(plane) => plane.flows.get(&id).is_none_or(|flow| {
                flow.fin_dwell.is_some() || now.duration_since(flow.last_seen) >= FLOW_IDLE
            }),
        };
        if !expected {
            return self.tcp_failed(id).await;
        }
        if self.has_flow(id) {
            self.close_flow(id, true).await?;
        }
        Ok(())
    }

    pub async fn tcp_failed(&mut self, id: u64) -> Result<()> {
        if is_probe_flow(id) {
            if !self.has_flow(id) {
                return Ok(());
            }
            if !self.client() {
                return self.close_flow(id, true).await;
            }
            let Some(round) = self
                .round
                .as_mut()
                .filter(|round| round.tcp_id == Some(id) && round.retry_at.is_none())
            else {
                return Ok(());
            };
            round.tcp_id = None;
            round.failures.push((Candidate::Tcp, Reason::PathTimeout));
            // A candidate that failed after its echo must not win the verdict.
            round.verified.retain(|(attempt, ..)| *attempt != id);
            self.close_flow(id, true).await?;
            if self
                .round
                .as_ref()
                .is_some_and(|round| unanswered(round).is_empty())
            {
                // A verified echo in the grace window still wins; decide_round
                // fails the round when nothing was verified.
                self.decide_round().await?;
            }
            return Ok(());
        }
        // Reset-driven EOF/errors can overtake Close on the independent SSH channel.
        let reset_requested = match &self.plane {
            Plane::Channels(plane) => plane
                .flows
                .get(&id)
                .is_some_and(|flow| flow.reset_requested),
            Plane::Tcp(plane) => plane
                .flows
                .get(&id)
                .is_some_and(|flow| flow.reset_requested),
        };
        if reset_requested {
            return self.close_flow(id, true).await;
        }
        let recheck = self.readiness == Some(Readiness::Ready) && self.has_flow(id);
        if let Plane::Channels(plane) = &mut self.plane
            && let Some(selector) = plane.selector.as_mut()
        {
            let actions = selector.bind_failed(id, Reason::ChannelFailed, StdInstant::now());
            self.execute_actions(actions).await?;
        }
        // A failed active/committing connection cannot migrate to another transport.
        if self.has_flow(id) {
            self.close_flow(id, true).await?;
        }
        if recheck {
            if let PacketIo::Link(io) = &self.io {
                io.events
                    .send((io.epoch, link_io::Event::Checking))
                    .await
                    .context("packet event port closed")?;
            }
            self.arm_round().await?;
        }
        Ok(())
    }

    pub fn flow_count(&self) -> usize {
        match &self.plane {
            Plane::Channels(plane) => plane.flows.keys().filter(|&&id| !is_probe_flow(id)).count(),
            Plane::Tcp(plane) => plane.flows.keys().filter(|&&id| !is_probe_flow(id)).count(),
        }
    }

    // ────────────────────────── Open, bind, commit ──────────────────────────

    pub async fn flow_open(
        &mut self,
        flow_id: u64,
        flow: FlowKey,
        channel: Option<u64>,
    ) -> Result<()> {
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("flow_open outside channels mode");
        };
        let Some(channel_id) = channel else {
            ensure!(
                !is_probe_flow(flow_id),
                "server cannot originate preflight flow"
            );
            // Server-originated flow (s→c): the client registers it and picks a channel.
            if plane.flows.contains_key(&flow_id) {
                return Ok(());
            }
            if !flow.valid_for(self.client_ip) {
                self.stats.count_drop(
                    &self.drop_prefix,
                    "server-originated flow outside client subnet",
                );
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            plane.flows.insert(flow_id, Flow::new(flow, now));
            plane.by_key.insert(flow, flow_id);
            self.stats.opened_flows += 1;
            let Some(selector) = plane.selector.as_mut() else {
                bail!("server-originated flow without selector");
            };
            match selector.request(flow_id, flow, &[], StdInstant::now()) {
                Ok(actions) => self.execute_actions(actions).await?,
                Err(_) => {
                    self.close_flow(flow_id, true).await?;
                }
            }
            return Ok(());
        };
        ensure!(
            !is_probe_flow(flow_id) || plane.selector.is_none(),
            "preflight flow_open on client"
        );
        // Client flow (c→s): the server registers and acknowledges it.
        // FlowOpen ids need not increase: the selector emits them in HashMap
        // iteration order. A duplicate id is a repeat of an already-accepted flow.
        ensure!(flow.valid_for(self.client_ip), "invalid flow tuple");
        if plane.flows.contains_key(&flow_id)
            || (flow_id != PREFLIGHT_ID && plane.by_key.contains_key(&flow))
        {
            crate::debug!("flow_open reject duplicate id={flow_id}");
            return self
                .control
                .send(Message::FlowReject {
                    flow_id,
                    reason: Reason::Unsupported,
                })
                .await;
        }
        let now = tokio::time::Instant::now();
        let mut registered = Flow::new(flow, now);
        registered.channel = Some(channel_id);
        plane.flows.insert(flow_id, registered);
        if !is_probe_flow(flow_id) {
            self.stats.opened_flows += 1;
            let transport = plane
                .channels
                .get(&channel_id)
                .map(|h| h.candidate.to_string())
                .unwrap_or_else(|| "tcp".to_string());
            crate::debug!(
                "flow_open role=server id={flow_id} channel={channel_id} transport={transport}"
            );
        }
        // N3: the preflight flow must be reachable from the TUN side too —
        // the kernel's echo reply routes back through `by_key`.
        plane.by_key.insert(flow, flow_id);
        if !is_probe_flow(flow_id) {
            self.control
                .send(Message::FlowOpened {
                    flow_id,
                    flow,
                    channel: channel_id,
                })
                .await?;
        }
        // FLOW_PROBE on the channel confirms the binding of both directions.
        let challenge = channel::challenge().context("challenge generation failed")?;
        let queued = plane.channels.get(&channel_id).is_some_and(|handle| {
            handle
                .command
                .try_send(TaskCommand::Record(channel::Record::FlowProbe {
                    flow_id,
                    challenge,
                }))
                .is_ok()
        });
        if !queued {
            return self.close_flow(flow_id, true).await;
        }
        if let Some(flow_state) = plane.flows.get_mut(&flow_id) {
            flow_state.echo_pending = Some(challenge);
        }
        Ok(())
    }

    /// Server: the client picked a channel for a server-originated flow.
    pub async fn flow_channel(&mut self, flow_id: u64, channel: u64) -> Result<()> {
        ensure!(!is_probe_flow(flow_id), "unexpected preflight flow_channel");
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("flow_channel outside channels mode");
        };
        let Some(flow_state) = plane.flows.get_mut(&flow_id) else {
            return Ok(());
        };
        let key = flow_state.key;
        flow_state.channel = Some(channel);
        let challenge = channel::challenge().context("challenge generation failed")?;
        flow_state.echo_pending = Some(challenge);
        self.control
            .send(Message::FlowOpened {
                flow_id,
                flow: key,
                channel,
            })
            .await?;
        let queued = plane.channels.get(&channel).is_some_and(|handle| {
            handle
                .command
                .try_send(TaskCommand::Record(channel::Record::FlowProbe {
                    flow_id,
                    challenge,
                }))
                .is_ok()
        });
        if !queued {
            return self.close_flow(flow_id, true).await;
        }
        Ok(())
    }

    /// Client: the server registered the binding — move to commit.
    pub(crate) async fn flow_opened(&mut self, flow_id: u64, channel: u64) -> Result<()> {
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("flow_opened outside channels mode");
        };
        let Some(flow_state) = plane.flows.get_mut(&flow_id) else {
            return Ok(());
        };
        if is_probe_flow(flow_id) {
            ensure!(
                flow_state.channel.is_none() || flow_state.channel == Some(channel),
                "unexpected preflight flow_opened channel"
            );
            flow_state.channel = Some(channel);
            // N3 round mode commits directly; the verdict (ICMP reply) ends
            // the round instead of a selector transition. Challenge probe
            // flows follow the same path — and so do health-burst probes:
            // without the Commit the server never sends Committed and the
            // burst stays unarmed forever.
            if self.round.is_some()
                || self
                    .challenge
                    .as_ref()
                    .is_some_and(|challenge| challenge.owns(flow_id))
                || self
                    .burst
                    .as_ref()
                    .is_some_and(|burst| burst.attempt == flow_id)
            {
                crate::debug!("round: flow_opened preflight channel={channel}, committing");
                return self
                    .control
                    .send(Message::Commit {
                        flow_id,
                        attempt: 0,
                    })
                    .await;
            }
        } else {
            flow_state.channel = Some(channel);
        }
        let Some(selector) = plane.selector.as_mut() else {
            bail!("flow_opened on server");
        };
        let actions = selector.bind_succeeded(flow_id, StdInstant::now());
        ensure!(
            flow_id != PREFLIGHT_ID || !actions.is_empty(),
            "stale preflight binding"
        );
        self.execute_actions(actions).await
    }

    pub(crate) async fn flow_rejected(&mut self, flow_id: u64, _reason: Reason) -> Result<()> {
        if self
            .round
            .as_ref()
            .is_some_and(|round| round.tcp_id == Some(flow_id))
        {
            return self.tcp_failed(flow_id).await;
        }
        self.close_flow(flow_id, false).await
    }

    /// Server: commit barrier passed — DATA allowed, the queue drains to the channel.
    pub async fn commit(&mut self, flow_id: u64) -> Result<()> {
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("commit outside channels mode");
        };
        ensure!(
            !is_probe_flow(flow_id) || plane.selector.is_none(),
            "preflight commit on client"
        );
        let Some(flow_state) = plane.flows.get_mut(&flow_id) else {
            return Ok(());
        };
        if flow_state.active {
            return Ok(());
        }
        ensure!(
            !is_probe_flow(flow_id) || flow_state.echo_pending.is_none(),
            "preflight commit before flow echo"
        );
        flow_state.active = true;
        let queue = std::mem::take(&mut flow_state.pending);
        if is_probe_flow(flow_id) {
            return self.control.send(Message::Committed { flow_id }).await;
        }
        crate::debug!("flow_active role=server id={flow_id}");
        self.send_pending(flow_id, queue).await?;
        self.control.send(Message::Committed { flow_id }).await
    }

    /// Arm a probe burst: activate its flow and fire the first echo. The
    /// remaining echoes leave from `poll_burst` on the burst's schedule.
    fn arm_burst(plane: &mut Plane, burst: &mut Burst, now: tokio::time::Instant) -> Result<()> {
        if burst.armed.is_some() {
            return Ok(());
        }
        let Plane::Channels(plane) = plane else {
            return Ok(());
        };
        let Some(flow) = plane.flows.get_mut(&burst.attempt) else {
            return Ok(());
        };
        ensure!(
            flow.channel == Some(burst.channel),
            "unexpected burst committed channel"
        );
        flow.active = true;
        let request = packet::icmp_echo_request(
            flow.key.source,
            flow.key.destination,
            burst.icmp_id,
            burst.seq(0),
            &burst.payload,
        );
        if let Some(handle) = plane.channels.get(&burst.channel) {
            // A full datagram queue is packet loss; it ends as loss.
            handle
                .command
                .try_send(TaskCommand::Data(burst.attempt, request))
                .ok();
        }
        burst.arm(now);
        burst.mark_sent(now);
        Ok(())
    }

    /// Client: `committed` received — the pre-active queue drains to the
    /// channel. Arms the health burst when the probe owns the burst slot.
    pub(crate) fn arm_slotted_burst(&mut self, now: tokio::time::Instant) -> Result<()> {
        let Some(burst) = self.burst.as_mut() else {
            return Ok(());
        };
        Self::arm_burst(&mut self.plane, burst, now)
    }

    pub async fn committed(&mut self, flow_id: u64) -> Result<()> {
        if is_probe_flow(flow_id) {
            // a health burst owns this probe id, not the round.
            if self
                .burst
                .as_ref()
                .is_some_and(|burst| burst.attempt == flow_id)
            {
                return self.arm_slotted_burst(tokio::time::Instant::now());
            }
            // A challenge probe committed: arm its burst right away — every
            // challenger burst runs in parallel with the others.
            let now = tokio::time::Instant::now();
            if let Some(challenge) = self.challenge.as_mut()
                && let Some(challenger) = challenge.attempts.get_mut(&flow_id)
                && let Some(burst) = challenger.burst.as_mut()
            {
                return Self::arm_burst(&mut self.plane, burst, now);
            }
            // A round probe committed: (re)send the probe and start the clock.
            let Some(rc) = self
                .round
                .as_mut()
                .filter(|round| round.retry_at.is_none())
                .and_then(|round| round.pending.get_mut(&flow_id))
            else {
                return Ok(());
            };
            let Plane::Channels(plane) = &mut self.plane else {
                return Ok(());
            };
            let Some(flow) = plane.flows.get_mut(&flow_id) else {
                return Ok(());
            };
            ensure!(
                rc.channel.is_some() && flow.channel == rc.channel,
                "unexpected preflight committed channel"
            );
            flow.active = true;
            rc.resend_at = Some(tokio::time::Instant::now() + ROUND_RESEND);
            if let Some(handle) = rc.channel.and_then(|id| plane.channels.get(&id)) {
                // A full datagram queue is packet loss; ROUND_RESEND retries the probe.
                if handle
                    .command
                    .try_send(TaskCommand::Data(flow_id, rc.request.clone()))
                    .is_ok()
                {
                    // First send wins: resends never move the RTT baseline.
                    rc.sent_at.get_or_insert(tokio::time::Instant::now());
                }
            }
            return Ok(());
        }
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("committed outside channels mode");
        };
        let Some(selector) = plane.selector.as_mut() else {
            bail!("committed on server");
        };
        let actions = selector.committed(flow_id);
        let queue = selector.take_queue(flow_id);
        let Some(flow_state) = plane.flows.get_mut(&flow_id).filter(|_| queue.is_some()) else {
            return Ok(());
        };
        flow_state.active = true;
        crate::debug!("flow_active role=client id={flow_id}");
        if let Some(queue) = queue {
            self.send_pending(flow_id, queue).await?;
        }
        self.execute_actions(actions).await
    }

    /// Both commit paths count queued packets at transport admission, exactly once.
    pub async fn send_pending(&mut self, flow_id: u64, queue: VecDeque<Vec<u8>>) -> Result<()> {
        let Plane::Channels(plane) = &self.plane else {
            bail!("pending channel packets outside channels mode");
        };
        let flow = plane
            .flows
            .get(&flow_id)
            .context("pending flow disappeared")?;
        let tcp = flow.tcp.as_ref().and_then(|tcp| tcp.out.as_ref());
        let channel = flow.channel.and_then(|id| plane.channels.get(&id));
        for packet in queue {
            if packet.is_empty() {
                continue; // server-originated flow: no first packet
            }
            let length = packet.len();
            let accepted = match (tcp, channel) {
                (Some(send), _) => send.send(packet).await.is_ok(),
                (None, Some(channel)) => channel
                    .command
                    .try_send(TaskCommand::Data(flow_id, packet))
                    .is_ok(),
                (None, None) => false,
            };
            if accepted {
                self.stats.record_tx(length, true);
            } else {
                self.stats.count_drop(
                    &self.drop_prefix,
                    &format!("flow {flow_id} output unavailable at commit"),
                );
            }
        }
        Ok(())
    }

    /// Link lost: retire every flow of this session's
    /// link. Each TCP flow with a known last client ACK yields a best-effort
    /// RST plus one keepalive probe (id, bytes) toward the client TUN;
    /// flows without an ACK rely on respond-on-arrival; UDP/ICMP flows
    /// disappear silently.
    pub fn retire_flows_of(&mut self) -> Vec<(u64, [u8; 40])> {
        let now = StdInstant::now();
        let mut retired = Vec::new();
        // Every retired TCP tuple stays refused for the TTL; flows without a
        // known ACK rely on respond-on-arrival. UDP/ICMP tuples just vanish.
        let mut retire_tcp = |id: u64, key: FlowKey, last_ack: Option<u32>| {
            if key.protocol != 6 {
                return;
            }
            self.tombstones.insert(key, now);
            if let Some(ack) = last_ack {
                retired.push((id, packet::tcp_reset_seq(key, ack)));
                retired.push((id, packet::tcp_probe(key, ack.wrapping_sub(1))));
            }
        };
        match &mut self.plane {
            Plane::Channels(plane) => {
                plane.by_key.clear();
                plane.token_index.clear();
                for (id, flow) in plane.flows.drain() {
                    retire_tcp(id, flow.key, flow.last_ack);
                }
            }
            Plane::Tcp(plane) => {
                plane.by_key.clear();
                plane.token_index.clear();
                for (id, flow) in plane.flows.drain() {
                    retire_tcp(id, flow.key, flow.last_ack);
                }
            }
        }
        retired
    }

    /// Best-effort push of the retired resets on the dying link's packet
    /// port: never block, stop at the first full port. Packets the hub
    /// cannot route are dropped there; respond-on-arrival covers the rest.
    pub fn emit_retired_resets(&mut self) {
        let retired = self.retire_flows_of();
        let PacketIo::Link(io) = &self.io else {
            return;
        };
        for (id, bytes) in retired {
            if io
                .events
                .try_send((
                    io.epoch,
                    link_io::Event::Packet(link_io::Packet {
                        id,
                        bytes: bytes.to_vec(),
                    }),
                ))
                .is_err()
            {
                break;
            }
        }
    }

    pub async fn close_flow(&mut self, flow_id: u64, notify: bool) -> Result<()> {
        if flow_id == PREFLIGHT_ID && self.readiness.is_some() {
            // N3: a restarting round retires its half-open preflight flow.
            let round_retry = self
                .round
                .as_ref()
                .is_some_and(|round| round.pending.is_empty() && round.retry_at.is_some());
            // Stale echo after round_won dropped the loser channels: their
            // relay EOF on the server closes the flow we already retired.
            let stale_cleanup = self.round.is_none() && !self.has_flow(flow_id);
            ensure!(
                round_retry
                    || stale_cleanup
                    || (matches!(self.readiness, Some(Readiness::Verified(_)))
                        && self.has_flow(flow_id)),
                "preflight closed before verification or after cleanup"
            );
        }
        let mut actions = Vec::new();
        let mut closed_key = None;
        let mut closed_channel = None;
        match &mut self.plane {
            Plane::Channels(plane) => {
                if let Some(flow_state) = plane.flows.remove(&flow_id) {
                    closed_key = Some(flow_state.key);
                    closed_channel = flow_state.channel;
                    if plane.by_key.get(&flow_state.key) == Some(&flow_id) {
                        plane.by_key.remove(&flow_state.key);
                    }
                    if let Some(tcp) = flow_state.tcp.as_ref()
                        && let Some(token) = tcp.token
                    {
                        plane.token_index.remove(&token);
                    }
                    if !is_probe_flow(flow_id) {
                        self.stats.open_failed_flows += u64::from(!flow_state.active);
                        self.stats.closed_flows += 1;
                        crate::debug!("flow_close id={flow_id}");
                    }
                }
                if let Some(selector) = plane.selector.as_mut() {
                    actions = selector.closed(flow_id, Reason::ChannelFailed, StdInstant::now());
                }
                if let Some(key) = closed_key {
                    self.notify_closed(flow_id, key).await?;
                }
                if notify {
                    self.control.send(Message::FlowClose { flow_id }).await?;
                }
            }
            Plane::Tcp(..) => {
                self.tcp_close(flow_id).await?;
                if notify {
                    self.control.send(Message::Close { id: flow_id }).await?;
                }
            }
        }
        // A draining channel retires once its last flow closes (S3).
        if let Some(channel) = closed_channel {
            self.maybe_drain(channel).await?;
        }
        // execute_actions may return CloseFlow — break the recursion with a
        // box (only for close with binding failure; empty actions are not boxed).
        if !actions.is_empty() {
            Box::pin(self.execute_actions(actions)).await?;
        }
        Ok(())
    }

    /// Draining channel: the replaced incumbent serves its
    /// remaining flows; once the last one closes, retire the channel.
    pub(crate) async fn maybe_drain(&mut self, channel: u64) -> Result<()> {
        {
            let Plane::Channels(plane) = &self.plane else {
                return Ok(());
            };
            if !plane.draining.contains(&channel)
                || plane
                    .flows
                    .values()
                    .any(|flow| flow.channel == Some(channel))
            {
                return Ok(());
            }
        }
        crate::debug!("drain: channel {channel} retired (last flow closed)");
        self.stop_channel(channel).await;
        if let Plane::Channels(plane) = &mut self.plane {
            plane.draining.remove(&channel);
            plane.retire(channel);
        }
        self.control
            .send(Message::ChannelFailed {
                attempt: None,
                channel: Some(channel),
                reason: Reason::ChannelFailed,
            })
            .await
    }

    // ────────────────────────── Accessors ──────────────────────────

    pub fn has_flow(&self, id: u64) -> bool {
        match &self.plane {
            Plane::Channels(plane) => plane.flows.contains_key(&id),
            Plane::Tcp(plane) => plane.flows.contains_key(&id),
        }
    }
}
