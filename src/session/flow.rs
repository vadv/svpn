//! Flow lifecycle: admission and binding, the commit barrier, teardown, and
//! link-loss retirement.

use std::time::Instant as StdInstant;

use anyhow::{Context, Result, bail, ensure};

use crate::channel;
use crate::control::Message;
use crate::link_io::{self, PREFLIGHT_ID, is_probe_flow};
use crate::packet::{self, FlowKey};
use crate::selector::{Candidate, Reason};

use super::burst::Burst;
use super::round::{ROUND_RESEND, unanswered};
use super::state::idle_timeout;
use super::{FLOW_CAP, Flow, PROBE_FLOW_RESERVE, PacketIo, Plane, Readiness, Session, TaskCommand};

impl Session {
    // ────────────────────────── TCP transport events ──────────────────────────

    pub async fn tcp_connected(&mut self, id: u64, generation: u64) -> Result<()> {
        if !self.binding_current(id, generation) {
            return Ok(());
        }
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
        if !self.client() {
            let pending = match &mut self.plane {
                Plane::Channels(plane) => {
                    let flow = plane.flows.get_mut(&id).context("flow missing")?;
                    if !flow.tcp.as_ref().is_some_and(|tcp| {
                        tcp.receiver.is_none()
                            && tcp.out.as_ref().is_some_and(|out| !out.is_closed())
                    }) {
                        return Ok(());
                    }
                    flow.tcp_connected = true;
                    flow.commit_pending
                }
                Plane::Tcp(plane) => {
                    let flow = plane.flows.get_mut(&id).context("flow missing")?;
                    if flow.tcp_receiver.is_some()
                        || !flow.outgoing.as_ref().is_some_and(|out| !out.is_closed())
                    {
                        return Ok(());
                    }
                    flow.tcp_connected = true;
                    flow.commit_pending
                }
            };
            if pending {
                self.commit(id, generation).await?;
            }
            return Ok(());
        }
        if let Plane::Channels(plane) = &mut self.plane
            && let Some(selector) = plane.selector.as_mut()
        {
            let actions = selector.bind_succeeded(id, generation, StdInstant::now());
            self.execute_actions(actions).await?;
        } else if let Plane::Tcp(plane) = &mut self.plane
            && let Some(flow) = plane.flows.get_mut(&id)
        {
            let _ = flow;
            self.control
                .send(Message::Commit {
                    flow_id: id,
                    generation,
                })
                .await?;
        }
        Ok(())
    }

    pub async fn tcp_closed(&mut self, id: u64, generation: u64) -> Result<()> {
        if !self.binding_current(id, generation) {
            return Ok(());
        }
        if is_probe_flow(id) {
            return self.tcp_failed(id, generation).await;
        }
        let now = tokio::time::Instant::now();
        let expected = match &self.plane {
            Plane::Channels(plane) => plane.flows.get(&id).is_none_or(|flow| {
                flow.tcp_close.finished()
                    || now.duration_since(flow.last_seen) >= idle_timeout(flow.key.protocol)
            }),
            Plane::Tcp(plane) => plane.flows.get(&id).is_none_or(|flow| {
                flow.tcp_close.finished()
                    || now.duration_since(flow.last_seen) >= idle_timeout(flow.key.protocol)
            }),
        };
        if !expected {
            return self.tcp_failed(id, generation).await;
        }
        if self.has_flow(id) {
            self.close_flow(id, true).await?;
        }
        Ok(())
    }

    pub async fn tcp_failed(&mut self, id: u64, generation: u64) -> Result<()> {
        if !self.binding_current(id, generation) {
            return Ok(());
        }
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
        if self
            .retry_flow(id, generation, Reason::ChannelFailed)
            .await?
        {
            return Ok(());
        }
        let recheck = self.readiness == Some(Readiness::Ready) && self.has_flow(id);
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

    pub(crate) fn flow_limit_reached(&self, id: u64) -> bool {
        let count = match &self.plane {
            Plane::Channels(plane) => plane.flows.len(),
            Plane::Tcp(plane) => plane.flows.len(),
        };
        let ordinary = self.flow_count();
        if is_probe_flow(id) {
            count - ordinary >= PROBE_FLOW_RESERVE
        } else {
            ordinary >= FLOW_CAP
        }
    }

    // ────────────────────────── Open, bind, commit ──────────────────────────

    pub async fn flow_open(
        &mut self,
        flow_id: u64,
        generation: u64,
        flow: FlowKey,
        channel: Option<u64>,
        resume: bool,
    ) -> Result<()> {
        ensure!(generation != 0, "zero binding generation");
        let at_capacity = self.flow_limit_reached(flow_id);
        if channel.is_none() {
            let Plane::Channels(plane) = &mut self.plane else {
                bail!("flow_open outside channels mode")
            };
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
            if at_capacity {
                return self
                    .control
                    .send(Message::FlowReject {
                        flow_id,
                        generation,
                        reason: Reason::ResourceExhausted,
                    })
                    .await;
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
        }

        if !self
            .register_binding(flow_id, generation, flow, channel, resume)
            .await?
        {
            return Ok(());
        }
        let channel_id = channel.context("flow channel missing")?;
        let Plane::Channels(plane) = &mut self.plane else {
            unreachable!()
        };
        let registered = plane
            .flows
            .get_mut(&flow_id)
            .context("registered flow missing")?;
        if !is_probe_flow(flow_id) {
            let transport = plane
                .channels
                .get(&channel_id)
                .map(|h| h.candidate.to_string())
                .unwrap_or_default();
            crate::debug!(
                "flow_open role=server id={flow_id} generation={generation} channel={channel_id} transport={transport}"
            );
            self.control
                .send(Message::FlowOpened {
                    flow_id,
                    generation,
                    flow,
                    channel: channel_id,
                })
                .await?;
            if registered.active {
                self.control
                    .send(Message::Committed {
                        flow_id,
                        generation,
                    })
                    .await?;
            }
            return Ok(());
        }
        let challenge = match registered.echo_pending {
            Some(challenge) => challenge,
            None if registered.active => {
                self.control
                    .send(Message::FlowOpened {
                        flow_id,
                        generation,
                        flow,
                        channel: channel_id,
                    })
                    .await?;
                return self
                    .control
                    .send(Message::Committed {
                        flow_id,
                        generation,
                    })
                    .await;
            }
            None => channel::challenge().context("challenge generation failed")?,
        };
        registered.echo_pending = Some(challenge);
        let queued = plane.channels.get(&channel_id).is_some_and(|h| {
            h.command
                .try_send(TaskCommand::Record(channel::Record::FlowProbe {
                    flow_id,
                    generation,
                    challenge,
                }))
                .is_ok()
        });
        if !queued {
            self.close_flow(flow_id, true).await?;
        }
        Ok(())
    }

    /// Server: the client picked a channel for a server-originated flow.
    pub async fn flow_channel(
        &mut self,
        flow_id: u64,
        generation: u64,
        channel: u64,
    ) -> Result<()> {
        if !self.binding_current(flow_id, generation) {
            return Ok(());
        }
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("flow_channel outside channels mode")
        };
        let flow = plane.flows.get_mut(&flow_id).context("flow missing")?;
        flow.channel = Some(channel);
        self.control
            .send(Message::FlowOpened {
                flow_id,
                generation,
                flow: flow.key,
                channel,
            })
            .await
    }

    /// Client: the server registered the binding — move to commit.
    pub(crate) async fn flow_opened(
        &mut self,
        flow_id: u64,
        generation: u64,
        channel: u64,
    ) -> Result<()> {
        if !self.binding_current(flow_id, generation) {
            return Ok(());
        }
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
                        generation,
                    })
                    .await;
            }
        } else if flow_state.channel != Some(channel) {
            return Ok(());
        }
        let Some(selector) = plane.selector.as_mut() else {
            bail!("flow_opened on server");
        };
        let actions = selector.bind_succeeded(flow_id, generation, StdInstant::now());
        ensure!(
            flow_id != PREFLIGHT_ID || !actions.is_empty(),
            "stale preflight binding"
        );
        self.execute_actions(actions).await
    }

    pub(crate) async fn flow_rejected(
        &mut self,
        flow_id: u64,
        generation: u64,
        reason: Reason,
    ) -> Result<()> {
        if !self.binding_current(flow_id, generation) {
            return Ok(());
        }
        if self
            .round
            .as_ref()
            .is_some_and(|r| r.tcp_id == Some(flow_id))
        {
            return self.tcp_failed(flow_id, generation).await;
        }
        if !self.retry_flow(flow_id, generation, reason).await? {
            self.close_flow(flow_id, false).await?;
        }
        Ok(())
    }

    /// Server: commit barrier passed — DATA allowed, the queue drains to the channel.
    pub async fn commit(&mut self, flow_id: u64, generation: u64) -> Result<()> {
        if !self.binding_current(flow_id, generation) {
            return Ok(());
        }
        match &mut self.plane {
            Plane::Channels(plane) => {
                let flow = plane.flows.get_mut(&flow_id).context("flow missing")?;
                ensure!(
                    !is_probe_flow(flow_id) || flow.echo_pending.is_none(),
                    "preflight commit before flow echo"
                );
                flow.commit_pending = true;
                let ready = match &flow.tcp {
                    Some(tcp) => {
                        flow.tcp_connected && tcp.out.as_ref().is_some_and(|out| !out.is_closed())
                    }
                    None => flow
                        .channel
                        .and_then(|id| plane.channels.get(&id))
                        .is_some_and(|h| h.established && !h.command.is_closed()),
                };
                if !ready {
                    return Ok(());
                }
                flow.commit_pending = false;
                flow.active = true;
            }
            Plane::Tcp(plane) => {
                let flow = plane.flows.get_mut(&flow_id).context("flow missing")?;
                flow.commit_pending = true;
                if !flow.tcp_connected
                    || !flow.outgoing.as_ref().is_some_and(|out| !out.is_closed())
                {
                    return Ok(());
                }
                flow.commit_pending = false;
                flow.active = true;
                flow.binding_deadline = None;
            }
        }
        if !is_probe_flow(flow_id) {
            crate::debug!("flow_active role=server id={flow_id}");
        }
        self.control
            .send(Message::Committed {
                flow_id,
                generation,
            })
            .await?;
        if !is_probe_flow(flow_id) {
            self.flush_flow(flow_id).await?;
        }
        Ok(())
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
                .try_send(TaskCommand::Data {
                    flow_id: burst.attempt,
                    generation: flow.generation,
                    packet: request,
                })
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

    pub async fn committed(&mut self, flow_id: u64, generation: u64) -> Result<()> {
        if !self.binding_current(flow_id, generation) {
            return Ok(());
        }
        if let Plane::Tcp(plane) = &mut self.plane {
            let flow = plane.flows.get_mut(&flow_id).context("flow missing")?;
            flow.active = true;
            flow.binding_deadline = None;
            return self.flush_flow(flow_id).await;
        }
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
                    .try_send(TaskCommand::Data {
                        flow_id,
                        generation,
                        packet: rc.request.clone(),
                    })
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
        let actions = selector.committed(flow_id, generation);
        if !selector.binding_active(flow_id, generation) {
            return Ok(());
        }
        if let Some(flow) = plane.flows.get_mut(&flow_id) {
            flow.active = true;
        }
        crate::debug!("flow_active role=client id={flow_id}");
        // A quiet rebound flow has no data to prove the new binding with:
        // a challenge probe round-trip stands in until real traffic lands.
        if let Some(flow) = plane.flows.get_mut(&flow_id)
            && flow.recovery.is_some()
            && flow.echo_pending.is_none()
            && let Ok(challenge) = channel::challenge()
        {
            flow.echo_pending = Some(challenge);
            let channel_id = flow.channel;
            if let Some(handle) = channel_id.and_then(|id| plane.channels.get(&id)) {
                handle
                    .command
                    .try_send(TaskCommand::Record(channel::Record::FlowProbe {
                        flow_id,
                        generation,
                        challenge,
                    }))
                    .ok();
            }
        }
        self.flush_flow(flow_id).await?;
        self.execute_actions(actions).await
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
        let generation = self.flow_generation(flow_id).unwrap_or(1);
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
                        self.stats.open_failed_flows +=
                            u64::from(!flow_state.active && !flow_state.data_started);
                        if flow_state.recovery.is_some() {
                            crate::info!(
                                "flow_recovery_abandoned id={flow_id} generation={generation} reason=closed"
                            );
                        }
                        self.stats.closed_flows += 1;
                        crate::debug!("flow_close id={flow_id}");
                    }
                }
                if let Some(selector) = plane.selector.as_mut() {
                    selector.finished(flow_id);
                }
                if let Some(key) = closed_key {
                    self.notify_closed(flow_id, key).await?;
                }
                if notify {
                    self.control
                        .send(Message::FlowClose {
                            flow_id,
                            generation,
                        })
                        .await?;
                }
            }
            Plane::Tcp(..) => {
                self.tcp_close(flow_id).await?;
                if notify {
                    self.control
                        .send(Message::Close {
                            id: flow_id,
                            generation,
                        })
                        .await?;
                }
            }
        }
        // A draining channel retires once its last flow closes (S3).
        if let Some(channel) = closed_channel {
            self.maybe_drain(channel).await?;
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
