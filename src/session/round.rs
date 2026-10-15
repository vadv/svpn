//! N3 liveness rounds: every allowed candidate probes independently; only a
//! complete ICMP round-trip through the server TUN wins the round.

use std::{
    collections::{HashMap, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};

use crate::control::Message;
use crate::link_io::{self, PREFLIGHT_ID};
use crate::packet::{self, FlowKey};
use crate::selector::{Candidate, Reason, Selector};
use crate::{crypto, webrtc};

use super::{
    Flow, HEARTBEAT_TIMEOUT, PacketIo, Plane, Readiness, Session, TaskCommand, TcpFlow,
    candidate_strategy, prefixed, probe_payload_len, reason_en,
};

/// N3: a liveness round caps all in-flight attempts (UDP) after this.
const ROUND_CAP: Duration = Duration::from_secs(10);
/// A datagram request can vanish anywhere (driver burst drops, UDP loss):
/// re-send until the verdict or the round deadline; replies are idempotent.
pub(crate) const ROUND_RESEND: Duration = Duration::from_secs(2);
/// N3: failed rounds retry after 1s, 2s, 4s, 8s, 16s, then every 30s.
const ROUND_BACKOFF: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
];
const ROUND_BACKOFF_CAP: Duration = Duration::from_secs(30);

/// One candidate of a liveness round: the channel id once `channel_ready`
/// binds it, plus the client-side WebRTC transport.
pub struct RoundCandidate {
    pub candidate: Candidate,
    pub channel: Option<u64>,
    pub owned: bool,
    pub peer: Option<webrtc::Peer>,
    pub icmp_id: u16,
    pub request: Vec<u8>,
    pub deadline: tokio::time::Instant,
    pub resend_at: Option<tokio::time::Instant>,
}

/// Every configured candidate probes independently; only a complete
/// ICMP round-trip through the server TUN wins.
pub struct Round {
    pub id: u16,
    pub seq: u16,
    pub payload: Vec<u8>,
    pub request: Vec<u8>,
    pub pending: HashMap<u64, RoundCandidate>,
    pub failures: Vec<(Candidate, Reason)>,
    pub tcp_id: Option<u64>,
    pub backoff_step: u32,
    pub deadline: tokio::time::Instant,
    /// Failed round's retry time; None while attempts are in flight.
    pub retry_at: Option<tokio::time::Instant>,
}

impl Session {
    pub async fn begin_preflight(&mut self) -> Result<()> {
        if !matches!(self.io, PacketIo::Link(_)) {
            return Ok(());
        }
        ensure!(self.client(), "link preflight requires a client");
        ensure!(self.readiness.is_none(), "link preflight already started");
        self.arm_round().await
    }

    /// Arm a fresh TUN round for every allowed candidate, including fixed TCP.
    pub async fn arm_round(&mut self) -> Result<()> {
        let actions = match &mut self.plane {
            Plane::Channels(plane) => plane
                .selector
                .as_mut()
                .map(Selector::enter_checking)
                .unwrap_or_default(),
            Plane::Tcp(_) => Vec::new(),
        };
        self.execute_actions(actions).await?;
        ensure!(self.client(), "liveness round requires a client");
        let PacketIo::Link(io) = &self.io else {
            bail!("liveness round requires a packet port");
        };
        let peer_ip = io.peer_ip;
        if self
            .round
            .as_ref()
            .is_some_and(|round| round.retry_at.is_some())
        {
            io.events
                .send((io.epoch, link_io::Event::Checking))
                .await
                .context("packet event port closed")?;
        }
        let id = u16::from_ne_bytes(crypto::random()?);
        let seq = u16::from_ne_bytes(crypto::random()?);
        let mut payload = vec![0; probe_payload_len(self.mtu, id)?];
        getrandom::fill(&mut payload).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
        let request = packet::icmp_echo_request(self.client_ip, peer_ip, id, seq, &payload);
        let key = FlowKey {
            protocol: 1,
            source: self.client_ip,
            destination: peer_ip,
            source_port: id,
            destination_port: 0,
        };
        let now = tokio::time::Instant::now();
        let backoff_step = self.round.as_ref().map_or(0, |round| round.backoff_step);
        match &mut self.plane {
            Plane::Channels(plane) => {
                plane.flows.insert(PREFLIGHT_ID, Flow::new(key, now));
            }
            Plane::Tcp(plane) => {
                plane.flows.insert(
                    PREFLIGHT_ID,
                    TcpFlow {
                        key,
                        active: false,
                        reset_requested: false,
                        outgoing: None,
                        pending: VecDeque::new(),
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
            }
        }
        self.readiness = Some(Readiness::Probing);
        self.round = Some(Round {
            id,
            seq,
            payload,
            request,
            pending: HashMap::new(),
            failures: Vec::new(),
            tcp_id: None,
            backoff_step,
            deadline: now + ROUND_CAP,
            retry_at: None,
        });
        if matches!(self.plane, Plane::Tcp(_)) {
            return self.start_round_tcp().await;
        }
        self.start_round().await
    }

    /// Send `ChannelPrepare` for every allowed UDP candidate; a fresh
    /// attempt id each — the round owns them, not `plane.attempt`.
    async fn start_round(&mut self) -> Result<()> {
        let candidates: Vec<Candidate> = {
            let Plane::Channels(plane) = &self.plane else {
                bail!("liveness round requires the channels plane");
            };
            let Some(selector) = plane.selector.as_ref() else {
                bail!("liveness round requires a selector");
            };
            selector
                .allowed()
                .into_iter()
                .filter(|candidate| candidate != &Candidate::Tcp)
                .collect()
        };
        // TCP participates immediately; transport establishment is not a verdict.
        self.start_round_tcp().await?;
        for candidate in candidates {
            let attempt = self.next_round_attempt;
            self.next_round_attempt = attempt.checked_add(1).context("probe ID space exhausted")?;
            ensure!(attempt < PREFLIGHT_ID, "probe ID space exhausted");
            let Plane::Channels(plane) = &mut self.plane else {
                unreachable!()
            };
            let round = self.round.as_ref().context("round disappeared")?;
            let mut key = plane.flows[&PREFLIGHT_ID].key;
            let icmp_id = (0..=u16::MAX)
                .map(|offset| round.id.wrapping_add(offset))
                .find(|&id| {
                    !plane.flows.values().any(|flow| {
                        flow.key.protocol == 1
                            && flow.key.source == key.source
                            && flow.key.destination == key.destination
                            && flow.key.source_port == id
                    })
                })
                .context("ICMP probe identifiers exhausted")?;
            key.source_port = icmp_id;
            let request = packet::icmp_echo_request(
                key.source,
                key.destination,
                icmp_id,
                round.seq,
                &round.payload,
            );
            let channel = plane
                .selector
                .as_ref()
                .and_then(|selector| selector.ready_channel(candidate))
                .filter(|id| {
                    plane
                        .channels
                        .get(id)
                        .is_some_and(|handle| !handle.task.is_finished())
                });
            plane
                .flows
                .insert(attempt, Flow::new(key, tokio::time::Instant::now()));
            let mut hello = None;
            let mut peer = None;
            if candidate == Candidate::WebRtc && channel.is_none() {
                let (p, h) = webrtc::Peer::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
                    .context("WebRTC client peer")?;
                hello = Some(serde_json::to_string(&h).context("serialize WebRTC hello")?);
                peer = Some(p);
            }
            if let Some(round) = self.round.as_mut() {
                round.pending.insert(
                    attempt,
                    RoundCandidate {
                        candidate,
                        channel,
                        owned: channel.is_none(),
                        peer,
                        icmp_id,
                        request,
                        deadline: tokio::time::Instant::now() + crate::selector::ATTEMPT_BUDGET,
                        resend_at: None,
                    },
                );
            }
            if let Some(channel) = channel {
                self.control
                    .send(Message::FlowOpen {
                        flow_id: attempt,
                        flow: key,
                        channel: Some(channel),
                    })
                    .await?;
            } else {
                self.control
                    .send(Message::ChannelPrepare {
                        attempt,
                        strategy: candidate_strategy(candidate),
                        hello,
                    })
                    .await?;
            }
            crate::info!(
                "{} round: probing {} (attempt {attempt})",
                prefixed(self.tag(), "channel"),
                candidate.as_str()
            );
        }
        if self
            .round
            .as_ref()
            .is_some_and(|round| round.pending.is_empty() && round.tcp_id.is_none())
        {
            self.round_failed().await?;
        }
        Ok(())
    }

    /// Start the TCP candidate in the same round as UDP.
    async fn start_round_tcp(&mut self) -> Result<()> {
        let tcp_allowed = match &self.plane {
            Plane::Channels(plane) => plane
                .selector
                .as_ref()
                .is_some_and(|selector| selector.allowed().contains(&Candidate::Tcp)),
            Plane::Tcp(_) => true,
        };
        let round = self.round.as_ref().context("round disappeared")?;
        if round.tcp_id.is_some() || !tcp_allowed {
            return Ok(());
        }
        let id = self.next_round_attempt;
        self.next_round_attempt = id.checked_add(1).context("probe ID space exhausted")?;
        ensure!(id < PREFLIGHT_ID, "probe ID space exhausted");
        let now = tokio::time::Instant::now();
        let key = match &mut self.plane {
            Plane::Channels(plane) => {
                let key = plane
                    .flows
                    .get(&PREFLIGHT_ID)
                    .context("preflight flow disappeared")?
                    .key;
                plane.flows.insert(id, Flow::new(key, now));
                key
            }
            Plane::Tcp(plane) => {
                let key = plane
                    .flows
                    .get(&PREFLIGHT_ID)
                    .context("preflight flow disappeared")?
                    .key;
                plane.flows.insert(
                    id,
                    TcpFlow {
                        key,
                        active: false,
                        reset_requested: false,
                        outgoing: None,
                        pending: VecDeque::from([round.request.clone()]),
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
                key
            }
        };
        self.round.as_mut().context("round disappeared")?.tcp_id = Some(id);
        crate::info!(
            "{} round: probing tcp (attempt {id})",
            prefixed(self.tag(), "channel")
        );
        self.control.send(Message::Open { id, flow: key }).await
    }

    /// N3: one round candidate died — free both halves, maybe tail to TCP.
    pub async fn round_attempt_failed(&mut self, attempt: u64, reason: Reason) -> Result<()> {
        let removed = self
            .round
            .as_mut()
            .and_then(|round| round.pending.remove(&attempt));
        let Some(rc) = removed else {
            return Ok(());
        };
        if let Some(round) = self.round.as_mut() {
            round.failures.push((rc.candidate, reason));
        }
        self.close_flow(attempt, true).await?;
        if rc.owned {
            if let Some(channel) = rc.channel {
                self.stop_channel(channel).await;
                if let Plane::Channels(plane) = &mut self.plane {
                    plane.channels.remove(&channel);
                }
            }
            self.control
                .send(Message::ChannelFailed {
                    attempt: Some(attempt),
                    channel: rc.channel,
                    reason,
                })
                .await?;
        }
        if self
            .round
            .as_ref()
            .is_some_and(|round| round.pending.is_empty() && round.tcp_id.is_none())
        {
            self.round_failed().await?;
        }
        Ok(())
    }

    /// N3: the whole round failed — the link stays Checking, retries after
    /// backoff; the pool learns via `RoundFailed` (hub policy is N5).
    pub async fn round_failed(&mut self) -> Result<()> {
        if self
            .round
            .as_ref()
            .is_none_or(|round| round.retry_at.is_some())
        {
            return Ok(());
        }
        let tag = self.tag().to_owned();
        let attempts: Vec<u64> = self
            .round
            .as_ref()
            .map_or_else(Vec::new, |round| round.pending.keys().copied().collect());
        for attempt in attempts {
            let removed = self
                .round
                .as_mut()
                .and_then(|round| round.pending.remove(&attempt));
            if let Some(rc) = removed {
                self.close_flow(attempt, true).await?;
                if rc.owned {
                    if let Some(channel) = rc.channel {
                        self.stop_channel(channel).await;
                        if let Plane::Channels(plane) = &mut self.plane {
                            plane.channels.remove(&channel);
                        }
                    }
                    self.control
                        .send(Message::ChannelFailed {
                            attempt: Some(attempt),
                            channel: rc.channel,
                            reason: Reason::PathTimeout,
                        })
                        .await?;
                }
                if let Some(round) = self.round.as_mut() {
                    round.failures.push((rc.candidate, Reason::PathTimeout));
                }
            }
        }
        if let Some(id) = self.round.as_mut().and_then(|round| round.tcp_id.take()) {
            self.close_flow(id, true).await?;
            if let Some(round) = self.round.as_mut() {
                round.failures.push((Candidate::Tcp, Reason::PathTimeout));
            }
        }
        let Some(round) = self.round.as_mut() else {
            return Ok(());
        };
        round.backoff_step += 1;
        let delay = ROUND_BACKOFF
            .get(round.backoff_step as usize - 1)
            .copied()
            .unwrap_or(ROUND_BACKOFF_CAP);
        round.retry_at = Some(tokio::time::Instant::now() + delay);
        let table = round
            .failures
            .iter()
            .map(|(candidate, reason)| format!("{}: {}", candidate.as_str(), reason_en(*reason)))
            .collect::<Vec<_>>()
            .join(", ");
        crate::info!(
            "{} checking round failed ({table}), retry in {delay:?}",
            prefixed(&tag, "ssh")
        );
        if let PacketIo::Link(io) = &self.io {
            io.events
                .send((io.epoch, link_io::Event::RoundFailed))
                .await
                .context("packet event port closed")?;
        }
        Ok(())
    }

    pub async fn poll_round(&mut self, now: tokio::time::Instant) -> Result<()> {
        let Some(round) = self.round.as_ref() else {
            return Ok(());
        };
        if let Some(at) = round.retry_at {
            if now >= at {
                self.arm_round().await?;
            }
            return Ok(());
        }
        if now >= round.deadline {
            return self.round_failed().await;
        }
        let expired: Vec<_> = round
            .pending
            .iter()
            .filter(|(_, rc)| now >= rc.deadline)
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            self.round_attempt_failed(id, Reason::PathTimeout).await?;
        }
        self.resend_round_request().await
    }

    /// N3: the request datagram can drop anywhere — re-send it on the
    /// committed path until the verdict or the round deadline. Duplicated
    /// echo replies are harmless: the first verdict retires the round.
    async fn resend_round_request(&mut self) -> Result<()> {
        let Some(round) = self.round.as_mut() else {
            return Ok(());
        };
        if round.retry_at.is_some() {
            return Ok(());
        }
        let Plane::Channels(plane) = &self.plane else {
            // A TCP request uses a reliable stream; it needs no datagram resend.
            return Ok(());
        };
        let now = tokio::time::Instant::now();
        for (&id, rc) in &mut round.pending {
            if rc.resend_at.is_none_or(|at| now < at) {
                continue;
            }
            rc.resend_at = Some(now + ROUND_RESEND);
            if let Some(handle) = rc.channel.and_then(|channel| plane.channels.get(&channel)) {
                handle
                    .command
                    .try_send(TaskCommand::Data(id, rc.request.clone()))
                    .ok();
            }
        }
        Ok(())
    }

    /// The first matching echo wins; retire only this round's losers.
    pub async fn round_won(&mut self, channel: Option<u64>) -> Result<()> {
        let Some(round) = self.round.take() else {
            return Ok(());
        };
        let tag = self.tag().to_owned();
        for (attempt, rc) in round.pending {
            self.close_flow(attempt, true).await?;
            if !rc.owned || (rc.channel.is_some() && rc.channel == channel) {
                continue;
            }
            if let Some(id) = rc.channel {
                self.stop_channel(id).await;
                if let Plane::Channels(plane) = &mut self.plane {
                    plane.channels.remove(&id);
                }
            }
            self.control
                .send(Message::ChannelFailed {
                    attempt: Some(attempt),
                    channel: rc.channel,
                    reason: Reason::ChannelFailed,
                })
                .await?;
        }
        if let Some(id) = round.tcp_id {
            self.close_flow(id, true).await?;
        }
        let candidate = if let Plane::Channels(plane) = &mut self.plane {
            let candidate = match channel {
                Some(id) => {
                    plane
                        .channels
                        .get(&id)
                        .context("round winner channel lost")?
                        .candidate
                }
                None => Candidate::Tcp,
            };
            if let Some(selector) = plane.selector.as_mut() {
                selector.adopt(candidate, channel);
            }
            candidate
        } else {
            Candidate::Tcp
        };
        crate::info!(
            "{} {} verified — ICMP echo round-trip",
            prefixed(&tag, "channel"),
            candidate.as_str()
        );
        self.finish_preflight(channel).await
    }

    async fn finish_preflight(&mut self, channel: Option<u64>) -> Result<()> {
        ensure!(
            self.readiness == Some(Readiness::Probing),
            "stale preflight success"
        );
        ensure!(self.has_flow(PREFLIGHT_ID), "preflight flow disappeared");
        self.readiness = Some(Readiness::Verified(channel));
        self.close_flow(PREFLIGHT_ID, false).await
    }

    pub async fn announce_ready(
        &mut self,
        heartbeat: Option<tokio::time::Instant>,
        startup_deadline: Option<tokio::time::Instant>,
    ) -> Result<bool> {
        if self.readiness == Some(Readiness::Probing) {
            ensure!(self.has_flow(PREFLIGHT_ID), "preflight flow disappeared");
        }
        let Some(Readiness::Verified(channel)) = self.readiness else {
            return Ok(false);
        };
        ensure!(!self.has_flow(PREFLIGHT_ID), "preflight cleanup incomplete");
        let Some(heartbeat) = heartbeat
            .filter(|at| tokio::time::Instant::now().duration_since(*at) < HEARTBEAT_TIMEOUT)
        else {
            return Ok(false);
        };
        let PacketIo::Link(io) = &self.io else {
            bail!("link readiness requires packet port");
        };
        let permit = io
            .events
            .reserve()
            .await
            .context("packet event port closed")?;
        // Recheck after backpressure: no await may separate verification from publication.
        let now = tokio::time::Instant::now();
        if let Some(deadline) = startup_deadline {
            ensure!(now < deadline, "link readiness timed out");
        }
        ensure!(
            now.duration_since(heartbeat) < HEARTBEAT_TIMEOUT,
            "control heartbeat timeout"
        );
        if let Some(channel) = channel {
            let Plane::Channels(plane) = &self.plane else {
                bail!("verified UDP channel outside channels mode");
            };
            ensure!(
                plane
                    .channels
                    .get(&channel)
                    .is_some_and(|handle| !handle.task.is_finished()),
                "verified preflight channel lost before readiness"
            );
        }
        permit.send((io.epoch, link_io::Event::Ready));
        self.readiness = Some(Readiness::Ready);
        if let Plane::Channels(plane) = &mut self.plane
            && let Some(selector) = plane.selector.as_mut()
        {
            selector.resume();
        }
        Ok(true)
    }
}
