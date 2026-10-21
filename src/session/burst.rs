//! Probe bursts (EPIC-016): ten ICMP echoes over one live channel, spaced
//! 100 ms apart, measuring p90 RTT and loss while traffic keeps flowing.
//! The session owns the plumbing; the burst only accounts.

use anyhow::{Context, Result, ensure};
use tokio::time::{Duration, Instant};

use crate::control::Message;
use crate::crypto;
use crate::link_io::PREFLIGHT_ID;
use crate::packet::{self, FlowKey};

use super::{Flow, PacketIo, Plane, Session, TaskCommand, prefixed};

/// Health bursts run at most this often; each measures one channel.
pub const HEALTH_INTERVAL: Duration = Duration::from_secs(30);

pub const BURST_LEN: usize = 10;
pub const BURST_SPACING: Duration = Duration::from_millis(100);
/// After the last echo leaves, replies get one more second before they
/// count as loss.
pub const BURST_TAIL: Duration = Duration::from_secs(1);

/// One burst of echo probes over an existing channel.
pub struct Burst {
    /// Channel under test; replies on any other channel are not ours.
    pub channel: u64,
    /// Probe flow id, allocated from the round attempt space.
    pub attempt: u64,
    pub icmp_id: u16,
    base_seq: u16,
    pub payload: Vec<u8>,
    /// None until the probe flow commits: sends and the deadline start then.
    armed: Option<Instant>,
    sent: [Option<Instant>; BURST_LEN],
    rtts: [Option<Duration>; BURST_LEN],
    next: usize,
}

pub struct Outcome {
    pub p90: Option<Duration>,
    pub received: usize,
    pub lost: usize,
}

impl Burst {
    pub fn new(channel: u64, attempt: u64, icmp_id: u16, base_seq: u16, payload: Vec<u8>) -> Self {
        Self {
            channel,
            attempt,
            icmp_id,
            base_seq,
            payload,
            armed: None,
            sent: [None; BURST_LEN],
            rtts: [None; BURST_LEN],
            next: 0,
        }
    }

    /// The probe flow committed: the channel carries our packets now.
    pub fn arm(&mut self, now: Instant) {
        self.armed = Some(now);
    }

    pub fn seq(&self, index: usize) -> u16 {
        self.base_seq.wrapping_add(index as u16)
    }

    /// The echo index due at `now`, if any.
    pub fn due(&self, now: Instant) -> Option<usize> {
        let armed = self.armed?;
        if self.next < BURST_LEN && now >= armed + BURST_SPACING * self.next as u32 {
            Some(self.next)
        } else {
            None
        }
    }

    /// Echo `due()` left the session (a full channel queue still counts as
    /// sent here: without an echo it ends as loss anyway).
    pub fn mark_sent(&mut self, now: Instant) {
        self.sent[self.next] = Some(now);
        self.next += 1;
    }

    /// Whether `seq` is ours, recording its RTT at most once. Echoes for
    /// probes that never left cannot exist; a stray match is rejected.
    pub fn record_echo(&mut self, seq: u16, now: Instant) -> bool {
        let index = usize::from(seq.wrapping_sub(self.base_seq));
        if index >= BURST_LEN || self.rtts[index].is_some() {
            return false;
        }
        let Some(sent) = self.sent[index] else {
            return false;
        };
        self.rtts[index] = Some(now.saturating_duration_since(sent));
        true
    }

    fn complete(&self) -> bool {
        self.rtts.iter().all(Option::is_some)
    }

    fn deadline(&self) -> Option<Instant> {
        self.armed
            .map(|armed| armed + BURST_SPACING * (BURST_LEN as u32 - 1) + BURST_TAIL)
    }

    pub fn finished(&self, now: Instant) -> bool {
        self.armed.is_some()
            && (self.complete() || self.deadline().is_some_and(|deadline| now >= deadline))
    }

    /// When the session should wake next: the next send, or the loss
    /// deadline. None until armed or once finished.
    pub fn wake_at(&self) -> Option<Instant> {
        let armed = self.armed?;
        if self.next < BURST_LEN {
            return Some(armed + BURST_SPACING * self.next as u32);
        }
        if self.complete() {
            return None;
        }
        self.deadline()
    }

    pub fn outcome(&self) -> Outcome {
        let mut rtts: Vec<Duration> = self.rtts.iter().flatten().copied().collect();
        rtts.sort();
        // Nearest-rank p90: 9 of 10 echoes must be at or under it.
        let p90 = (!rtts.is_empty()).then(|| rtts[(9 * rtts.len()).div_ceil(10) - 1]);
        Outcome {
            p90,
            received: rtts.len(),
            lost: BURST_LEN - rtts.len(),
        }
    }
}

impl Session {
    /// Next health-burst wake for the select loop; None on servers, on the
    /// fixed-TCP plane, and before the first Ready arms the timer.
    pub fn health_wake(&self) -> Option<Instant> {
        if !self.client() || !self.accepts_packets() || !matches!(self.plane, Plane::Channels(_)) {
            return None;
        }
        if let Some(burst) = &self.burst {
            return burst.wake_at();
        }
        self.health_at
    }

    /// Whether a new burst may start now. `health_at` is armed by
    /// `announce_ready` and re-armed by `finish_burst`; a dead channel
    /// clears both the burst and the timer.
    fn health_due(&self, now: Instant) -> bool {
        self.client()
            && self.accepts_packets()
            && matches!(self.plane, Plane::Channels(_))
            && self.burst.is_none()
            && self.health_at.is_some_and(|at| now >= at)
    }

    /// Drive the burst: start when due, send the echoes that are due, close
    /// out at the deadline. Runs from the health timer arm and the tick.
    pub(crate) async fn poll_burst(&mut self, now: Instant) -> Result<()> {
        if self.health_due(now) {
            self.start_burst(now).await?;
        }
        let peer_ip = match &self.io {
            PacketIo::Link(io) => io.peer_ip,
            PacketIo::Device(_) => return Ok(()),
        };
        let tag = self.tag().to_owned();
        let mut finished = false;
        if let Some(burst) = self.burst.as_mut() {
            while let Some(index) = burst.due(now) {
                let seq = burst.seq(index);
                let request = packet::icmp_echo_request(
                    self.client_ip,
                    peer_ip,
                    burst.icmp_id,
                    seq,
                    &burst.payload,
                );
                let Plane::Channels(plane) = &mut self.plane else {
                    return Ok(());
                };
                let sent = plane.channels.get(&burst.channel).is_some_and(|handle| {
                    handle
                        .command
                        .try_send(TaskCommand::Data(burst.attempt, request))
                        .is_ok()
                });
                if !sent {
                    crate::debug!(
                        "{} health: echo {seq} not sent (queue full or channel gone)",
                        prefixed(&tag, "channel")
                    );
                }
                burst.mark_sent(now);
            }
            finished = burst.finished(now);
        }
        if finished {
            self.finish_burst(now).await?;
        }
        Ok(())
    }

    /// Open one probe flow over the live channel: the adopted one, or any
    /// live channel before adoption (like a round probe over a ready
    /// channel). The first echo leaves when the flow commits.
    async fn start_burst(&mut self, now: Instant) -> Result<()> {
        let PacketIo::Link(io) = &self.io else {
            return Ok(());
        };
        let peer_ip = io.peer_ip;
        let (channel, borrowed) = {
            let Plane::Channels(plane) = &self.plane else {
                return Ok(());
            };
            let Some(selector) = plane.selector.as_ref() else {
                return Ok(());
            };
            let adopted = selector
                .last_good
                .and_then(|candidate| selector.ready_channel(candidate));
            match adopted.filter(|id| plane.channels.contains_key(id)) {
                Some(id) => (id, false),
                None => match plane
                    .channels
                    .iter()
                    .find(|(_, handle)| !handle.task.is_finished())
                {
                    Some((id, _)) => (*id, true),
                    None => return Ok(()),
                },
            }
        };
        let attempt = self.next_round_attempt;
        self.next_round_attempt = attempt.checked_add(1).context("probe ID space exhausted")?;
        ensure!(attempt < PREFLIGHT_ID, "probe ID space exhausted");
        // Same rule as rounds: no live flow may share the ICMP 5-tuple.
        let base = u16::from_ne_bytes(crypto::random()?);
        let Plane::Channels(plane) = &self.plane else {
            unreachable!()
        };
        let icmp_id = (0..=u16::MAX)
            .map(|offset| base.wrapping_add(offset))
            .find(|&id| {
                !plane.flows.values().any(|flow| {
                    flow.key.protocol == 1
                        && flow.key.source == self.client_ip
                        && flow.key.destination == peer_ip
                        && flow.key.source_port == id
                })
            })
            .context("ICMP probe identifiers exhausted")?;
        let key = FlowKey {
            protocol: 1,
            source: self.client_ip,
            destination: peer_ip,
            source_port: icmp_id,
            destination_port: 0,
        };
        let mut payload = vec![0u8; 32];
        getrandom::fill(&mut payload).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
        let base_seq = u16::from_ne_bytes(crypto::random()?);
        let burst = Burst::new(channel, attempt, icmp_id, base_seq, payload);
        let Plane::Channels(plane) = &mut self.plane else {
            unreachable!()
        };
        plane.flows.insert(attempt, Flow::new(key, now));
        crate::debug!(
            "{} health: burst attempt={attempt} channel={channel} icmp_id={icmp_id} borrowed={borrowed}",
            prefixed(self.tag(), "channel")
        );
        self.burst = Some(burst);
        self.control
            .send(Message::FlowOpen {
                flow_id: attempt,
                flow: key,
                channel: Some(channel),
            })
            .await
    }

    /// Burst done: log the outcome, count loss as a transport failure,
    /// re-arm the health timer, close the probe flow.
    pub(crate) async fn finish_burst(&mut self, now: Instant) -> Result<()> {
        let Some(burst) = self.burst.take() else {
            return Ok(());
        };
        self.health_at = Some(now + HEALTH_INTERVAL);
        let outcome = burst.outcome();
        let name = match &self.plane {
            Plane::Channels(plane) => plane
                .channels
                .get(&burst.channel)
                .map(|handle| handle.candidate.as_str().to_owned())
                .unwrap_or_else(|| format!("channel-{}", burst.channel)),
            Plane::Tcp(_) => format!("channel-{}", burst.channel),
        };
        let p90 = outcome
            .p90
            .map(|rtt| format!("{}ms", rtt.as_millis()))
            .unwrap_or_else(|| "-".to_owned());
        if outcome.lost == 0 {
            crate::debug!(
                "{} health: {name} ok p90={p90} ({}/{BURST_LEN} echoes)",
                prefixed(self.tag(), "channel"),
                outcome.received
            );
        } else {
            crate::info!(
                "{} health: {name} degraded p90={p90} ({}/{BURST_LEN} lost)",
                prefixed(self.tag(), "channel"),
                outcome.lost
            );
            let entry = self.stats.transport_failures.entry(name).or_default();
            *entry = entry.saturating_add(outcome.lost as u64);
        }
        self.close_flow(burst.attempt, true).await
    }
}
