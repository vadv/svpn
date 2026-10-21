//! Background re-selection (EPIC-016 S2): while the link runs on a TCP
//! incumbent, expired UDP bans get a challenger round in the background —
//! traffic keeps flowing, and a healthy UDP challenger takes over.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant as StdInstant;

use anyhow::{Context, Result, bail, ensure};
use tokio::time::{Duration, Instant};

use crate::control::Message;
use crate::link_io::PREFLIGHT_ID;
use crate::selector::{Candidate, Reason};
use crate::{crypto, packet, webrtc};

use super::burst::{Burst, HEALTH_INTERVAL, Outcome};
use super::{Flow, PacketIo, Plane, Readiness, Session, candidate_strategy, prefixed, reason_en};

/// A background challenge caps all in-flight challenger work after this.
const CHALLENGE_CAP: Duration = Duration::from_secs(30);

/// One UDP challenger: prepared channel, then a probe burst over it.
pub struct Challenger {
    pub candidate: Candidate,
    pub channel: Option<u64>,
    pub peer: Option<webrtc::Peer>,
    /// Created when the channel binds; moved into `session.burst` when the
    /// burst slot is free (bursts run one at a time).
    pub burst: Option<Burst>,
}

pub struct Challenge {
    /// Every in-flight challenger by its probe attempt id.
    pub attempts: HashMap<u64, Challenger>,
    /// Bound attempts waiting for the burst slot.
    pub queue: VecDeque<u64>,
    /// Finished bursts: (candidate, channel, outcome).
    pub measured: Vec<(Candidate, u64, u64, Outcome)>,
    pub deadline: Instant,
}

impl Challenge {
    pub fn owns(&self, attempt: u64) -> bool {
        self.attempts.contains_key(&attempt)
    }

    /// Attempt riding `channel`, if any (task-failure path carries no attempt).
    pub fn attempt_on(&self, channel: u64) -> Option<u64> {
        self.attempts
            .iter()
            .find(|(_, challenger)| challenger.channel == Some(channel))
            .map(|(&attempt, _)| attempt)
    }

    fn done(&self) -> bool {
        self.attempts.is_empty()
    }
}

impl Session {
    /// Trigger 1: the incumbent is TCP and a UDP candidate is eligible
    /// again (its ban expired). Runs without pausing admission: the link
    /// stays Ready and flows keep binding to the incumbent.
    pub async fn maybe_start_challenge(&mut self) -> Result<()> {
        if !self.client()
            || self.readiness != Some(Readiness::Ready)
            || self.round.is_some()
            || self.challenge.is_some()
            || !matches!(self.plane, Plane::Channels(_))
        {
            return Ok(());
        }
        let candidates = {
            let Plane::Channels(plane) = &self.plane else {
                unreachable!()
            };
            let Some(selector) = plane.selector.as_ref() else {
                return Ok(());
            };
            if selector.last_good != Some(Candidate::Tcp) {
                return Ok(());
            }
            // The `allowed` field is live eligibility (bans retained out);
            // the `allowed()` method returns the configured list.
            selector
                .allowed
                .iter()
                .copied()
                .filter(|candidate| *candidate != Candidate::Tcp)
                .collect::<Vec<_>>()
        };
        if candidates.is_empty() {
            return Ok(());
        }
        // WebRTC peer creation is CPU-heavy (~300 ms on routers); build it
        // in the background, like rounds do.
        let mut webrtc_task = candidates.contains(&Candidate::WebRtc).then(|| {
            tokio::task::spawn_blocking(|| {
                webrtc::Peer::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            })
        });
        let mut attempts = HashMap::new();
        let mut names = Vec::new();
        for candidate in candidates {
            let attempt = self.next_round_attempt;
            self.next_round_attempt = attempt.checked_add(1).context("probe ID space exhausted")?;
            ensure!(attempt < PREFLIGHT_ID, "probe ID space exhausted");
            let mut hello = None;
            let mut peer = None;
            if candidate == Candidate::WebRtc {
                let (p, h) = match webrtc_task.take() {
                    Some(task) => task
                        .await
                        .context("WebRTC peer task")?
                        .context("WebRTC client peer")?,
                    None => webrtc::Peer::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
                        .context("WebRTC client peer")?,
                };
                hello = Some(serde_json::to_string(&h).context("serialize WebRTC hello")?);
                peer = Some(p);
            }
            self.control
                .send(Message::ChannelPrepare {
                    attempt,
                    strategy: candidate_strategy(candidate),
                    hello,
                })
                .await?;
            names.push(candidate.as_str());
            attempts.insert(
                attempt,
                Challenger {
                    candidate,
                    channel: None,
                    peer,
                    burst: None,
                },
            );
        }
        self.challenge = Some(Challenge {
            attempts,
            queue: VecDeque::new(),
            measured: Vec::new(),
            deadline: Instant::now() + CHALLENGE_CAP,
        });
        crate::info!(
            "{} challenge: probing {} in the background (tcp keeps serving)",
            prefixed(self.tag(), "channel"),
            names.join(", ")
        );
        Ok(())
    }

    /// A challenger channel bound: build its probe flow and queue the burst.
    /// Called from `channel_ready` (QUIC: from the handshake task event),
    /// before the channel task reports `Established`. The probe `FlowOpen`
    /// goes out on `Established` — announcing earlier races the server's
    /// channel-task spawn, and the `Established` handler is the single sender
    /// (a bind-time send duplicates it and draws a `FlowReject`).
    pub(crate) fn challenge_channel_bound(&mut self, attempt: u64, channel: u64) -> Result<()> {
        let PacketIo::Link(io) = &self.io else {
            bail!("challenge requires a packet port");
        };
        let peer_ip = io.peer_ip;
        let Some(challenge) = self.challenge.as_mut() else {
            return Ok(());
        };
        let Some(challenger) = challenge.attempts.get_mut(&attempt) else {
            return Ok(());
        };
        challenger.channel = Some(channel);
        // Same rule as rounds: no live flow may share the ICMP 5-tuple.
        let base = u16::from_ne_bytes(crypto::random()?);
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("challenge requires the channels plane");
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
        let key = packet::FlowKey {
            protocol: 1,
            source: self.client_ip,
            destination: peer_ip,
            source_port: icmp_id,
            destination_port: 0,
        };
        // The committed probe requires the bound channel on the flow.
        let mut probe = Flow::new(key, Instant::now());
        probe.channel = Some(channel);
        plane.flows.insert(attempt, probe);
        let mut payload = vec![0u8; 32];
        getrandom::fill(&mut payload).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
        let base_seq = u16::from_ne_bytes(crypto::random()?);
        challenge
            .attempts
            .get_mut(&attempt)
            .context("challenger disappeared")?
            .burst = Some(Burst::new(channel, attempt, icmp_id, base_seq, payload));
        challenge.queue.push_back(attempt);
        Ok(())
    }

    /// The burst slot is free: start the next queued challenger. Finishes
    /// the challenge when nothing is left or the deadline passed.
    pub async fn challenge_drive(&mut self, now: Instant) -> Result<()> {
        let Some(challenge) = self.challenge.as_ref() else {
            return Ok(());
        };
        if now >= challenge.deadline {
            return self.finish_challenge(true).await;
        }
        if self.burst.is_some() || challenge.queue.is_empty() {
            if challenge.done() && self.burst.is_none() {
                return self.finish_challenge(false).await;
            }
            return Ok(());
        }
        let attempt = self
            .challenge
            .as_mut()
            .and_then(|challenge| challenge.queue.pop_front())
            .context("challenge queue disappeared")?;
        let burst = self
            .challenge
            .as_mut()
            .and_then(|challenge| challenge.attempts.get_mut(&attempt))
            .and_then(|challenger| challenger.burst.take());
        let Some(burst) = burst else {
            // Failed between queueing and driving: nothing to start.
            return Ok(());
        };
        self.burst = Some(burst);
        Ok(())
    }

    /// A burst finished: record the outcome and drive the next challenger.
    pub(crate) async fn challenge_burst_done(
        &mut self,
        attempt: u64,
        outcome: Outcome,
    ) -> Result<()> {
        if let Some(challenge) = self.challenge.as_mut()
            && let Some(challenger) = challenge.attempts.remove(&attempt)
        {
            let Some(channel) = challenger.channel else {
                return Ok(());
            };
            challenge
                .measured
                .push((challenger.candidate, channel, attempt, outcome));
        }
        self.challenge_drive(Instant::now()).await
    }

    /// A challenger failed (prepare rejected or its channel died): re-ban
    /// the candidate with the doubled backoff and move on. Returns true
    /// when the attempt/channel belonged to the challenge. Generic channel
    /// cleanup (stats, channel removal, burst clearing) has already run.
    pub(crate) async fn challenge_channel_failed(
        &mut self,
        attempt: Option<u64>,
        channel: Option<u64>,
        reason: Reason,
    ) -> Result<bool> {
        let Some(challenge) = self.challenge.as_mut() else {
            return Ok(false);
        };
        let attempt = attempt
            .filter(|attempt| challenge.attempts.contains_key(attempt))
            .or_else(|| channel.and_then(|channel| challenge.attempt_on(channel)));
        let Some(attempt) = attempt else {
            return Ok(false);
        };
        let Some(challenger) = challenge.attempts.remove(&attempt) else {
            return Ok(false);
        };
        challenge.queue.retain(|queued| *queued != attempt);
        if let Plane::Channels(plane) = &mut self.plane
            && let Some(selector) = plane.selector.as_mut()
        {
            selector.ban_candidate(challenger.candidate, reason, StdInstant::now());
        }
        crate::info!(
            "{} challenge: {} failed — {}",
            prefixed(self.tag(), "channel"),
            challenger.candidate.as_str(),
            reason_en(reason)
        );
        self.close_flow(attempt, true).await?;
        self.challenge_drive(Instant::now()).await?;
        Ok(true)
    }

    /// Verdict: the measured challenger with the lowest p90 replaces the
    /// TCP incumbent immediately (UDP beats TCP by construction); the
    /// losers' channels retire. Dead challengers (no reply at all) re-ban
    /// with the doubled backoff — keeping them allowed would restart the
    /// challenge on every health tick. Every probe flow closes.
    async fn finish_challenge(&mut self, expired: bool) -> Result<()> {
        let Some(mut challenge) = self.challenge.take() else {
            return Ok(());
        };
        // The challenge borrowed the probe slot; resume periodic health
        // bursts unless the session is tearing down.
        if self.readiness == Some(crate::session::Readiness::Ready) {
            self.health_at = Some(Instant::now() + HEALTH_INTERVAL);
        }
        let tag = self.tag().to_owned();
        if expired {
            // Whatever never answered by the deadline is a failure: re-ban
            // with the doubled backoff, retire the half-built channel.
            let attempts: Vec<u64> = challenge.attempts.keys().copied().collect();
            for attempt in attempts {
                let Some(challenger) = challenge.attempts.remove(&attempt) else {
                    continue;
                };
                if let Plane::Channels(plane) = &mut self.plane
                    && let Some(selector) = plane.selector.as_mut()
                {
                    selector.ban_candidate(
                        challenger.candidate,
                        Reason::PathTimeout,
                        StdInstant::now(),
                    );
                }
                if self
                    .burst
                    .as_ref()
                    .is_some_and(|burst| burst.attempt == attempt)
                {
                    self.burst = None;
                }
                self.close_flow(attempt, true).await?;
                if let Some(channel) = challenger.channel {
                    self.stop_channel(channel).await;
                    if let Plane::Channels(plane) = &mut self.plane {
                        plane.channels.remove(&channel);
                    }
                }
                self.control
                    .send(Message::ChannelFailed {
                        attempt: Some(attempt),
                        channel: challenger.channel,
                        reason: Reason::PathTimeout,
                    })
                    .await?;
            }
        }
        let best = challenge
            .measured
            .iter()
            .filter_map(|(candidate, channel, attempt, outcome)| {
                outcome.p90.map(|p90| (*candidate, *channel, *attempt, p90))
            })
            .min_by_key(|(.., p90)| *p90);
        let winner_channel = best.map(|(_, channel, ..)| channel);
        for (candidate, _, _, outcome) in &challenge.measured {
            if outcome.p90.is_none()
                && let Plane::Channels(plane) = &mut self.plane
                && let Some(selector) = plane.selector.as_mut()
            {
                selector.ban_candidate(*candidate, Reason::PathTimeout, StdInstant::now());
            }
        }
        for (candidate, channel, attempt, _) in &challenge.measured {
            // The probe flow served its purpose even for the winner; its
            // channel stays and later health bursts open fresh flows.
            self.close_flow(*attempt, true).await?;
            if winner_channel == Some(*channel) {
                continue;
            }
            crate::debug!(
                "{} challenge: retiring loser {} (channel {channel})",
                prefixed(&tag, "channel"),
                candidate.as_str()
            );
            self.stop_channel(*channel).await;
            if let Plane::Channels(plane) = &mut self.plane {
                plane.channels.remove(channel);
            }
            self.control
                .send(Message::ChannelFailed {
                    attempt: None,
                    channel: Some(*channel),
                    reason: Reason::ChannelFailed,
                })
                .await?;
        }
        match best {
            Some((candidate, channel, _, p90)) => {
                if let Plane::Channels(plane) = &mut self.plane
                    && let Some(selector) = plane.selector.as_mut()
                {
                    selector.adopt(candidate, Some(channel));
                }
                crate::info!(
                    "{} challenge: {} wins (p90 {}ms) — new flows leave tcp",
                    prefixed(&tag, "channel"),
                    candidate.as_str(),
                    p90.as_millis()
                );
            }
            None => {
                crate::info!(
                    "{} challenge: udp still unavailable — tcp keeps serving",
                    prefixed(&tag, "channel")
                );
            }
        }
        Ok(())
    }

    /// The link dropped into a fresh round: the challenge dies with the old
    /// world. Owned channels retire; the server frees its halves.
    pub async fn abort_challenge(&mut self) -> Result<()> {
        let Some(challenge) = self.challenge.take() else {
            return Ok(());
        };
        if self
            .burst
            .as_ref()
            .is_some_and(|burst| challenge.owns(burst.attempt))
        {
            self.burst = None;
        }
        for (attempt, challenger) in challenge.attempts {
            self.close_flow(attempt, true).await?;
            if let Some(channel) = challenger.channel {
                self.stop_channel(channel).await;
                if let Plane::Channels(plane) = &mut self.plane {
                    plane.channels.remove(&channel);
                }
            }
            self.control
                .send(Message::ChannelFailed {
                    attempt: Some(attempt),
                    channel: challenger.channel,
                    reason: Reason::ChannelFailed,
                })
                .await?;
        }
        Ok(())
    }
}
