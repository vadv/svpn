//! Background re-selection: while the link runs on a TCP
//! incumbent, expired UDP bans get a challenger round in the background —
//! traffic keeps flowing, and a healthy UDP challenger takes over. S3: a
//! degraded incumbent is probed alongside its challengers, a switch needs
//! the margin (20 % and 5 ms) twice in a row, and the replaced channel
//! drains instead of dying mid-flow.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant as StdInstant;

use anyhow::{Context, Result, bail, ensure};
use tokio::time::{Duration, Instant};

use crate::control::Message;
use crate::link_io::PREFLIGHT_ID;
use crate::selector::{Candidate, Reason};
use crate::{crypto, packet, webrtc};

use super::burst::{BURST_LEN, Burst, HEALTH_INTERVAL, Outcome};
use super::round::TCP_PENALTY;
use super::{Flow, PacketIo, Plane, Readiness, Session, candidate_strategy, prefixed, reason_en};

/// A background challenge caps all in-flight challenger work after this.
const CHALLENGE_CAP: Duration = Duration::from_secs(30);

/// Remeasure cadence jitter, ±20 % like the ban backoff (selector.rs).
pub(crate) fn jittered(interval: Duration, seed: u64) -> Duration {
    let jitter = (seed % 41) as i64 - 20;
    interval * (100 + jitter) as u32 / 100
}

/// One UDP challenger: prepared channel, then a probe burst over it.
pub struct Challenger {
    pub candidate: Candidate,
    pub channel: Option<u64>,
    pub peer: Option<webrtc::Peer>,
    /// Created when the channel binds (immediately for the incumbent
    /// probe); armed by `committed()`. All challenger bursts run in
    /// parallel: a shared bottleneck then hits every candidate alike.
    /// shortcut: bursts arm at commit, not at a common start gate; prepare
    /// skew (~0.3-2 s) shifts them by less than one burst, revisit if a
    /// challenger ever takes minutes to prepare.
    pub burst: Option<Burst>,
}

pub struct Challenge {
    /// Every in-flight challenger by its probe attempt id.
    pub attempts: HashMap<u64, Challenger>,
    /// Finished bursts: (candidate, channel, attempt, outcome).
    pub measured: Vec<(Candidate, u64, u64, Outcome)>,
    /// S3: the probed incumbent (attempt, candidate, channel), if any.
    /// Never re-banned, never retired — it is serving traffic.
    pub incumbent: Option<(u64, Candidate, u64)>,
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

    pub(crate) fn done(&self) -> bool {
        self.attempts.is_empty()
    }
}

impl Session {
    /// Trigger 1 (`degraded = false`): the incumbent is TCP and a UDP
    /// candidate is eligible again (its ban expired). Trigger 2
    /// (`degraded = true`, S3): the incumbent's health burst degraded —
    /// the incumbent is probed alongside its challengers and keeps
    /// serving unless beaten by the margin twice in a row. Runs without
    /// pausing admission: the link stays Ready and flows keep binding.
    pub async fn maybe_start_challenge(&mut self, degraded: bool) -> Result<()> {
        if !self.client()
            || self.readiness != Some(Readiness::Ready)
            || self.round.is_some()
            || self.challenge.is_some()
            || !matches!(self.plane, Plane::Channels(_))
        {
            return Ok(());
        }
        // Re-selection runs at most once per remeasure interval (spec:
        // triggers are checked every interval). None = fixed strategy or
        // `remeasure-interval = 0`: no challenger rounds at all.
        let Some(interval) = self.remeasure else {
            return Ok(());
        };
        if self
            .next_challenge_at
            .is_some_and(|at| StdInstant::now() < at)
        {
            return Ok(());
        }
        let (incumbent, incumbent_channel, candidates) = {
            let Plane::Channels(plane) = &self.plane else {
                unreachable!()
            };
            let Some(selector) = plane.selector.as_ref() else {
                return Ok(());
            };
            let Some(incumbent) = selector.last_good else {
                return Ok(());
            };
            if degraded == (incumbent == Candidate::Tcp) {
                // Expiry trigger: TCP incumbent. Degradation: UDP only —
                // TCP carries no health bursts to degrade.
                return Ok(());
            }
            // The `allowed` field is live eligibility (bans retained out);
            // the `allowed()` method returns the configured list.
            let candidates = selector
                .allowed
                .iter()
                .copied()
                .filter(|candidate| *candidate != Candidate::Tcp && *candidate != incumbent)
                .collect::<Vec<_>>();
            let channel = if incumbent == Candidate::Tcp {
                None
            } else {
                selector.ready_channel(incumbent)
            };
            (incumbent, channel, candidates)
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
        let mut incumbent_probe = None;
        // The incumbent is probed on its live channel alongside the
        // challengers: the margin verdict compares like for like. The
        // channel is long established, so the FlowOpen goes out immediately.
        if let Some(channel) = incumbent_channel {
            let attempt = self.next_round_attempt;
            self.next_round_attempt = attempt.checked_add(1).context("probe ID space exhausted")?;
            ensure!(attempt < PREFLIGHT_ID, "probe ID space exhausted");
            let burst = self.open_probe(attempt, channel)?;
            let key = {
                let Plane::Channels(plane) = &self.plane else {
                    unreachable!()
                };
                plane.flows[&attempt].key
            };
            self.control
                .send(Message::FlowOpen {
                    flow_id: attempt,
                    flow: key,
                    channel: Some(channel),
                })
                .await?;
            attempts.insert(
                attempt,
                Challenger {
                    candidate: incumbent,
                    channel: Some(channel),
                    peer: None,
                    burst: Some(burst),
                },
            );
            incumbent_probe = Some((attempt, incumbent, channel));
        }
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
        self.next_challenge_at =
            Some(StdInstant::now() + jittered(interval, self.next_round_attempt));
        self.challenge = Some(Challenge {
            attempts,
            measured: Vec::new(),
            incumbent: incumbent_probe,
            deadline: Instant::now() + CHALLENGE_CAP,
        });
        crate::info!(
            "{} challenge: probing {} in the background ({} keeps serving)",
            prefixed(self.tag(), "channel"),
            names.join(", "),
            if incumbent == Candidate::Tcp {
                "tcp"
            } else {
                incumbent.as_str()
            }
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
        let Some(challenge) = self.challenge.as_mut() else {
            return Ok(());
        };
        let Some(challenger) = challenge.attempts.get_mut(&attempt) else {
            return Ok(());
        };
        challenger.channel = Some(channel);
        let burst = self.open_probe(attempt, channel)?;
        let challenge = self.challenge.as_mut().context("challenge disappeared")?;
        challenge
            .attempts
            .get_mut(&attempt)
            .context("challenger disappeared")?
            .burst = Some(burst);
        Ok(())
    }

    /// Probe flow + burst over an established channel: the ICMP echo id
    /// avoids every live 5-tuple, and the flow carries the channel for
    /// `committed()`.
    fn open_probe(&mut self, attempt: u64, channel: u64) -> Result<Burst> {
        let PacketIo::Link(io) = &self.io else {
            bail!("challenge requires a packet port");
        };
        let peer_ip = io.peer_ip;
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
        Ok(Burst::new(channel, attempt, icmp_id, base_seq, payload))
    }

    /// A burst finished: record the outcome. The caller (`finish_probe`)
    /// closes the probe flow and finishes the challenge when done.
    pub(crate) async fn challenge_burst_done(
        &mut self,
        attempt: u64,
        outcome: Outcome,
    ) -> Result<()> {
        if let Some(challenge) = self.challenge.as_mut()
            && let Some(challenger) = challenge.attempts.remove(&attempt)
            && let Some(channel) = challenger.channel
        {
            challenge
                .measured
                .push((challenger.candidate, channel, attempt, outcome));
        }
        Ok(())
    }

    /// A challenger failed (prepare rejected or its channel died): re-ban
    /// the candidate with the doubled backoff and move on. Returns true
    /// when the attempt/channel belonged to the challenge. The incumbent
    /// dying is not a challenger failure: the challenge aborts and the
    /// ordinary dead-incumbent path (already run) decides. Generic channel
    /// cleanup (stats, channel removal, burst clearing) has already run.
    pub(crate) async fn challenge_channel_failed(
        &mut self,
        attempt: Option<u64>,
        channel: Option<u64>,
        reason: Reason,
    ) -> Result<bool> {
        let incumbent = self
            .challenge
            .as_ref()
            .and_then(|challenge| challenge.incumbent);
        if let Some((inc_attempt, _, inc_channel)) = incumbent
            && (attempt == Some(inc_attempt) || channel == Some(inc_channel))
        {
            self.abort_challenge().await?;
            return Ok(false);
        }
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
        if self
            .challenge
            .as_ref()
            .is_some_and(|challenge| challenge.done())
        {
            self.finish_challenge(false).await?;
        }
        Ok(true)
    }

    /// Verdict (S3): the incumbent is probed alongside the challengers; a
    /// challenger must beat it by 20 % and 5 ms (TCP carries its round
    /// penalty) with loss ≤ 1 to win the round. A winner must repeat in a
    /// confirming round after at least one health interval before the
    /// switch lands; until then its channel retires like any loser's. On
    /// the switch the replaced incumbent's channel drains: no new flows,
    /// the last bound flow's close tears it down. Every probe flow closes.
    pub async fn finish_challenge(&mut self, expired: bool) -> Result<()> {
        let Some(mut challenge) = self.challenge.take() else {
            return Ok(());
        };
        // The challenge borrowed the probe slot; resume periodic health
        // bursts unless the session is tearing down.
        if self.readiness == Some(crate::session::Readiness::Ready) {
            self.health_at = Some(Instant::now() + HEALTH_INTERVAL);
        }
        let tag = self.tag().to_owned();
        let incumbent = challenge.incumbent;
        let incumbent_attempt = incumbent.map(|(attempt, ..)| attempt);
        if expired {
            // Whatever never answered by the deadline is a failure: re-ban
            // with the doubled backoff, retire the half-built channel. The
            // incumbent only lost the measurement race — it keeps serving.
            let attempts: Vec<u64> = challenge.attempts.keys().copied().collect();
            for attempt in attempts {
                let Some(challenger) = challenge.attempts.remove(&attempt) else {
                    continue;
                };
                self.close_flow(attempt, true).await?;
                if Some(attempt) == incumbent_attempt {
                    continue;
                }
                if let Plane::Channels(plane) = &mut self.plane
                    && let Some(selector) = plane.selector.as_mut()
                {
                    selector.ban_candidate(
                        challenger.candidate,
                        Reason::PathTimeout,
                        StdInstant::now(),
                    );
                }
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
        // The margin verdict, on adjusted p90 (TCP carries its penalty).
        let incumbent_adjusted = incumbent.and_then(|(attempt, candidate, _)| {
            challenge
                .measured
                .iter()
                .find(|(.., measured_attempt, _)| *measured_attempt == attempt)
                .and_then(|(.., outcome)| outcome.p90)
                .map(|p90| adjusted_p90(candidate, p90))
        });
        let best = challenge
            .measured
            .iter()
            .filter(|(.., attempt, _)| Some(*attempt) != incumbent_attempt)
            .filter(|(.., outcome)| outcome.lost <= 1)
            .filter_map(|(candidate, channel, _, outcome)| {
                outcome
                    .p90
                    .map(|p90| (*candidate, *channel, p90, outcome.lost))
            })
            .min_by_key(|(candidate, _, p90, _)| adjusted_p90(*candidate, *p90));
        let winner = best.filter(|(candidate, _, p90, _)| match incumbent_adjusted {
            Some(reference) => adjusted_p90(*candidate, *p90) + win_margin(reference) <= reference,
            None => true,
        });
        // Two consecutive rounds confirm the switch, at least one remeasure
        // interval apart (challenges start at most once per interval, so the
        // confirming round only needs to win again); the first win just arms
        // the retry and the winner's channel retires like a loser's.
        let gap = self.remeasure.unwrap_or(HEALTH_INTERVAL);
        let deciding = winner.filter(|(candidate, ..)| {
            self.switch_pending.is_some_and(|(pending, armed_at)| {
                pending == *candidate && armed_at.elapsed() >= gap
            })
        });
        self.switch_pending = match (winner, deciding) {
            (Some((candidate, ..)), None) => {
                crate::debug!(
                    "{} challenge: {} won this round — retried next interval to confirm",
                    prefixed(&tag, "channel"),
                    candidate.as_str()
                );
                Some((candidate, StdInstant::now()))
            }
            _ => None,
        };
        // Dead challengers re-ban — a live incumbent never does.
        for (candidate, _, attempt, outcome) in &challenge.measured {
            if outcome.p90.is_none()
                && Some(*attempt) != incumbent_attempt
                && let Plane::Channels(plane) = &mut self.plane
                && let Some(selector) = plane.selector.as_mut()
            {
                selector.ban_candidate(*candidate, Reason::PathTimeout, StdInstant::now());
            }
        }
        // Probe flows close; channels retire except the incumbent's and
        // the deciding winner's.
        let incumbent_channel = incumbent.map(|(.., channel)| channel);
        let deciding_channel = deciding.map(|(_, channel, ..)| channel);
        for (candidate, channel, attempt, _) in &challenge.measured {
            // The probe flow served its purpose even for the winner; its
            // channel stays and later health bursts open fresh flows.
            self.close_flow(*attempt, true).await?;
            if Some(*channel) == incumbent_channel || Some(*channel) == deciding_channel {
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
        match deciding {
            Some((candidate, channel, p90, loss)) => {
                let Plane::Channels(plane) = &mut self.plane else {
                    unreachable!()
                };
                let Some(selector) = plane.selector.as_mut() else {
                    return Ok(());
                };
                let old_incumbent = selector.last_good;
                let old_channel = old_incumbent
                    .filter(|old| *old != Candidate::Tcp)
                    .and_then(|old| selector.ready_channel(old));
                selector.adopt(candidate, Some(channel), Some(p90));
                crate::info!(
                    "{} reselection: {} replaces {} (p90 {}ms vs {}ms, loss {}/{BURST_LEN})",
                    prefixed(&tag, "channel"),
                    candidate.as_str(),
                    old_incumbent.map(|old| old.as_str()).unwrap_or("-"),
                    p90.as_millis(),
                    incumbent_adjusted
                        .map(|reference| reference.as_millis().to_string())
                        .unwrap_or_else(|| "-".to_owned()),
                    loss
                );
                if let (Some(old), Some(old_channel)) = (old_incumbent, old_channel) {
                    selector.channels.remove(&old);
                    plane.draining.insert(old_channel);
                    self.maybe_drain(old_channel).await?;
                }
            }
            None if incumbent.is_none() && winner.is_none() => {
                crate::info!(
                    "{} challenge: udp still unavailable — tcp keeps serving",
                    prefixed(&tag, "channel")
                );
            }
            None => {
                // A pending winner already logged its own line above.
                if winner.is_none() {
                    crate::debug!(
                        "{} challenge: the incumbent holds (no challenger beat the margin)",
                        prefixed(&tag, "channel")
                    );
                }
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
        let incumbent_attempt = challenge.incumbent.map(|(attempt, ..)| attempt);
        for (attempt, challenger) in challenge.attempts {
            self.close_flow(attempt, true).await?;
            if Some(attempt) == incumbent_attempt {
                // The incumbent's channel is serving traffic — the round
                // machinery or the dead-incumbent path retires it.
                continue;
            }
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

/// Verdict comparison: TCP carries its round penalty (round.rs).
fn adjusted_p90(candidate: Candidate, p90: Duration) -> Duration {
    if candidate == Candidate::Tcp {
        p90 + TCP_PENALTY
    } else {
        p90
    }
}

/// The switch margin (S3): at least 20 % and at least 5 ms better.
fn win_margin(reference: Duration) -> Duration {
    (reference / 5).max(Duration::from_millis(5))
}
