//! Channel-task events and selector actions applied to the session.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Instant as StdInstant,
};

use anyhow::{Context, Result, bail};

use crate::control::{Message, Strategy};
use crate::link_io::{PREFLIGHT_ID, is_probe_flow};
use crate::selector::{Action, Reason};
use crate::webrtc;

use super::{Plane, Session, TaskEvent, candidate_strategy, prefixed, reason_en};

impl Session {
    pub async fn dispatch_task_event(&mut self, event: TaskEvent) -> Result<()> {
        match event {
            TaskEvent::Handshake {
                attempt,
                channel,
                candidate,
                key,
                max_wire,
                io,
            } => match io {
                Some(io) => {
                    // QUIC: the handshake ran in a detached task, so the
                    // challenge binding skipped `channel_ready` — bind now.
                    if self
                        .challenge
                        .as_ref()
                        .is_some_and(|challenge| challenge.owns(attempt))
                    {
                        self.challenge_channel_bound(attempt, channel)?;
                    }
                    self.finish_channel_ready(attempt, channel, candidate, io, key, max_wire)
                        .await?
                }
                None if self
                    .round
                    .as_ref()
                    .is_some_and(|round| round.pending.contains_key(&attempt)) =>
                {
                    self.round_attempt_failed(attempt, Reason::PathTimeout)
                        .await?;
                }
                None => {
                    crate::info!(
                        "{} {candidate} failed — handshake failed (attempt {attempt})",
                        prefixed(self.tag(), "channel")
                    );
                    let actions = {
                        let Plane::Channels(plane) = &mut self.plane else {
                            bail!("handshake event outside channels mode");
                        };
                        let Some(selector) = plane.selector.as_mut() else {
                            bail!("handshake event on server");
                        };
                        selector.attempt_failed(
                            candidate,
                            attempt,
                            Reason::PathTimeout,
                            StdInstant::now(),
                        )
                    };
                    // A half-open server channel must die with the attempt.
                    self.control
                        .send(Message::ChannelFailed {
                            attempt: Some(attempt),
                            channel: Some(channel),
                            reason: Reason::PathTimeout,
                        })
                        .await?;
                    self.execute_actions(actions).await?;
                }
            },
            TaskEvent::Established { channel } => {
                if !matches!(&self.plane, Plane::Channels(plane) if plane.channels.contains_key(&channel))
                {
                    return Ok(());
                }
                crate::debug!("channel_established id={channel}");
                self.control
                    .send(Message::ChannelVerified { channel })
                    .await?;
                // N3: a round winner binds the PREFLIGHT flow to the channel
                // directly; the selector learns it through `adopt` at the verdict.
                let probe_id = self
                    .round
                    .as_ref()
                    .and_then(|round| {
                        round
                            .pending
                            .iter()
                            .find(|(_, rc)| rc.channel == Some(channel))
                            .map(|(&id, _)| id)
                    })
                    .or_else(|| {
                        self.challenge.as_ref().and_then(|challenge| {
                            challenge
                                .attempts
                                .iter()
                                .find(|(_, challenger)| challenger.channel == Some(channel))
                                .map(|(&id, _)| id)
                        })
                    });
                if let Some(flow_id) = probe_id {
                    let Plane::Channels(plane) = &self.plane else {
                        unreachable!()
                    };
                    let Some(flow) = plane.flows.get(&flow_id) else {
                        return Ok(());
                    };
                    return self
                        .control
                        .send(Message::FlowOpen {
                            flow_id,
                            flow: flow.key,
                            channel: Some(channel),
                        })
                        .await;
                }
                let Plane::Channels(plane) = &mut self.plane else {
                    bail!("task event outside channels mode");
                };
                if let Some(selector) = plane.selector.as_mut()
                    && let Some(handle) = plane.channels.get(&channel)
                {
                    let actions =
                        selector.probes_passed(handle.candidate, channel, StdInstant::now());
                    self.execute_actions(actions).await?;
                }
            }
            TaskEvent::Failed { channel, reason } => {
                // The client drives attempts: a strategy failure is a
                // user-facing event. The server's copy of the same failure
                // is debug-only.
                let client_side =
                    matches!(&self.plane, Plane::Channels(plane) if plane.selector.is_some());
                if client_side {
                    let strategy = match &self.plane {
                        Plane::Channels(plane) => plane
                            .channels
                            .get(&channel)
                            .map(|handle| handle.candidate.as_str().to_owned())
                            .unwrap_or_else(|| format!("channel {channel}")),
                        _ => unreachable!(),
                    };
                    crate::info!(
                        "{} {strategy} failed — {reason:#}",
                        prefixed(self.tag(), "channel")
                    );
                } else {
                    crate::debug!("channel_failed id={channel}: {reason:#}");
                }
                self.channel_failed(None, Some(channel), Reason::ChannelFailed)
                    .await?;
                // Tell the peer: the server will drop the channel and its flows.
                self.control
                    .send(Message::ChannelFailed {
                        attempt: None,
                        channel: Some(channel),
                        reason: Reason::ChannelFailed,
                    })
                    .await?;
            }
            TaskEvent::FlowEcho {
                channel,
                flow_id,
                echo,
            } => {
                let Plane::Channels(plane) = &mut self.plane else {
                    bail!("task event outside channels mode");
                };
                let Some(flow_state) = plane.flows.get_mut(&flow_id) else {
                    return Ok(());
                };
                if flow_state.channel != Some(channel) || flow_state.echo_pending != Some(echo) {
                    if flow_id != PREFLIGHT_ID {
                        crate::error!(
                            "{} echo mismatch id={flow_id} channel={channel}",
                            prefixed(self.tag(), "flow")
                        );
                    }
                    self.close_flow(flow_id, true).await?;
                    return Ok(());
                }
                flow_state.echo_pending = None;
                if is_probe_flow(flow_id) {
                    self.control
                        .send(Message::FlowOpened {
                            flow_id,
                            flow: flow_state.key,
                            channel,
                        })
                        .await?;
                } else {
                    crate::debug!("flow_echo_ok id={flow_id}");
                }
            }
        }
        Ok(())
    }

    pub async fn execute_actions(&mut self, actions: Vec<Action>) -> Result<()> {
        for action in actions {
            match action {
                Action::PrepareChannel { candidate, attempt } => {
                    let Plane::Channels(plane) = &mut self.plane else {
                        bail!("actions outside channels mode");
                    };
                    let strategy = candidate_strategy(candidate);
                    let mut hello = None;
                    let mut peer = None;
                    if matches!(strategy, Strategy::WebRtc) {
                        let (p, h) =
                            webrtc::Peer::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
                                .context("WebRTC client peer")?;
                        hello = Some(serde_json::to_string(&h).context("serialize WebRTC hello")?);
                        peer = Some(p);
                    }
                    plane.attempt = Some((attempt, candidate, None, peer));
                    self.control
                        .send(Message::ChannelPrepare {
                            attempt,
                            strategy,
                            hello,
                        })
                        .await?;
                    crate::info!(
                        "{} trying {} (attempt {attempt})",
                        prefixed(self.tag(), "channel"),
                        format!("{strategy:?}").to_lowercase()
                    );
                }
                Action::AbortChannel {
                    candidate: _,
                    attempt,
                } => {
                    let Plane::Channels(plane) = &mut self.plane else {
                        continue;
                    };
                    if plane
                        .attempt
                        .as_ref()
                        .is_some_and(|pending| pending.0 == attempt)
                        && let Some((_, _, Some(channel_id), _)) = plane.attempt.take()
                    {
                        self.stop_channel(channel_id).await;
                        if let Plane::Channels(plane) = &mut self.plane {
                            plane.channels.remove(&channel_id);
                        }
                    }
                    self.control
                        .send(Message::ChannelFailed {
                            attempt: Some(attempt),
                            channel: None,
                            reason: Reason::PathTimeout,
                        })
                        .await?;
                }
                Action::OpenFlow {
                    flow_id,
                    candidate: _,
                    channel,
                } => {
                    let Plane::Channels(plane) = &mut self.plane else {
                        continue;
                    };
                    let Some(flow_state) = plane.flows.get_mut(&flow_id) else {
                        continue;
                    };
                    flow_state.channel = Some(channel);
                    let flow = flow_state.key;
                    self.control
                        .send(Message::FlowOpen {
                            flow_id,
                            flow,
                            channel: Some(channel),
                        })
                        .await?;
                }
                Action::TryTcp {
                    flow_id,
                    attempt: _,
                } => {
                    let Plane::Channels(plane) = &mut self.plane else {
                        bail!("TryTcp outside channels mode");
                    };
                    let Some(flow_state) = plane.flows.get_mut(&flow_id) else {
                        continue;
                    };
                    flow_state.channel = None;
                    let flow = flow_state.key;
                    self.control
                        .send(Message::Open { id: flow_id, flow })
                        .await?;
                }
                Action::Commit {
                    flow_id, attempt, ..
                } => {
                    self.control
                        .send(Message::Commit { flow_id, attempt })
                        .await?;
                }
                Action::FailFlow {
                    flow_id,
                    flow,
                    reason,
                } => {
                    let _ = flow;
                    self.control
                        .send(Message::FlowReject { flow_id, reason })
                        .await?;
                    self.close_flow(flow_id, false).await?;
                }
                Action::CloseFlow { flow_id } => {
                    self.close_flow(flow_id, false).await?;
                }
                Action::BanExpired { candidate } => {
                    crate::info!(
                        "{} candidate {} eligible again (ban expired)",
                        prefixed(self.tag(), "channel"),
                        format!("{:?}", candidate_strategy(candidate)).to_lowercase()
                    );
                    self.maybe_start_challenge(false).await?;
                }
                Action::Exhausted { reasons } => {
                    // Proactive-auto: nothing could be raised — bail out.
                    let table = reasons
                        .iter()
                        .map(|(candidate, reason)| {
                            format!("{}: {}", candidate.as_str(), reason_en(*reason))
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    bail!("no strategy succeeded: {table}");
                }
            }
        }
        Ok(())
    }
}
