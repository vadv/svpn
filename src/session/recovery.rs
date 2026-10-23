//! Binding retries within one live control session.

use std::time::Instant as StdInstant;

use anyhow::{Result, ensure};
use tokio::time::Instant;

use crate::control::Message;
use crate::link_io::is_probe_flow;
use crate::packet::FlowKey;
use crate::selector::{ATTEMPT_BUDGET, Candidate, FLOW_BUDGET, RECOVERY_BUDGET, Reason};

use super::state::Recovery;
use super::{Flow, Plane, Session};

impl Session {
    pub fn flow_generation(&self, id: u64) -> Option<u64> {
        match &self.plane {
            Plane::Channels(plane) => plane.flows.get(&id).map(|flow| flow.generation),
            Plane::Tcp(plane) => plane.flows.get(&id).map(|flow| flow.generation),
        }
    }

    pub(crate) fn binding_current(&self, id: u64, generation: u64) -> bool {
        generation != 0 && self.flow_generation(id) == Some(generation)
    }

    pub(crate) async fn register_binding(
        &mut self,
        id: u64,
        generation: u64,
        key: FlowKey,
        channel: Option<u64>,
        resume: bool,
    ) -> Result<bool> {
        ensure!(
            !self.client() && generation != 0 && key.valid_for(self.client_ip),
            "invalid flow binding"
        );
        let at_capacity = self.flow_limit_reached(id);
        let Plane::Channels(plane) = &mut self.plane else {
            unreachable!()
        };
        let reason = if channel.is_some_and(|channel| !plane.channels.contains_key(&channel)) {
            Some(Reason::ChannelFailed)
        } else if let Some(flow) = plane.flows.get(&id) {
            if generation < flow.generation {
                return Ok(false);
            }
            if flow.key != key
                || (generation == flow.generation && flow.channel != channel)
                || (generation > flow.generation && flow.data_started && !resume)
                || (resume && (key.protocol != 6 || flow.tcp.is_some() || channel.is_none()))
            {
                Some(Reason::Unsupported)
            } else {
                None
            }
        } else if resume || plane.by_key.get(&key).is_some_and(|&owner| owner != id) {
            Some(Reason::Unsupported)
        } else if at_capacity
            || (!is_probe_flow(id)
                && plane
                    .flows
                    .iter()
                    .filter(|(id, flow)| !is_probe_flow(**id) && !flow.active)
                    .count()
                    >= crate::selector::PENDING_FLOWS)
        {
            Some(Reason::ResourceExhausted)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.control
                .send(Message::FlowReject {
                    flow_id: id,
                    generation,
                    reason,
                })
                .await?;
            return Ok(false);
        }
        let now = Instant::now();
        if let Some(flow) = plane.flows.get_mut(&id) {
            if generation == flow.generation {
                return Ok(true);
            }
            if let Some(tcp) = flow.tcp.take()
                && let Some(token) = tcp.token
            {
                plane.token_index.remove(&token);
            }
            flow.generation = generation;
            flow.channel = channel;
            flow.active = false;
            flow.commit_pending = false;
            flow.tcp_connected = false;
            flow.echo_pending = None;
            if resume && flow.recovery.is_none() {
                flow.recovery = Some(Recovery {
                    started: now,
                    from: None,
                    attempts: 1,
                });
            }
        } else {
            let mut flow = Flow::new(key, now);
            flow.generation = generation;
            flow.channel = channel;
            plane.flows.insert(id, flow);
            plane.by_key.insert(key, id);
            if !is_probe_flow(id) {
                self.stats.opened_flows += 1;
            }
        }
        Ok(true)
    }

    pub(crate) fn reset_binding(
        &mut self,
        id: u64,
        generation: u64,
        from: Option<Candidate>,
        reason: Reason,
    ) {
        let Plane::Channels(plane) = &mut self.plane else {
            return;
        };
        let Some(flow) = plane
            .flows
            .get_mut(&id)
            .filter(|flow| generation > flow.generation)
        else {
            return;
        };
        let recovery = flow.recovery.get_or_insert(Recovery {
            started: Instant::now(),
            from,
            attempts: 0,
        });
        recovery.attempts += 1;
        flow.generation = generation;
        flow.active = false;
        flow.commit_pending = false;
        flow.tcp_connected = false;
        flow.channel = None;
        flow.echo_pending = None;
        if let Some(tcp) = flow.tcp.take()
            && let Some(token) = tcp.token
        {
            plane.token_index.remove(&token);
        }
        crate::info!(
            "flow_recovery_start id={id} generation={generation} kind={} from={from:?} reason={reason:?}",
            if flow.data_started {
                "tcp_rebind"
            } else {
                "opening"
            }
        );
    }

    pub(crate) async fn retry_flow(
        &mut self,
        id: u64,
        generation: u64,
        reason: Reason,
    ) -> Result<bool> {
        if is_probe_flow(id) || !self.binding_current(id, generation) {
            return Ok(false);
        }
        let client = self.client();
        match &mut self.plane {
            Plane::Channels(plane) => {
                let flow = &mut plane.flows.get_mut(&id).expect("binding checked above");
                if flow.reset_requested
                    || flow.tcp_close.finished()
                    || (flow.data_started && (flow.key.protocol != 6 || flow.tcp.is_some()))
                {
                    return Ok(false);
                }
                if let Some(selector) = plane.selector.as_mut() {
                    let actions = if flow.data_started {
                        selector.recover(id, generation, reason, StdInstant::now())
                    } else {
                        selector.bind_failed(id, generation, reason, StdInstant::now())
                    };
                    self.execute_actions(actions).await?;
                } else {
                    flow.active = false;
                    flow.commit_pending = false;
                    flow.tcp_connected = false;
                    if flow.data_started {
                        flow.recovery.get_or_insert(Recovery {
                            started: Instant::now(),
                            from: None,
                            attempts: 1,
                        });
                    }
                    self.control
                        .send(Message::FlowReject {
                            flow_id: id,
                            generation,
                            reason,
                        })
                        .await?;
                }
            }
            Plane::Tcp(plane) => {
                let flow = plane.flows.get_mut(&id).expect("binding checked above");
                if flow.data_started
                    || flow.reset_requested
                    || Instant::now().duration_since(flow.created) >= FLOW_BUDGET
                {
                    return Ok(false);
                }
                flow.active = false;
                flow.commit_pending = false;
                flow.tcp_connected = false;
                if !client {
                    self.control
                        .send(Message::FlowReject {
                            flow_id: id,
                            generation,
                            reason,
                        })
                        .await?;
                    return Ok(true);
                }
                let Some(next) = generation.checked_add(1) else {
                    return Ok(false);
                };
                flow.generation = next;
                if let Some(task) = flow.task.take() {
                    task.abort();
                }
                flow.outgoing = None;
                flow.binding_deadline = None;
                flow.tcp_key = None;
                flow.retry_at = Some(Instant::now() + ATTEMPT_BUDGET);
                let recovery = flow.recovery.get_or_insert(Recovery {
                    started: Instant::now(),
                    from: Some(Candidate::Tcp),
                    attempts: 0,
                });
                recovery.attempts += 1;
                crate::info!(
                    "flow_recovery_start id={id} generation={next} kind=opening from=Tcp reason={reason:?}"
                );
            }
        }
        Ok(true)
    }

    /// Delivery evidence: a current-generation packet reached the TUN
    /// (`peer_packet`), or the probe round-trip confirmed the new binding
    /// (`probe`) for a flow too quiet to show data. Commit alone is
    /// readiness, not proof the flow carries traffic.
    pub(crate) fn recovery_delivered(&mut self, id: u64, stage: &str) {
        let (generation, destination, recovery) = match &mut self.plane {
            Plane::Channels(plane) => {
                let Some(flow) = plane.flows.get_mut(&id) else {
                    return;
                };
                // A vanished channel means the destination is unknown mid-rebind;
                // never guess a candidate in the journal.
                let destination = flow
                    .channel
                    .and_then(|channel| plane.channels.get(&channel))
                    .map(|handle| handle.candidate)
                    .map_or_else(|| "unknown".to_string(), |candidate| candidate.to_string());
                (flow.generation, destination, flow.recovery.take())
            }
            Plane::Tcp(plane) => {
                let Some(flow) = plane.flows.get_mut(&id) else {
                    return;
                };
                (
                    flow.generation,
                    Candidate::Tcp.to_string(),
                    flow.recovery.take(),
                )
            }
        };
        if let Some(recovery) = recovery {
            crate::info!(
                "flow_recovery_restored id={id} generation={generation} stage={stage} from={:?} to={destination} attempts={} elapsed_ms={}",
                recovery.from,
                recovery.attempts,
                recovery.started.elapsed().as_millis()
            );
        }
    }

    pub(crate) async fn flush_flow(&mut self, id: u64) -> Result<()> {
        let mut closed = false;
        let mut full = false;
        let Some(generation) = self.flow_generation(id) else {
            return Ok(());
        };
        match &mut self.plane {
            Plane::Channels(plane) => {
                let Some(flow) = plane.flows.get_mut(&id).filter(|flow| flow.active) else {
                    return Ok(());
                };
                loop {
                    let queued = plane.selector.as_ref().is_some_and(|s| s.has_queued(id))
                        || !flow.pending.is_empty();
                    if !queued {
                        break;
                    }
                    if let Some(tcp) = flow.tcp.as_ref() {
                        let Some(send) = tcp.out.as_ref() else {
                            closed = true;
                            break;
                        };
                        match send.try_reserve() {
                            Ok(permit) => {
                                let Some(packet) = plane
                                    .selector
                                    .as_mut()
                                    .and_then(|s| s.pop_packet(id))
                                    .or_else(|| flow.pending.pop_front())
                                else {
                                    // has_queued may be true while the
                                    // selector stage holds the queue.
                                    break;
                                };
                                if packet.is_empty() {
                                    continue;
                                }
                                let len = packet.len();
                                permit.send(packet);
                                flow.data_started = true;
                                self.stats.record_tx(len, true);
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                full = true;
                                break;
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                closed = true;
                                break;
                            }
                        }
                    } else {
                        let Some(handle) = flow
                            .channel
                            .and_then(|channel| plane.channels.get(&channel))
                        else {
                            closed = true;
                            break;
                        };
                        match handle.command.try_reserve() {
                            Ok(permit) => {
                                let Some(packet) = plane
                                    .selector
                                    .as_mut()
                                    .and_then(|s| s.pop_packet(id))
                                    .or_else(|| flow.pending.pop_front())
                                else {
                                    // has_queued may be true while the
                                    // selector stage holds the queue.
                                    break;
                                };
                                if packet.is_empty() {
                                    continue;
                                }
                                let len = packet.len();
                                permit.send(super::TaskCommand::Data {
                                    flow_id: id,
                                    generation,
                                    packet,
                                });
                                flow.data_started = true;
                                self.stats.record_tx(len, true);
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                full = true;
                                break;
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                closed = true;
                                break;
                            }
                        }
                    }
                }
            }
            Plane::Tcp(plane) => {
                let Some(flow) = plane.flows.get_mut(&id).filter(|flow| flow.active) else {
                    return Ok(());
                };
                while !flow.pending.is_empty() {
                    let Some(send) = flow.outgoing.as_ref() else {
                        closed = true;
                        break;
                    };
                    match send.try_reserve() {
                        Ok(permit) => {
                            let packet = flow.pending.pop_front().expect("queue checked above");
                            let len = packet.len();
                            permit.send(packet);
                            flow.data_started = true;
                            self.stats.record_tx(len, true);
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            full = true;
                            break;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            closed = true;
                            break;
                        }
                    }
                }
            }
        }
        if full {
            self.flush_at
                .get_or_insert_with(|| Instant::now() + std::time::Duration::from_millis(10));
        }
        if closed && !Box::pin(self.retry_flow(id, generation, Reason::ChannelFailed)).await? {
            self.close_flow(id, true).await?;
        }
        Ok(())
    }

    pub(crate) async fn flush_pending(&mut self) -> Result<()> {
        self.flush_at = None;
        let ids: Vec<_> = match &self.plane {
            Plane::Channels(plane) => plane
                .flows
                .iter()
                .filter(|(id, flow)| {
                    flow.active
                        && (!flow.pending.is_empty()
                            || plane.selector.as_ref().is_some_and(|s| s.has_queued(**id)))
                })
                .map(|(&id, _)| id)
                .collect(),
            Plane::Tcp(plane) => plane
                .flows
                .iter()
                .filter(|(_, flow)| flow.active && !flow.pending.is_empty())
                .map(|(&id, _)| id)
                .collect(),
        };
        for id in ids {
            self.flush_flow(id).await?;
        }
        Ok(())
    }

    pub(crate) async fn poll_recovery(&mut self, now: Instant) -> Result<()> {
        let Plane::Tcp(plane) = &mut self.plane else {
            return Ok(());
        };
        if plane.server_ip.is_none() {
            return Ok(());
        }
        let due: Vec<_> = plane
            .flows
            .iter()
            .filter(|(_, flow)| flow.retry_at.is_some_and(|at| now >= at))
            .map(|(&id, flow)| (id, flow.generation, flow.key))
            .collect();
        for (id, generation, key) in due {
            if let Plane::Tcp(plane) = &mut self.plane {
                let flow = plane.flows.get_mut(&id).expect("flow collected above");
                flow.retry_at = None;
                flow.binding_deadline = Some(now + ATTEMPT_BUDGET);
            }
            self.control
                .send(Message::Open {
                    id,
                    generation,
                    flow: key,
                })
                .await?;
        }
        Ok(())
    }
}

pub(super) fn recovery_expired(recovery: &Option<Recovery>, now: Instant) -> bool {
    recovery
        .as_ref()
        .is_some_and(|r| now.duration_since(r.started) >= RECOVERY_BUDGET)
}
