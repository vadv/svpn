//! Channel pump: one task per channel — probe establishment, then the
//! DATA/keepalive loop until a transport error or shutdown.

use anyhow::{Result, bail};
use tokio::{
    sync::{mpsc, oneshot},
    time::MissedTickBehavior,
};

use crate::selector::Candidate;
use crate::udp::Incoming;
use crate::{channel, drivers, probe};

use super::{CONSENT_TIMEOUT, KEEPALIVE};

/// Event from a channel task to the session.
pub enum TaskEvent {
    /// Result of the async channel handshake (QUIC connect): None = failure.
    Handshake {
        attempt: u64,
        channel: u64,
        candidate: Candidate,
        key: [u8; 16],
        max_wire: u16,
        io: Option<drivers::Io>,
    },
    /// Establishment (probes A/AB/B + size) succeeded.
    Established { channel: u64 },
    /// Task finished: channel lost.
    Failed { channel: u64, reason: String },
    /// FLOW_ECHO from the peer: the server verifies the challenge.
    FlowEcho {
        channel: u64,
        flow_id: u64,
        echo: [u8; 16],
    },
}

/// Command from the session to a channel task.
pub enum TaskCommand {
    /// Outgoing flow IP packet (the task fragments and encrypts it).
    Data(u64, Vec<u8>),
    /// Control record (server FLOW_PROBE).
    Record(channel::Record),
}

pub struct ChannelHandle {
    pub candidate: Candidate,
    /// Kept so a reused channel answers a fresh `ChannelPrepare`
    /// with its real key.
    pub key: [u8; 16],
    /// Handshake done; a reused channel never re-emits `Established`.
    pub established: bool,
    pub cancel: Option<oneshot::Sender<()>>,
    pub command: mpsc::Sender<TaskCommand>,
    pub task: tokio::task::JoinHandle<()>,
    pub relay: Option<tokio::task::AbortHandle>,
}

impl ChannelHandle {
    pub(crate) async fn stop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        } else {
            self.task.abort();
        }
        let _ = (&mut self.task).await;
        if let Some(relay) = self.relay.take() {
            relay.abort();
        }
    }
}

impl Drop for ChannelHandle {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(relay) = &self.relay {
            relay.abort();
        }
    }
}

/// Single-channel task: probe establishment, then the DATA/keepalive pump
/// until a transport error or shutdown.
/// Fields come from the `channel_ready` control message.
pub struct ChannelReadyParams {
    pub attempt: u64,
    pub channel: u64,
    pub port: u16,
    pub key: [u8; 16],
    pub max_wire: u16,
    pub hello: Option<String>,
    pub relay: Option<u16>,
}

/// Shared channel-task context: event streams and channel parameters.
pub struct ChannelCtx {
    pub events: mpsc::Sender<TaskEvent>,
    pub incoming: mpsc::Sender<Incoming>,
    pub client: bool,
    pub channel_id: u64,
    pub max_wire: u16,
}

pub(crate) async fn channel_task(
    mut io: drivers::Io,
    mut chan: channel::Channel,
    mut command: mpsc::Receiver<TaskCommand>,
    ctx: ChannelCtx,
    cancel: oneshot::Receiver<()>,
) {
    let result = tokio::select! {
        result = pump(&mut io, &mut chan, &mut command, &ctx) => Some(result),
        _ = cancel => None,
    };
    io.close().await;
    let Some(result) = result else { return };
    match result {
        Err(reason) => {
            let _ = ctx
                .events
                .send(TaskEvent::Failed {
                    channel: ctx.channel_id,
                    reason: format!("{reason:#}"),
                })
                .await;
        }
        Ok(()) => crate::debug!("channel_task ok-exit id={}", ctx.channel_id),
    }
}

pub async fn pump(
    io: &mut drivers::Io,
    chan: &mut channel::Channel,
    command: &mut mpsc::Receiver<TaskCommand>,
    ctx: &ChannelCtx,
) -> Result<()> {
    let cap = usize::from(ctx.max_wire);
    // Probes (A/AB/B + size) take several RTTs; the deadline equals the
    // selector's attempt budget: a dead candidate must enter hold-down within
    // ATTEMPT_BUDGET, otherwise four 20s candidates never overlap in
    // hold-down and auto mode never reaches TCP within FLOW_BUDGET.
    let deadline = tokio::time::Instant::now() + crate::selector::ATTEMPT_BUDGET;
    if ctx.client {
        probe::client(io, chan, cap, deadline).await?;
    } else {
        probe::server(io, chan, cap, deadline).await?;
    }
    ctx.events
        .send(TaskEvent::Established {
            channel: ctx.channel_id,
        })
        .await
        .ok();
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_seen = tokio::time::Instant::now();
    let mut next_packet_id: u64 = 0;
    let chunk_cap = usize::from(ctx.max_wire).saturating_sub(45).max(512);
    loop {
        let silence = last_seen + CONSENT_TIMEOUT;
        tokio::select! {
            cmd = command.recv() => match cmd {
                Some(TaskCommand::Data(flow_id, packet)) => {
                    let packet_id = next_packet_id;
                    next_packet_id += 1;
                    for record in channel::fragment_packet(flow_id, packet_id, &packet, chunk_cap)? {
                        let sealed = chan.seal(&record)?;
                        io.command.send(drivers::Command::Send(sealed)).await?;
                    }
                }
                Some(TaskCommand::Record(record)) => {
                    let sealed = chan.seal(&record)?;
                    io.command.send(drivers::Command::Send(sealed)).await?;
                }
                None => return Ok(()),
            },
            event = io.events.recv() => match event {
                Some(drivers::Event::Wire(bytes)) => {
                    let Some(record) = chan.open(&bytes, std::time::Instant::now())? else {
                        continue;
                    };
                    last_seen = tokio::time::Instant::now();
                    match record {
                        channel::Record::Data { .. } => {
                            if let Some(packet) = chan.assemble(&record, std::time::Instant::now())? {
                                ctx.incoming.send(Incoming { id: flow_id_of(&record), channel: Some(ctx.channel_id), packet }).await.ok();
                            }
                        }
                        channel::Record::FlowProbe { flow_id, challenge } => {
                            let sealed = chan.seal(&channel::Record::FlowEcho {
                                flow_id,
                                echo: challenge,
                            })?;
                            io.command.send(drivers::Command::Send(sealed)).await?;
                        }
                        channel::Record::FlowEcho { flow_id, echo } => {
                            ctx.events
                                .send(TaskEvent::FlowEcho {
                                    channel: ctx.channel_id,
                                    flow_id,
                                    echo,
                                })
                                .await
                                .ok();
                        }
                        channel::Record::Keepalive => {}
                        _ => {} // probes are done: ignore repeats
                    }
                }
                Some(drivers::Event::Failed(reason)) => bail!("{reason}"),
                None => bail!("transport task closed"),
            },
            _ = keepalive.tick() => {
                let sealed = chan.seal(&channel::Record::Keepalive)?;
                io.command.send(drivers::Command::Send(sealed)).await?;
            }
            _ = tokio::time::sleep_until(silence) => {
                bail!("consent expired");
            }
        }
    }
}

fn flow_id_of(record: &channel::Record) -> u64 {
    match record {
        channel::Record::Data { flow_id, .. } => *flow_id,
        _ => unreachable!("flow_id_of takes DATA records only"),
    }
}
