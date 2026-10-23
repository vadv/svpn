//! UDP channel transport tasks. Every strategy gives the
//! session the same interface: a command channel + an event stream.
//! `Event::Wire` carries the channel sealed record ([seq 8][ct][tag 16])
//! AFTER removing the strategy camouflage; the sender applies it. The AEAD
//! state (`Channel`) stays in the session loop — the task only moves bytes.
//!
//! Datagram strategies (plain/mosh/obfs) and the server-side QUIC relay run
//! on tokio; WebRTC drives str0m by UDP readiness, commands, and
//! ICE/DTLS/SCTP timers without blocking waits between outbound records.
#![allow(dead_code)]

use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::profile::{self, Profile};
use crate::quic;
use crate::webrtc;

/// Driver event queue capacity.
pub const EVENTS_QUEUE: usize = 1024;

/// Session command to the transport task.
pub enum Command {
    /// Send a sealed record (the task applies the camouflage).
    Send(Vec<u8>),
    /// Stop the task and release resources; it is idiomatic to send Close
    /// before dropping `Io` — the task also ends when the channels break.
    Close,
}

/// Transport task event for the session.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// Received sealed record after removing the camouflage.
    Wire(Vec<u8>),
    /// Transport is dead: the reason for `channel_failed`/channel closure.
    /// If full, task exit closes the command receiver instead of queuing Failed.
    Failed(String),
}

/// Transport task interface: commands out, events into the session.
/// Dropping it aborts all owned transport tasks, including pending I/O.
pub struct Io {
    pub command: mpsc::Sender<Command>,
    /// The record queue is bounded: a lagging session loses Wire records
    /// (the channel is datagram-based — a loss equals a lost packet), but
    /// the network cannot grow memory without a limit.
    pub events: mpsc::Receiver<Event>,
    pub tasks: JoinSet<()>,
}

impl Io {
    /// Await socket release before another candidate reuses its fixed port.
    pub async fn close(&mut self) {
        self.tasks.shutdown().await;
    }
}

/// Datagram transport of a profile (plain/mosh/obfs) on a ready socket.
/// `dest = None` — server mode: the peer address is learned from the
/// first valid packet (the client initiates, NAT-safe); Some — client.
/// `Profile::Plain` also serves as the server side of the QUIC channel:
/// accept_relay delivers records to the loopback socket as plain datagrams.
pub fn datagram(socket: UdpSocket, profile: Profile, dest: Option<SocketAddr>) -> Io {
    let (command_tx, mut command_rx) = mpsc::channel::<Command>(64);
    let (events_tx, events_rx) = mpsc::channel::<Event>(EVENTS_QUEUE);
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let mut peer = dest;
        let mut wire = vec![0u8; profile::MAX_WIRE];
        let mut dropped = 0u64;
        let reason = loop {
            tokio::select! {
                command = command_rx.recv() => match command {
                    Some(Command::Send(mut bytes)) => {
                        let Some(target) = peer else {
                            break "send before peer learned".into();
                        };
                        if let Err(e) = profile.wrap_in_place(&mut bytes) {
                            break format!("wrap: {e}");
                        }
                        if let Err(e) = socket.send_to(&bytes, target).await {
                            break format!("send: {e}");
                        }
                    }
                    Some(Command::Close) | None => break String::new(),
                },
                packet = socket.recv_from(&mut wire) => match packet {
                    Ok((len, from)) => {
                        if peer.is_some_and(|learned| learned != from) {
                            continue; // foreign source: ignore
                        }
                        // Cheap length check before copying: scanner junk
                        // is not allocated. Other profiles check the same
                        // inside unwrap_in_place.
                        if !(profile::MIN_WIRE..=profile::MAX_WIRE).contains(&len) {
                            dropped += 1;
                            continue;
                        }
                        let mut bytes = wire[..len].to_vec();
                        match profile.unwrap_in_place(&mut bytes) {
                            Ok(()) => {
                                if peer.is_none() {
                                    // Valid record: the peer address is now
                                    // fixed for the channel's lifetime.
                                    peer = Some(from);
                                }
                                if events_tx.try_send(Event::Wire(bytes)).is_err() {
                                    dropped += 1;
                                }
                            }
                            Err(_) => dropped += 1,
                        }
                    }
                    Err(e) => break format!("recv: {e}"),
                },
            }
        };
        finish(&events_tx, dropped, reason);
    });
    Io {
        command: command_tx,
        events: events_rx,
        tasks,
    }
}

/// Server side of the QUIC channel: a loopback socket + one accept_relay.
/// `endpoint` — the shared QUIC listener; every connection is relayed to
/// its own channel loopback socket (see `quic::accept_relay`).
pub fn quic_server(endpoint: quinn::Endpoint, loopback: UdpSocket) -> Io {
    let target = loopback.local_addr().expect("bound socket has local addr");
    let mut io = datagram(loopback, Profile::Plain, None);
    io.tasks.spawn(async move {
        if let Err(e) = quic::accept_relay(&endpoint, target).await {
            crate::debug!("QUIC relay ended: {e:#}");
        }
    });
    io
}

/// Client side of the QUIC channel: owns the tunnel, records go as
/// HTTP datagrams without extra camouflage.
pub fn quic_client(tunnel: quic::Tunnel) -> Io {
    let (command_tx, mut command_rx) = mpsc::channel::<Command>(64);
    let (events_tx, events_rx) = mpsc::channel::<Event>(EVENTS_QUEUE);
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let mut dropped = 0u64;
        let reason = loop {
            tokio::select! {
                command = command_rx.recv() => match command {
                    Some(Command::Send(bytes)) => {
                        if let Err(e) = tunnel.send(&bytes) {
                            break format!("send: {e:#}");
                        }
                    }
                    Some(Command::Close) | None => {
                        tunnel.close();
                        break String::new();
                    }
                },
                datagram = tunnel.recv() => match datagram {
                    Ok(bytes) => {
                        if events_tx.try_send(Event::Wire(bytes.to_vec())).is_err() {
                            dropped += 1;
                        }
                    }
                    Err(e) => {
                        tunnel.close();
                        break format!("recv: {e:#}");
                    }
                },
            }
        };
        finish(&events_tx, dropped, reason);
    });
    Io {
        command: command_tx,
        events: events_rx,
        tasks,
    }
}

/// Drives str0m by events: new commands do not wait for incoming packets or a tick.
pub fn webrtc_channel(mut peer: webrtc::Peer) -> Io {
    let (command_tx, mut command_rx) = mpsc::channel::<Command>(64);
    let (events_tx, events_rx) = mpsc::channel::<Event>(EVENTS_QUEUE);
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let mut dropped = 0u64;
        // Bounded queue for before DCEP and when the SCTP send buffer fills.
        let mut outbox: std::collections::VecDeque<Vec<u8>> = Default::default();
        let result: anyhow::Result<()> = async {
            loop {
                let deadline = peer.poll().await?;
                while let Some(bytes) = peer.take_received() {
                    if events_tx.try_send(Event::Wire(bytes)).is_err() {
                        dropped += 1;
                    }
                }
                if peer.is_ready()
                    && let Some(bytes) = outbox.front()
                    && peer.write(bytes)?
                {
                    outbox.pop_front();
                    continue; // After each str0m mutation, flush all Transmit.
                }
                tokio::select! {
                    command = command_rx.recv() => match command {
                        Some(Command::Send(bytes)) => {
                            // Unreliable channel: overload drops a datagram, not flows.
                            if outbox.len() < 64 {
                                outbox.push_back(bytes);
                            } else {
                                crate::debug!("webrtc send queue full: datagram dropped");
                            }
                        },
                        Some(Command::Close) | None => return Ok(()),
                    },
                    _ = events_tx.closed() => return Ok(()),
                    result = peer.input(deadline) => result?,
                }
            }
        }
        .await;
        if dropped > 0 {
            crate::info!("channel: {dropped} records lost — session could not keep up");
        }
        if let Err(error) = result {
            let _ = events_tx.try_send(Event::Failed(format!("WebRTC: {error:#}")));
        }
    });
    Io {
        command: command_tx,
        events: events_rx,
        tasks,
    }
}

/// Exit path shared by the datagram-style drivers: report records lost to a
/// lagging session, then queue the failure; an empty reason is a clean Close.
fn finish(events_tx: &mpsc::Sender<Event>, dropped: u64, reason: String) {
    if dropped > 0 {
        crate::info!("channel: {dropped} records lost — session could not keep up");
    }
    if !reason.is_empty() {
        let _ = events_tx.try_send(Event::Failed(reason));
    }
}
