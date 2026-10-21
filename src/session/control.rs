//! Control-channel dispatch and the channel handshake: `channel_prepare`,
//! `channel_ready`, failure propagation, and verification.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant as StdInstant},
};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};

use crate::control::{Message, Strategy};
use crate::link_io;
use crate::selector::{Candidate, Reason, Selector};
use crate::{channel, crypto, drivers, quic, webrtc};

use super::pump::channel_task;
use super::{
    CHANNEL_QUEUE, ChannelCtx, ChannelHandle, ChannelReadyParams, PacketIo, Plane, Readiness,
    Session, TaskEvent, candidate_strategy, candidate_strategy_from, prefixed, strategy_max_wire,
    strategy_profile,
};

impl Session {
    pub async fn dispatch_control(&mut self, message: Message) -> Result<()> {
        match message {
            Message::Heartbeat { stats } => {
                crate::debug!("heartbeat received stats={stats:?}");
            }
            Message::ServerHooks { .. } => {
                bail!("unexpected server_hooks in session");
            }
            Message::HookResult { .. } => {
                bail!("unexpected hook_result in session");
            }
            Message::ChannelPrepare {
                attempt,
                strategy,
                hello,
            } => self.channel_prepare(attempt, strategy, hello).await?,
            Message::ChannelReady {
                attempt,
                channel,
                port,
                key,
                max_wire,
                hello,
                relay,
            } => {
                self.channel_ready(ChannelReadyParams {
                    attempt,
                    channel,
                    port,
                    key,
                    max_wire,
                    hello,
                    relay,
                })
                .await?;
            }
            Message::ChannelFailed {
                attempt,
                channel,
                reason,
            } => {
                self.channel_failed(attempt, channel, reason).await?;
            }
            Message::ChannelVerified { channel } => self.channel_verified(channel).await?,
            Message::FlowOpen {
                flow_id,
                flow,
                channel,
            } => {
                self.flow_open(flow_id, flow, channel).await?;
            }
            Message::FlowChannel { flow_id, channel } => {
                self.flow_channel(flow_id, channel).await?;
            }
            Message::FlowOpened {
                flow_id, channel, ..
            } => self.flow_opened(flow_id, channel).await?,
            Message::FlowReject { flow_id, reason } => self.flow_rejected(flow_id, reason).await?,
            Message::Commit { flow_id, .. } => self.commit(flow_id).await?,
            Message::Committed { flow_id } => self.committed(flow_id).await?,
            Message::FlowClose { flow_id } => {
                if self
                    .round
                    .as_ref()
                    .is_some_and(|round| round.tcp_id == Some(flow_id))
                {
                    self.tcp_failed(flow_id).await?;
                } else {
                    self.close_flow(flow_id, false).await?;
                }
            }
            // ── EPIC-003 TCP mode ──
            Message::Open { id, flow } if matches!(self.plane, Plane::Tcp(_)) => {
                self.tcp_open_server(id, flow).await?
            }
            Message::Opened {
                id,
                port,
                key,
                token,
            } if matches!(self.plane, Plane::Tcp(_)) => {
                self.tcp_opened_client(id, port, key, token).await?
            }
            Message::Close { id } if matches!(self.plane, Plane::Tcp(_)) => {
                if self
                    .round
                    .as_ref()
                    .is_some_and(|round| round.tcp_id == Some(id))
                {
                    self.tcp_failed(id).await?;
                } else {
                    self.tcp_close(id).await?;
                }
            }
            // ── TCP candidate in channel mode (I09) ──
            Message::Open { id, flow } if matches!(self.plane, Plane::Channels(_)) => {
                self.channels_tcp_open(id, flow).await?
            }
            Message::Opened {
                id,
                port,
                key,
                token,
            } if matches!(self.plane, Plane::Channels(_)) => {
                self.channels_tcp_opened(id, port, key, token).await?
            }
            other => {
                let _ = other;
                bail!("unexpected control message");
            }
        }
        Ok(())
    }

    /// Server: allocate strategy resources and reply `channel_ready`.
    pub async fn channel_prepare(
        &mut self,
        attempt: u64,
        strategy: Strategy,
        hello: Option<String>,
    ) -> Result<()> {
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("channel_prepare outside channels mode");
        };
        let Some(&port) = plane.ports.get(&strategy) else {
            self.control
                .send(Message::ChannelFailed {
                    attempt: Some(attempt),
                    channel: None,
                    reason: Reason::Unsupported,
                })
                .await?;
            return Ok(());
        };
        let key = crypto::random().context("channel key generation failed")?;
        let channel_id = plane.next_channel_id;
        plane.next_channel_id += 1;
        let max_wire = strategy_max_wire(strategy);
        let candidate = candidate_strategy_from(strategy);
        let mut server_hello = None;
        let mut relay = None;
        let mut relay_task = None;
        let io = async {
            match strategy {
                Strategy::Mosh | Strategy::Obfs | Strategy::Plain => {
                    let socket = UdpSocket::bind((plane.bind, port))
                        .await
                        .with_context(|| format!("bind {strategy:?} channel on port {port}"))?;
                    // Burst absorption: TUN bursts overflow the kernel default
                    // receive buffer and drop datagrams before the pump reads
                    // them (same rationale as the WebRTC socket, W01).
                    socket2::SockRef::from(&socket)
                        .set_recv_buffer_size(1024 * 1024)
                        .context("channel receive buffer")?;
                    Ok::<drivers::Io, anyhow::Error>(drivers::datagram(
                        socket,
                        strategy_profile(strategy),
                        None,
                    ))
                }
                Strategy::Quic => {
                    let (endpoint, _) = plane
                        .quic
                        .as_ref()
                        .context("QUIC strategy requires server endpoint")?;
                    let loopback = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                        .await
                        .context("bind QUIC channel loopback")?;
                    relay = Some(
                        loopback
                            .local_addr()
                            .context("loopback socket has no local address")?
                            .port(),
                    );
                    let endpoint = endpoint.clone();
                    let target = loopback.local_addr().context("QUIC loopback address")?;
                    relay_task = Some(self.tasks.spawn(async move {
                        if let Err(error) = quic::accept_relay(&endpoint, target).await {
                            crate::debug!("QUIC relay ended: {error:#}");
                        }
                    }));
                    Ok(drivers::datagram(
                        loopback,
                        crate::profile::Profile::Plain,
                        None,
                    ))
                }
                Strategy::WebRtc => {
                    let bind = SocketAddr::from((plane.bind, port));
                    // With bind 0.0.0.0 the candidate is meaningless (0.0.0.0 is
                    // unreachable): don't publish it — the client substitutes
                    // the server address itself.
                    let public = (plane.bind != Ipv4Addr::UNSPECIFIED).then_some(bind);
                    let (mut peer, peer_hello) = webrtc::Peer::server(bind, public)
                        .with_context(|| format!("WebRTC server peer on {bind}"))?;
                    // ICE/DTLS is bidirectional: the server needs the client's
                    // credentials from its Hello, otherwise the handshake never
                    // completes and the probes hit the deadline.
                    let client_hello: webrtc::Hello = serde_json::from_str(
                        hello
                            .as_deref()
                            .context("WebRTC server requires client hello")?,
                    )
                    .context("deserialize WebRTC client hello")?;
                    peer.configure(&client_hello)
                        .context("configure WebRTC server peer")?;
                    server_hello =
                        Some(serde_json::to_string(&peer_hello).context("serialize WebRTC hello")?);
                    Ok(drivers::webrtc_channel(peer))
                }
            }
        }
        .await;
        let io = match io {
            Ok(io) => io,
            Err(error) => {
                // A liveness round and a selector attempt can target the same
                // strategy concurrently: the second bind fails. One dead
                // candidate must not kill the whole session.
                crate::info!(
                    "{} {} candidate failed to start on port {port} — {error:#}",
                    prefixed(self.tag(), "channel"),
                    candidate.as_str()
                );
                self.control
                    .send(Message::ChannelFailed {
                        attempt: Some(attempt),
                        channel: None,
                        reason: Reason::ChannelFailed,
                    })
                    .await?;
                return Ok(());
            }
        };
        self.control
            .send(Message::ChannelReady {
                attempt,
                channel: channel_id,
                port,
                key,
                max_wire,
                hello: server_hello,
                relay,
            })
            .await?;
        self.spawn_channel(channel_id, candidate, io, key, max_wire, relay_task)?;
        if let Plane::Channels(plane) = &mut self.plane {
            plane.prepared.insert(attempt, channel_id);
        }
        Ok(())
    }

    pub(crate) async fn stop_channel(&mut self, id: u64) {
        if let Plane::Channels(plane) = &mut self.plane
            && let Some(handle) = plane.channels.get_mut(&id)
        {
            handle.stop().await;
        }
    }

    fn spawn_channel(
        &mut self,
        channel_id: u64,
        candidate: Candidate,
        io: drivers::Io,
        key: [u8; 16],
        max_wire: u16,
        relay: Option<tokio::task::AbortHandle>,
    ) -> Result<()> {
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("spawn_channel outside channels mode");
        };
        let (command_tx, command_rx) = mpsc::channel(CHANNEL_QUEUE);
        let (cancel, cancelled) = oneshot::channel();
        // Only the client has a selector.
        let client = plane.selector.is_some();
        let task = tokio::spawn(channel_task(
            io,
            channel::Channel::new(key, channel_id, client),
            command_rx,
            ChannelCtx {
                events: self.task_events.0.clone(),
                incoming: self.incoming.0.clone(),
                client,
                channel_id,
                max_wire,
            },
            cancelled,
        ));
        plane.channels.insert(
            channel_id,
            ChannelHandle {
                candidate,
                command: command_tx,
                cancel: Some(cancel),
                task,
                relay,
            },
        );
        crate::debug!(
            "channel_open id={channel_id} candidate={candidate:?} role={}",
            if client { "client" } else { "server" }
        );
        Ok(())
    }

    /// Client: connect the strategy transport and start the channel task.
    pub async fn channel_ready(&mut self, params: ChannelReadyParams) -> Result<()> {
        let ChannelReadyParams {
            attempt,
            channel,
            port,
            key,
            max_wire,
            hello,
            relay,
        } = params;
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("channel_ready outside channels mode");
        };
        // N3: a round attempt binds its own candidate + peer; selector
        // attempts keep the pre-round path via `plane.attempt`.
        let (candidate, mut peer) = if let Some(round) = self.round.as_mut()
            && let Some(rc) = round.pending.get_mut(&attempt)
        {
            rc.channel = Some(channel);
            crate::debug!("round: channel_ready bound attempt={attempt} channel={channel}");
            (rc.candidate, rc.peer.take())
        } else if let Some(challenge) = self.challenge.as_mut()
            && let Some(challenger) = challenge.attempts.get_mut(&attempt)
        {
            if challenger.channel.is_some() {
                return Ok(());
            }
            (challenger.candidate, challenger.peer.take())
        } else {
            let Some((pending_attempt, candidate, pending_channel, peer)) = plane.attempt.as_mut()
            else {
                return Ok(());
            };
            if *pending_attempt != attempt || pending_channel.is_some() {
                return Ok(());
            }
            *pending_channel = Some(channel);
            (*candidate, peer.take())
        };
        let Some(_) = plane.selector.as_mut() else {
            bail!("channel_ready on server");
        };
        let server_ip = plane.server_ip.context("client requires server address")?;
        let strategy = candidate_strategy(candidate);
        let io = match strategy {
            Strategy::Mosh | Strategy::Obfs | Strategy::Plain => {
                let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                    .await
                    .context("bind channel UDP socket")?;
                // Burst absorption on the client downlink (see the server
                // channel socket above).
                socket2::SockRef::from(&socket)
                    .set_recv_buffer_size(1024 * 1024)
                    .context("channel receive buffer")?;
                drivers::datagram(
                    socket,
                    strategy_profile(strategy),
                    Some(SocketAddr::from((server_ip, port))),
                )
            }
            Strategy::Quic => {
                let pin = plane
                    .quic_pin
                    .context("QUIC strategy requires certificate pin in endpoints")?;
                let relay = relay.context("QUIC channel requires relay port")?;
                let target = SocketAddr::from((Ipv4Addr::LOCALHOST, relay));
                // Connect must not block the session loop: with UDP
                // unreachable, a hung connect would stall the heartbeat
                // exchange (the server would die by its own timeout). The
                // handshake moves to a task; the result arrives as an event.
                let events = self.task_events.0.clone();
                let remote = SocketAddr::from((server_ip, port));
                self.tasks.spawn(async move {
                    // Selector poll cancels preparation after ATTEMPT_BUDGET —
                    // the margin on top keeps the task from hanging forever
                    // after a failure.
                    let budget = crate::selector::ATTEMPT_BUDGET + Duration::from_secs(1);
                    let io = match tokio::time::timeout(
                        budget,
                        quic::connect(remote, quic::SNI, pin, target),
                    )
                    .await
                    {
                        Ok(Ok(tunnel)) => Some(drivers::quic_client(tunnel)),
                        _ => None,
                    };
                    let _ = events
                        .send(TaskEvent::Handshake {
                            attempt,
                            channel,
                            candidate,
                            key,
                            max_wire,
                            io,
                        })
                        .await;
                });
                return Ok(());
            }
            Strategy::WebRtc => {
                let mut peer = peer
                    .take()
                    .context("WebRTC channel requires prepared peer")?;
                let mut hello: webrtc::Hello = serde_json::from_str(
                    hello
                        .as_deref()
                        .context("WebRTC channel requires server hello")?,
                )
                .context("deserialize WebRTC hello")?;
                // The server's bind address may be private behind NAT; use the SSH target.
                hello.candidate = Some(SocketAddr::from((server_ip, port)));
                peer.configure(&hello).context("configure WebRTC peer")?;
                drivers::webrtc_channel(peer)
            }
        };
        if self
            .challenge
            .as_ref()
            .is_some_and(|challenge| challenge.owns(attempt))
        {
            self.challenge_channel_bound(attempt, channel)?;
            self.challenge_drive(tokio::time::Instant::now()).await?;
        }
        self.finish_channel_ready(attempt, channel, candidate, io, key, max_wire)
            .await
    }

    /// Common tail of channel preparation: the selector learns readiness,
    /// the channel task starts, and the selector's actions run.
    pub(crate) async fn finish_channel_ready(
        &mut self,
        attempt: u64,
        channel: u64,
        candidate: Candidate,
        io: drivers::Io,
        key: [u8; 16],
        max_wire: u16,
    ) -> Result<()> {
        let actions = {
            let Plane::Channels(plane) = &mut self.plane else {
                bail!("finish_channel_ready outside channels mode");
            };
            let current_round = self.round.as_ref().is_some_and(|round| {
                round
                    .pending
                    .get(&attempt)
                    .is_some_and(|rc| rc.channel == Some(channel))
            });
            let current_selector = plane
                .attempt
                .as_ref()
                .is_some_and(|pending| pending.0 == attempt && pending.2 == Some(channel));
            let current_challenge = self.challenge.as_ref().is_some_and(|challenge| {
                challenge
                    .attempts
                    .get(&attempt)
                    .is_some_and(|challenger| challenger.channel == Some(channel))
            });
            if !current_round && !current_selector && !current_challenge {
                return Ok(());
            }
            if current_selector {
                plane.attempt = None;
            }
            if current_challenge {
                vec![]
            } else {
                let Some(selector) = plane.selector.as_mut() else {
                    bail!("finish_channel_ready on server");
                };
                selector.channel_ready(candidate, attempt, channel, StdInstant::now())
            }
        };
        self.spawn_channel(channel, candidate, io, key, max_wire, None)?;
        self.execute_actions(actions).await
    }

    pub async fn channel_failed(
        &mut self,
        attempt: Option<u64>,
        channel: Option<u64>,
        reason: Reason,
    ) -> Result<()> {
        let channel = channel
            .or_else(|| match &self.plane {
                Plane::Channels(plane) => attempt.and_then(|id| plane.prepared.get(&id).copied()),
                Plane::Tcp(_) => None,
            })
            .or_else(|| attempt.and_then(|id| self.round.as_ref()?.pending.get(&id)?.channel))
            .or_else(|| attempt.and_then(|id| self.challenge.as_ref()?.attempts.get(&id)?.channel));
        if let Some(Readiness::Verified(Some(verified))) = self.readiness {
            ensure!(
                channel != Some(verified),
                "verified preflight channel lost before readiness"
            );
        }
        // A failed borrowed transport still needs ordinary active-flow cleanup.
        let round_attempt = match attempt {
            Some(attempt) => self
                .round
                .as_ref()
                .is_some_and(|round| round.pending.contains_key(&attempt))
                .then_some(attempt),
            None => channel.and_then(|channel| {
                self.round.as_ref().and_then(|round| {
                    round
                        .pending
                        .iter()
                        .find(|(_, rc)| rc.channel == Some(channel))
                        .map(|(attempt, _)| *attempt)
                })
            }),
        };
        if let Some(attempt) = round_attempt {
            self.round_attempt_failed(attempt, reason).await?;
        }
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("channel_failed outside channels mode");
        };
        // EPIC-016: count the failure under the channel's transport. A burst
        // riding this channel dies with it; the timer waits for the next Ready.
        if let Some(id) = channel {
            if let Some(handle) = plane.channels.get(&id) {
                let entry = self
                    .stats
                    .transport_failures
                    .entry(handle.candidate.as_str().to_owned())
                    .or_default();
                *entry = entry.saturating_add(1);
            }
            if self.burst.as_ref().is_some_and(|burst| burst.channel == id) {
                self.burst = None;
                self.health_at = None;
            }
        }
        let recheck = self.readiness == Some(Readiness::Ready)
            && self.round.is_none()
            && channel.is_some_and(|id| {
                plane.channels.get(&id).is_some_and(|handle| {
                    plane.selector.as_ref().is_some_and(|selector| {
                        selector.ready_channel(handle.candidate) == Some(id)
                    })
                })
            });
        if recheck {
            let actions = plane
                .selector
                .as_mut()
                .map(Selector::enter_checking)
                .unwrap_or_default();
            self.execute_actions(actions).await?;
        }
        if let Some(id) = channel {
            self.stop_channel(id).await;
        }
        let Plane::Channels(plane) = &mut self.plane else {
            unreachable!()
        };
        let actions = plane.channel_failed(attempt, channel, reason, StdInstant::now());
        self.execute_actions(actions).await?;
        if recheck {
            if let PacketIo::Link(io) = &self.io {
                io.events
                    .send((io.epoch, link_io::Event::Checking))
                    .await
                    .context("packet event port closed")?;
            }
            self.arm_round().await?;
        }
        self.challenge_channel_failed(attempt, channel, reason)
            .await?;
        Ok(())
    }

    async fn channel_verified(&mut self, channel: u64) -> Result<()> {
        let tag = self.tag().to_owned();
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("channel_verified outside channels mode");
        };
        if let Some(selector) = plane.selector.as_mut()
            && let Some(handle) = plane.channels.get(&channel)
        {
            let actions = selector.peer_verified(handle.candidate, channel, StdInstant::now());
            crate::info!(
                "{} {} established",
                prefixed(&tag, "channel"),
                handle.candidate.as_str()
            );
            // A round candidate with a live channel may still win the
            // verdict: mark its progress so decide_round extends the window.
            if let Some(rc) = self.round.as_mut().and_then(|round| {
                round
                    .pending
                    .values_mut()
                    .find(|rc| rc.channel == Some(channel))
            }) {
                rc.established = true;
            }
            self.execute_actions(actions).await?;
        } else {
            crate::debug!("channel_verified id={channel} role=server");
        }
        Ok(())
    }
}
