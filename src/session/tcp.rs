//! EPIC-003 TCP mode (per-flow connections) and the TCP candidate of the
//! channel mode (I09).

use std::{collections::VecDeque, net::SocketAddr};

use anyhow::{Context, Result, bail, ensure};
use tokio::sync::mpsc;

use crate::control::Message;
use crate::crypto;
use crate::link_io::{PREFLIGHT_ID, is_probe_flow};
use crate::packet::FlowKey;
use crate::selector::Reason;

use super::{CHANNEL_QUEUE, Flow, FlowTcp, Plane, Readiness, Session, TcpFlow, prefixed};

impl Session {
    /// Channel mode, server: TCP candidate `Open` — key, token, port.
    pub async fn channels_tcp_open(&mut self, flow_id: u64, flow: FlowKey) -> Result<()> {
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("channels_tcp_open outside channels mode");
        };
        ensure!(
            !is_probe_flow(flow_id) || plane.selector.is_none(),
            "preflight open on client"
        );
        ensure!(flow.valid_for(self.client_ip), "invalid flow tuple");
        if plane.flows.contains_key(&flow_id)
            || (flow_id != PREFLIGHT_ID && plane.by_key.contains_key(&flow))
        {
            return self
                .control
                .send(Message::FlowReject {
                    flow_id,
                    reason: Reason::Unsupported,
                })
                .await;
        }
        let port = plane
            .tcp_port
            .context("TCP candidate is not enabled on server")?;
        let Ok(key) = crypto::random() else {
            bail!("flow key generation failed");
        };
        let Ok(token) = crypto::random() else {
            bail!("binding token generation failed");
        };
        let (send, receiver) = mpsc::channel(CHANNEL_QUEUE);
        plane.flows.insert(
            flow_id,
            Flow {
                tcp: Some(FlowTcp {
                    key,
                    token: Some(token),
                    out: Some(send),
                    receiver: Some(receiver),
                    task: None,
                }),
                ..Flow::new(flow, tokio::time::Instant::now())
            },
        );
        plane.token_index.insert(token, flow_id);
        plane.by_key.insert(flow, flow_id);
        if !is_probe_flow(flow_id) {
            self.stats.opened_flows += 1;
            crate::debug!("flow_open role=server id={flow_id} transport=tcp");
        }
        self.control
            .send(Message::Opened {
                id: flow_id,
                port,
                key,
                token: Some(token),
            })
            .await
    }

    /// Bind TCP without user data; the selector drains it only after committed.
    pub async fn channels_tcp_opened(
        &mut self,
        flow_id: u64,
        port: u16,
        key: [u8; 16],
        token: Option<[u8; 16]>,
    ) -> Result<()> {
        if is_probe_flow(flow_id)
            && self
                .round
                .as_ref()
                .is_none_or(|round| round.tcp_id != Some(flow_id) || round.retry_at.is_some())
        {
            return Ok(());
        }
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("channels_tcp_opened outside channels mode");
        };
        let Some(flow_state) = plane.flows.get_mut(&flow_id) else {
            return Ok(());
        };
        ensure!(
            !is_probe_flow(flow_id) || flow_state.tcp.is_none(),
            "duplicate TCP preflight opened"
        );
        let token = token.context("TCP candidate requires a binding token")?;
        let server_ip = plane.server_ip.context("client requires server address")?;
        let remote = SocketAddr::from((server_ip, port));
        let (send, outgoing) = mpsc::channel::<Vec<u8>>(CHANNEL_QUEUE);
        if !is_probe_flow(flow_id)
            && !plane
                .selector
                .as_ref()
                .is_some_and(|selector| selector.tcp_binding(flow_id))
        {
            return Ok(());
        }
        let first = if is_probe_flow(flow_id) {
            self.round
                .as_ref()
                .map(|round| round.request.clone())
                .context("unexpected TCP preflight opened")?
        } else {
            // A binding may overtake Commit on SSH; never put user data in it.
            Vec::new()
        };
        send.try_send(first)
            .map_err(|_| anyhow::anyhow!("TCP binding queue closed"))?;
        flow_state.tcp = Some(FlowTcp {
            key,
            token: None,
            out: Some(send),
            receiver: None,
            task: None,
        });
        let events = self.tcp_events.0.clone();
        let failure = events.clone();
        let tag = self.tag().to_owned();
        let task = tokio::spawn(async move {
            if let Err(error) = crate::tcp::connect(
                remote,
                crate::framing::Camouflage::Ssh,
                flow_id,
                key,
                token,
                outgoing,
                events,
            )
            .await
            {
                if !is_probe_flow(flow_id) {
                    crate::error!(
                        "{} {flow_id} failed — tcp: {error:#}",
                        prefixed(&tag, "flow")
                    );
                } else {
                    crate::debug!("{} TCP failed — {error:#}", prefixed(&tag, "preflight"));
                }
                failure
                    .send(crate::tcp::Event::Failed { id: flow_id })
                    .await
                    .ok();
            }
        });
        let Plane::Channels(plane) = &mut self.plane else {
            unreachable!("plane kind cannot change");
        };
        if let Some(flow_state) = plane.flows.get_mut(&flow_id)
            && let Some(tcp) = flow_state.tcp.as_mut()
        {
            tcp.task = Some(task);
        }
        if !is_probe_flow(flow_id) {
            crate::debug!("flow_connect role=client id={flow_id} tcp_remote={remote}");
        }
        Ok(())
    }

    pub async fn tcp_open_server(&mut self, id: u64, flow: FlowKey) -> Result<()> {
        let Plane::Tcp(plane) = &mut self.plane else {
            bail!("tcp_open_server outside TCP mode");
        };
        ensure!(
            !is_probe_flow(id) || plane.server_ip.is_none(),
            "preflight open on client"
        );
        ensure!(flow.valid_for(self.client_ip), "invalid flow tuple");
        if plane.flows.contains_key(&id) || (id != PREFLIGHT_ID && plane.by_key.contains_key(&flow))
        {
            return self.control.send(Message::Close { id }).await;
        }
        let now = tokio::time::Instant::now();
        plane.by_key.insert(flow, id);
        plane.flows.insert(
            id,
            TcpFlow {
                key: flow,
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
        if !is_probe_flow(id) {
            self.stats.opened_flows += 1;
        }
        let mode = plane.mode;
        let Ok(flow_key) = crypto::random() else {
            bail!("flow key generation failed");
        };
        let Ok(token) = crypto::random() else {
            bail!("binding token generation failed");
        };
        let (send, receiver) = mpsc::channel(CHANNEL_QUEUE);
        let flow_state = plane
            .flows
            .get_mut(&id)
            .context("flow disappeared during open")?;
        flow_state.outgoing = Some(send);
        flow_state.tcp_key = Some(flow_key);
        flow_state.tcp_token = Some(token);
        flow_state.tcp_receiver = Some(receiver);
        plane.token_index.insert(token, id);
        if !is_probe_flow(id) {
            crate::debug!("flow_open role=server id={id} transport=tcp");
        }
        self.control
            .send(Message::Opened {
                id,
                port: mode.port,
                key: flow_key,
                token: Some(token),
            })
            .await
    }

    pub async fn tcp_opened_client(
        &mut self,
        id: u64,
        port: u16,
        key: [u8; 16],
        token: Option<[u8; 16]>,
    ) -> Result<()> {
        if is_probe_flow(id)
            && self
                .round
                .as_ref()
                .is_none_or(|round| round.tcp_id != Some(id) || round.retry_at.is_some())
        {
            return Ok(());
        }
        let tag = self.tag().to_owned();
        let Plane::Tcp(plane) = &mut self.plane else {
            bail!("tcp_opened_client outside TCP mode");
        };
        if !plane.flows.contains_key(&id) {
            return Ok(());
        }
        let token = token.context("TCP transport requires a binding token")?;
        let server_ip = plane.server_ip.context("client requires server address")?;
        let remote = SocketAddr::from((server_ip, port));
        let (send, outgoing) = mpsc::channel::<Vec<u8>>(CHANNEL_QUEUE);
        let flow_state = plane
            .flows
            .get_mut(&id)
            .context("flow disappeared during open")?;
        ensure!(
            !is_probe_flow(id) || flow_state.task.is_none(),
            "duplicate TCP preflight opened"
        );
        while let Some(packet) = flow_state.pending.pop_front() {
            let length = packet.len();
            let result = send.try_send(packet);
            if !is_probe_flow(id) {
                self.stats.record_tx(length, result.is_ok());
            }
            result.map_err(|_| anyhow::anyhow!("pending flow queue exceeds limit"))?;
        }
        flow_state.outgoing = Some(send);
        let camouflage = plane.mode.camouflage;
        let events = self.tcp_events.0.clone();
        let failure = events.clone();
        let task = tokio::spawn(async move {
            if let Err(error) =
                crate::tcp::connect(remote, camouflage, id, key, token, outgoing, events).await
            {
                if !is_probe_flow(id) {
                    crate::error!("{} {id} failed — {error:#}", prefixed(&tag, "flow"));
                } else {
                    crate::debug!("{} TCP failed — {error:#}", prefixed(&tag, "preflight"));
                }
                let _ = failure.send(crate::tcp::Event::Failed { id }).await;
            }
        });
        let flow_state = plane.flows.get_mut(&id).context("flow index mismatch")?;
        if let Some(previous) = flow_state.task.replace(task) {
            previous.abort();
        }
        if !is_probe_flow(id) {
            crate::debug!("flow_open role=client id={id} tcp_remote={remote}");
        }
        Ok(())
    }

    pub fn resolve_binding(&mut self, token: &[u8; 16]) -> anyhow::Result<crate::tcp::Bound> {
        let token = *token;
        if let Plane::Tcp(plane) = &mut self.plane {
            let &id = plane
                .token_index
                .get(&token)
                .context("unknown TCP binding token")?;
            plane.token_index.remove(&token);
            let flow_state = plane
                .flows
                .get_mut(&id)
                .context("flow disappeared before bind")?;
            let key = flow_state
                .tcp_key
                .context("flow is not awaiting TCP binding")?;
            let outgoing = flow_state
                .tcp_receiver
                .take()
                .context("flow is already bound")?;
            flow_state.tcp_token = None;
            return Ok(crate::tcp::Bound { id, key, outgoing });
        }
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("resolve_binding outside TCP modes");
        };
        let &id = plane
            .token_index
            .get(&token)
            .context("unknown TCP binding token")?;
        plane.token_index.remove(&token);
        let flow_state = plane
            .flows
            .get_mut(&id)
            .context("flow disappeared before bind")?;
        let tcp = flow_state
            .tcp
            .as_mut()
            .context("flow is not awaiting TCP binding")?;
        tcp.token = None;
        let key = tcp.key;
        let outgoing = tcp.receiver.take().context("flow is already bound")?;
        Ok(crate::tcp::Bound { id, key, outgoing })
    }

    pub async fn tcp_close(&mut self, id: u64) -> Result<()> {
        if id == PREFLIGHT_ID && !self.has_flow(id) {
            return Ok(());
        }
        if id == PREFLIGHT_ID && self.round.is_some() {
            return Ok(()); // The marker is local, not a peer-owned TCP flow.
        }
        if id == PREFLIGHT_ID && self.readiness.is_some() {
            ensure!(
                matches!(self.readiness, Some(Readiness::Verified(_))) && self.has_flow(id),
                "TCP preflight closed before verification or after cleanup"
            );
        }
        let Plane::Tcp(plane) = &mut self.plane else {
            bail!("tcp_close outside TCP mode");
        };
        if let Some(flow_state) = plane.flows.remove(&id) {
            let key = flow_state.key;
            if plane.by_key.get(&key) == Some(&id) {
                plane.by_key.remove(&key);
            }
            if let Some(token) = flow_state.tcp_token {
                plane.token_index.remove(&token);
            }
            let active = flow_state.active;
            drop(flow_state);
            if !is_probe_flow(id) {
                self.stats.open_failed_flows += u64::from(!active);
                self.stats.closed_flows += 1;
                crate::debug!("flow_close id={id}");
                self.notify_closed(id, key).await?;
            }
        }
        Ok(())
    }
}
