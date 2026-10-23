//! Per-flow TCP bindings, shared by fixed mode and the TCP candidate.

use std::net::SocketAddr;

use anyhow::{Context, Result, bail, ensure};
use tokio::sync::{mpsc, oneshot};

use crate::control::Message;
use crate::crypto;
use crate::link_io::{PREFLIGHT_ID, is_probe_flow};
use crate::packet::FlowKey;
use crate::selector::Reason;

use super::{CHANNEL_QUEUE, FlowTcp, Plane, Readiness, Session, TcpFlow, prefixed};

impl Session {
    pub async fn channels_tcp_open(
        &mut self,
        id: u64,
        generation: u64,
        flow: FlowKey,
    ) -> Result<()> {
        if !self
            .register_binding(id, generation, flow, None, false)
            .await?
        {
            return Ok(());
        }
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("TCP candidate outside channels mode")
        };
        let port = plane.tcp_port.context("TCP candidate disabled")?;
        let state = plane
            .flows
            .get_mut(&id)
            .context("registered flow missing")?;
        if state.tcp.is_none() {
            let (send, receiver) = mpsc::channel(CHANNEL_QUEUE);
            let key = crypto::random().context("flow key generation failed")?;
            let token = crypto::random().context("binding token generation failed")?;
            state.tcp = Some(FlowTcp {
                key,
                token: Some(token),
                out: Some(send),
                receiver: Some(receiver),
                task: None,
                cancel: None,
            });
            plane.token_index.insert(token, (id, generation));
            if !is_probe_flow(id) {
                crate::debug!(
                    "flow_open role=server id={id} generation={generation} transport=tcp"
                );
            }
        }
        let tcp = state.tcp.as_ref().context("TCP binding missing")?;
        self.control
            .send(Message::Opened {
                id,
                generation,
                port,
                key: tcp.key,
                token: tcp.token,
            })
            .await
    }

    pub async fn channels_tcp_opened(
        &mut self,
        id: u64,
        generation: u64,
        port: u16,
        key: [u8; 16],
        token: Option<[u8; 16]>,
    ) -> Result<()> {
        if !self.binding_current(id, generation) {
            return Ok(());
        }
        if is_probe_flow(id)
            && self
                .round
                .as_ref()
                .is_none_or(|r| r.tcp_id != Some(id) || r.retry_at.is_some())
        {
            return Ok(());
        }
        let Plane::Channels(plane) = &mut self.plane else {
            bail!("TCP candidate outside channels mode")
        };
        let state = plane.flows.get_mut(&id).context("flow missing")?;
        if let Some(tcp) = state.tcp.as_ref() {
            ensure!(tcp.key == key, "conflicting TCP binding key");
            return Ok(());
        }
        if !is_probe_flow(id) && !plane.selector.as_ref().is_some_and(|s| s.tcp_binding(id)) {
            return Ok(());
        }
        let token = token.context("TCP candidate requires a binding token")?;
        let (send, outgoing) = mpsc::channel(CHANNEL_QUEUE);
        let first = if is_probe_flow(id) {
            self.round
                .as_ref()
                .context("preflight round missing")?
                .request
                .clone()
        } else {
            Vec::new()
        };
        send.try_send(first).context("TCP binding queue closed")?;
        state.tcp = Some(FlowTcp {
            key,
            token: None,
            out: Some(send),
            receiver: None,
            task: None,
            cancel: None,
        });
        let task = self.start_tcp_binding(
            (id, generation),
            port,
            key,
            token,
            outgoing,
            crate::framing::Camouflage::Ssh,
        )?;
        let Plane::Channels(plane) = &mut self.plane else {
            unreachable!()
        };
        plane
            .flows
            .get_mut(&id)
            .and_then(|f| f.tcp.as_mut())
            .context("TCP binding missing")?
            .task = Some(task);
        Ok(())
    }

    pub async fn tcp_open_server(&mut self, id: u64, generation: u64, key: FlowKey) -> Result<()> {
        ensure!(
            !self.client() && generation != 0 && key.valid_for(self.client_ip),
            "invalid TCP binding"
        );
        let at_capacity = self.flow_limit_reached(id);
        let Plane::Tcp(plane) = &mut self.plane else {
            bail!("TCP open outside TCP mode")
        };
        if let Some(flow) = plane.flows.get(&id) {
            if generation < flow.generation {
                return Ok(());
            }
            if flow.key != key || (generation > flow.generation && flow.data_started) {
                return self
                    .control
                    .send(Message::FlowReject {
                        flow_id: id,
                        generation,
                        reason: Reason::Unsupported,
                    })
                    .await;
            }
        } else if at_capacity
            || plane.by_key.get(&key).is_some_and(|&owner| owner != id)
            || (!is_probe_flow(id)
                && plane
                    .flows
                    .iter()
                    .filter(|(id, flow)| !is_probe_flow(**id) && !flow.active)
                    .count()
                    >= crate::selector::PENDING_FLOWS)
        {
            return self
                .control
                .send(Message::FlowReject {
                    flow_id: id,
                    generation,
                    reason: Reason::ResourceExhausted,
                })
                .await;
        } else {
            plane
                .flows
                .insert(id, TcpFlow::new(key, tokio::time::Instant::now()));
            plane.by_key.insert(key, id);
            if !is_probe_flow(id) {
                self.stats.opened_flows += 1;
            }
        }
        let flow = plane
            .flows
            .get_mut(&id)
            .context("registered TCP flow missing")?;
        if generation != flow.generation || flow.tcp_key.is_none() {
            if let Some(token) = flow.tcp_token.take() {
                plane.token_index.remove(&token);
            }
            if let Some(task) = flow.task.take() {
                task.abort();
            }
            flow.cancel = None;
            flow.generation = generation;
            flow.active = false;
            flow.commit_pending = false;
            flow.tcp_connected = false;
            let (send, receiver) = mpsc::channel(CHANNEL_QUEUE);
            let key = crypto::random().context("flow key generation failed")?;
            let token = crypto::random().context("binding token generation failed")?;
            flow.outgoing = Some(send);
            flow.tcp_receiver = Some(receiver);
            flow.tcp_key = Some(key);
            flow.tcp_token = Some(token);
            plane.token_index.insert(token, (id, generation));
            if !is_probe_flow(id) {
                crate::debug!(
                    "flow_open role=server id={id} generation={generation} transport=tcp"
                );
            }
        }
        self.control
            .send(Message::Opened {
                id,
                generation,
                port: plane.mode.port,
                key: flow.tcp_key.context("TCP key missing")?,
                token: flow.tcp_token,
            })
            .await
    }

    pub async fn tcp_opened_client(
        &mut self,
        id: u64,
        generation: u64,
        port: u16,
        key: [u8; 16],
        token: Option<[u8; 16]>,
    ) -> Result<()> {
        if !self.binding_current(id, generation) {
            return Ok(());
        }
        if is_probe_flow(id)
            && self
                .round
                .as_ref()
                .is_none_or(|r| r.tcp_id != Some(id) || r.retry_at.is_some())
        {
            return Ok(());
        }
        let Plane::Tcp(plane) = &mut self.plane else {
            bail!("TCP opened outside TCP mode")
        };
        let flow = plane.flows.get_mut(&id).context("TCP flow missing")?;
        if flow.task.is_some() {
            ensure!(flow.tcp_key == Some(key), "conflicting TCP binding key");
            return Ok(());
        }
        let token = token.context("TCP transport requires a binding token")?;
        let (send, outgoing) = mpsc::channel(CHANNEL_QUEUE);
        let first = if is_probe_flow(id) {
            flow.pending
                .pop_front()
                .context("TCP preflight packet missing")?
        } else {
            Vec::new()
        };
        send.try_send(first).context("TCP binding queue closed")?;
        flow.outgoing = Some(send);
        flow.tcp_key = Some(key);
        flow.retry_at = None;
        let camouflage = plane.mode.camouflage;
        let task =
            self.start_tcp_binding((id, generation), port, key, token, outgoing, camouflage)?;
        let Plane::Tcp(plane) = &mut self.plane else {
            unreachable!()
        };
        plane.flows.get_mut(&id).context("TCP flow missing")?.task = Some(task);
        Ok(())
    }

    fn start_tcp_binding(
        &self,
        binding: (u64, u64),
        port: u16,
        key: [u8; 16],
        token: [u8; 16],
        outgoing: mpsc::Receiver<Vec<u8>>,
        camouflage: crate::framing::Camouflage,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let ip = match &self.plane {
            Plane::Channels(p) => p.server_ip,
            Plane::Tcp(p) => p.server_ip,
        }
        .context("client requires server address")?;
        let remote = SocketAddr::from((ip, port));
        // e2e greps this token to tell TCP-transport flows from UDP channels.
        if !is_probe_flow(binding.0) {
            crate::debug!(
                "flow_connect role=client id={} tcp_remote={remote}",
                binding.0
            );
        }
        let events = self.tcp_events.0.clone();
        let failure = events.clone();
        let tag = self.tag().to_owned();
        Ok(tokio::spawn(async move {
            if let Err(error) =
                crate::tcp::connect(remote, camouflage, binding, key, token, outgoing, events).await
            {
                crate::debug!(
                    "{} {} generation={} binding failed — {error:#}",
                    prefixed(&tag, "flow"),
                    binding.0,
                    binding.1
                );
                let _ = failure
                    .send(crate::tcp::Event::Failed {
                        id: binding.0,
                        generation: binding.1,
                    })
                    .await;
            }
        }))
    }

    pub fn resolve_binding(&mut self, token: &[u8; 16]) -> Result<crate::tcp::Bound> {
        let (id, generation, key, outgoing, cancel) = match &mut self.plane {
            Plane::Tcp(plane) => {
                let (id, generation) = plane
                    .token_index
                    .remove(token)
                    .context("unknown TCP binding token")?;
                let flow = plane
                    .flows
                    .get_mut(&id)
                    .filter(|f| f.generation == generation)
                    .context("stale TCP binding")?;
                let outgoing = flow.tcp_receiver.take().context("flow already bound")?;
                let (cancel, cancelled) = oneshot::channel();
                flow.cancel = Some(cancel);
                (
                    id,
                    generation,
                    flow.tcp_key.context("TCP key missing")?,
                    outgoing,
                    cancelled,
                )
            }
            Plane::Channels(plane) => {
                let (id, generation) = plane
                    .token_index
                    .remove(token)
                    .context("unknown TCP binding token")?;
                let flow = plane
                    .flows
                    .get_mut(&id)
                    .filter(|f| f.generation == generation)
                    .context("stale TCP binding")?;
                let tcp = flow.tcp.as_mut().context("TCP binding missing")?;
                let outgoing = tcp.receiver.take().context("flow already bound")?;
                let (cancel, cancelled) = oneshot::channel();
                tcp.cancel = Some(cancel);
                (id, generation, tcp.key, outgoing, cancelled)
            }
        };
        Ok(crate::tcp::Bound {
            id,
            generation,
            key,
            outgoing,
            cancel: Some(cancel),
        })
    }

    pub async fn tcp_close(&mut self, id: u64) -> Result<()> {
        if id == PREFLIGHT_ID && (!self.has_flow(id) || self.round.is_some()) {
            return Ok(());
        }
        if id == PREFLIGHT_ID && self.readiness.is_some() {
            ensure!(
                matches!(self.readiness, Some(Readiness::Verified(_))) && self.has_flow(id),
                "TCP preflight closed before verification or after cleanup"
            );
        }
        let Plane::Tcp(plane) = &mut self.plane else {
            bail!("TCP close outside TCP mode")
        };
        if let Some(flow) = plane.flows.remove(&id) {
            let key = flow.key;
            if plane.by_key.get(&key) == Some(&id) {
                plane.by_key.remove(&key);
            }
            if let Some(token) = flow.tcp_token {
                plane.token_index.remove(&token);
            }
            if !is_probe_flow(id) {
                self.stats.open_failed_flows += u64::from(!flow.active && !flow.data_started);
                self.stats.closed_flows += 1;
                if flow.recovery.is_some() {
                    crate::info!(
                        "flow_recovery_abandoned id={id} generation={} reason=closed",
                        flow.generation
                    );
                }
            }
            drop(flow);
            self.notify_closed(id, key).await?;
        }
        Ok(())
    }
}
