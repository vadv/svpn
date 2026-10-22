use std::net::Ipv4Addr;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::mpsc,
    task::JoinSet,
};

use crate::packet::FlowKey;
use crate::selector::Reason;

pub const VERSION: u32 = 2;
pub const MAX_LINE: usize = 4096;
pub const QUEUE: usize = 256;

/// UDP channel strategy; the strings are the wire names (`plain` is a
/// diagnostic-only L0, not an auto candidate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Strategy {
    Plain,
    Mosh,
    WebRtc,
    Quic,
    Obfs,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub inner_tx_packets: u64,
    pub inner_rx_packets: u64,
    pub inner_tx_bytes: u64,
    pub inner_rx_bytes: u64,
    pub dropped_packets: u64,
    pub opened_flows: u64,
    pub open_failed_flows: u64,
    pub closed_flows: u64,
    pub active_flows: usize,
    /// Last winning transport candidate on the client; server leaves it None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_candidate: Option<String>,
    /// Packet-level failure counters per transport since start.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub transport_failures: std::collections::BTreeMap<String, u64>,
}

impl Stats {
    /// Count acceptance by the transport queue, not delivery to the remote peer.
    pub fn record_tx(&mut self, length: usize, accepted: bool) {
        if length == 0 {
            return; // TCP binding/preflight sentinel, not an inner IP packet.
        }
        if accepted {
            self.inner_tx_packets += 1;
            self.inner_tx_bytes += length as u64;
        } else {
            self.dropped_packets += 1;
        }
    }

    /// Every counted loss names its reason in the log (#124).
    pub fn count_drop(&mut self, prefix: &str, reason: &str) {
        self.dropped_packets += 1;
        crate::error!("{prefix} {reason}");
    }

    /// An expected drop (a protocol race, traffic we do not carry): counted
    /// the same, logged at debug — ERROR stays for bugs and real data loss.
    pub fn count_drop_expected(&mut self, prefix: &str, reason: &str) {
        self.dropped_packets += 1;
        crate::debug!("{prefix} {reason}");
    }
}

/// The strategy's actual UDP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub strategy: Strategy,
    pub port: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    Hello {
        version: u32,
        client_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        mtu: u16,
        /// Client asks the server to assign a free tunnel address pair (#181).
        addr_auto: bool,
    },
    Ready {
        version: u32,
    },
    /// Server → client: the tunnel address pair to use (confirmed or freshly
    /// assigned), before the server TUN is created. Client answers AcceptAddr
    /// or DeclineAddr (address already taken locally, auto mode only).
    Assigned {
        server_ip: Ipv4Addr,
        client_ip: Ipv4Addr,
    },
    AcceptAddr,
    DeclineAddr,
    TunReady,
    /// Client → server: shell commands to run on the server after its TUN is up
    /// (`up`) and before it exits (`down`). Sent after server `TunReady`, before
    /// client `TunReady`. Server replies with `HookResult` once `up` finishes.
    ServerHooks {
        up: Option<String>,
        down: Option<String>,
    },
    /// Server → client: result of the `up` hook. `stdout`/`stderr` are truncated
    /// to 4 KiB each.
    HookResult {
        ok: bool,
        stdout: String,
        stderr: String,
    },
    Open {
        id: u64,
        flow: FlowKey,
    },
    Opened {
        id: u64,
        /// UDP: the server flow socket's port; TCP: the TCP transport's listening port.
        port: u16,
        key: [u8; 16],
        /// TCP-mode binding token; always None in UDP mode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<[u8; 16]>,
    },
    Close {
        id: u64,
    },
    // ─── Control v2 protocol messages ───
    /// The server's actual endpoints, before TUN creation.
    Endpoints {
        udp: Vec<Endpoint>,
        tcp: Option<u16>,
        /// QUIC: SHA-256 fingerprint of the server certificate.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pin: Option<[u8; 32]>,
    },
    ChannelPrepare {
        attempt: u64,
        strategy: Strategy,
        /// WebRTC: the client's JSON hello for ICE/DTLS.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hello: Option<String>,
    },
    ChannelReady {
        attempt: u64,
        channel: u64,
        port: u16,
        key: [u8; 16],
        max_wire: u16,
        /// WebRTC: the server's JSON hello for ICE/DTLS.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hello: Option<String>,
        /// QUIC: the channel's loopback relay port on the server.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay: Option<u16>,
    },
    ChannelFailed {
        attempt: Option<u64>,
        channel: Option<u64>,
        reason: Reason,
    },
    ChannelVerified {
        channel: u64,
    },
    /// Client: open a flow on a ready channel. Server: `channel: None` means the
    /// client picks the channel; the reply arrives as `flow_channel`.
    FlowOpen {
        flow_id: u64,
        flow: FlowKey,
        channel: Option<u64>,
    },
    FlowChannel {
        flow_id: u64,
        channel: u64,
    },
    FlowReject {
        flow_id: u64,
        reason: Reason,
    },
    FlowOpened {
        flow_id: u64,
        flow: FlowKey,
        channel: u64,
    },
    Commit {
        flow_id: u64,
        attempt: u64,
    },
    Committed {
        flow_id: u64,
    },
    FlowClose {
        flow_id: u64,
    },
    Heartbeat {
        stats: Stats,
    },
}

pub struct Control {
    outbound: mpsc::Sender<Message>,
    inbound: mpsc::Receiver<Result<Message>>,
    tasks: JoinSet<()>,
}

impl Control {
    pub fn new<R, W>(reader: R, writer: W) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (outbound, outgoing) = mpsc::channel(QUEUE);
        let (incoming, inbound) = mpsc::channel(QUEUE);
        let mut tasks = JoinSet::new();
        tasks.spawn(run_writer(writer, outgoing, incoming.clone()));
        tasks.spawn(run_reader(reader, incoming));
        Self {
            outbound,
            inbound,
            tasks,
        }
    }

    pub async fn send(&self, message: Message) -> Result<()> {
        self.outbound
            .send(message)
            .await
            .map_err(|_| anyhow!("control writer unavailable"))
    }

    pub async fn recv(&mut self) -> Result<Message> {
        self.inbound
            .recv()
            .await
            .context("control reader stopped")?
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

pub async fn read_message<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Message> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf().await.context("control read failed")?;
        if buffer.is_empty() {
            bail!("control EOF");
        }
        let end = buffer.iter().position(|byte| *byte == b'\n');
        let length = end.map_or(buffer.len(), |index| index + 1);
        if line.len() + length > MAX_LINE {
            bail!("control line exceeds {MAX_LINE} bytes");
        }
        line.extend_from_slice(&buffer[..length]);
        reader.consume(length);
        if end.is_some() {
            // Untrusted JSON and key material never reach the diagnostics.
            return serde_json::from_slice(&line).map_err(|_| anyhow!("invalid control JSON"));
        }
    }
}

async fn run_writer<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut outgoing: mpsc::Receiver<Message>,
    errors: mpsc::Sender<Result<Message>>,
) {
    let result: Result<()> = async {
        while let Some(message) = outgoing.recv().await {
            let mut line = zeroize::Zeroizing::new(serde_json::to_vec(&message)?);
            line.push(b'\n');
            writer.write_all(&line).await?;
            writer.flush().await?;
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => crate::debug!("control writer: queue closed, exiting"),
        Err(error) => {
            let _ = errors
                .send(Err(error.context("control write failed")))
                .await;
        }
    }
}

async fn run_reader<R: AsyncRead + Unpin>(reader: R, incoming: mpsc::Sender<Result<Message>>) {
    let mut reader = BufReader::new(reader);
    loop {
        let result = read_message(&mut reader).await;
        let failed = result.is_err();
        if incoming.send(result).await.is_err() || failed {
            break;
        }
    }
}
