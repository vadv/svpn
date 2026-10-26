//! LocalExit core: a second, local SVPN server path for home-country traffic
//! (docs/LOCAL-EXIT.md). It is a packet path, not a TCP proxy: the local
//! serve creates a REAL second TUN and runs the unchanged server session, so
//! the host kernel forwarding/conntrack/NAT handles the egress. The control
//! channel is the existing JSONL protocol over an in-memory duplex; the data
//! plane is the existing TCP-mode raw-IP flow framing over a loopback-only
//! ephemeral listener (`127.0.0.1:0`, no camouflage) — no SSH, no external
//! listener, no application TCP termination. The client side exposes the
//! `session::run_link` parts for the Hub to spawn; both sessions heartbeat
//! through the existing session loop.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    io::split,
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

use crate::control::{Control, Message, Stats, VERSION};
use crate::framing::Camouflage;
use crate::link_io::{Delivery, Epoch, Event, LinkIo, Packet};
use crate::session::TransportConfig;
use crate::tcp::Mode;

/// Default dedicated inner pair: the last pool index, reserved for the local
/// path so a normal pool scan never reaches it in practice. The primary and
/// local TUNs must never share an address: duplicate point-to-point
/// addresses on different TUNs silently misroute instead of failing.
pub const LOCAL_PAIR: (Ipv4Addr, Ipv4Addr) =
    (Ipv4Addr::new(10, 77, 254, 1), Ipv4Addr::new(10, 77, 254, 2));

/// Per-direction buffering of the in-memory control channel: one control
/// line plus slack, matching `control::MAX_LINE`.
const CONTROL_BUFFER: usize = 8192;

/// Fixed inner pair of the local exit, validated against the primary pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalPair {
    /// TUN-local address of the local serve.
    pub server: Ipv4Addr,
    /// TUN peer (session client) address of the local serve.
    pub client: Ipv4Addr,
}

impl LocalPair {
    /// The default dedicated pair, rejected when it shares any address with
    /// the primary tunnel pair.
    pub fn new(primary_server: Ipv4Addr, primary_client: Ipv4Addr) -> Result<Self> {
        let (server, client) = LOCAL_PAIR;
        ensure!(
            server != primary_server
                && server != primary_client
                && client != primary_server
                && client != primary_client,
            "local-exit pair {server}/{client} collides with the primary pair \
             {primary_server}/{primary_client}"
        );
        Ok(Self { server, client })
    }

    /// Claim a distinct pool pair for both local TUNs. The port token also
    /// prevents another SVPN process from reusing the addresses.
    pub fn claim(
        primary_server: Ipv4Addr,
        primary_client: Ipv4Addr,
    ) -> Result<(Self, crate::addrpool::PairGuard)> {
        let mut start = 254;
        for _ in 0..crate::addrpool::POOL_SIZE {
            let (guard, server, client) = crate::addrpool::claim(start)?;
            let pair = Self { server, client };
            start = crate::addrpool::pool_index(server, client).map_or(0, |n| n + 1);
            if server == primary_server
                || server == primary_client
                || client == primary_server
                || client == primary_client
            {
                drop(guard);
                continue;
            }
            return Ok((pair, guard));
        }
        bail!("no free local-exit address pair")
    }
}

/// Local serve task: aborted on drop, joinable for a clean stop.
pub struct LocalServer {
    task: JoinHandle<()>,
    /// Terminal serve result, sent as the task's last act.
    result: oneshot::Receiver<Result<()>>,
}

impl LocalServer {
    /// Emergency stop: kills the serve task immediately. Down hooks do not
    /// run; the kernel closes the TUN descriptor. Prefer dropping the client
    /// control half, which ends the serve gracefully.
    pub fn abort(&self) {
        self.task.abort();
    }

    /// Wait for the serve task to end and return its result.
    pub async fn join(&mut self) -> Result<()> {
        let outcome = (&mut self.result).await;
        let _ = (&mut self.task).await;
        match outcome {
            Ok(result) => result,
            // The sender is dropped only on a panic or an abort; the joined
            // task error above is already unwound or ignored at this point.
            Err(_) => bail!("local serve task ended without a result"),
        }
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Everything the Hub needs to spawn and own the local client session:
/// `session::run_link(control, pair.server, pair.client, mtu, config, io)`,
/// with `outgoing`/`events` as the packet ports of that session.
pub struct LocalExit {
    /// Control channel of the local client session (handshake complete).
    pub control: Control,
    /// `TransportConfig::Tcp` for `run_link`: loopback, no camouflage.
    pub config: TransportConfig,
    /// Packet port of the local client session. `peer_ip` (the local server
    /// TUN address) is the probe destination; `packets` receives translated
    /// client-TUN reads.
    pub io: LinkIo,
    /// Fixed inner pair of the local exit.
    pub pair: LocalPair,
    /// Send translated client-TUN packets into the local client session.
    pub outgoing: mpsc::Sender<Packet>,
    /// Events of the local client session: packets to translate back into
    /// the client TUN, and flow closes.
    pub events: mpsc::Receiver<(Epoch, Event)>,
    /// Latest heartbeat snapshot of the local client session.
    pub latest: watch::Receiver<Stats>,
    /// Delivery counters of the local client session.
    pub delivery: std::sync::Arc<Delivery>,
    /// The local serve task; dropped with the handle.
    pub server: LocalServer,
}

/// Bring up the local exit: a spawned local serve (control handshake, a real
/// second TUN named `tun_name`, the server session) and the client-side
/// handshake for `session::run_link`. `epoch` tags the LinkIo events; the
/// hooks are the configured `server_up`/`server_down`, applied to the local
/// serve with the same semantics as a remote serve.
pub async fn start(
    epoch: Epoch,
    primary: (Ipv4Addr, Ipv4Addr),
    mtu: u16,
    server_up: Option<String>,
    server_down: Option<String>,
    tun_name: Option<String>,
) -> Result<LocalExit> {
    let (pair, pair_guard) = LocalPair::claim(primary.0, primary.1)?;
    crate::validate_addresses(pair.server, pair.client, mtu)?;
    let (client_stream, server_stream) = tokio::io::duplex(CONTROL_BUFFER);
    let (server_read, server_write) = split(server_stream);
    let (client_read, client_write) = split(client_stream);
    let server_control = Control::new(server_read, server_write);
    let mut client_control = Control::new(client_read, client_write);
    let (result_tx, result_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let result = serve_local(server_control, pair, pair_guard, mtu, tun_name.as_deref()).await;
        // The serve task ends only after its result is handed over; the
        // server session and its TUN are gone by the time the send returns.
        let _ = result_tx.send(result);
    });
    let mut server = LocalServer {
        task,
        result: result_rx,
    };
    let port = match client_handshake(&mut client_control, pair, mtu, server_up, server_down).await
    {
        Ok(port) => port,
        Err(client_error) => {
            // Dropping the control half is the graceful stop: the serve task
            // unwinds through its own error path, closes its TUN and runs
            // the down hook. No task or TUN outlives this call.
            drop(client_control);
            let server_error = server
                .join()
                .await
                .err()
                .map(|error| format!(" — {error:#}"))
                .unwrap_or_default();
            bail!("local exit handshake failed{server_error} — {client_error:#}");
        }
    };
    let (stats, latest) = watch::channel(Stats::default());
    let delivery = std::sync::Arc::new(Delivery::default());
    let (outgoing, packets) = mpsc::channel(crate::hub::QUEUE);
    let (events, returned) = mpsc::channel(crate::hub::QUEUE);
    let io = LinkIo {
        epoch,
        peer_ip: pair.server,
        tag: "[local]".to_owned(),
        packets,
        events,
        stats,
        delivery: delivery.clone(),
    };
    Ok(LocalExit {
        control: client_control,
        config: TransportConfig::Tcp {
            mode: Mode {
                port,
                camouflage: Camouflage::None,
            },
            listener: None,
            connect_ip: Some(Ipv4Addr::LOCALHOST),
        },
        io,
        pair,
        outgoing,
        events: returned,
        latest,
        delivery,
        server,
    })
}

/// Local serve: the remote serve handshake without SSH, UDP strategies,
/// perf and addrpool claims — the fixed inner pair is honored as given, and
/// the data plane is the loopback-only TCP listener.
async fn serve_local(
    mut control: Control,
    pair: LocalPair,
    pair_guard: crate::addrpool::PairGuard,
    mtu: u16,
    tun_name: Option<&str>,
) -> Result<()> {
    let _pair_guard = pair_guard;
    let Message::Hello {
        version,
        client_ip,
        server_ip,
        mtu: hello_mtu,
        addr_auto,
    } = crate::bootstrap(&mut control).await?
    else {
        bail!("expected hello");
    };
    ensure!(version == VERSION, "unsupported control version");
    ensure!(!addr_auto, "the local exit does not negotiate addresses");
    ensure!(
        (client_ip, server_ip) == (pair.client, pair.server),
        "unexpected local address pair {server_ip}/{client_ip}"
    );
    crate::validate_addresses(server_ip, client_ip, hello_mtu)?;
    ensure!(hello_mtu == mtu, "local MTU mismatch");
    control.send(Message::Ready { version: VERSION }).await?;
    // Loopback-only and ephemeral: raw-IP flow framing, not an application
    // TCP proxy; the actual port is announced in endpoints and reused by the
    // session.
    let listener = crate::tcp::bind_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let port = listener
        .local_addr()
        .context("local TCP listener address")?
        .port();
    crate::info!(
        "local exit: serve pair {} {} mtu {mtu} port {port}",
        pair.server,
        pair.client
    );
    control
        .send(Message::Endpoints {
            udp: Vec::new(),
            tcp: Some(port),
            pin: None,
        })
        .await?;
    control
        .send(Message::Assigned {
            server_ip: pair.server,
            client_ip: pair.client,
        })
        .await?;
    match crate::bootstrap(&mut control).await? {
        Message::AcceptAddr => {}
        Message::DeclineAddr => bail!("client declined the local address pair"),
        _ => bail!("expected accept_addr or decline_addr"),
    }
    // The REAL second TUN: the server session must run unchanged so the
    // host kernel forwarding/conntrack/NAT owns the egress.
    let tun = crate::open_tun(tun_name, pair.server, pair.client, mtu).await?;
    let tun_name = tun.name().context("local-exit TUN name")?;
    let _peer_route = crate::tun::PeerRoute::install(pair.client, &tun_name)?;
    let config = TransportConfig::Tcp {
        mode: Mode {
            port,
            camouflage: Camouflage::None,
        },
        listener: Some(listener),
        connect_ip: None,
    };
    crate::serve_tail(control, tun, pair.server, pair.client, mtu, config).await
}

/// Client side of the local handshake (the `open_link` sequence without SSH):
/// Hello/Ready, Endpoints, Assigned/AcceptAddr, TunReady, optional
/// ServerHooks with HookResult, final TunReady. Returns the data-plane port.
async fn client_handshake(
    control: &mut Control,
    pair: LocalPair,
    mtu: u16,
    server_up: Option<String>,
    server_down: Option<String>,
) -> Result<u16> {
    control
        .send(Message::Hello {
            version: VERSION,
            client_ip: pair.client,
            server_ip: pair.server,
            mtu,
            addr_auto: false,
        })
        .await?;
    ensure!(
        matches!(
            crate::bootstrap(control).await?,
            Message::Ready { version: VERSION }
        ),
        "unexpected local server greeting"
    );
    let Message::Endpoints { udp, tcp, .. } = crate::bootstrap(control).await? else {
        bail!("expected endpoints");
    };
    ensure!(udp.is_empty(), "the local exit has no UDP strategies");
    let Some(port) = tcp else {
        bail!("the local exit requires the TCP data plane");
    };
    let Message::Assigned {
        server_ip,
        client_ip,
    } = crate::bootstrap(control).await?
    else {
        bail!("expected assigned");
    };
    ensure!(
        (server_ip, client_ip) == (pair.server, pair.client),
        "local server offered an unexpected address pair {server_ip}/{client_ip}"
    );
    control.send(Message::AcceptAddr).await?;
    ensure!(
        matches!(crate::bootstrap(control).await?, Message::TunReady),
        "local server TUN not ready"
    );
    if server_up.is_some() || server_down.is_some() {
        control
            .send(Message::ServerHooks {
                up: server_up,
                down: server_down,
            })
            .await?;
        let Message::HookResult { ok, stdout, stderr } = crate::bootstrap(control).await? else {
            bail!("expected hook_result");
        };
        if !stdout.is_empty() {
            crate::info!("local hook stdout: {stdout}");
        }
        if !stderr.is_empty() {
            crate::info!("local hook stderr: {stderr}");
        }
        ensure!(ok, "local server up hook failed");
    }
    control.send(Message::TunReady).await?;
    Ok(port)
}
