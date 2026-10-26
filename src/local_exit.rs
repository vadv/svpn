//! local-exit passes raw IPv4 through a local serve and a second TUN.
//! Control uses a duplex; packet framing reuses loopback TCP transport.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    io::split,
    sync::{mpsc, watch},
    task::JoinHandle,
};

use crate::control::{Control, Message, Stats, VERSION};
use crate::framing::Camouflage;
use crate::link_io::{Delivery, Epoch, Event, LinkIo, Packet};
use crate::session::TransportConfig;
use crate::tcp::Mode;

const CONTROL_BUFFER: usize = 8192;

/// Claimed inner pair of the local exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalPair {
    /// TUN-local address of the local serve.
    pub server: Ipv4Addr,
    /// TUN peer (session client) address of the local serve.
    pub client: Ipv4Addr,
}

impl LocalPair {
    /// Claim a distinct pair and hold its ownership token.
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

/// Local serve task, stopped with its owner.
pub struct LocalServer {
    task: JoinHandle<Result<()>>,
}

impl LocalServer {
    /// Abort immediately; down hooks do not run.
    pub fn abort(&self) {
        self.task.abort();
    }

    pub async fn join(&mut self) -> Result<()> {
        match (&mut self.task).await {
            Ok(result) => result,
            Err(error) => bail!("local serve task: {error}"),
        }
    }

    pub async fn shutdown(mut self) -> Result<()> {
        match tokio::time::timeout(
            crate::hooks::DEADLINE + crate::session::HEARTBEAT_TIMEOUT,
            self.join(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                self.abort();
                bail!("local-exit shutdown timeout")
            }
        }
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Client-side session parts owned by the Hub.
pub struct LocalExit {
    pub control: Control,
    pub config: TransportConfig,
    pub io: LinkIo,
    pub pair: LocalPair,
    pub outgoing: mpsc::Sender<Packet>,
    pub events: mpsc::Receiver<(Epoch, Event)>,
    pub latest: watch::Receiver<Stats>,
    pub delivery: std::sync::Arc<Delivery>,
    pub server: LocalServer,
}

/// Start the local serve and complete the client handshake.
pub async fn start(
    epoch: Epoch,
    primary: (Ipv4Addr, Ipv4Addr),
    primary_tun: &str,
    mtu: u16,
    server_up: Option<String>,
    server_down: Option<String>,
    tun_name: Option<String>,
) -> Result<LocalExit> {
    let (pair, pair_guard) = LocalPair::claim(primary.0, primary.1)?;
    crate::validate_addresses(pair.server, pair.client, mtu)?;
    let primary_tun = primary_tun.to_owned();
    let (client_stream, server_stream) = tokio::io::duplex(CONTROL_BUFFER);
    let (server_read, server_write) = split(server_stream);
    let (client_read, client_write) = split(client_stream);
    let server_control = Control::new(server_read, server_write);
    let mut client_control = Control::new(client_read, client_write);
    let task = tokio::spawn(async move {
        serve_local(
            server_control,
            pair,
            pair_guard,
            mtu,
            tun_name.as_deref(),
            primary.1,
            &primary_tun,
        )
        .await
    });
    let mut server = LocalServer { task };
    let port = match client_handshake(&mut client_control, pair, mtu, server_up, server_down).await
    {
        Ok(port) => port,
        Err(client_error) => {
            // Closing control lets the serve close its TUN and run down hooks.
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

/// Run the server handshake and session without SSH or UDP strategies.
async fn serve_local(
    mut control: Control,
    pair: LocalPair,
    pair_guard: crate::addrpool::PairGuard,
    mtu: u16,
    tun_name: Option<&str>,
    primary_client: Ipv4Addr,
    primary_tun: &str,
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
    // The second TUN is the kernel forwarding/NAT boundary.
    let tun = crate::open_tun(tun_name, pair.server, pair.client, mtu).await?;
    let tun_name = tun.name().context("local-exit TUN name")?;
    let _peer_route = crate::tun::PeerRoute::install(pair.client, &tun_name)?;
    let _local_policy =
        crate::tun::LocalPolicy::install(pair.client, &tun_name, primary_client, primary_tun)?;
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

/// Complete the client handshake and return the loopback TCP port.
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
