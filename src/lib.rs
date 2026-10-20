// Hardware AES is mandatory on aarch64/x86_64: software AES+GHASH is the
// dominant CPU cost on router-class ARM, so refuse the build instead of
// shipping the slow path silently. `.cargo/config.toml` enables the feature;
// a custom RUSTFLAGS override must include it too.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const _: () = {
    #[cfg(not(target_feature = "aes"))]
    compile_error!(
        "hardware AES required on this architecture: build with -C target-feature=+aes (see .cargo/config.toml)"
    );
};

pub mod channel;
pub mod cli;
mod cmdline;
pub mod config;
pub mod control;
pub mod crypto;
pub mod drivers;
pub mod framing;
pub mod hooks;
pub mod hub;
pub mod limits;
pub mod link_io;
pub mod logging;
mod mimic;
pub mod packet;
pub mod pcap;
pub mod perf;
pub mod pool;
pub mod probe;
pub mod profile;
pub mod quic;
#[cfg(test)]
pub mod sctp_lab;
pub mod selector;
pub mod server_spec;
pub mod session;
pub mod ssh;
pub mod stats;
pub mod tcp;
mod tun;
pub mod udp;
pub mod webrtc;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    process::ExitCode,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::time::timeout;

use control::{Control, Endpoint, Message, Strategy, VERSION};
use mimic::{DEFAULT_STRATEGIES, tcp_only_mode};
use server_spec::{LinkParams, resolve_perf, resolve_servers};
use tun::{create_tun, stale_tun_holders};

pub use cli::{Cli, Mode};
pub use cmdline::{parse_byte_size, parse_port_range, serve_command, shell_quote};
pub(crate) use mimic::DEFAULT_PORT_RANGE;
pub use mimic::{MimicArg, MimicPlan, plan_mimic};
pub use tun::{is_busy_tun, validate_tun_name};

/// Binary entry point: parses CLI, sets up logging and the runtime.
pub fn main_entry() -> ExitCode {
    let cli = Cli::parse();
    let level = match &cli.command {
        Mode::Client(args) => args.globals.log_level,
        Mode::Perf { globals, .. } => globals.log_level,
        Mode::Serve { log_level, .. } => *log_level,
    };
    if logging::init(level).is_err() {
        return ExitCode::FAILURE;
    }
    limits::raise_and_report();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            crate::error!("runtime: {error}");
            logging::finish();
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async {
        // The client owns an asynchronous cleanup path; do not drop it on a signal.
        if matches!(&cli.command, Mode::Client(_)) {
            return run(cli).await;
        }
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("install SIGTERM handler")?;
        tokio::select! {
            result = run(cli) => result,
            result = tokio::signal::ctrl_c() => result.context("wait for interrupt"),
            _ = terminate.recv() => Ok(()),
        }
    });
    if let Err(error) = &result {
        crate::error!("svpn: {error:#}");
    }
    // Tokio stdin may hold a blocking read; fail-stop does not wait for bytes.
    runtime.shutdown_timeout(Duration::from_millis(100));
    logging::finish();
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Mode::Serve {
            tun_name,
            log_level: _,
            udp_port_range,
            mimic,
            tcp_port,
        } => {
            let plan = plan_mimic(&mimic, tcp_port)?;
            // TCP-only: --mimic is set but without UDP strategies.
            let tcp = tcp_only_mode(&mimic, &plan)?;
            let strategies = if plan.strategies.is_empty() && tcp.is_none() {
                DEFAULT_STRATEGIES.to_vec()
            } else {
                plan.strategies
            };
            // TCP fallback in auto: port 0 — ephemeral, the actual one goes into endpoints.
            let tcp_fallback = match (tcp.is_some(), plan.tcp) {
                (false, Some((port, _))) => Some(port.unwrap_or(0)),
                _ => None,
            };
            serve(
                tun_name.as_deref(),
                udp_port_range,
                &strategies,
                tcp.as_ref(),
                tcp_fallback,
            )
            .await
        }
        Mode::Client(args) => {
            let hooks = args.hooks.resolve()?;
            let servers = resolve_servers(&args.server, &args.globals)?;
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .context("install SIGINT handler")?;
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .context("install SIGTERM handler")?;
            let (stop, shutdown) = tokio::sync::watch::channel(false);
            let client = hub::run(servers, None, args.stats_interval, hooks, shutdown);
            tokio::pin!(client);
            tokio::select! {
                result = &mut client => result,
                _ = interrupt.recv() => {
                    stop.send_replace(true);
                    client.await
                }
                _ = terminate.recv() => {
                    stop.send_replace(true);
                    client.await
                }
            }
        }
        Mode::Perf {
            server,
            globals,
            time,
            interval,
            parallel,
            len,
            bytes,
            reverse,
            omit,
            json,
        } => {
            let params = resolve_perf(&server, &globals)?;
            ensure!((1..=128).contains(&parallel), "--parallel: 1..=128");
            ensure!(interval >= 1, "--interval: >= 1 s");
            ensure!(time >= 1 || bytes.is_some(), "specify --time or --bytes");
            ensure!(len >= 1024, "--len: >= 1024 bytes");
            let (started, ready) = tokio::sync::oneshot::channel();
            let args = perf::MeasureArgs {
                peer: params.peer_addr,
                duration: time,
                interval,
                streams: parallel,
                segment: len,
                total: bytes,
                reverse,
                omit,
            };
            let measure = async {
                ready
                    .await
                    .context("VPN stopped before the measurement started")?;
                perf::measure(&args).await
            };
            tokio::pin!(measure);
            let (_stop, shutdown) = tokio::sync::watch::channel(false);
            let Some(outcome) = tokio::select! {
                result = hub::run(vec![params], Some(started), 0, hooks::Hooks::default(), shutdown) => {
                    result.context("VPN session ended before the measurement finished").map(|()| None)
                }
                result = &mut measure => result.map(Some),
            }?
            else {
                bail!("VPN session ended before the measurement finished");
            };
            if json {
                perf::print_json(&outcome)?;
            } else {
                perf::print_text(&outcome);
            }
            Ok(())
        }
    }
}

/// Bootstrap SSH and the server TUN. The packet port can run probes before
/// the supervisor creates the single client TUN. Shared by client and perf.
pub(crate) async fn open_link(
    params: &LinkParams,
    tag: &str,
) -> Result<(Control, ssh::SshTail, session::TransportConfig, Ipv4Addr)> {
    let plan = plan_mimic(&params.mimic, params.tcp_port)?;
    // TCP-only: connect to the given port with the given camouflage; in auto
    // the fallback candidate port comes from endpoints.
    let tcp = tcp_only_mode(&params.mimic, &plan)?;
    let user = params
        .user
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .context("user not set: pass --ssh-user or set USER")?;
    let command = serve_command(
        &params.remote_bin,
        &params.peer_tun_name,
        params.log_level,
        params.udp_port_range,
        &params.mimic,
        plan.tcp.map(|(port, _)| port.unwrap_or(0)),
    );
    let target = ssh::SshTarget {
        user,
        identity: params.identity.clone(),
        host_key: params.host_key,
        host_label: format!("{}:{}", params.server, params.ssh_port),
    };
    let server_ip = server_spec::resolve_ipv4(&params.server).await?;
    crate::debug!(
        "{} resolved {} to {server_ip}",
        session::prefixed(tag, "ssh"),
        params.server
    );
    let session = ssh::connect(
        &target,
        SocketAddr::from((server_ip, params.ssh_port)),
        &command,
        tag,
    )
    .await?;
    let (stdin, stdout, tail) = session.into_io();
    let mut control = Control::new(stdout, stdin);
    control
        .send(Message::Hello {
            version: VERSION,
            client_ip: params.tun_addr,
            server_ip: params.peer_addr,
            mtu: params.mtu,
        })
        .await?;
    ensure!(
        matches!(
            bootstrap(&mut control).await?,
            Message::Ready { version: VERSION }
        ),
        "unexpected server greeting"
    );
    // TCP mode takes the port from Endpoints.tcp; UDP — from Endpoints.udp.
    let Message::Endpoints {
        udp,
        pin,
        tcp: server_tcp,
        ..
    } = bootstrap(&mut control).await?
    else {
        bail!("expected endpoints");
    };
    ensure!(
        matches!(bootstrap(&mut control).await?, Message::TunReady),
        "server TUN not ready"
    );
    if params.server_up.is_some() || params.server_down.is_some() {
        control
            .send(Message::ServerHooks {
                up: params.server_up.clone(),
                down: params.server_down.clone(),
            })
            .await?;
        let Message::HookResult { ok, stdout, stderr } = bootstrap(&mut control).await? else {
            bail!("expected hook_result");
        };
        if !stdout.is_empty() {
            crate::info!("server hook stdout: {stdout}");
        }
        if !stderr.is_empty() {
            crate::info!("server hook stderr: {stderr}");
        }
        ensure!(ok, "server up hook failed");
    }
    // Ready to exchange transport probes, not to route user IP packets yet.
    control.send(Message::TunReady).await?;
    let config = match tcp {
        Some(mode) => session::TransportConfig::Tcp {
            mode,
            listener: None,
        },
        None => session::TransportConfig::Client {
            strategies: plan.strategies,
            endpoints: udp,
            pin,
            // Without TCP camouflage the server will not send a tcp candidate.
            tcp: if plan.tcp.is_some() { server_tcp } else { None },
            tcp_camouflage: plan.tcp.as_ref().map(|(_, camouflage)| *camouflage),
        },
    };
    Ok((control, tail, config, server_ip))
}

async fn serve(
    tun_name: Option<&str>,
    udp_port_range: (u16, u16),
    strategies: &[Strategy],
    tcp: Option<&tcp::Mode>,
    tcp_fallback: Option<u16>,
) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "server requires Linux");
    let mut control = Control::new(tokio::io::stdin(), tokio::io::stdout());
    let Message::Hello {
        version,
        client_ip,
        server_ip,
        mtu,
    } = bootstrap(&mut control).await?
    else {
        bail!("expected hello");
    };
    ensure!(version == VERSION, "unsupported control version");
    validate_addresses(client_ip, server_ip, mtu)?;
    let bind = ssh_server_address(
        &std::env::var("SSH_CONNECTION").context("server requires SSH_CONNECTION from sshd")?,
    )?;
    control.send(Message::Ready { version: VERSION }).await?;
    // Bind the TCP-mode listener before Endpoints so the actual (possibly
    // ephemeral) port is announced everywhere and reused by the session.
    let tcp = match tcp {
        Some(mode) => {
            let mut mode = *mode;
            let listener = crate::tcp::bind(mode.port).await?;
            mode.port = listener
                .local_addr()
                .context("TCP listener address")?
                .port();
            Some((mode, listener))
        }
        None => None,
    };
    let (ports, quic) = match &tcp {
        Some(_) => (Vec::new(), None),
        None => bind_strategies(bind, udp_port_range, strategies).await?,
    };
    // TCP fallback in auto: a listener (possibly ephemeral) + the actual port.
    let tcp_candidate = match (tcp.is_some(), tcp_fallback) {
        (false, Some(port)) => {
            let listener = crate::tcp::bind(port).await?;
            let actual = listener
                .local_addr()
                .context("TCP listener address")?
                .port();
            Some((listener, actual))
        }
        _ => None,
    };
    control
        .send(Message::Endpoints {
            udp: ports.clone(),
            tcp: match (tcp.as_ref(), tcp_candidate.as_ref()) {
                (Some((mode, _)), _) => Some(mode.port),
                (None, Some((_, port))) => Some(*port),
                (None, None) => None,
            },
            pin: quic.as_ref().map(|(_, pin)| *pin),
        })
        .await?;
    let strategy_names: Vec<String> = strategies
        .iter()
        .map(|s| format!("{:?}", s).to_lowercase())
        .collect();
    match (&tcp, &tcp_candidate) {
        (Some((mode, _)), _) => {
            crate::info!(
                "serve: tcp_mode={:?} port={} bind={}",
                mode.camouflage,
                mode.port,
                bind
            );
        }
        (None, Some((_, port))) => {
            crate::info!(
                "serve: strategies={} udp_ports={} tcp_fallback={} bind={}",
                strategy_names.join("+"),
                ports
                    .iter()
                    .map(|e| e.port.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                port,
                bind
            );
        }
        (None, None) => {
            crate::info!(
                "serve: strategies={} udp_ports={} bind={}",
                strategy_names.join("+"),
                ports
                    .iter()
                    .map(|e| e.port.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                bind
            );
        }
    }
    let name = match tun_name {
        None | Some("") => None,
        Some(name) => {
            validate_tun_name(name)?;
            Some(name)
        }
    };
    // A previous session's serve can hold the TUN name for up to its heartbeat
    // window after the SSH client is gone; wait it out instead of failing fast.
    let tun = match name {
        Some(name) => {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                match create_tun(server_ip, client_ip, mtu, Some(name), false) {
                    Ok(tun) => break tun,
                    Err(error) if is_busy_tun(&error) => {
                        ensure!(
                            tokio::time::Instant::now() < deadline,
                            "TUN {name} still busy — another svpn serve holds it{}",
                            stale_tun_holders()
                        );
                        crate::info!("tun: {name} held by the previous session, waiting");
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        None => create_tun(server_ip, client_ip, mtu, None, false)?,
    };
    perf::spawn(server_ip);
    control.send(Message::TunReady).await?;
    let (server_down, expect_tun_ready) = match control.recv().await? {
        Message::ServerHooks { up, down } => {
            let context = hooks::TunContext {
                name: tun.name().context("TUN name")?,
                local: server_ip,
                peer: client_ip,
            };
            if let Some(up) = up {
                let hook = hooks::Hook::Command(up);
                let (ok, stdout, stderr) =
                    match hooks::run_with_capture(&hook, "up", &context).await {
                        Ok((stdout, stderr)) => (true, stdout, stderr),
                        Err(error) => {
                            let message = format!("{error:#}");
                            crate::error!("hook: up failed — {message}");
                            (false, String::new(), message)
                        }
                    };
                control
                    .send(Message::HookResult { ok, stdout, stderr })
                    .await?;
                ensure!(ok, "server up hook failed");
            } else {
                control
                    .send(Message::HookResult {
                        ok: true,
                        stdout: String::new(),
                        stderr: String::new(),
                    })
                    .await?;
            }
            (down, true)
        }
        Message::TunReady => (None, false),
        _ => bail!("expected server_hooks or tun_ready"),
    };
    if expect_tun_ready {
        ensure!(
            matches!(bootstrap(&mut control).await?, Message::TunReady),
            "client TUN not ready"
        );
    }
    let config = match tcp {
        Some((mode, listener)) => session::TransportConfig::Tcp {
            mode,
            listener: Some(listener),
        },
        None => session::TransportConfig::Server {
            ports,
            bind,
            quic,
            tcp: tcp_candidate,
        },
    };
    let tun_name = tun.name().context("TUN name")?;
    let result = session::run(control, tun, None, client_ip, mtu, config).await;
    if let Some(down) = server_down {
        let context = hooks::TunContext {
            name: tun_name,
            local: server_ip,
            peer: client_ip,
        };
        let hook = hooks::Hook::Command(down);
        if let Err(error) = hooks::run_with_capture(&hook, "down", &context).await {
            crate::error!("hook: down failed — {error:#}");
        }
    }
    result
}

/// Allocates one UDP port per strategy from the range and brings up the
/// shared QUIC endpoint with a self-signed certificate if quic is enabled.
async fn bind_strategies(
    bind: Ipv4Addr,
    range: (u16, u16),
    strategies: &[Strategy],
) -> Result<(Vec<Endpoint>, Option<(quinn::Endpoint, [u8; 32])>)> {
    ensure!(!strategies.is_empty(), "no UDP strategies");
    let mut ports = Vec::with_capacity(strategies.len());
    let mut next = u32::from(range.0);
    for strategy in strategies {
        let port = claim_udp_port(bind, &mut next, range.1).await?;
        ports.push(Endpoint {
            strategy: *strategy,
            port,
        });
    }
    let quic = if strategies.contains(&Strategy::Quic) {
        let quic_port = ports
            .iter()
            .find(|e| e.strategy == Strategy::Quic)
            .expect("quic endpoint allocated above")
            .port;
        let cert = rcgen::generate_simple_self_signed(vec![quic::SNI.to_string()])
            .context("generate QUIC certificate")?;
        let key =
            quinn::rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let cert = cert.cert.der().clone();
        let endpoint = quic::server_endpoint(
            SocketAddr::V4(SocketAddrV4::new(bind, quic_port)),
            cert.clone(),
            key,
        )?;
        Some((endpoint, quic::cert_pin(&cert)))
    } else {
        None
    };
    Ok((ports, quic))
}

/// Binds and releases a port to check availability; busy ports are skipped.
pub async fn claim_udp_port(bind: Ipv4Addr, next: &mut u32, max: u16) -> Result<u16> {
    loop {
        ensure!(*next <= u32::from(max), "port range exhausted");
        let port = u16::try_from(*next).context("port range exhausted")?;
        *next += 1;
        match tokio::net::UdpSocket::bind(SocketAddrV4::new(bind, port)).await {
            Ok(_socket) => return Ok(port),
            Err(_) => continue,
        }
    }
}

pub fn ssh_server_address(connection: &str) -> Result<Ipv4Addr> {
    let fields: Vec<_> = connection.split_whitespace().collect();
    ensure!(fields.len() == 4, "invalid SSH_CONNECTION");
    let address = fields[2]
        .parse()
        .context("SSH server address must be IPv4")?;
    ensure!(
        packet::unicast(address),
        "SSH server address must be unicast"
    );
    Ok(address)
}

async fn bootstrap(control: &mut Control) -> Result<Message> {
    timeout(Duration::from_secs(10), control.recv())
        .await
        .context("bootstrap timeout")?
}

pub fn validate_addresses(local: Ipv4Addr, peer: Ipv4Addr, mtu: u16) -> Result<()> {
    ensure!(
        packet::unicast(local) && packet::unicast(peer) && local != peer,
        "invalid point-to-point addresses"
    );
    ensure!(
        (576..=1400).contains(&mtu),
        "MTU must be between 576 and 1400"
    );
    Ok(())
}
