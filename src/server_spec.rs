//! Composite server arguments and owned, validated bootstrap configuration.

use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;
use russh::keys::ssh_key::Fingerprint;

use crate::{
    DEFAULT_PORT_RANGE, MimicArg, logging, packet, parse_port_range, plan_mimic,
    validate_addresses, validate_tun_name,
};

/// Global CLI defaults; each server may override its link-specific settings.
#[derive(Clone, Debug, clap::Args)]
pub struct Globals {
    /// Private or public key; unset — use a suitable ssh-agent key (SSH_AUTH_SOCK).
    #[arg(long)]
    pub ssh_identity: Option<PathBuf>,
    #[arg(long)]
    pub ssh_user: Option<String>,
    #[arg(long, default_value_t = 22, value_parser = clap::value_parser!(u16).range(1..))]
    pub ssh_port: u16,
    /// Server host-key fingerprint SHA256:…; only valid with one server.
    #[arg(long)]
    pub ssh_host_key: Option<String>,
    /// Path to svpn on the server, launched over SSH.
    #[arg(long, default_value = "/usr/local/bin/svpn")]
    pub ssh_remote_bin: String,
    /// Server TUN name; unset — the kernel assigns one.
    #[arg(long)]
    pub peer_tun_name: Option<String>,
    /// Client tunnel IPv4; unset (with peer-addr) — the server assigns a pair.
    #[arg(long)]
    pub tun_addr: Option<Ipv4Addr>,
    /// Server tunnel IPv4; unset (with tun-addr) — the server assigns a pair.
    #[arg(long)]
    pub peer_addr: Option<Ipv4Addr>,
    #[arg(long, default_value_t = 1280)]
    pub mtu: u16,
    #[arg(long)]
    pub tun_name: Option<String>,
    /// Log level for both sides: error, info (default), or debug.
    #[arg(long, value_enum, default_value_t = logging::Level::Info)]
    pub log_level: logging::Level,
    /// Server UDP port range MIN-MAX, passed to serve.
    #[arg(long, value_parser = parse_port_range, default_value = DEFAULT_PORT_RANGE)]
    pub udp_port_range: (u16, u16),
    /// Traffic camouflage. Repeatable for client; unset — auto. Perf requires
    /// exactly one camouflage, here or in --server mimic=VALUE.
    #[arg(long, value_enum)]
    pub mimic: Vec<MimicArg>,
    /// Average interval in seconds between background probes of each
    /// candidate (auto mode only, jittered ±50%); 0 disables background
    /// probing. Unset — 60.
    #[arg(long, value_name = "SECONDS")]
    pub remeasure_interval: Option<u32>,
    /// Server TCP fallback port; 0 — ephemeral (default in auto).
    #[arg(long)]
    pub tcp_port: Option<u16>,
    /// Shell command run on the server after its TUN is up; empty — no hook.
    #[arg(long)]
    pub server_up: Option<String>,
    /// Shell command run on the server before it exits; empty — no hook.
    #[arg(long)]
    pub server_down: Option<String>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ServerSpec {
    #[serde(rename = "address", deserialize_with = "deserialize_host")]
    server: String,
    ssh_port: Option<u16>,
    weight: Option<u32>,
    #[serde(rename = "ssh-user")]
    user: Option<String>,
    #[serde(rename = "ssh-identity")]
    identity: Option<PathBuf>,
    #[serde(
        default,
        rename = "ssh-host-key",
        deserialize_with = "crate::config::pin"
    )]
    host_key: Option<Fingerprint>,
    mimic: Option<Vec<MimicArg>>,
    #[serde(rename = "ssh-remote-bin")]
    remote_bin: Option<String>,
    peer_tun_name: Option<String>,
    peer_addr: Option<Ipv4Addr>,
    #[serde(default, deserialize_with = "crate::config::port_range")]
    udp_port_range: Option<(u16, u16)>,
    tcp_port: Option<u16>,
    server_up: Option<String>,
    server_down: Option<String>,
}

/// Owned configuration retained across future supervisor retries.
#[derive(Clone, Debug)]
pub struct LinkParams {
    pub server: String,
    pub weight: u32,
    pub identity: Option<PathBuf>,
    pub user: Option<String>,
    pub ssh_port: u16,
    pub host_key: Option<Fingerprint>,
    pub remote_bin: String,
    pub peer_tun_name: Option<String>,
    pub log_level: logging::Level,
    pub udp_port_range: (u16, u16),
    pub mimic: Vec<MimicArg>,
    /// Re-selection cadence; 0/None disables it. Auto mode only.
    pub remeasure_interval: Option<u32>,
    pub tcp_port: Option<u16>,
    pub tun_addr: Ipv4Addr,
    pub peer_addr: Ipv4Addr,
    /// Server assigns the tunnel pair; tun_addr/peer_addr hold the preference.
    pub addr_auto: bool,
    pub mtu: u16,
    pub tun_name: Option<String>,
    pub server_up: Option<String>,
    pub server_down: Option<String>,
}

impl ServerSpec {
    pub(crate) fn from_host(host: &str) -> Result<Self> {
        Ok(Self {
            server: normalize_host(host)?,
            ..Self::default()
        })
    }

    pub(crate) fn without_weight(&self, mode: &str) -> Result<()> {
        ensure!(self.weight.is_none(), "weight is not supported by {mode}");
        Ok(())
    }

    pub(crate) fn validate_fields(&self) -> Result<()> {
        ensure!(self.ssh_port != Some(0), "ssh-port must be in 1..=65535");
        ensure!(self.weight != Some(0), "weight must be nonzero");
        ensure!(
            self.user.as_ref().is_none_or(|v| !v.is_empty()),
            "ssh-user must not be empty"
        );
        ensure!(
            self.remote_bin.as_ref().is_none_or(|v| !v.is_empty()),
            "ssh-remote-bin must not be empty"
        );
        ensure!(
            self.identity
                .as_ref()
                .is_none_or(|v| !v.as_os_str().is_empty()),
            "ssh-identity must not be empty"
        );
        ensure!(
            self.peer_addr.is_none_or(packet::unicast),
            "peer-addr must be unicast IPv4"
        );
        ensure!(
            self.server_up.as_ref().is_none_or(|v| !v.trim().is_empty()),
            "server-up must not be empty"
        );
        ensure!(
            self.server_up
                .as_ref()
                .is_none_or(|v| v.len() <= crate::config::MAX_SERVER_HOOK),
            "server-up exceeds {} bytes",
            crate::config::MAX_SERVER_HOOK
        );
        ensure!(
            self.server_down
                .as_ref()
                .is_none_or(|v| !v.trim().is_empty()),
            "server-down must not be empty"
        );
        ensure!(
            self.server_down
                .as_ref()
                .is_none_or(|v| v.len() <= crate::config::MAX_SERVER_HOOK),
            "server-down exceeds {} bytes",
            crate::config::MAX_SERVER_HOOK
        );
        if let Some(name) = self.peer_tun_name.as_deref().filter(|v| !v.is_empty()) {
            validate_tun_name(name).context("peer-tun-name")?;
        }
        validate_mimic_fields(self.mimic.as_deref().unwrap_or_default())?;
        Ok(())
    }

    pub(crate) fn relative_identity(&mut self, base: &std::path::Path) {
        if let Some(path) = &mut self.identity {
            *path = base.join(&*path);
        }
    }

    pub fn resolve(&self, globals: &Globals) -> Result<LinkParams> {
        let (tun_addr, peer_addr, addr_auto) =
            match (globals.tun_addr, self.peer_addr.or(globals.peer_addr)) {
                (None, None) => (
                    crate::addrpool::pair_of(0).1,
                    crate::addrpool::pair_of(0).0,
                    true,
                ),
                (Some(tun), Some(peer)) => (tun, peer, false),
                _ => bail!("set both tun-addr and peer-addr, or neither for automatic assignment"),
            };
        let params = LinkParams {
            server: self.server.clone(),
            weight: self.weight.unwrap_or(1),
            identity: self
                .identity
                .as_ref()
                .or(globals.ssh_identity.as_ref())
                .cloned(),
            user: self.user.as_ref().or(globals.ssh_user.as_ref()).cloned(),
            ssh_port: self.ssh_port.unwrap_or(globals.ssh_port),
            host_key: match self.host_key {
                Some(pin) => Some(pin),
                None => globals
                    .ssh_host_key
                    .as_deref()
                    .map(parse_host_key)
                    .transpose()?,
            },
            remote_bin: self
                .remote_bin
                .as_ref()
                .unwrap_or(&globals.ssh_remote_bin)
                .clone(),
            peer_tun_name: self
                .peer_tun_name
                .as_ref()
                .or(globals.peer_tun_name.as_ref())
                .cloned(),
            log_level: globals.log_level,
            udp_port_range: self.udp_port_range.unwrap_or(globals.udp_port_range),
            mimic: self.mimic.as_ref().unwrap_or(&globals.mimic).clone(),
            remeasure_interval: globals.remeasure_interval,
            tcp_port: self.tcp_port.or(globals.tcp_port),
            tun_addr,
            peer_addr,
            addr_auto,
            mtu: globals.mtu,
            tun_name: globals.tun_name.clone().filter(|name| !name.is_empty()),
            server_up: self.server_up.clone().or_else(|| globals.server_up.clone()),
            server_down: self
                .server_down
                .clone()
                .or_else(|| globals.server_down.clone()),
        };
        ensure!(params.weight != 0, "weight must be nonzero");
        ensure!(params.ssh_port != 0, "SSH port must be 1..=65535");
        ensure!(
            params.udp_port_range.0 != 0 && params.udp_port_range.0 <= params.udp_port_range.1,
            "UDP ports require 1<=MIN<=MAX"
        );
        ensure!(
            !params.remote_bin.is_empty(),
            "remote-bin must not be empty"
        );
        ensure!(
            params.user.as_ref().is_none_or(|user| !user.is_empty()),
            "user must not be empty"
        );
        ensure!(
            params
                .identity
                .as_ref()
                .is_none_or(|path| !path.as_os_str().is_empty()),
            "identity must not be empty"
        );
        validate_addresses(params.tun_addr, params.peer_addr, params.mtu)?;
        if let Some(name) = params.peer_tun_name.as_deref().filter(|v| !v.is_empty()) {
            validate_tun_name(name)?;
        }
        if let Some(name) = params.tun_name.as_deref().filter(|name| !name.is_empty()) {
            validate_local_tun_name(name, cfg!(target_os = "macos"))?;
        }
        plan_mimic(&params.mimic, params.tcp_port)?;
        Ok(params)
    }
}

impl FromStr for ServerSpec {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let mut parts = value.split(',');
        let address = parts.next().unwrap_or_default();
        let parse = || -> Result<Self> {
            let (host, port) = match address.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (address, None),
            };
            let server = normalize_host(host)?;
            let ssh_port = port
                .map(|port| port.parse::<u16>().context("SSH port must be 1..=65535"))
                .transpose()?;
            ensure!(ssh_port != Some(0), "SSH port must be 1..=65535");
            let mut spec = Self {
                server,
                ssh_port,
                weight: None,
                user: None,
                identity: None,
                host_key: None,
                mimic: None,
                remote_bin: None,
                peer_tun_name: None,
                peer_addr: None,
                udp_port_range: None,
                tcp_port: None,
                server_up: None,
                server_down: None,
            };
            let mut seen = HashSet::new();
            for part in parts {
                let (key, value) = part.split_once('=').context("expected key=value")?;
                ensure!(!key.is_empty(), "empty key");
                ensure!(seen.insert(key), "repeated key {key:?}");
                ensure!(!value.is_empty(), "empty value for {key:?}");
                match key {
                    "weight" => {
                        let weight = value
                            .parse::<u32>()
                            .context("weight must be 1..=4294967295")?;
                        ensure!(weight != 0, "weight must be nonzero");
                        spec.weight = Some(weight);
                    }
                    "user" => spec.user = Some(value.into()),
                    "identity" => spec.identity = Some(value.into()),
                    "hostkey" => spec.host_key = Some(parse_host_key(value)?),
                    "mimic" => {
                        spec.mimic = Some(
                            value
                                .split('+')
                                .map(|value| {
                                    MimicArg::from_str(value, false).map_err(anyhow::Error::msg)
                                })
                                .collect::<Result<_>>()?,
                        );
                    }
                    "remote-bin" => spec.remote_bin = Some(value.into()),
                    "peer-tun" => spec.peer_tun_name = Some(value.into()),
                    "peer-addr" => {
                        spec.peer_addr = Some(value.parse().context("peer-addr must be IPv4")?)
                    }
                    "udp-ports" => {
                        spec.udp_port_range =
                            Some(parse_port_range(value).map_err(anyhow::Error::msg)?)
                    }
                    "tcp-port" => {
                        spec.tcp_port = Some(value.parse().context("tcp-port must be 0..=65535")?)
                    }
                    _ => bail!("unknown key {key:?}"),
                }
            }
            Ok(spec)
        };
        // Include the reason in Display as clap displays only the outer error.
        parse().map_err(|error| anyhow::anyhow!("--server ({address}): {error:#}"))
    }
}

impl Globals {
    pub(crate) fn validate_fields(&self) -> Result<()> {
        ensure!(self.ssh_port != 0, "ssh-port must be in 1..=65535");
        ensure!(
            self.ssh_user.as_ref().is_none_or(|v| !v.is_empty()),
            "ssh-user must not be empty"
        );
        ensure!(
            !self.ssh_remote_bin.is_empty(),
            "ssh-remote-bin must not be empty"
        );
        ensure!(
            self.ssh_identity
                .as_ref()
                .is_none_or(|v| !v.as_os_str().is_empty()),
            "ssh-identity must not be empty"
        );
        if let Some(pin) = &self.ssh_host_key {
            parse_host_key(pin)?;
        }
        ensure!(
            self.tun_addr.is_none_or(packet::unicast) && self.peer_addr.is_none_or(packet::unicast),
            "TUN addresses must be unicast IPv4"
        );
        ensure!(
            (576..=1400).contains(&self.mtu),
            "MTU must be between 576 and 1400"
        );
        ensure!(
            self.udp_port_range.0 != 0 && self.udp_port_range.0 <= self.udp_port_range.1,
            "UDP ports require 1<=MIN<=MAX"
        );
        if let Some(name) = self.peer_tun_name.as_deref().filter(|v| !v.is_empty()) {
            validate_tun_name(name).context("peer-tun-name")?;
        }
        if let Some(name) = self.tun_name.as_deref().filter(|v| !v.is_empty()) {
            validate_local_tun_name(name, cfg!(target_os = "macos")).context("tun-name")?;
        }
        ensure!(
            self.server_up.as_ref().is_none_or(|v| !v.trim().is_empty()),
            "server-up must not be empty"
        );
        ensure!(
            self.server_up
                .as_ref()
                .is_none_or(|v| v.len() <= crate::config::MAX_SERVER_HOOK),
            "server-up exceeds {} bytes",
            crate::config::MAX_SERVER_HOOK
        );
        ensure!(
            self.server_down
                .as_ref()
                .is_none_or(|v| !v.trim().is_empty()),
            "server-down must not be empty"
        );
        ensure!(
            self.server_down
                .as_ref()
                .is_none_or(|v| v.len() <= crate::config::MAX_SERVER_HOOK),
            "server-down exceeds {} bytes",
            crate::config::MAX_SERVER_HOOK
        );
        validate_mimic_fields(&self.mimic)
    }
}

/// Resolve once per SSH attempt, never while parsing configuration.
/// Literal addresses have already passed ServerSpec validation.
pub async fn resolve_ipv4(host: &str) -> Result<Ipv4Addr> {
    if let Ok(ip) = host.parse() {
        return Ok(ip);
    }
    let addresses =
        tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host((host, 0)))
            .await
            .with_context(|| format!("resolve {host}: timeout"))?
            .with_context(|| format!("resolve {host}"))?;
    let ip = addresses
        .filter_map(|address| match address {
            SocketAddr::V4(address) => Some(*address.ip()),
            SocketAddr::V6(_) => None,
        })
        .next()
        .with_context(|| format!("resolve {host}: no IPv4 addresses"))?;
    ensure!(
        server_ipv4(ip),
        "resolve {host}: not a unicast IPv4 address"
    );
    Ok(ip)
}

/// Validate the entire pool without DNS, SSH connections or TUN creation.
pub fn resolve_servers(servers: &[ServerSpec], globals: &Globals) -> Result<Vec<LinkParams>> {
    globals.validate_fields()?;
    ensure!(!servers.is_empty(), "at least one --server is required");
    ensure!(
        servers.len() == 1 || globals.ssh_host_key.is_none(),
        "global --ssh-host-key requires exactly one --server; use per-server hostkey"
    );
    let mut hosts = HashSet::new();
    servers
        .iter()
        .enumerate()
        .map(|(index, spec)| {
            let context = || format!("servers[{index}] ({})", spec.server);
            ensure!(
                hosts.insert(spec.server.as_str()),
                "{}: duplicate server host",
                context()
            );
            spec.validate_fields().with_context(context)?;
            spec.resolve(globals).with_context(context)
        })
        .collect()
}

pub fn resolve_perf(server: &ServerSpec, globals: &Globals) -> Result<LinkParams> {
    ensure!(
        server.weight.is_none(),
        "--server #1 ({}): weight is not supported by perf",
        server.server
    );
    globals.validate_fields()?;
    server.validate_fields()?;
    let mut params = server
        .resolve(globals)
        .with_context(|| format!("--server #1 ({})", server.server))?;
    // Perf targets the peer address directly; keep it deterministic.
    params.addr_auto = false;
    ensure!(
        params.mimic.len() == 1,
        "perf requires exactly one --mimic or per-server mimic"
    );
    Ok(params)
}

pub fn validate_local_tun_name(name: &str, macos: bool) -> Result<()> {
    if !macos {
        return validate_tun_name(name);
    }
    let index = name
        .strip_prefix("utun")
        .filter(|index| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|index| index.parse::<u32>().ok());
    ensure!(
        index.is_some_and(|index| index < u32::MAX),
        "local TUN name on macOS must be utunN, N in 0..=4294967294"
    );
    Ok(())
}

fn server_ipv4(ip: Ipv4Addr) -> bool {
    packet::unicast(ip) && ip.octets()[0] != 0 && ip.octets()[0] < 240
}

fn normalize_host(host: &str) -> Result<String> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        ensure!(server_ipv4(ip), "host must be a unicast IPv4 address");
        return Ok(ip.to_string());
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    ensure!(
        !name.is_empty()
            && name.len() <= 253
            && !name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }),
        "host must be a unicast IPv4 address or ASCII hostname"
    );
    Ok(host.to_ascii_lowercase())
}

pub(crate) fn parse_host_key(value: &str) -> Result<Fingerprint> {
    let pin = value
        .parse::<Fingerprint>()
        .context("hostkey / --ssh-host-key expects SHA256:…")?;
    ensure!(
        matches!(pin, Fingerprint::Sha256(_)),
        "hostkey / --ssh-host-key expects SHA256:…"
    );
    Ok(pin)
}

fn deserialize_host<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let host = <String as serde::Deserialize>::deserialize(deserializer)?;
    normalize_host(&host).map_err(serde::de::Error::custom)
}

fn validate_mimic_fields(mimic: &[MimicArg]) -> Result<()> {
    ensure!(
        mimic.iter().filter(|v| v.camouflage().is_some()).count() <= 1,
        "--mimic allows only one TCP camouflage level"
    );
    Ok(())
}
