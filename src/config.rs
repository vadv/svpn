//! One bounded TOML file, with paths relative to its supplied directory.

use std::{
    fs::OpenOptions,
    io::Read,
    net::Ipv4Addr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use crate::{
    MimicArg,
    cli::ClientArgs,
    hooks, logging,
    server_spec::{Globals, ServerSpec},
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;

pub const MAX_CONFIG: u64 = 1024 * 1024;
/// Maximum length of a server hook command, to keep `ServerHooks` within the
/// control channel line limit (`MAX_LINE`).
pub const MAX_SERVER_HOOK: usize = 1500;

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct FileConfig {
    server: Option<String>,
    servers: Option<Vec<ServerSpec>>,
    ssh_user: Option<String>,
    ssh_identity: Option<PathBuf>,
    ssh_port: Option<u16>,
    ssh_host_key: Option<String>,
    ssh_remote_bin: Option<String>,
    peer_tun_name: Option<String>,
    tun_name: Option<String>,
    tun_addr: Option<Ipv4Addr>,
    peer_addr: Option<Ipv4Addr>,
    mtu: Option<u16>,
    log_level: Option<logging::Level>,
    #[serde(default, deserialize_with = "port_range")]
    udp_port_range: Option<(u16, u16)>,
    mimic: Option<Vec<MimicArg>>,
    remeasure_interval: Option<u32>,
    tcp_port: Option<u16>,
    stats_interval: Option<u32>,
    exit_policy: Option<crate::cli::ExitPolicy>,
    geo_db: Option<PathBuf>,
    exit_state: Option<PathBuf>,
    up_script: Option<PathBuf>,
    down_script: Option<PathBuf>,
    up_command: Option<String>,
    down_command: Option<String>,
    server_up: Option<String>,
    server_down: Option<String>,
}

pub fn load(path: &Path, multi: bool) -> Result<ClientArgs> {
    let read = || -> Result<String> {
        // Opening a FIFO must not block before the regular-file check.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(path)?;
        ensure!(file.metadata()?.is_file(), "config must be a regular file");
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= MAX_CONFIG, "config exceeds 1 MiB");
        String::from_utf8(bytes).context("config must be UTF-8")
    };
    let text = read().with_context(|| format!("{}: read config", path.display()))?;
    parse(
        &text,
        path.parent().unwrap_or_else(|| Path::new(".")),
        multi,
    )
    .and_then(|args| {
        crate::server_spec::resolve_servers(&args.server, &args.globals)?;
        Ok(args)
    })
    .with_context(|| path.display().to_string())
}

pub fn parse(text: &str, base: &Path, multi: bool) -> Result<ClientArgs> {
    let file: FileConfig = toml::from_str(text).map_err(|error: toml::de::Error| {
        let offset = error.span().map_or(0, |span| span.start).min(text.len());
        let prefix = &text.as_bytes()[..offset];
        let line = 1 + prefix.iter().filter(|byte| **byte == b'\n').count();
        let column = 1 + prefix
            .iter()
            .rev()
            .take_while(|byte| **byte != b'\n')
            .count();
        // Neither Display nor message() is safe: serde errors can echo a field value.
        let reason = if error.message().starts_with("unknown field") {
            "unknown field"
        } else if error.message().starts_with("missing field") {
            "missing required field"
        } else if error.message().contains("duplicate") {
            "duplicate field"
        } else if error.message().starts_with("invalid type") {
            "invalid value type"
        } else {
            "invalid TOML or field value"
        };
        let field = text
            .lines()
            .nth(line - 1)
            .and_then(|line| line.split_once('='))
            .map(|(key, _)| key.trim().trim_matches('"'))
            .filter(|key| {
                !key.is_empty()
                    && key.len() <= 64
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .map(|key| format!(" ({key})"))
            .unwrap_or_default();
        anyhow::anyhow!("line {line}, column {column}{field}: {reason}")
    })?;
    let mut servers = if multi {
        ensure!(
            file.server.is_none(),
            "field 'server' is not allowed in multi mode"
        );
        let servers = file.servers.context("multi requires [[servers]]")?;
        ensure!(!servers.is_empty(), "multi requires at least one server");
        servers
    } else {
        ensure!(
            file.servers.is_none(),
            "field 'servers' is not allowed in single mode"
        );
        vec![ServerSpec::from_host(
            &file.server.context("single requires field 'server'")?,
        )?]
    };
    let mut globals = Globals {
        ssh_user: file.ssh_user,
        ssh_identity: file.ssh_identity,
        ssh_port: file.ssh_port.unwrap_or(22),
        ssh_host_key: file.ssh_host_key,
        ssh_remote_bin: file
            .ssh_remote_bin
            .unwrap_or_else(|| "/usr/local/bin/svpn".into()),
        peer_tun_name: file.peer_tun_name,
        tun_name: file.tun_name,
        tun_addr: file.tun_addr,
        peer_addr: file.peer_addr,
        mtu: file.mtu.unwrap_or(1280),
        log_level: file.log_level.unwrap_or(logging::Level::Info),
        udp_port_range: file.udp_port_range.unwrap_or((60000, 60009)),
        mimic: file.mimic.unwrap_or_default(),
        remeasure_interval: file.remeasure_interval,
        tcp_port: file.tcp_port,
        server_up: file.server_up,
        server_down: file.server_down,
    };
    // Check raw values before inheritance or join("") can conceal an error.
    globals.validate_fields()?;
    for (index, server) in servers.iter_mut().enumerate() {
        server
            .validate_fields()
            .with_context(|| format!("servers[{index}]"))?;
        server.relative_identity(base);
    }
    if let Some(path) = &mut globals.ssh_identity {
        *path = base.join(&*path);
    }
    let mut hooks = hooks::Args {
        up_script: file.up_script,
        down_script: file.down_script,
        up_command: file.up_command,
        down_command: file.down_command,
    };
    for (name, script, command) in [
        ("up", &mut hooks.up_script, &hooks.up_command),
        ("down", &mut hooks.down_script, &hooks.down_command),
    ] {
        ensure!(
            script.is_none() || command.is_none(),
            "{name}-script and {name}-command conflict"
        );
        if let Some(path) = script {
            ensure!(
                !path.as_os_str().is_empty(),
                "{name}-script must not be empty"
            );
            *path = base.join(&*path);
        }
        if let Some(command) = command {
            ensure!(
                !command.trim().is_empty(),
                "{name}-command must not be empty"
            );
        }
    }
    Ok(ClientArgs {
        config: None,
        server: servers,
        globals,
        stats_interval: file.stats_interval.unwrap_or(30),
        exit_policy: file.exit_policy.unwrap_or_default(),
        geo_db: file.geo_db.map(|path| base.join(path)),
        exit_state: file.exit_state.map(|path| base.join(path)),
        hooks,
    })
}

pub(crate) fn port_range<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<(u16, u16)>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|value| crate::parse_port_range(&value).map_err(serde::de::Error::custom))
        .transpose()
}

pub(crate) fn pin<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<russh::keys::ssh_key::Fingerprint>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|value| {
            crate::server_spec::parse_host_key(&value)
                .map_err(|_| serde::de::Error::custom("ssh-host-key expects SHA256 pin"))
        })
        .transpose()
}
