//! `svpn setup`: bounded SSH provisioning of the server binary and hooks.
//! It never opens a TUN, starts a service, or executes the deployed hooks.

use std::{net::SocketAddr, path::Path, time::Duration};

use anyhow::{Context, Result, anyhow, ensure};
use sha2::{Digest, Sha256};

use crate::{config, shell_quote, ssh};

pub const SETUP_SCRIPT: &str = include_str!("../scripts/setup");
pub const SERVER_UP: &str = include_str!("../scripts/server-up");
pub const SERVER_DOWN: &str = include_str!("../scripts/server-down");

const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(60);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_PREFLIGHT_OUTPUT: usize = 64 * 1024;
const MAX_INSTALL_OUTPUT: usize = 256 * 1024;
const MAX_INSTALL_INPUT: usize = 256 * 1024;

/// Verified result of one host.
struct HostSuccess {
    version: String,
    downgrade: Option<String>,
    changed: Vec<String>,
}

/// Per-host report. `Unknown` means the final host state was lost (channel
/// error, timeout, interruption); `Partial` means the installer exited
/// nonzero after replacing at least one managed file.
enum HostReport {
    Success(HostSuccess),
    Failed(anyhow::Error),
    Partial {
        version: String,
        downgrade: Option<String>,
        changed: Vec<String>,
        error: anyhow::Error,
    },
    Unknown(anyhow::Error),
}

/// Provision every configured VPS sequentially, continuing after ordinary host failures.
pub async fn run(path: &Path) -> Result<()> {
    let args = match config::load(path, true) {
        Ok(args) => args,
        Err(multi_error) => config::load(path, false).map_err(|single_error| {
            anyhow!(
                "config is neither valid multi nor single mode:\nmulti: {multi_error:#}\nsingle: {single_error:#}"
            )
        })?,
    };
    // Resolve and validate the complete target list before opening the first SSH connection.
    let servers = crate::server_spec::resolve_servers(&args.server, &args.globals)?;
    let mut hosts = Vec::new();
    for params in servers {
        let user = params
            .user
            .clone()
            .or_else(|| std::env::var("USER").ok())
            .context("user not set: set ssh-user or USER")?;
        if let Some(identity) = &params.identity {
            ssh::load_identity(identity)
                .with_context(|| format!("invalid SSH identity {}", identity.display()))?;
        }
        let server_ip = crate::server_spec::resolve_ipv4(&params.server).await?;
        let address = SocketAddr::from((server_ip, params.ssh_port));
        let target = ssh::SshTarget {
            user,
            identity: params.identity.clone(),
            host_key: params.host_key,
            host_label: format!("{}:{}", params.server, params.ssh_port),
        };
        hosts.push((params, target, address));
    }
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("install SIGTERM handler")?;
    let mut failures = 0;
    let mut interrupted = false;
    for (params, target, address) in hosts {
        let host = &params.server;
        let port = params.ssh_port;
        if interrupted {
            failures += 1;
            println!("SETUP host={host} port={port} status=not-attempted");
            continue;
        }
        let report = tokio::select! {
            report = run_host(&target, address) => match report {
                Ok(success) => HostReport::Success(success),
                Err(report) => report,
            },
            _ = tokio::signal::ctrl_c() => {
                interrupted = true;
                HostReport::Unknown(anyhow!("interrupted by SIGINT"))
            }
            _ = terminate.recv() => {
                interrupted = true;
                HostReport::Unknown(anyhow!("interrupted by SIGTERM"))
            }
        };
        match report {
            HostReport::Success(success) => println!(
                "SETUP host={host} port={port} status=success version={}{} changed={}",
                success.version,
                downgrade_field(&success.downgrade),
                success.changed.join(",")
            ),
            HostReport::Partial {
                version,
                downgrade,
                changed,
                error,
            } => {
                failures += 1;
                println!(
                    "SETUP host={host} port={port} status=partial version={version}{} changed={} error={error:#}",
                    downgrade_field(&downgrade),
                    changed.join(",")
                );
            }
            HostReport::Failed(error) => {
                failures += 1;
                println!("SETUP host={host} port={port} status=failed error={error:#}");
            }
            HostReport::Unknown(error) => {
                failures += 1;
                println!("SETUP host={host} port={port} status=unknown error={error:#}");
            }
        }
    }
    ensure!(!interrupted, "setup interrupted");
    ensure!(failures == 0, "setup failed for {failures} host(s)");
    Ok(())
}

async fn run_host(
    target: &ssh::SshTarget,
    address: SocketAddr,
) -> std::result::Result<HostSuccess, HostReport> {
    let handle = ssh::connect_handle(target, address, "")
        .await
        .map_err(HostReport::Failed)?;
    let result = run_connected(&handle).await;
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        handle.disconnect(russh::Disconnect::ByApplication, "setup complete", "en"),
    )
    .await;
    result
}

async fn run_connected(
    handle: &russh::client::Handle<ssh::HostKeyCheck>,
) -> std::result::Result<HostSuccess, HostReport> {
    let preflight = ssh::exec(
        handle,
        "exec /bin/sh -eu -s",
        &preflight_input(),
        MAX_PREFLIGHT_OUTPUT,
        PREFLIGHT_TIMEOUT,
    )
    .await
    .map_err(HostReport::Failed)?;
    print_output(&preflight);
    ensure_status(&preflight, "preflight").map_err(HostReport::Failed)?;

    let install = ssh::exec(
        handle,
        "exec /bin/sh -eu -s",
        &installer_input(env!("CARGO_PKG_VERSION")).map_err(HostReport::Failed)?,
        MAX_INSTALL_OUTPUT,
        INSTALL_TIMEOUT,
    )
    .await
    .map_err(HostReport::Unknown)?;
    print_output(&install);
    let changed = changed_paths(&install.stdout);
    let downgrade = downgrade_report(&install.stdout);
    if install.status != 0 {
        let error = anyhow!("remote installer exited with status {}", install.status);
        let Some(version) = selected_version(&install.stdout).ok() else {
            return Err(HostReport::Failed(error));
        };
        if changed.is_empty() {
            return Err(HostReport::Failed(error));
        }
        return Err(HostReport::Partial {
            version,
            downgrade,
            changed,
            error,
        });
    }
    let version = selected_version(&install.stdout).map_err(HostReport::Unknown)?;
    Ok(HostSuccess {
        version,
        downgrade,
        changed,
    })
}

fn ensure_status(output: &ssh::ExecOutput, operation: &str) -> Result<()> {
    ensure!(
        output.status == 0,
        "remote {operation} exited with status {}",
        output.status
    );
    Ok(())
}

fn print_output(output: &ssh::ExecOutput) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        for line in text.lines().filter(|line| !line.is_empty()) {
            println!("  {line}");
        }
    }
}

pub fn selected_version(stdout: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(stdout).context("installer stdout is not UTF-8")?;
    let version = text
        .lines()
        .find_map(|line| line.strip_prefix("SVPN_SETUP_SELECTED="))
        .context("installer did not report a selected version")?;
    ensure!(!version.is_empty(), "installer reported an empty version");
    Ok(version.to_string())
}

/// Managed paths the installer reported replacing, in report order.
pub fn changed_paths(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|line| line.strip_prefix("SVPN_SETUP_CHANGED=").map(str::to_string))
        .collect()
}

/// Explicit downgrade notice: the selected release is older than the
/// installed one. Installer output is remote data: accept only version pairs.
pub fn downgrade_report(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let line = text
        .lines()
        .find_map(|line| line.strip_prefix("SVPN_SETUP_DOWNGRADE="))?;
    let (from, to) = line.split_once("->")?;
    let version =
        |value: &str| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    (version(from) && version(to)).then(|| line.to_string())
}

fn downgrade_field(downgrade: &Option<String>) -> String {
    downgrade
        .as_ref()
        .map(|value| format!(" downgrade={value}"))
        .unwrap_or_default()
}

pub fn preflight_input() -> Vec<u8> {
    let mut input = SETUP_SCRIPT.as_bytes().to_vec();
    input.extend_from_slice(b"\nsvpn_setup_preflight\n");
    input
}

pub fn installer_input(version: &str) -> Result<Vec<u8>> {
    let up_hash = hex(&Sha256::digest(SERVER_UP.as_bytes()));
    let down_hash = hex(&Sha256::digest(SERVER_DOWN.as_bytes()));
    let mut input = format!("SVPN_CLIENT_VERSION={}\n", shell_quote(version)).into_bytes();
    input.extend_from_slice(SETUP_SCRIPT.as_bytes());
    input.extend_from_slice(b"\nsvpn_setup_install <<'SVPN_SETUP_PAYLOAD'\n");
    input.extend_from_slice(format!("server-up {up_hash} {}\n", SERVER_UP.len()).as_bytes());
    input.extend_from_slice(SERVER_UP.as_bytes());
    input.extend_from_slice(format!("server-down {down_hash} {}\n", SERVER_DOWN.len()).as_bytes());
    input.extend_from_slice(SERVER_DOWN.as_bytes());
    input.extend_from_slice(b"SVPN_SETUP_PAYLOAD\n");
    ensure!(
        input.len() <= MAX_INSTALL_INPUT,
        "installer input exceeds {MAX_INSTALL_INPUT} bytes"
    );
    ensure!(
        framing_safe(SERVER_UP) && framing_safe(SERVER_DOWN),
        "embedded payload contains its framing delimiter"
    );
    Ok(input)
}

/// A hook line equal to the heredoc delimiter would terminate the payload
/// early, so it must not appear anywhere in an embedded script.
pub fn framing_safe(script: &str) -> bool {
    !script.lines().any(|line| line == "SVPN_SETUP_PAYLOAD")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}
