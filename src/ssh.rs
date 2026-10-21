//! Built-in SSH client (N06): connection, private-key authentication from
//! a file or via the ssh agent, exec of the server binary
//! without a PTY. Strict host-key pinning is optional (`--host-key SHA256:…`);
//! without a pin, TOFU checks saved fingerprints when a known-hosts path is available.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use russh::{
    Disconnect,
    client::{AuthResult, Config, Handle, Handler},
    keys::{
        HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate,
        agent::client::AgentClient, ssh_key::Fingerprint,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::{io::duplex, net::ToSocketAddrs, task::JoinHandle};

use crate::{logging, session::prefixed};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// SSH-level probe interval (the ServerAliveInterval analogue): keeps NAT
/// mappings warm on mobile networks and detects a hung sshd behind a live
/// TCP connection. The fast liveness check stays with the JSONL heartbeat.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_MAX: usize = 3;
/// Silence bound that closes the transport. Must cover the full keepalive
/// window (`KEEPALIVE_INTERVAL * (KEEPALIVE_MAX + 1)`), otherwise inactivity
/// fires first and the probes above never go out.
const SSH_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(60);

pub const STDIN_BUF: usize = 16 * 1024;
pub const STDOUT_BUF: usize = 64 * 1024;

/// Serializes the TOFU read-check-write across pool links: without it, two
/// parallel first connects can each append their host key and the second
/// write erases the first link's entry.
static KNOWN_HOSTS_LOCK: Mutex<()> = Mutex::new(());

/// Credentials for the SSH connection.
pub struct SshTarget {
    pub user: String,
    /// Private key file; `None` — any key from the ssh agent.
    pub identity: Option<PathBuf>,
    /// Host-key fingerprint of the form `SHA256:…`; without it — TOFU via known_hosts.
    pub host_key: Option<Fingerprint>,
    /// Host label in known_hosts (`host:port`).
    pub host_label: String,
}

/// Loaded identity: a private key from a file or any agent key
/// (tried in turn).
#[derive(Debug)]
pub enum Identity {
    Key(Arc<PrivateKey>),
    /// No key specified: try every ssh-agent key in turn.
    AgentAny,
}

pub struct HostKeyCheck {
    pub expected: Option<Fingerprint>,
    pub seen: Arc<Mutex<Option<String>>>,
    /// Pool log tag; empty for a single server.
    pub tag: String,
    /// TOFU file (`host:port SHA256:…`); `None` — no pin and HOME unset:
    /// accept any key, the fingerprint goes to the log only.
    pub known_hosts: Option<PathBuf>,
    pub host_label: String,
}

/// TOFU decision from known_hosts contents.
pub enum HostKeyDecision {
    /// Host is known, fingerprint matches.
    Match,
    /// Host not seen before: remember the fingerprint.
    Learn,
    /// Fingerprint differs from the remembered one (value — the remembered fingerprint).
    Mismatch(String),
}

/// Live SSH session with the server process running.
pub struct SshSession {
    /// Writes to the server process stdin.
    pub stdin: DuplexStream,
    /// Reads the server process stdout (Data only; stderr goes to the log).
    pub stdout: DuplexStream,
    pub tail: SshTail,
}

/// Transport part of the session after handing the streams to `Control`.
pub struct SshTail {
    pub pump: JoinHandle<()>,
    pub handle: Handle<HostKeyCheck>,
}

/// Channel pump event: Control input or an SSH channel message.
enum PumpEvent {
    Stdin(usize),
    StdinEof,
    Chan(Option<russh::ChannelMsg>),
}

impl Handler for HostKeyCheck {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            // Host certificates are not checked against the pin: a trusted CA is beyond the first version.
            PublicKeyOrCertificate::Certificate(_) => return Ok(false),
        };
        let fingerprint = key.fingerprint(HashAlg::Sha256);
        *self.seen.lock().expect("host key lock") = Some(fingerprint.to_string());
        if let Some(expected) = &self.expected {
            return Ok(expected == &fingerprint);
        }
        let Some(path) = &self.known_hosts else {
            return Ok(true);
        };
        let fingerprint = fingerprint.to_string();
        let _guard = KNOWN_HOSTS_LOCK.lock().expect("known_hosts lock");
        let stored_entries = match fs::read_to_string(path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                crate::info!(
                    "{} failed to read {}: {e}",
                    prefixed(&self.tag, "ssh"),
                    path.display()
                );
                return Ok(false);
            }
        };
        match decide_known_hosts(&stored_entries, &self.host_label, &fingerprint) {
            HostKeyDecision::Match => Ok(true),
            HostKeyDecision::Learn => {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let mut entries = stored_entries;
                if !entries.is_empty() && !entries.ends_with('\n') {
                    entries.push('\n');
                }
                entries.push_str(&format!("{} {}\n", self.host_label, fingerprint));
                // A store write failure means rejection: TOFU without a record
                // is useless (fail closed), and russh::Error cannot express IO errors.
                if let Err(e) = std::fs::write(path, entries) {
                    crate::info!(
                        "{} failed to write {}: {e}",
                        prefixed(&self.tag, "ssh"),
                        path.display()
                    );
                    return Ok(false);
                }
                crate::info!(
                    "{} remembered host key for {}",
                    prefixed(&self.tag, "ssh"),
                    self.host_label
                );
                Ok(true)
            }
            HostKeyDecision::Mismatch(stored) => {
                crate::info!(
                    "{} host key for {} does not match the remembered one ({} != {})",
                    prefixed(&self.tag, "ssh"),
                    self.host_label,
                    fingerprint,
                    stored
                );
                Ok(false)
            }
        }
    }
}

impl SshSession {
    /// Splits the session into streams for `Control::new` and a tail for `close`.
    pub fn into_io(self) -> (DuplexStream, DuplexStream, SshTail) {
        (self.stdin, self.stdout, self.tail)
    }
}

impl SshTail {
    /// Closes the SSH connection and stops the pump.
    pub async fn close(mut self) {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            self.handle
                .disconnect(Disconnect::ByApplication, "session closed", "en"),
        )
        .await;
        self.pump.abort();
        let _ = (&mut self.pump).await;
    }
}

impl Drop for SshTail {
    fn drop(&mut self) {
        // Bootstrap errors and cancellation must not leave the SSH pump detached.
        self.pump.abort();
    }
}

/// Connects, authenticates, and runs `command` on the server.
/// Returns a pair of streams for `Control::new`. `tag` names the pool link
/// in log lines; empty for a single server.
pub async fn connect<A: ToSocketAddrs>(
    target: &SshTarget,
    addr: A,
    command: &str,
    tag: &str,
) -> Result<SshSession> {
    let seen = Arc::new(Mutex::new(None));
    let handler = HostKeyCheck {
        expected: target.host_key,
        seen: seen.clone(),
        tag: tag.to_string(),
        known_hosts: known_hosts_path(),
        host_label: target.host_label.clone(),
    };
    let config = Arc::new(Config {
        inactivity_timeout: Some(SSH_INACTIVITY_TIMEOUT),
        keepalive_interval: Some(KEEPALIVE_INTERVAL),
        keepalive_max: KEEPALIVE_MAX,
        ..Config::default()
    });

    crate::info!(
        "{} connecting to {}",
        prefixed(tag, "ssh"),
        target.host_label
    );
    // A stalled peer (e.g. silent after its banner) leaves russh's spawned
    // session task holding the socket: dropping the connect future does not
    // cancel it, and with keepalive enabled russh resets the inactivity timer
    // on every pre-auth keepalive tick (0.64.x), so the task never exits.
    // Owning the TCP stream lets us shutdown() a dup of the fd to kill it.
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("SSH connection timeout"))?
        .map_err(|e| anyhow::anyhow!("SSH connection failed (host unreachable): {e}"))?;
    let _ = stream.set_nodelay(true);
    let std_stream = stream.into_std()?;
    let killer = std_stream.try_clone().ok();
    std_stream.set_nonblocking(true)?;
    let stream = tokio::net::TcpStream::from_std(std_stream)?;
    let connect = russh::client::connect_stream(config, stream, handler);
    tokio::pin!(connect);
    let mut handle = match tokio::time::timeout(CONNECT_TIMEOUT, &mut connect).await {
        Err(_) => {
            if let Some(sock) = &killer {
                // Bare syscall on an idle socket: cheap enough for async code.
                let _ = sock.shutdown(std::net::Shutdown::Both);
            }
            anyhow::bail!("SSH connection timeout");
        }
        Ok(Err(e)) => {
            anyhow::bail!("SSH connection failed (host key rejected or malformed handshake): {e}")
        }
        Ok(Ok(handle)) => handle,
    };

    let identity = match &target.identity {
        Some(path) => load_identity(path)?,
        None => Identity::AgentAny,
    };
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        authenticate(&mut handle, &target.user, &identity, tag),
    )
    .await
    .map_err(|_| anyhow::anyhow!("authentication timeout"))??;

    let channel = tokio::time::timeout(CONNECT_TIMEOUT, handle.channel_open_session())
        .await
        .map_err(|_| anyhow::anyhow!("channel open timeout"))?
        .context("opening the channel")?;
    channel
        .exec(true, command)
        .await
        .context("starting the command on the server")?;

    let fingerprint = seen
        .lock()
        .expect("host key lock")
        .clone()
        .unwrap_or_default();
    let pin_status = if target.host_key.is_some() {
        "matches the pin"
    } else {
        "(no pin set)"
    };
    crate::info!(
        "{} host key {fingerprint} {pin_status}",
        prefixed(tag, "ssh")
    );

    let (stdin_writer, stdin_reader) = duplex(STDIN_BUF);
    let (stdout_writer, stdout_reader) = duplex(STDOUT_BUF);
    let pump = tokio::spawn(pump_channel(
        channel,
        stdin_reader,
        stdout_writer,
        tag.to_string(),
    ));

    Ok(SshSession {
        stdin: stdin_writer,
        stdout: stdout_reader,
        tail: SshTail { pump, handle },
    })
}

pub async fn authenticate(
    handle: &mut Handle<HostKeyCheck>,
    user: &str,
    identity: &Identity,
    tag: &str,
) -> Result<()> {
    let result = match identity {
        Identity::Key(key) => {
            let hash = rsa_hash(handle, key.algorithm().is_rsa()).await?;
            handle
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(key.clone(), hash))
                .await
                .context("authenticating with the key from file")?
        }
        Identity::AgentAny => {
            let mut agent = AgentClient::connect_env()
                .await
                .context("--ssh-identity not given and ssh agent unavailable (SSH_AUTH_SOCK)")?;
            let identities = agent
                .request_identities()
                .await
                .context("agent did not return the key list")?;
            ensure!(!identities.is_empty(), "ssh agent holds no keys");
            let mut failures = Vec::new();
            for identity in &identities {
                let public = identity.public_key().clone().into_owned();
                let hash = rsa_hash(handle, public.algorithm().is_rsa()).await?;
                let attempt = handle
                    .authenticate_publickey_with(user, public.clone(), hash, &mut agent)
                    .await
                    .context("agent authentication")?;
                match attempt {
                    AuthResult::Success => {
                        crate::info!(
                            "{} accepted agent key {}",
                            prefixed(tag, "ssh"),
                            public.fingerprint(HashAlg::Sha256)
                        );
                        return Ok(());
                    }
                    AuthResult::Failure { .. } => {
                        failures.push(public.fingerprint(HashAlg::Sha256).to_string())
                    }
                }
            }
            bail!(
                "server rejected all ssh-agent keys: {}",
                failures.join(", ")
            )
        }
    };
    match result {
        AuthResult::Success => Ok(()),
        AuthResult::Failure {
            remaining_methods, ..
        } => {
            bail!("server rejected the key (available methods: {remaining_methods:?})")
        }
    }
}

/// Reads `path` as an OpenSSH private key. Public keys and
/// password-protected keys are not accepted: those authenticate through
/// the ssh agent (omit --ssh-identity).
pub fn load_identity(path: &Path) -> Result<Identity> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    ensure!(
        !content.trim().is_empty(),
        "key file is empty: {}",
        path.display()
    );
    match PrivateKey::from_openssh(&content) {
        Ok(key) => Ok(Identity::Key(Arc::new(key))),
        Err(err) => bail!(
            "{} is not a readable private key: {err}; \
             password-protected keys work through the ssh agent — omit --ssh-identity",
            path.display()
        ),
    }
}

pub fn decide_known_hosts(entries: &str, host_label: &str, fingerprint: &str) -> HostKeyDecision {
    for line in entries.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(host_label) {
            return match parts.next() {
                Some(stored) if stored == fingerprint => HostKeyDecision::Match,
                Some(stored) => HostKeyDecision::Mismatch(stored.to_string()),
                None => HostKeyDecision::Learn,
            };
        }
    }
    HostKeyDecision::Learn
}

/// Sole owner of the channel: stdout (Data) goes to Control, stderr
/// (ExtendedData) — to the local log, stdin — from Control. Eof/Close/None
/// end the pump; waiting goes through an event enum so that `wait()` and
/// `data()` do not fight over channel borrows.
pub async fn pump_channel(
    mut channel: russh::Channel<russh::client::Msg>,
    mut stdin: DuplexStream,
    mut stdout: DuplexStream,
    tag: String,
) {
    let mut buf = vec![0u8; STDIN_BUF];
    loop {
        let event = {
            let wait = channel.wait();
            let read = stdin.read(&mut buf);
            tokio::pin!(wait);
            tokio::pin!(read);
            tokio::select! {
                read = &mut read => match read {
                    Ok(0) | Err(_) => PumpEvent::StdinEof,
                    Ok(n) => PumpEvent::Stdin(n),
                },
                msg = &mut wait => PumpEvent::Chan(msg),
            }
        };
        match event {
            PumpEvent::Stdin(n) => {
                if channel.data(&buf[..n]).await.is_err() {
                    break;
                }
            }
            PumpEvent::StdinEof => {
                crate::debug!("ssh pump: stdin eof — all control senders are gone");
                let _ = channel.eof().await;
                break;
            }
            PumpEvent::Chan(Some(russh::ChannelMsg::Data { data })) => {
                if stdout.write_all(&data).await.is_err() {
                    break;
                }
            }
            PumpEvent::Chan(Some(russh::ChannelMsg::ExtendedData { data, .. })) => {
                relay_server_stderr(&tag, &data);
            }
            PumpEvent::Chan(Some(russh::ChannelMsg::ExitStatus { exit_status })) => {
                crate::info!(
                    "{} server process exited, code {exit_status}",
                    prefixed(&tag, "ssh")
                );
            }
            PumpEvent::Chan(Some(russh::ChannelMsg::Eof))
            | PumpEvent::Chan(Some(russh::ChannelMsg::Close))
            | PumpEvent::Chan(None) => {
                crate::debug!("ssh pump: channel closed ({:?})", event_label(&event));
                break;
            }
            PumpEvent::Chan(Some(_)) => {}
        }
    }
}

/// `[server h1]` inside a pool; single-server output stays byte-identical.
pub fn server_stderr_line(tag: &str, text: &str) -> String {
    let host = tag.trim_matches(['[', ']']);
    if host.is_empty() {
        format!("[server] {text}")
    } else {
        format!("[server {host}] {text}")
    }
}

async fn rsa_hash(handle: &mut Handle<HostKeyCheck>, key_is_rsa: bool) -> Result<Option<HashAlg>> {
    if !key_is_rsa {
        return Ok(None);
    }
    // RSA needs a sha2 hash negotiated with the server; Ok(None) — the server rejects RSA.
    match handle
        .best_supported_rsa_hash()
        .await
        .context("requesting the RSA hash from the server")?
    {
        Some(hash) => Ok(hash),
        None => bail!("server does not support RSA keys"),
    }
}

/// known_hosts path: `$SVPN_KNOWN_HOSTS` or `$HOME/.config/svpn/known_hosts`;
/// without HOME — `None` (TOFU off, the key is only logged).
fn known_hosts_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SVPN_KNOWN_HOSTS") {
        return Some(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/svpn/known_hosts"))
}

/// Server stderr already carries its own `t+…s`; the client time scale is
/// shared, so the foreign timestamp is stripped and the line gets a role tag.
fn relay_server_stderr(tag: &str, data: &[u8]) {
    for line in String::from_utf8_lossy(data).lines() {
        let mut text = line;
        if text.starts_with("t+")
            && let Some((_, rest)) = text.split_once('s')
            && rest.starts_with(' ')
        {
            text = rest.trim_start();
        }
        if !text.is_empty() {
            logging::write(server_stderr_line(tag, text));
        }
    }
}

fn event_label(event: &PumpEvent) -> &'static str {
    match event {
        PumpEvent::Stdin(_) => "stdin",
        PumpEvent::StdinEof => "stdin-eof",
        PumpEvent::Chan(Some(russh::ChannelMsg::Eof)) => "eof",
        PumpEvent::Chan(Some(russh::ChannelMsg::Close)) => "close",
        PumpEvent::Chan(Some(_)) => "msg",
        PumpEvent::Chan(None) => "none",
    }
}
