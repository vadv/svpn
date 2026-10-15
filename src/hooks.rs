//! Local, bounded TUN hooks. Commands and their environment never go over SSH.

use std::{
    net::Ipv4Addr,
    os::{fd::AsFd, unix::process::CommandExt},
    path::PathBuf,
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use nix::{
    errno::Errno,
    fcntl::{AT_FDCWD, AtFlags},
    sys::signal::{Signal, killpg},
    unistd::{AccessFlags, Pid, faccessat},
};
use tokio::{
    process::{Child, Command},
    time::{Instant, sleep_until},
};

const DEADLINE: Duration = Duration::from_secs(10);

#[derive(clap::Args, Default)]
pub struct Args {
    /// Execute a local file after configuring the client TUN.
    #[arg(long, value_name = "PATH", conflicts_with = "up_command")]
    pub up_script: Option<PathBuf>,
    /// Execute a local file before closing the client TUN.
    #[arg(long, value_name = "PATH", conflicts_with = "down_command")]
    pub down_script: Option<PathBuf>,
    /// Execute a local command through /bin/sh -c after configuring the TUN.
    #[arg(long, value_name = "COMMAND", conflicts_with = "up_script")]
    pub up_command: Option<String>,
    /// Execute a local command through /bin/sh -c before closing the TUN.
    #[arg(long, value_name = "COMMAND", conflicts_with = "down_script")]
    pub down_command: Option<String>,
}

pub enum Hook {
    Script(PathBuf),
    Command(String),
}

pub struct TunContext {
    pub name: String,
    pub local: Ipv4Addr,
    pub peer: Ipv4Addr,
}

#[derive(Default)]
pub struct Hooks {
    up: Option<Hook>,
    down: Option<Hook>,
    pub context: Option<TunContext>,
    pub running: Option<Running>,
}

pub struct Running {
    child: Child,
    pub group: Pid,
    event: &'static str,
    pub deadline: Instant,
    pub finished: bool,
}

impl Args {
    pub fn resolve(self) -> Result<Hooks> {
        Ok(Hooks {
            up: resolve(self.up_script, self.up_command)?,
            down: resolve(self.down_script, self.down_command)?,
            context: None,
            running: None,
        })
    }
}

impl Hooks {
    pub fn start(&mut self, name: String, local: Ipv4Addr, peer: Ipv4Addr) -> Result<()> {
        ensure!(self.context.is_none(), "TUN hooks already started");
        self.context = Some(TunContext { name, local, peer });
        if let Some(up) = &self.up {
            let context = self.context.as_ref().context("missing TUN hook context")?;
            self.running = Some(Running::spawn(up, "up", context)?);
        }
        Ok(())
    }

    pub fn starting(&self) -> bool {
        self.running.is_some()
    }

    /// Cancellation safe: the owner retains the process and absolute deadline.
    pub async fn wait_up(&mut self) -> Result<()> {
        let Some(running) = self.running.as_mut() else {
            return std::future::pending().await;
        };
        let result = running.wait().await;
        if result.is_err()
            && !running.finished
            && let Err(error) = running.stop().await
        {
            crate::error!("hook: cleanup after up failed — {error:#}");
            return result;
        }
        self.running = None;
        result
    }

    pub async fn cancel_up(&mut self) -> Result<()> {
        if let Some(mut running) = self.running.take() {
            running.stop().await?;
        }
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.cancel_up().await?;
        // Taking the context makes repeated cleanup a no-op, including failed down.
        if let Some(context) = self.context.take()
            && let Some(down) = &self.down
        {
            Running::spawn(down, "down", &context)?.wait().await?;
        }
        Ok(())
    }
}

impl Running {
    pub fn spawn(hook: &Hook, event: &'static str, context: &TunContext) -> Result<Self> {
        let mut command = match hook {
            Hook::Script(path) => Command::new(path),
            Hook::Command(text) => {
                let mut command = Command::new("/bin/sh");
                command.args(["-c", text]);
                command
            }
        };
        command.as_std_mut().process_group(0);
        command
            .env("SVPN_EVENT", event)
            .env("SVPN_TUN_NAME", &context.name)
            .env("SVPN_TUN_ADDR", context.local.to_string())
            .env("SVPN_PEER_ADDR", context.peer.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::from(std::io::stderr().as_fd().try_clone_to_owned()?))
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let child = command
            .spawn()
            .with_context(|| format!("hook {event}: spawn failed"))?;
        let id = child.id().context("hook process has no id")?;
        let group = Pid::from_raw(i32::try_from(id).context("hook process id is out of range")?);
        crate::info!("hook: {event} started");
        Ok(Self {
            child,
            group,
            event,
            deadline: Instant::now() + DEADLINE,
            finished: false,
        })
    }

    pub async fn wait(&mut self) -> Result<()> {
        // A previous poll may have been canceled while reaping a timed-out child.
        if Instant::now() >= self.deadline {
            self.stop().await?;
            bail!(
                "hook {}: timed out after {} seconds",
                self.event,
                DEADLINE.as_secs()
            );
        }
        tokio::select! {
            result = self.child.wait() => {
                let status = result.with_context(|| format!("hook {}: wait failed", self.event))?;
                // A finished shell may still have ordinary children, including after exit 0.
                self.kill_group()?;
                self.finished = true;
                ensure!(status.success(), "hook {}: {status}", self.event);
                crate::info!("hook: {} completed", self.event);
                Ok(())
            }
            _ = sleep_until(self.deadline) => {
                self.stop().await?;
                bail!("hook {}: timed out after {} seconds", self.event, DEADLINE.as_secs())
            }
        }
    }

    async fn stop(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.kill_group()?;
        self.child.wait().await.context("reap stopped hook")?;
        self.finished = true;
        Ok(())
    }

    fn kill_group(&self) -> Result<()> {
        match killpg(self.group, Signal::SIGKILL) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(error) => Err(error).context("terminate hook process group"),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.finished {
            // Explicit shutdown awaits stop(); this only guards an unexpected drop.
            let _ = self.kill_group();
        }
    }
}

pub fn resolve(script: Option<PathBuf>, command: Option<String>) -> Result<Option<Hook>> {
    ensure!(
        script.is_none() || command.is_none(),
        "hook script and command conflict"
    );
    if let Some(path) = script {
        ensure!(!path.as_os_str().is_empty(), "hook script path is empty");
        // An executable without a slash would otherwise be searched in PATH.
        let path = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()?.join(path)
        };
        let metadata = path.metadata().context("hook script is not accessible")?;
        ensure!(metadata.is_file(), "hook script is not a regular file");
        faccessat(AT_FDCWD, &path, AccessFlags::X_OK, AtFlags::AT_EACCESS)
            .context("hook script is not executable")?;
        return Ok(Some(Hook::Script(path)));
    }
    if let Some(command) = command {
        ensure!(!command.trim().is_empty(), "hook command is empty");
        return Ok(Some(Hook::Command(command)));
    }
    Ok(None)
}
