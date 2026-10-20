//! Up/down hooks: CLI validation, script resolution, process behavior, lifecycle.

use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use svpn::hooks::*;
use tokio::time::Instant;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    hooks: Args,
}

fn context() -> TunContext {
    TunContext {
        name: "utun$(false); literal".into(),
        local: Ipv4Addr::new(10, 77, 0, 2),
        peer: Ipv4Addr::new(10, 77, 0, 1),
    }
}

fn temporary_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "svpn hook {} {}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

// ── parsing and resolution ──

#[test]
fn parser_rejects_conflicts_repetition_and_invalid_values() {
    for args in [
        vec!["test", "--up-script", "a", "--up-command", "true"],
        vec!["test", "--down-script", "a", "--down-command", "true"],
        vec!["test", "--up-command", "true", "--up-command", "false"],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
    for args in [
        vec!["test", "--up-command", " \n\t"],
        vec!["test", "--down-command", ""],
        vec!["test", "--up-script", ""],
        vec!["test", "--down-script", "/definitely/not/a/hook"],
        vec!["test", "--up-script", "/tmp"],
    ] {
        assert!(match Cli::try_parse_from(args) {
            Ok(cli) => cli.hooks.resolve().is_err(),
            Err(_) => true,
        });
    }
}

#[tokio::test]
async fn script_with_spaces_runs_directly_and_requires_execute_permission() {
    let dir = temporary_dir();
    let path = dir.join("script with spaces");
    write_script(&path).await;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(resolve(Some(path.clone()), None).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let hook = resolve(Some(path), None).unwrap().unwrap();
    Running::spawn(&hook, "up", &context())
        .unwrap()
        .wait()
        .await
        .unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn script_validation_uses_callers_execute_permissions() {
    let dir = temporary_dir();
    let path = dir.join("hook");
    write_script(&path).await;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o601)).unwrap();
    let resolved = resolve(Some(path.clone()), None);
    let spawned = Running::spawn(&Hook::Script(path), "up", &context());
    let executable = spawned.is_ok();
    let spawn_error = spawned.as_ref().err().map(|error| format!("{error:#}"));
    if let Ok(mut running) = spawned {
        running.wait().await.unwrap();
    }
    std::fs::remove_dir_all(dir).unwrap();
    assert_eq!(resolved.is_ok(), executable, "spawn error: {spawn_error:?}");
}

// ── running process ──

#[tokio::test]
async fn environment_is_literal_and_stdin_is_closed() {
    let hook = Hook::Command("test \"$SVPN_EVENT\" = up && test \"$SVPN_TUN_NAME\" = 'utun$(false); literal' && test \"$SVPN_TUN_ADDR\" = 10.77.0.2 && test \"$SVPN_PEER_ADDR\" = 10.77.0.1 && ! read -r line".into());
    Running::spawn(&hook, "up", &context())
        .unwrap()
        .wait()
        .await
        .unwrap();
}

#[tokio::test]
async fn exit_signal_spawn_and_timeout_are_errors() {
    for text in ["exit 7", "kill -TERM $$"] {
        assert!(
            Running::spawn(&Hook::Command(text.into()), "up", &context())
                .unwrap()
                .wait()
                .await
                .is_err()
        );
    }
    assert!(Running::spawn(&Hook::Script("/no/such/hook".into()), "up", &context()).is_err());
    let mut running =
        Running::spawn(&Hook::Command("sleep 60 & wait".into()), "up", &context()).unwrap();
    let pid = running.group;
    running.deadline = Instant::now() + Duration::from_millis(100);
    assert!(
        running
            .wait()
            .await
            .unwrap_err()
            .to_string()
            .contains("timed out")
    );
    assert!(running.finished);
    assert_eq!(nix::sys::signal::kill(pid, None), Err(Errno::ESRCH));
}

#[tokio::test]
async fn completed_hook_stops_remaining_group() {
    for ending in ["exit 0", "exit 7", "kill -TERM $$"] {
        let dir = temporary_dir();
        let path = dir.join("child.pid");
        let mut context = context();
        context.name = path.to_str().unwrap().into();
        let hook = Hook::Command(format!("sleep 60 & echo $! > \"$SVPN_TUN_NAME\"; {ending}"));
        let mut running = Running::spawn(&hook, "up", &context).unwrap();
        assert_eq!(running.wait().await.is_ok(), ending == "exit 0");
        let pid = Pid::from_raw(
            std::fs::read_to_string(&path)
                .unwrap()
                .trim()
                .parse()
                .unwrap(),
        );
        let gone = tokio::time::timeout(Duration::from_secs(2), async {
            while nix::sys::signal::kill(pid, None) != Err(Errno::ESRCH) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok();
        if !gone {
            let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
        }
        std::fs::remove_dir_all(dir).unwrap();
        assert!(gone, "hook descendant survived {ending}");
    }
}

// ── up/down lifecycle ──

#[tokio::test]
async fn failed_up_runs_compensation_once_with_same_context() {
    let dir = temporary_dir();
    let path = dir.join("events");
    let record = "printf '%s %s %s\\n' \"$SVPN_EVENT\" \"$SVPN_TUN_ADDR\" \"$SVPN_PEER_ADDR\" >> \"$SVPN_TUN_NAME\"";
    let mut hooks = Args {
        up_command: Some(format!("{record}; exit 7")),
        down_command: Some(record.into()),
        ..Args::default()
    }
    .resolve()
    .unwrap();
    hooks
        .start(
            path.to_str().unwrap().into(),
            context().local,
            context().peer,
        )
        .unwrap();
    assert!(hooks.wait_up().await.is_err());
    hooks.finish().await.unwrap();
    hooks.finish().await.unwrap();
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        "up 10.77.0.2 10.77.0.1\ndown 10.77.0.2 10.77.0.1\n"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn failed_down_is_not_retried_and_never_runs_before_tun() {
    let mut hooks = Args {
        down_command: Some("exit 7".into()),
        ..Args::default()
    }
    .resolve()
    .unwrap();
    hooks.finish().await.unwrap();
    hooks
        .start(context().name, context().local, context().peer)
        .unwrap();
    assert!(!hooks.starting());
    assert!(hooks.finish().await.is_err());
    hooks.finish().await.unwrap();
}

#[tokio::test]
async fn cancellation_finishes_up_before_single_down() {
    let mut hooks = Args {
        up_command: Some("sleep 60".into()),
        down_command: Some("test \"$SVPN_EVENT\" = down".into()),
        ..Args::default()
    }
    .resolve()
    .unwrap();
    hooks
        .start(context().name, context().local, context().peer)
        .unwrap();
    let pid = hooks.running.as_ref().unwrap().group;
    assert!(hooks.starting());
    hooks.finish().await.unwrap();
    assert!(!hooks.starting());
    assert!(hooks.context.is_none());
    assert_eq!(nix::sys::signal::kill(pid, None), Err(Errno::ESRCH));
    hooks.finish().await.unwrap();
}

async fn write_script(path: &std::path::Path) {
    // A child-owned writer cannot be inherited by other tests' concurrent spawns.
    let mut context = context();
    context.name = path.to_str().unwrap().into();
    let hook = Hook::Command("printf '#!/bin/sh\\nexit 0\\n' > \"$SVPN_TUN_NAME\"".into());
    Running::spawn(&hook, "up", &context)
        .unwrap()
        .wait()
        .await
        .unwrap();
}

// ── capture ──

#[tokio::test]
async fn run_with_capture_returns_truncated_output() {
    let hook =
        Hook::Command("printf 'out'; printf 'err' >&2; printf '%*s' 5000 x | tr ' ' y".into());
    let (stdout, stderr) = run_with_capture(&hook, "up", &context()).await.unwrap();
    assert_eq!(stdout.len(), 1500);
    assert!(stdout.starts_with("out"));
    assert!(stdout.ends_with("y"));
    assert_eq!(stderr, "err");
}

#[tokio::test]
async fn run_with_capture_supports_script() {
    let dir = temporary_dir();
    let path = dir.join("script");
    write_script(&path).await;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let hook = Hook::Script(path);
    let (stdout, stderr) = run_with_capture(&hook, "up", &context()).await.unwrap();
    assert_eq!(stdout, "");
    assert_eq!(stderr, "");
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn run_with_capture_enforces_deadline_and_kills_group() {
    let hook = Hook::Command("sleep 60".into());
    let start = Instant::now();
    let result = run_with_capture(&hook, "up", &context()).await;
    assert!(result.is_err());
    assert!(format!("{:#}", result.err().unwrap()).contains("timed out"));
    assert!(start.elapsed() >= Duration::from_secs(10));
}

#[tokio::test]
async fn run_with_capture_reports_failure() {
    let hook = Hook::Command("exit 7".into());
    let result = run_with_capture(&hook, "up", &context()).await;
    assert!(result.is_err());
    assert!(format!("{:#}", result.err().unwrap()).contains("exit status: 7"));
}
