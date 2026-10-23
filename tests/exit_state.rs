//! Exit state: failover transitions persist across restarts, corruption degrades to empty.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use svpn::exit_state::ExitState;

fn state_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "svpn-exit-state-{name}-{}.json",
        std::process::id()
    ))
}

// ── persistence ──

#[test]
fn roundtrip_survives_reload() {
    let path = state_path("roundtrip");
    let mut state = ExitState::load(Some(path.clone()));
    state.assign(42, "node-a");
    state.assign(43, "node-b");
    state.flush();

    let reloaded = ExitState::load(Some(path.clone()));
    assert_eq!(reloaded.owner(42).map(String::as_str), Some("node-a"));
    assert_eq!(reloaded.owner(43).map(String::as_str), Some("node-b"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn missing_file_starts_empty() {
    let state = ExitState::load(Some(state_path("missing")));
    assert_eq!(state.owner(42), None);
}

// ── degradation, never an error ──

#[test]
fn version_mismatch_starts_empty() {
    let path = state_path("version");
    std::fs::write(&path, r#"{"version":2,"owners":{"42":"node-a"}}"#).unwrap();
    let state = ExitState::load(Some(path.clone()));
    assert_eq!(state.owner(42), None, "a foreign version is not adopted");
    let _ = std::fs::remove_file(path);
}

#[test]
fn corrupt_file_starts_empty() {
    let path = state_path("corrupt");
    std::fs::write(&path, b"not json at all").unwrap();
    let state = ExitState::load(Some(path.clone()));
    assert_eq!(state.owner(42), None);
    let _ = std::fs::remove_file(path);
}

// ── batching ──

#[test]
fn flush_due_batches_writes() {
    let path = state_path("batching");
    let mut state = ExitState::load(Some(path.clone()));
    state.assign(42, "node-a");

    state.flush_due(Instant::now());
    assert!(!path.exists(), "flush is batched: not due within 5s");

    state.flush_due(Instant::now() + Duration::from_secs(6));
    assert!(path.exists(), "flush fires once the interval passes");
    let _ = std::fs::remove_file(path);
}

#[test]
fn repeat_assign_is_not_dirty() {
    let path = state_path("repeat");
    let mut state = ExitState::load(Some(path.clone()));
    state.assign(42, "node-a");
    state.assign(42, "node-a");

    state.flush_due(Instant::now() + Duration::from_secs(6));
    assert!(path.exists(), "the first assign is pending");
    let _ = std::fs::remove_file(&path);

    state.assign(42, "node-a");
    state.flush_due(Instant::now() + Duration::from_secs(12));
    assert!(!path.exists(), "an unchanged owner schedules no write");
}

// ── node churn ──

#[test]
fn retain_nodes_drops_departed() {
    let path = state_path("retain");
    let mut state = ExitState::load(Some(path.clone()));
    state.assign(42, "node-a");
    state.assign(43, "node-b");
    state.retain_nodes(&["node-a".to_string()]);
    assert_eq!(
        state.owner(43),
        None,
        "groups of departed nodes are dropped"
    );
    state.flush();

    let reloaded = ExitState::load(Some(path.clone()));
    assert_eq!(reloaded.owner(42).map(String::as_str), Some("node-a"));
    assert_eq!(reloaded.owner(43), None);
    let _ = std::fs::remove_file(path);
}

// ── write errors ──

#[test]
fn failed_write_stays_pending_and_recovers() {
    // Parent directory does not exist: the write fails.
    let path = state_path("enoent").with_file_name(format!(
        "svpn-exit-state-enoent-{}/state.json",
        std::process::id()
    ));
    let mut state = ExitState::load(Some(path.clone()));
    state.assign(42, "node-a");
    state.flush();
    assert!(!path.exists(), "the failed write produced no file");

    // After the directory appears, the next flush must persist: a failed
    // write keeps the pending state instead of discarding it.
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    state.flush();
    let reloaded = ExitState::load(Some(path.clone()));
    assert_eq!(
        reloaded.owner(42).map(String::as_str),
        Some("node-a"),
        "a failed write must not lose the pending transition"
    );
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
