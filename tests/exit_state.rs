//! Exit state: typed country/ASN owners persist across restarts, corruption
//! degrades to empty.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use svpn::exit_state::{ExitKey, ExitState};

fn state_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "svpn-exit-state-{name}-{}.json",
        std::process::id()
    ))
}

// ── persistence ──

#[test]
fn roundtrip_survives_reload_per_domain() {
    let path = state_path("roundtrip");
    let mut state = ExitState::load(Some(path.clone()));
    state.assign(ExitKey::Asn(64512), "node-a");
    state.assign(ExitKey::ScopedAsn("RU".into(), 64500), "node-b");
    state.assign(ExitKey::Country("RU".into()), "node-b");
    state.flush();

    let reloaded = ExitState::load(Some(path.clone()));
    assert_eq!(
        reloaded.owner(&ExitKey::Asn(64512)).map(String::as_str),
        Some("node-a")
    );
    assert_eq!(
        reloaded
            .owner(&ExitKey::ScopedAsn("RU".into(), 64500))
            .map(String::as_str),
        Some("node-b")
    );
    assert_eq!(
        reloaded
            .owner(&ExitKey::Country("RU".into()))
            .map(String::as_str),
        Some("node-b")
    );
    // The maps are independent: one domain never answers another's query.
    assert_eq!(reloaded.owner(&ExitKey::Country("DE".into())), None);
    assert_eq!(
        reloaded.owner(&ExitKey::Asn(64500)),
        None,
        "scoped and global ASN are distinct keys"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn written_document_keeps_both_maps_with_typed_string_keys() {
    let path = state_path("format");
    let mut state = ExitState::load(Some(path.clone()));
    state.assign(ExitKey::Asn(64512), "node-a");
    state.assign(ExitKey::ScopedAsn("RU".into(), 64500), "node-b");
    state.assign(ExitKey::Country("RU".into()), "node-c");
    state.flush();
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(document["version"], 2);
    assert_eq!(document["country"]["RU"], "node-c");
    assert_eq!(document["asn"]["64512"], "node-a");
    assert_eq!(document["asn"]["RU:64500"], "node-b");
    assert_eq!(document["country"].as_object().unwrap().len(), 1);
    assert_eq!(document["asn"].as_object().unwrap().len(), 2);
    let _ = std::fs::remove_file(path);
}

#[test]
fn missing_file_starts_empty() {
    let state = ExitState::load(Some(state_path("missing")));
    assert_eq!(state.owner(&ExitKey::Asn(42)), None);
    assert_eq!(state.owner(&ExitKey::Country("RU".into())), None);
}

// ── v1 migration ──

#[test]
fn v1_owners_migrate_into_global_asn_only() {
    let path = state_path("v1");
    std::fs::write(
        &path,
        r#"{"version":1,"owners":{"64512":"node-a","junk":"node-b"}}"#,
    )
    .unwrap();
    let mut state = ExitState::load(Some(path.clone()));
    assert_eq!(
        state.owner(&ExitKey::Asn(64512)).map(String::as_str),
        Some("node-a")
    );
    assert_eq!(
        state.owner(&ExitKey::Country("RU".into())),
        None,
        "a v1 file has no country owners"
    );
    // Non-numeric v1 group keys cannot be global ASN keys and are dropped.
    assert_eq!(state.owner(&ExitKey::Asn(0)), None);

    // The migration persists once the state is written again, as v2.
    state.assign(ExitKey::Country("DE".into()), "node-c");
    state.flush();
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(document["version"], 2);
    assert_eq!(document["asn"].as_object().unwrap().len(), 1);
    assert_eq!(document["country"]["DE"], "node-c");
    let _ = std::fs::remove_file(path);
}

// ── degradation, never an error ──

#[test]
fn foreign_and_corrupt_documents_start_empty() {
    for text in [
        "not json at all",
        r#"{"version":3,"country":{},"asn":{}}"#,
        r#"{"version":2,"country":{"RU":"node-a"}}"#,
        r#"{"version":1,"country":{},"asn":{}}"#,
        r#"{"version":2,"country":{"RU":"node-a"},"asn":{},"extra":1}"#,
    ] {
        let path = state_path("foreign");
        std::fs::write(&path, text).unwrap();
        let state = ExitState::load(Some(path.clone()));
        assert_eq!(state.owner(&ExitKey::Asn(1)), None, "{text}");
        assert_eq!(state.owner(&ExitKey::Country("RU".into())), None, "{text}");
        let _ = std::fs::remove_file(&path);
    }
}

// ── batching ──

#[test]
fn flush_due_batches_writes() {
    let path = state_path("batching");
    let mut state = ExitState::load(Some(path.clone()));
    state.assign(ExitKey::Asn(42), "node-a");

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
    state.assign(ExitKey::Asn(42), "node-a");
    state.assign(ExitKey::Asn(42), "node-a");

    state.flush_due(Instant::now() + Duration::from_secs(6));
    assert!(path.exists(), "the first assign is pending");
    let _ = std::fs::remove_file(&path);

    state.assign(ExitKey::Asn(42), "node-a");
    state.flush_due(Instant::now() + Duration::from_secs(12));
    assert!(!path.exists(), "an unchanged owner schedules no write");
}

// ── node churn ──

#[test]
fn retain_nodes_drops_departed_in_both_maps() {
    let path = state_path("retain");
    let mut state = ExitState::load(Some(path.clone()));
    state.assign(ExitKey::Asn(42), "node-a");
    state.assign(ExitKey::ScopedAsn("DE".into(), 64500), "node-a");
    state.assign(ExitKey::Country("RU".into()), "node-b");
    state.retain_nodes(&["node-a".to_string()]);
    assert_eq!(state.owner(&ExitKey::Country("RU".into())), None);
    state.flush();

    let reloaded = ExitState::load(Some(path.clone()));
    assert_eq!(
        reloaded.owner(&ExitKey::Asn(42)).map(String::as_str),
        Some("node-a")
    );
    assert_eq!(
        reloaded
            .owner(&ExitKey::ScopedAsn("DE".into(), 64500))
            .map(String::as_str),
        Some("node-a")
    );
    assert_eq!(reloaded.owner(&ExitKey::Country("RU".into())), None);
    let _ = std::fs::remove_file(path);
}

// ── restore ──

#[test]
fn owner_indices_are_typed_and_skip_foreign_entries() {
    let path = state_path("indices");
    std::fs::write(
        &path,
        r#"{"version":2,"country":{"RU":"node-a","??":"node-a"},
            "asn":{"64512":"node-a","RU:64500":"node-b","junk":"node-a"}}"#,
    )
    .unwrap();
    let state = ExitState::load(Some(path.clone()));
    let ids = ["node-a".to_string(), "node-b".to_string()];
    let mut indices = state.owner_indices(&ids);
    assert_eq!(indices.remove(&ExitKey::Asn(64512)), Some(0));
    assert_eq!(
        indices.remove(&ExitKey::ScopedAsn("RU".to_string(), 64500)),
        Some(1)
    );
    assert_eq!(indices.remove(&ExitKey::Country("RU".to_string())), Some(0));
    assert!(
        indices.is_empty(),
        "unparseable stored keys are not restored"
    );
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
    state.assign(ExitKey::Asn(42), "node-a");
    state.flush();
    assert!(!path.exists(), "the failed write produced no file");

    // After the directory appears, the next flush must persist: a failed
    // write keeps the pending state instead of discarding it.
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    state.flush();
    let reloaded = ExitState::load(Some(path.clone()));
    assert_eq!(
        reloaded.owner(&ExitKey::Asn(42)).map(String::as_str),
        Some("node-a"),
        "a failed write must not lose the pending transition"
    );
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
