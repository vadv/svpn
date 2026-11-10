//! Linux binaries, musl and GNU alike: jemalloc uses the embedded reclamation
//! defaults.

#![cfg(target_os = "linux")]

use std::process::Command;

// ── compiled defaults ──

#[test]
fn musl_binary_uses_jemalloc_with_compiled_defaults() {
    let output = Command::new(env!("CARGO_BIN_EXE_svpn"))
        .arg("--version")
        .env("_RJEM_MALLOC_CONF", "confirm_conf:true,abort_conf:true")
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("malloc_conf #1"), "{stderr}");
    assert!(
        stderr.contains(
            "dirty_decay_ms:30000,muzzy_decay_ms:30000,background_thread:true,metadata_thp:auto"
        ),
        "{stderr}"
    );
    for option in [
        "dirty_decay_ms:30000",
        "muzzy_decay_ms:30000",
        "background_thread:true",
        "metadata_thp:auto",
    ] {
        assert!(
            stderr.contains(&format!("Set conf value: {option}")),
            "{stderr}"
        );
    }
}
