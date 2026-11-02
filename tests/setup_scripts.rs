//! Embedded setup and server hook scripts.

use std::{
    io::Write,
    process::{Command, Stdio},
};

use svpn::setup::{SERVER_DOWN, SERVER_UP, SETUP_SCRIPT};

const SCRIPTS: [(&str, &str); 3] = [
    ("setup", SETUP_SCRIPT),
    ("server-up", SERVER_UP),
    ("server-down", SERVER_DOWN),
];

// ── embedded scripts ──

#[test]
fn server_hooks_match_quickstart() {
    assert_eq!(SERVER_UP, script_with_shebang("server-up"));
    assert_eq!(SERVER_DOWN, script_with_shebang("server-down"));
}

#[test]
fn shell_scripts_parse() {
    for (name, script) in SCRIPTS {
        let mut child = Command::new("/bin/sh")
            .args(["-n", "-s"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// ── helpers ──

fn script_with_shebang(name: &str) -> String {
    let readme =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).unwrap();
    let start = format!("{name} = '''\n");
    let body = readme
        .split_once(&start)
        .and_then(|(_, tail)| tail.split_once("\n'''"))
        .map(|(body, _)| body)
        .unwrap();
    format!("#!/bin/sh\n{body}\n")
}
