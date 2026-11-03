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
