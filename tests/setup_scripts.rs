//! Embedded setup and server hook scripts.

use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
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

#[test]
fn server_up_fails_without_a_default_route() {
    use std::os::unix::fs::PermissionsExt;
    let root = temporary_dir();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let log = root.join("ip.log");
    write_exec(&bin.join("cat"), "#!/bin/sh\necho 1\n");
    write_exec(
        &bin.join("ip"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$IP_LOG\"\n",
    );
    let mut child = Command::new("/bin/sh")
        .arg("-s")
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("IP_LOG", &log)
        .env("SVPN_PEER_ADDR", "10.77.0.1")
        .env("SVPN_SESSION_ID", "4242")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(SERVER_UP.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no IPv4 default route"),
        "{output:?}"
    );
    assert!(
        fs::read_to_string(&log)
            .unwrap()
            .contains("route show default")
    );
    fs::remove_dir_all(root).unwrap();
}

fn temporary_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "svpn setup scripts {} {}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn write_exec(path: &std::path::Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
