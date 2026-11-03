//! Automatic client-route script: command fixtures, rollback and owner cleanup.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use svpn::{Cli, Mode, client_routing, hooks, server_spec};

const SERVERS: &str = "198.51.100.10 198.51.100.20";

struct Fixture {
    root: PathBuf,
    bin: PathBuf,
    log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = temporary_dir();
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        let log = root.join("calls.log");
        write_exec(
            &bin.join("uname"),
            "#!/bin/sh\nprintf '%s\\n' \"$FAKE_OS\"\n",
        );
        write_exec(
            &bin.join("ip"),
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CALL_LOG\"\n\
             if [ \"$1 $2 $3 $4\" = '-4 route show default' ]; then\n\
             [ \"${NO_DEFAULT:-0}\" = 1 ] || echo 'default via 192.0.2.1 dev eth0'\n\
             fi\n\
             if [ \"${FAIL_SPLIT:-0}\" = 1 ] && [ \"$3\" = '0.0.0.0/1' ]; then exit 1; fi\n",
        );
        write_exec(
            &bin.join("route"),
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CALL_LOG\"\n\
             if [ \"$1 $2 $3\" = '-n get default' ]; then\n\
             printf '   route to: default\\n       gateway: 192.0.2.1\\n     interface: en0\\n'\n\
             fi\n\
             if [ \"${FAIL_SPLIT:-0}\" = 1 ] && [ \"$4\" = '0.0.0.0/1' ]; then exit 1; fi\n",
        );
        Self { root, bin, log }
    }

    fn run(&self, event: &str, os: &str, no_default: bool, fail_split: bool) -> Output {
        Command::new("/bin/sh")
            .arg(script())
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("FAKE_OS", os)
            .env("CALL_LOG", &self.log)
            .env("NO_DEFAULT", if no_default { "1" } else { "0" })
            .env("FAIL_SPLIT", if fail_split { "1" } else { "0" })
            .env("SVPN_ROUTE_STATE_DIR", self.root.join("state"))
            .env("SVPN_SESSION_ID", "4242")
            .env("SVPN_EVENT", event)
            .env("SVPN_TUN_NAME", "svpn-test0")
            .env("SVPN_SERVER_ADDRS", SERVERS)
            .output()
            .unwrap()
    }

    fn clear_log(&self) {
        fs::write(&self.log, "").unwrap();
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn state_exists(&self) -> bool {
        self.root.join("state/full-tunnel-4242").exists()
    }
}

#[test]
fn script_parses_as_posix_shell() {
    assert!(
        Command::new("/bin/sh")
            .args(["-n", script().to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn linux_up_down_installs_and_removes_only_owned_routes() {
    let fixture = Fixture::new();
    let output = fixture.run("up", "Linux", false, false);
    assert!(output.status.success(), "{output:?}");
    let log = fixture.log();
    for expected in [
        "route replace 198.51.100.10/32 via 192.0.2.1 dev eth0",
        "route replace 198.51.100.20/32 via 192.0.2.1 dev eth0",
        "route replace 0.0.0.0/1 dev svpn-test0",
        "route replace 128.0.0.0/1 dev svpn-test0",
    ] {
        assert!(log.contains(expected), "missing {expected} in {log}");
    }
    assert!(fixture.state_exists());

    fixture.clear_log();
    let output = fixture.run("down", "Linux", false, false);
    assert!(output.status.success(), "{output:?}");
    let log = fixture.log();
    for expected in [
        "route del 198.51.100.10/32",
        "route del 198.51.100.20/32",
        "route del 0.0.0.0/1 dev svpn-test0",
        "route del 128.0.0.0/1 dev svpn-test0",
    ] {
        assert!(log.contains(expected), "missing {expected} in {log}");
    }
    assert!(!fixture.state_exists());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn repeated_up_reclaims_previous_owner_first() {
    let fixture = Fixture::new();
    assert!(fixture.run("up", "Linux", false, false).status.success());
    fixture.clear_log();
    assert!(fixture.run("up", "Linux", false, false).status.success());
    let log = fixture.log();
    let first_change = log.lines().find(|line| !line.is_empty()).unwrap();
    assert_eq!(first_change, "route del 198.51.100.10/32", "{log}");
    assert!(fixture.run("down", "Linux", false, false).status.success());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn missing_default_fails_before_any_route_change() {
    let fixture = Fixture::new();
    let output = fixture.run("up", "Linux", true, false);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no IPv4 default route"),
        "{output:?}"
    );
    assert!(
        !fixture.log().contains("route replace"),
        "{}",
        fixture.log()
    );
    assert!(!fixture.state_exists());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn failed_split_route_rolls_back_host_routes() {
    let fixture = Fixture::new();
    let output = fixture.run("up", "Linux", false, true);
    assert!(!output.status.success());
    let log = fixture.log();
    assert!(log.contains("route replace 198.51.100.10/32"), "{log}");
    assert!(log.contains("route del 198.51.100.10/32"), "{log}");
    assert!(log.contains("route del 198.51.100.20/32"), "{log}");
    assert!(!fixture.state_exists());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn down_without_owned_state_is_a_noop() {
    let fixture = Fixture::new();
    let output = fixture.run("down", "Linux", false, false);
    assert!(output.status.success(), "{output:?}");
    assert!(fixture.log().is_empty(), "{}", fixture.log());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn macos_up_down_uses_route_commands() {
    let fixture = Fixture::new();
    let output = fixture.run("up", "Darwin", false, false);
    assert!(output.status.success(), "{output:?}");
    let log = fixture.log();
    for expected in [
        "add -inet -host 198.51.100.10 192.0.2.1",
        "add -inet -host 198.51.100.20 192.0.2.1",
        "add -inet 0.0.0.0/1 -interface svpn-test0",
        "add -inet 128.0.0.0/1 -interface svpn-test0",
    ] {
        assert!(log.contains(expected), "missing {expected} in {log}");
    }
    fixture.clear_log();
    let output = fixture.run("down", "Darwin", false, false);
    assert!(output.status.success(), "{output:?}");
    let log = fixture.log();
    assert!(log.contains("delete -inet -host 198.51.100.10"), "{log}");
    assert!(
        log.contains("delete -inet 0.0.0.0/1 -interface svpn-test0"),
        "{log}"
    );
    assert!(!fixture.state_exists());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn manual_hook_preserves_precedence_over_automatic_route() {
    let auto = hooks::Args::default().resolve().unwrap();
    assert!(auto.needs_auto_up() && auto.needs_auto_down());
    let manual = hooks::Args {
        up_command: Some("true".into()),
        down_command: Some("true".into()),
        ..Default::default()
    }
    .resolve()
    .unwrap();
    assert!(!manual.needs_auto_up() && !manual.needs_auto_down());
}

#[tokio::test]
async fn server_addresses_are_resolved_and_joined_in_stable_order() {
    let cli = Cli::try_parse_from([
        "svpn",
        "multi",
        "--server",
        "198.51.100.20",
        "--server",
        "198.51.100.10",
        "--peer-tun-name",
        "svpn0",
    ])
    .unwrap();
    let Mode::Client(args) = cli.command else {
        unreachable!()
    };
    let servers = server_spec::resolve_servers(&args.server, &args.globals).unwrap();
    let addresses = client_routing::server_addrs(&servers).await.unwrap();
    assert_eq!(addresses, "198.51.100.10 198.51.100.20");
}

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/client-route")
}

fn temporary_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "svpn client route {} {}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn write_exec(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
