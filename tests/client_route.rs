//! Automatic client-up/down scripts: command fixtures, signature reclaim and rollback.

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
        // The fixture PATH contains ONLY fake tools plus the POSIX utilities
        // the scripts call (cut, awk, ...): a removed fake can never fall
        // through to the host's real nft/ip.
        link_system_tools(&bin, &["cut", "awk", "grep", "mv", "cat", "rm"]);
        // The fake ip/nft track installed objects in marker files next to the
        // call log the way the kernel does: routes live in calls.log.routes
        // (full argument string, proto included), rules in calls.log.rule.PREF,
        // the nft table in calls.log.nft. Ownership detection in the scripts
        // is therefore exercised against emulated kernel state, not the log.
        write_exec(
            &bin.join("ip"),
            r#"#!/bin/sh
printf '%s\n' "$*" >> "$CALL_LOG"
ROUTES="$CALL_LOG.routes"
[ -f "$ROUTES" ] || : > "$ROUTES"
if [ "$1 $2 $3" = '-4 route get' ]; then
    if [ "${NO_SERVER_ROUTE:-0}" = 1 ]; then exit 0; fi
    if [ "${PPPOE:-0}" = 1 ]; then printf '%s dev ppp0 src 10.0.0.2\n' "$4"; exit 0; fi
    if [ "${MULTI_WAN:-0}" = 1 ] && [ "$4" = 198.51.100.20 ]; then
        printf '%s via 192.0.2.2 dev eth1 src 10.0.0.2\n' "$4"; exit 0
    fi
    printf '%s via 192.0.2.1 dev eth0 src 10.0.0.2\n' "$4"
    exit 0
fi
if [ "$1 $2 $3 $4" = '-4 route show default' ]; then
    [ "${NO_DEFAULT:-0}" = 1 ] && exit 0
    if [ "${PPPOE:-0}" = 1 ]; then echo 'default dev ppp0'; exit 0; fi
    echo 'default via 192.0.2.1 dev eth0'
    exit 0
fi
if [ "$1 $2 $3 $4 $5" = '-4 route show table all' ] && [ "$6 $7" = 'proto 30' ]; then
    awk '/ proto 30$/ { print }' "$ROUTES"
    exit 0
fi
if [ "$1 $2 $3 $4" = '-4 route show table' ] || [ "$1 $2 $3" = 'route show table' ]; then
    t=$(printf '%s\n' "$*" | awk '{for(i=1;i<NF;i++) if($i=="table") print $(i+1)}')
    if [ "${FOREIGN_TABLE:-0}" = 1 ]; then echo 'default via 192.0.2.1 dev eth0'; exit 0; fi
    awk -v t="$t" '$0 ~ (" table " t " ") { print }' "$ROUTES"
    exit 0
fi
if [ "$1 $2" = 'rule add' ] && [ "$3" = pref ]; then
    : > "$CALL_LOG.rule.$4"
    exit 0
fi
if [ "$1 $2" = 'rule del' ] && [ "$3" = pref ]; then
    if [ -f "$CALL_LOG.rule.$4" ]; then rm -f "$CALL_LOG.rule.$4"; exit 0; fi
    exit 1
fi
if [ "$1 $2 $3" = 'rule show pref' ]; then
    if [ "${FOREIGN_RULE:-0}" = 1 ] && [ "$4" = 10003 ]; then
        echo '10003: from all lookup main'
        exit 0
    fi
    cat "$CALL_LOG.rule.$4" 2>/dev/null
    exit 0
fi
if [ "${FAIL_SPLIT:-0}" = 1 ] && [ "$3" = '0.0.0.0/1' ]; then exit 1; fi
if [ "$1 $2" = 'route replace' ]; then
    shift 2
    grep -v -F -x "$*" "$ROUTES" > "$ROUTES.new" || true
    printf '%s\n' "$*" >> "$ROUTES.new"
    mv "$ROUTES.new" "$ROUTES"
    exit 0
fi
if [ "$1 $2" = 'route del' ]; then
    awk -v p="$3" 'index($0, p " ") == 1 && / proto 30$/ { next } { print }' \
        "$ROUTES" > "$ROUTES.new"
    mv "$ROUTES.new" "$ROUTES"
    exit 0
fi
if [ "$1 $2" = 'route flush' ] && [ "$3" = table ] && [ "$5 $6" = 'proto 30' ]; then
    awk -v t="$4" '
        {
            keep = 1
            if ($0 ~ / proto 30$/) {
                if (t == "main" && $0 !~ / table /) keep = 0
                if (t != "main" && $0 ~ (" table " t " ")) keep = 0
            }
            if (keep) print
        }
    ' "$ROUTES" > "$ROUTES.new"
    mv "$ROUTES.new" "$ROUTES"
    exit 0
fi
exit 0
"#,
        );
        write_exec(
            &bin.join("nft"),
            r#"#!/bin/sh
printf '%s\n' "$*" >> "$CALL_LOG"
if [ "$1 $2" = 'add table' ]; then
    : > "$CALL_LOG.nft"
    exit 0
fi
if [ "$1 $2" = 'list table' ]; then
    if [ "${NFT_TABLE_EXISTS:-0}" = 1 ] || [ -f "$CALL_LOG.nft" ]; then exit 0; fi
    exit 1
fi
if [ "$1 $2" = 'delete table' ]; then
    rm -f "$CALL_LOG.nft"
    exit 0
fi
if [ "$1 $2" = '-f -' ]; then
    cat >> "$CALL_LOG"
    [ "${FAIL_NFT:-0}" = 1 ] && exit 1 || exit 0
fi
"#,
        );
        write_exec(
            &bin.join("route"),
            r#"#!/bin/sh
printf '%s\n' "$*" >> "$CALL_LOG"
if [ "$1 $2 $3" = '-n get default' ]; then
    printf '   route to: default\n       gateway: 192.0.2.1\n     interface: en0\n'
fi
if [ "$1 $2" = '-n get' ] && [ "$3" != default ]; then
    [ "${NO_SERVER_ROUTE:-0}" = 1 ] || printf '   route to: %s\n       gateway: 192.0.2.1\n     interface: en0\n' "$3"
fi
if [ "${FAIL_SPLIT:-0}" = 1 ] && [ "$4" = '0.0.0.0/1' ]; then exit 1; fi
"#,
        );
        Self { root, bin, log }
    }

    fn run(&self, event: &str, os: &str, no_default: bool, fail_split: bool) -> Output {
        self.run_with_no_server_route(event, os, no_default, fail_split, false)
    }

    fn run_with_no_server_route(
        &self,
        event: &str,
        os: &str,
        no_default: bool,
        fail_split: bool,
        no_server_route: bool,
    ) -> Output {
        self.run_with_knobs(
            event,
            os,
            &[
                ("NO_DEFAULT", if no_default { "1" } else { "0" }),
                ("FAIL_SPLIT", if fail_split { "1" } else { "0" }),
                ("NO_SERVER_ROUTE", if no_server_route { "1" } else { "0" }),
            ],
        )
    }

    fn run_with_knobs(&self, event: &str, os: &str, knobs: &[(&str, &str)]) -> Output {
        let mut command = Command::new("/bin/sh");
        command
            .arg(script_for(event))
            // Fixture-only PATH: no host fallback, see Fixture::new.
            .env("SVPN_ROUTE_PATH", format!("{}", self.bin.display()))
            .env("SVPN_OS", os)
            .env("CALL_LOG", &self.log)
            .env("SVPN_TUN_NAME", "svpn-test0")
            .env("SVPN_SERVER_ADDRS", SERVERS)
            // Third octet 3 derives table_id = pref 10003 and mark 0x00020003:
            // deliberately unlike any old literal, so leftover hardcode fails.
            .env("SVPN_PEER_ADDR", "10.77.3.1");
        for (key, value) in knobs {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn clear_log(&self) {
        fs::write(&self.log, "").unwrap();
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Emulated kernel routing table content (see Fixture::new).
    fn routes(&self) -> String {
        fs::read_to_string(self.log.with_extension("log.routes")).unwrap_or_default()
    }

    fn seed_route(&self, line: &str) {
        let path = self.log.with_extension("log.routes");
        let mut current = fs::read_to_string(&path).unwrap_or_default();
        current.push_str(line);
        current.push('\n');
        fs::write(&path, current).unwrap();
    }

    fn rules_dir_file(&self, pref: &str) -> PathBuf {
        self.log.with_file_name(format!("calls.log.rule.{pref}"))
    }
}

#[test]
fn scripts_parse_as_posix_shell() {
    for event in ["up", "down"] {
        assert!(
            Command::new("/bin/sh")
                .args(["-n", script_for(event).to_str().unwrap()])
                .status()
                .unwrap()
                .success()
        );
    }
}

#[test]
fn scripts_use_no_state_files() {
    for event in ["up", "down"] {
        let source = fs::read_to_string(script_for(event)).unwrap();
        assert!(!source.contains("SVPN_ROUTE_STATE_DIR"), "{event}");
        assert!(!source.contains("full-tunnel-"), "{event}"); // no state file name
    }
}

#[test]
fn linux_up_down_installs_and_removes_only_owned_routes() {
    let fixture = Fixture::new();
    let output = fixture.run("up", "linux", false, false);
    assert!(output.status.success(), "{output:?}");
    let log = fixture.log();
    for expected in [
        "route replace 198.51.100.10/32 via 192.0.2.1 dev eth0 proto 30",
        "route replace 198.51.100.20/32 via 192.0.2.1 dev eth0 proto 30",
        "route replace default via 192.0.2.1 dev eth0 table 10003 proto 30",
        "rule add pref 10003 fwmark 0x00020003/0x00020003 lookup 10003",
        "rule add pref 11003 fwmark 0x00020003/0x00020003 lookup main suppress_prefixlength 1",
        "add table inet svpn-local-services",
        "iifname \"eth0\" ct direction original ct mark 0 ct mark set 0x00020003",
        "ct direction reply ct mark & 0x00020003 == 0x00020003 meta mark set meta mark | 0x00020003",
        "route replace 0.0.0.0/1 dev svpn-test0 proto 30",
        "route replace 128.0.0.0/1 dev svpn-test0 proto 30",
    ] {
        assert!(log.contains(expected), "missing {expected} in {log}");
    }
    // No snapshot of connected networks: main is consulted through the
    // suppress rule instead, so the direct table holds only the WAN default.
    assert!(!log.contains("scope link table 10003"), "{log}");
    // Nothing owned yet: the first up must not flush anything.
    assert!(!log.contains("route flush"), "{log}");

    fixture.clear_log();
    let output = fixture.run("down", "linux", false, false);
    assert!(output.status.success(), "{output:?}");
    let log = fixture.log();
    for expected in [
        "route del 198.51.100.10/32 proto 30",
        "route del 198.51.100.20/32 proto 30",
        "route del 0.0.0.0/1 dev svpn-test0 proto 30",
        "route del 128.0.0.0/1 dev svpn-test0 proto 30",
        "route flush table 10003 proto 30",
        "rule del pref 10003 fwmark 0x00020003/0x00020003 lookup 10003",
        "rule del pref 11003 fwmark 0x00020003/0x00020003 lookup main",
        "delete table inet svpn-local-services",
    ] {
        assert!(log.contains(expected), "missing {expected} in {log}");
    }
    assert!(fixture.routes().trim().is_empty(), "{}", fixture.routes());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn repeated_up_reclaims_leftovers_first() {
    let fixture = Fixture::new();
    assert!(fixture.run("up", "linux", false, false).status.success());
    fixture.clear_log();
    assert!(fixture.run("up", "linux", false, false).status.success());
    let log = fixture.log();
    let first_change = log.lines().find(|line| !line.is_empty()).unwrap();
    assert_eq!(first_change, "-4 route show table all proto 30", "{log}");
    // Leftovers are flushed in every table that still holds owned routes.
    assert!(log.contains("route flush table main proto 30"), "{log}");
    assert!(log.contains("route flush table 10003 proto 30"), "{log}");
    let reclaim = log.find("delete table inet svpn-local-services").unwrap();
    let install = log.find("add table inet svpn-local-services").unwrap();
    assert!(reclaim < install, "{log}");
    assert!(fixture.run("down", "linux", false, false).status.success());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn missing_default_route_does_not_block_auto_routing() {
    let fixture = Fixture::new();
    let output = fixture.run("up", "linux", true, false);
    assert!(output.status.success(), "{output:?}");
    let log = fixture.log();
    assert!(log.contains("route get 198.51.100.10"), "{log}");
    // No WAN default in main: the WAN is treated as on-link.
    assert!(
        log.contains("route replace default dev eth0 table 10003 proto 30"),
        "{log}"
    );
    assert!(
        log.contains("route replace 0.0.0.0/1 dev svpn-test0 proto 30"),
        "{log}"
    );
    assert!(fixture.run("down", "linux", false, false).status.success());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn missing_server_route_fails_before_split_default() {
    let fixture = Fixture::new();
    let output = fixture.run_with_no_server_route("up", "linux", false, false, true);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("cannot determine the route to 198.51.100.10"),
        "{output:?}"
    );
    assert!(
        !fixture.log().contains("route replace 0.0.0.0/1"),
        "{}",
        fixture.log()
    );
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn failed_split_route_rolls_back_host_routes() {
    let fixture = Fixture::new();
    let output = fixture.run("up", "linux", false, true);
    assert!(!output.status.success());
    let log = fixture.log();
    assert!(log.contains("route replace 198.51.100.10/32"), "{log}");
    assert!(log.contains("route del 198.51.100.10/32 proto 30"), "{log}");
    assert!(log.contains("route del 198.51.100.20/32 proto 30"), "{log}");
    assert!(log.contains("rule del pref 10003"), "{log}");
    assert!(log.contains("rule del pref 11003"), "{log}");
    assert!(
        log.contains("delete table inet svpn-local-services"),
        "{log}"
    );
    assert!(log.contains("route flush table 10003 proto 30"), "{log}");
    assert!(fixture.routes().trim().is_empty(), "{}", fixture.routes());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn underivable_peer_addr_fails_before_any_change() {
    let fixture = Fixture::new();
    for event in ["up", "down"] {
        let output = fixture.run_with_knobs(event, "linux", &[("SVPN_PEER_ADDR", "10.77")]);
        assert!(!output.status.success(), "{event}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("cannot derive reply routing ids from SVPN_PEER_ADDR"),
            "{event}: {output:?}"
        );
    }
    assert!(fixture.log().is_empty(), "{}", fixture.log());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn missing_nft_fails_before_any_route_change() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.bin.join("nft")).unwrap();
    let output = fixture.run("up", "linux", false, false);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("nft is required"),
        "{output:?}"
    );
    assert!(fixture.log().is_empty(), "{}", fixture.log());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn foreign_reply_objects_fail_before_mutations() {
    for (knob, message) in [
        ("FOREIGN_RULE", "preference 10003 is already in use"),
        ("FOREIGN_TABLE", "table 10003 is already in use"),
    ] {
        let fixture = Fixture::new();
        let output = fixture.run_with_knobs("up", "linux", &[(knob, "1")]);
        assert!(!output.status.success(), "{knob}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{knob}: {output:?}"
        );
        let log = fixture.log();
        assert!(!log.contains("route replace"), "{knob}: {log}");
        assert!(!log.contains("rule add"), "{knob}: {log}");
        assert!(!log.contains("add table"), "{knob}: {log}");
        fs::remove_dir_all(fixture.root).unwrap();
    }
}

#[test]
fn leftover_nft_table_is_reclaimed_first() {
    let fixture = Fixture::new();
    let output = fixture.run_with_knobs("up", "linux", &[("NFT_TABLE_EXISTS", "1")]);
    assert!(output.status.success(), "{output:?}");
    let log = fixture.log();
    let reclaim = log.find("delete table inet svpn-local-services").unwrap();
    let install = log.find("add table inet svpn-local-services").unwrap();
    assert!(reclaim < install, "{log}");
    // A leftover nft table alone proves no owned routes: nothing is flushed.
    assert!(!log.contains("route flush"), "{log}");
    assert!(fixture.run("down", "linux", false, false).status.success());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn down_without_owned_objects_is_safe_and_idempotent() {
    let fixture = Fixture::new();
    // A foreign static route must survive any number of downs untouched.
    fixture.seed_route("192.0.0.0/24 via 192.0.2.254 dev eth0");
    for _ in 0..2 {
        let output = fixture.run("down", "linux", false, false);
        assert!(output.status.success(), "{output:?}");
    }
    let log = fixture.log();
    assert!(!log.contains("rule add"), "{log}");
    assert!(!log.contains("add table"), "{log}");
    assert!(!log.contains("route replace"), "{log}");
    assert!(
        fixture
            .routes()
            .contains("192.0.0.0/24 via 192.0.2.254 dev eth0"),
        "{}",
        fixture.routes()
    );
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn failed_nft_load_rolls_back_reply_objects() {
    let fixture = Fixture::new();
    let output = fixture.run_with_knobs("up", "linux", &[("FAIL_NFT", "1")]);
    assert!(!output.status.success(), "{output:?}");
    let log = fixture.log();
    for expected in [
        "rule del pref 10003",
        "rule del pref 11003",
        "delete table inet svpn-local-services",
        "route flush table 10003 proto 30",
        "route del 198.51.100.10/32 proto 30",
    ] {
        assert!(log.contains(expected), "missing {expected} in {log}");
    }
    assert!(fixture.routes().trim().is_empty(), "{}", fixture.routes());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn pppoe_underlay_uses_device_default() {
    let fixture = Fixture::new();
    let output = fixture.run_with_knobs("up", "linux", &[("PPPOE", "1")]);
    assert!(output.status.success(), "{output:?}");
    let log = fixture.log();
    for expected in [
        "route replace default dev ppp0 table 10003 proto 30",
        "iifname \"ppp0\" ct direction original ct mark 0 ct mark set 0x00020003",
    ] {
        assert!(log.contains(expected), "missing {expected} in {log}");
    }
    // Connected networks stay in main; the suppress rule covers them.
    assert!(!log.contains("scope link table 10003"), "{log}");
    assert!(fixture.run("down", "linux", false, false).status.success());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn multi_wan_servers_fail_before_reply_or_split_routes() {
    let fixture = Fixture::new();
    let output = fixture.run_with_knobs("up", "linux", &[("MULTI_WAN", "1")]);
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires one underlay"),
        "{output:?}"
    );
    let log = fixture.log();
    assert!(!log.contains("rule add pref 10003"), "{log}");
    assert!(!log.contains("route replace 0.0.0.0/1"), "{log}");
    // The pinned host routes are rolled back before failing.
    assert!(log.contains("route del 198.51.100.10/32 proto 30"), "{log}");
    assert!(fixture.routes().trim().is_empty(), "{}", fixture.routes());
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn interrupted_cleanup_is_reclaimed_by_next_up() {
    // A down killed after the rules were deleted but before the routes were
    // flushed: owned routes in main and table 10003, the nft table alive.
    let fixture = Fixture::new();
    assert!(fixture.run("up", "linux", false, false).status.success());
    fs::remove_file(fixture.rules_dir_file("10003")).unwrap();
    fs::remove_file(fixture.rules_dir_file("11003")).unwrap();
    fixture.clear_log();
    let output = fixture.run("up", "linux", false, false);
    assert!(output.status.success(), "{output:?}");
    let log = fixture.log();
    assert!(log.contains("route flush table main proto 30"), "{log}");
    assert!(log.contains("route flush table 10003 proto 30"), "{log}");
    let reclaim = log.find("delete table inet svpn-local-services").unwrap();
    let install = log.find("add table inet svpn-local-services").unwrap();
    assert!(reclaim < install, "{log}");
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn peer_change_reclaims_old_tables_and_refuses_foreign_new_one() {
    let fixture = Fixture::new();
    assert!(fixture.run("up", "linux", false, false).status.success());
    fixture.clear_log();
    // Same host restarted with a new peer address: table 10004 is foreign.
    let output = fixture.run_with_knobs(
        "up",
        "linux",
        &[("SVPN_PEER_ADDR", "10.77.4.1"), ("FOREIGN_TABLE", "1")],
    );
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("table 10004 is already in use"),
        "{output:?}"
    );
    let log = fixture.log();
    // The previous peer's owned objects were reclaimed across all tables.
    assert!(log.contains("route flush table main proto 30"), "{log}");
    assert!(log.contains("route flush table 10003 proto 30"), "{log}");
    assert!(!log.contains("route flush table 10004"), "{log}");
    fs::remove_dir_all(fixture.root).unwrap();
}

#[test]
fn macos_up_down_uses_route_commands() {
    let fixture = Fixture::new();
    let output = fixture.run("up", "macos", false, false);
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
    let output = fixture.run("down", "macos", false, false);
    assert!(output.status.success(), "{output:?}");
    let log = fixture.log();
    assert!(log.contains("delete -inet -host 198.51.100.10"), "{log}");
    assert!(
        log.contains("delete -inet 0.0.0.0/1 -interface svpn-test0"),
        "{log}"
    );
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

fn script_for(event: &str) -> PathBuf {
    let name = if event == "up" {
        "client-up"
    } else {
        "client-down"
    };
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("scripts/{name}"))
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

/// Symlink the POSIX utilities the scripts call from the test process PATH
/// into the fixture bin dir, keeping the fixture PATH host-free.
fn link_system_tools(bin: &Path, tools: &[&str]) {
    for tool in tools {
        for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap()) {
            let candidate = dir.join(tool);
            if candidate.is_file() {
                std::os::unix::fs::symlink(&candidate, bin.join(tool)).unwrap();
                break;
            }
        }
    }
}
