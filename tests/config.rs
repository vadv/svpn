//! Config text: parsing, defaults, inheritance, and rejection of invalid fields.

use std::path::Path;

use svpn::MimicArg;
use svpn::cli::{Cli, Mode};
use svpn::config::parse;
use svpn::server_spec::resolve_servers;

const SINGLE: &str = "server = 'vpn.example'\npeer-tun-name = 'svpn0'\n";
const MULTI: &str = "peer-tun-name = 'svpn0'\n[[servers]]\naddress = 'vpn.example'\n";

// ── defaults and inheritance ──

#[test]
fn typed_modes_defaults_and_inheritance() {
    let file = parse(SINGLE, Path::new("/config"), false).unwrap();
    let cli = match Cli::try_parse_from([
        "svpn",
        "--server",
        "vpn.example",
        "--peer-tun-name",
        "svpn0",
    ])
    .unwrap()
    .command
    {
        Mode::Client(args) => args,
        _ => unreachable!(),
    };
    assert_eq!(
        format!(
            "{:?}",
            resolve_servers(&file.server, &file.globals).unwrap()
        ),
        format!("{:?}", resolve_servers(&cli.server, &cli.globals).unwrap())
    );
    assert_eq!(file.stats_interval, 30);
    let disabled = parse(
        &format!("{SINGLE}stats-interval = 0\n"),
        Path::new("/config"),
        false,
    )
    .unwrap();
    assert_eq!(disabled.stats_interval, 0);
    let file = parse(
        "peer-tun-name = ''\nssh-port = 2222\nmimic = ['mosh']\n\
         [[servers]]\naddress = 'VPN.example'\nweight = 2\n\
         [[servers]]\naddress = '203.0.113.2'\nssh-port = 2200\nmimic = []\n",
        Path::new("/config"),
        true,
    )
    .unwrap();
    let params = resolve_servers(&file.server, &file.globals).unwrap();
    assert_eq!(params[0].server, "vpn.example");
    assert_eq!((params[0].ssh_port, params[0].weight), (2222, 2));
    assert_eq!(params[0].mimic, [MimicArg::Mosh]);
    assert!(
        params[0]
            .peer_tun_name
            .as_deref()
            .is_none_or(|v| v.is_empty())
    );
    assert_eq!(params[1].ssh_port, 2200);
    assert!(params[1].mimic.is_empty());
}

#[test]
fn paths_are_relative_to_file_but_remote_paths_and_commands_are_literal() {
    let args = parse(
        "server = 'vpn.example'\npeer-tun-name = 'svpn0'\n\
         ssh-identity = 'keys/client key'\nssh-remote-bin = '~/bin/$SVPN'\n\
         up-script = 'scripts/up script'\ndown-command = 'echo $HOME; ./down'\n",
        Path::new("/configs"),
        false,
    )
    .unwrap();
    assert_eq!(
        args.globals.ssh_identity.unwrap(),
        Path::new("/configs/keys/client key")
    );
    assert_eq!(args.globals.ssh_remote_bin, "~/bin/$SVPN");
    assert_eq!(
        args.hooks.up_script.unwrap(),
        Path::new("/configs/scripts/up script")
    );
    assert_eq!(args.hooks.down_command.unwrap(), "echo $HOME; ./down");
    let args = parse(
        "ssh-identity = 'global key'\npeer-tun-name = 'svpn0'\n\
         [[servers]]\naddress = 'a.example'\nssh-identity = '/absolute/key'\n\
         [[servers]]\naddress = 'b.example'\nssh-identity = '~/relative/key'\n",
        Path::new("/configs"),
        true,
    )
    .unwrap();
    let params = resolve_servers(&args.server, &args.globals).unwrap();
    assert_eq!(
        params[0].identity.as_deref(),
        Some(Path::new("/absolute/key"))
    );
    assert_eq!(
        params[1].identity.as_deref(),
        Some(Path::new("/configs/~/relative/key"))
    );
}

#[test]
fn numeric_boundaries_and_cli_relative_identity_are_preserved() {
    let args = parse(
        "peer-tun-name = ''\nssh-port = 65535\ntcp-port = 0\n\
         mtu = 1400\nudp-port-range = '1-65535'\n[[servers]]\n\
         address = 'a.example'\nweight = 4294967295\n",
        Path::new("."),
        true,
    )
    .unwrap();
    let params = resolve_servers(&args.server, &args.globals).unwrap();
    assert_eq!(params[0].weight, u32::MAX);
    assert_eq!(params[0].ssh_port, 65535);
    assert_eq!(params[0].tcp_port, Some(0));
    assert_eq!(params[0].mtu, 1400);
    let Mode::Client(args) = Cli::try_parse_from([
        "svpn",
        "--server",
        "a.example,peer-tun=svpn0",
        "--ssh-identity",
        "relative/key",
    ])
    .unwrap()
    .command
    else {
        panic!("expected client")
    };
    assert_eq!(
        args.globals.ssh_identity.as_deref(),
        Some(Path::new("relative/key"))
    );
}

// ── rejected configurations ──

#[test]
fn rejects_unknown_wrong_typed_and_conflicting_fields() {
    for text in [
        "",
        "server = 'a:22'",
        "server = 'a,mimic=mosh'",
        "server = ['a']",
        "server = '::1'",
        "server = 'a'\nservers = []",
        "server = 'a'\nweight = 1",
        "server = 'a'\nconfig = 'other'",
        "server = 'a'\nssh = {}",
        "server = 'a'\nprofile = 'work'",
        "server = 'a'\nserver = 'b'",
        "server = 'a'\nmode = 'single'",
    ] {
        assert!(parse(text, Path::new("."), false).is_err(), "{text}");
    }
    for field in [
        "mtu = '1280'",
        "mtu = -1",
        "mtu = 1401",
        "mtu = 1.5",
        "ssh-port = 0",
        "ssh-port = 65536",
        "ssh-port = -1",
        "tcp-port = 65536",
        "stats-interval = -1",
        "stats-interval = 4294967296",
        "log-level = 'INFO'",
        "mimic = 'mosh'",
        "mimic = ['auto']",
        "mimic = ['ssh', 'banner']",
        "udp-port-range = '0-1'",
        "udp-port-range = [1, 2]",
        "udp-port-range = '2-1'",
        "ssh-user = ''",
        "ssh-identity = ''",
        "ssh-remote-bin = ''",
        "ssh-host-key = 'bad'",
        "tun-addr = '::1'",
        "tun-addr = '0.0.0.0'",
        "up-script = ''",
        "up-command = ' '",
        "down-command = ''",
        "up-script = 'up'\nup-command = 'true'",
        "down-script = 'down'\ndown-command = 'true'",
    ] {
        let text = format!("{SINGLE}{field}\n");
        assert!(parse(&text, Path::new("."), false).is_err(), "{field}");
    }
    for text in [
        "servers = []",
        "server = 'a'",
        "server = 'a'\n[[servers]]\naddress = 'a'",
        "[[servers]]\naddress = 'a:22'",
        "[[servers]]\nserver = 'a'",
        "[[servers]]\naddress = 'a'\nweight = 0",
        "[[servers]]\naddress = 'a'\nweight = 4294967296",
        "[[servers]]\naddress = 'a'\nssh-user = ''",
        "[[servers]]\naddress = 'a'\nup-command = 'true'",
        "[[servers]]\naddress = 'a'\nstats-interval = 0",
        "[[servers]]\naddress = 'a'\ntun-name = ''",
    ] {
        assert!(parse(text, Path::new("."), true).is_err(), "{text}");
    }
}

#[test]
fn invalid_globals_cannot_be_hidden_by_valid_server_overrides() {
    for (global, local) in [
        ("ssh-port = 0", "ssh-port = 22"),
        ("ssh-identity = ''", "ssh-identity = '/key'"),
        (
            "ssh-host-key = 'bad'",
            "ssh-host-key = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
        ),
        ("ssh-user = ''", "ssh-user = 'root'"),
        ("ssh-remote-bin = ''", "ssh-remote-bin = '/svpn'"),
        ("udp-port-range = '0-1'", "udp-port-range = '1-2'"),
        ("peer-addr = '0.0.0.0'", "peer-addr = '10.77.0.1'"),
    ] {
        let text = format!("{global}\n{MULTI}{local}\n");
        assert!(parse(&text, Path::new("."), true).is_err(), "{global}");
    }
}

#[test]
fn malformed_values_are_not_echoed_in_errors() {
    for field in ["ssh-port", "log-level", "mimic"] {
        let text = format!("{SINGLE}{field} = 'PRIVATE_MARKER_DO_NOT_LOG'");
        let error = parse(&text, Path::new("."), false)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("PRIVATE_MARKER"), "{error}");
        assert!(error.contains("line 3") && error.contains(field), "{error}");
    }
}

// ── server hooks ──

#[test]
fn server_hooks_root_and_per_server_override() {
    let text = "server = 'vpn.example'\npeer-tun-name = 'svpn0'\n\
                server-up = 'echo root-up'\nserver-down = 'echo root-down'\n";
    let args = parse(text, Path::new("/config"), false).unwrap();
    let params = resolve_servers(&args.server, &args.globals).unwrap();
    assert_eq!(params[0].server_up.as_deref(), Some("echo root-up"));
    assert_eq!(params[0].server_down.as_deref(), Some("echo root-down"));

    let text = "peer-tun-name = 'svpn0'\nserver-up = 'echo root-up'\n\
                [[servers]]\naddress = 'a.example'\n\
                [[servers]]\naddress = 'b.example'\nserver-up = 'echo b-up'\n";
    let args = parse(text, Path::new("/config"), true).unwrap();
    let params = resolve_servers(&args.server, &args.globals).unwrap();
    assert_eq!(params[0].server_up.as_deref(), Some("echo root-up"));
    assert_eq!(params[1].server_up.as_deref(), Some("echo b-up"));
    assert_eq!(params[1].server_down, None);
}

#[test]
fn server_hooks_empty_rejected() {
    for field in ["server-up", "server-down"] {
        let text = format!("{SINGLE}{field} = ''\n");
        let error = parse(&text, Path::new("."), false)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("must not be empty"), "{error}");
        assert!(error.contains(field), "{error}");
    }
    for field in ["server-up", "server-down"] {
        let text =
            format!("peer-tun-name = 'ok'\n[[servers]]\naddress = 'a.example'\n{field} = '  '\n");
        let error = parse(&text, Path::new("."), true).err().unwrap();
        let error = format!("{error:#}");
        assert!(error.contains("must not be empty"), "{error}");
        assert!(error.contains(field), "{error}");
    }
}

#[test]
fn server_hooks_cli_parity() {
    let cli = match Cli::try_parse_from([
        "svpn",
        "--server",
        "vpn.example",
        "--peer-tun-name",
        "svpn0",
        "--server-up",
        "echo cli-up",
        "--server-down",
        "echo cli-down",
    ])
    .unwrap()
    .command
    {
        Mode::Client(args) => args,
        _ => unreachable!(),
    };
    let params = resolve_servers(&cli.server, &cli.globals).unwrap();
    assert_eq!(params[0].server_up.as_deref(), Some("echo cli-up"));
    assert_eq!(params[0].server_down.as_deref(), Some("echo cli-down"));
}
