use std::path::Path;

use svpn::MimicArg;
use svpn::cli::ClientArgs;
use svpn::config::*;
use svpn::{
    cli::{Cli, Mode},
    server_spec::resolve_servers,
};

const SINGLE: &str = "server = 'vpn.example'\npeer-tun-name = 'svpn0'\n";
const MULTI: &str = "peer-tun-name = 'svpn0'\n[[servers]]\naddress = 'vpn.example'\n";

#[test]
fn readme_configs_match_and_validate() {
    fn configs(readme: &str) -> Vec<&str> {
        readme
            .split("```toml\n")
            .skip(1)
            .map(|block| block.split_once("\n```").unwrap().0)
            .collect()
    }
    let blocks = configs(include_str!("../README.md"));
    assert_eq!(blocks, configs(include_str!("../README.en.md")));
    assert_eq!(blocks.len(), 2);
    let base = blocks[0]
        .lines()
        .filter(|line| !line.starts_with("up-command") && !line.starts_with("down-command"))
        .collect::<Vec<_>>()
        .join("\n");
    let macos = format!("{base}\n{}", blocks[1]);
    for example in [blocks[0], &macos] {
        let args = parse(example, Path::new("/config"), false).unwrap();
        let servers = resolve_servers(&args.server, &args.globals).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].server, "vpn.example.com");
        assert_eq!(servers[0].tcp_port, Some(41020));
        assert_eq!(args.globals.ssh_user.as_deref(), Some("root"));
        assert!(args.globals.tun_name.is_none());
        for hook in [args.hooks.up_command, args.hooks.down_command] {
            let hook = hook.unwrap();
            assert!(hook.contains("$SVPN_TUN_NAME"));
            assert!(
                std::process::Command::new("/bin/sh")
                    .args(["-n", "-c", &hook])
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
    let args = parse(&macos, Path::new("/config"), false).unwrap();
    // Mock route: never change the host network, even in the cleanup check.
    let mock = "route() { if [ \"$2\" = get ]; then \
        test -n \"$TEST_ROUTE_IF\" || return 1; \
        printf '  interface: %s\\n' \"$TEST_ROUTE_IF\"; \
        else printf '%s\\n' \"$@\"; fi; };";
    let command = format!("{mock}\n{}", args.hooks.down_command.unwrap());
    for interface in ["utun99", "en0", ""] {
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &command])
            .env("SVPN_TUN_NAME", "utun99")
            .env("TEST_ROUTE_IF", interface)
            .output()
            .unwrap();
        assert!(output.status.success());
        let expected = if interface == "utun99" {
            "-n\ndelete\n-host\n1.1.1.1\n-interface\nutun99\n"
        } else {
            ""
        };
        assert_eq!(output.stdout, expected.as_bytes());
    }
}

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
    assert!(params[0].peer_tun_name.is_empty());
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

#[test]
fn bounded_regular_utf8_file_and_config_positions() {
    use std::{fs, os::unix::fs::symlink};
    let base = std::env::temp_dir().join(format!("svpn config test {}", std::process::id()));
    fs::create_dir(&base).unwrap();
    let path = base.join("config.toml");
    fs::write(&path, SINGLE).unwrap();
    assert!(load(&path, false).is_ok());
    let link = base.join("link.toml");
    symlink(&path, &link).unwrap();
    assert!(load(&link, false).is_ok());
    fs::write(&path, MULTI).unwrap();
    for args in [
        vec!["svpn", "--config", path.to_str().unwrap(), "multi"],
        vec!["svpn", "multi", "--config", path.to_str().unwrap()],
    ] {
        assert!(Cli::try_parse_from(args).is_ok());
    }
    assert!(load(&base, false).is_err());
    assert!(load(&base.join("missing"), false).is_err());
    fs::write(&path, [0xff]).unwrap();
    assert!(
        load(&path, false)
            .err()
            .unwrap()
            .to_string()
            .contains("read config")
    );
    let mut limit = SINGLE.to_string();
    limit.extend(std::iter::repeat_n(' ', MAX_CONFIG as usize - limit.len()));
    fs::write(&path, &limit).unwrap();
    assert!(load(&path, false).is_ok());
    limit.push(' ');
    fs::write(&path, &limit).unwrap();
    assert!(format!("{:#}", load(&path, false).err().unwrap()).contains("exceeds 1 MiB"));
    let fifo = base.join("fifo");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
    assert!(format!("{:#}", load(&fifo, false).err().unwrap()).contains("regular file"));
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn semantic_errors_keep_file_and_field_but_not_raw_tun_values() {
    let base = std::env::temp_dir().join(format!("svpn config errors {}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("input.toml");
    for (text, multi, field) in [
        (
            "server = 'a.example'\npeer-tun-name = 'PRIVATE_MARKER_DO_NOT_LOG'",
            false,
            "peer-tun",
        ),
        (
            "server = 'a.example'\npeer-tun-name = 'ok'\ntun-name = 'PRIVATE_MARKER_DO_NOT_LOG'",
            false,
            "tun",
        ),
        (
            "[[servers]]\naddress = 'a.example'\npeer-tun-name = 'PRIVATE_MARKER_DO_NOT_LOG'",
            true,
            "peer-tun",
        ),
        ("server = 'a.example'", false, "peer-tun-name"),
        (
            "peer-tun-name = 'ok'\n[[servers]]\naddress = 'a.example'\n[[servers]]\naddress = 'a.example'",
            true,
            "servers[1]",
        ),
        (
            "server = 'a.example'\npeer-tun-name = 'ok'\ntun-addr = '10.77.0.1'",
            false,
            "point-to-point",
        ),
        (
            "server = 'a.example'\npeer-tun-name = 'ok'\nmimic = ['ssh']",
            false,
            "tcp-port",
        ),
    ] {
        std::fs::write(&path, text).unwrap();
        let mut argv = vec!["svpn"];
        if multi {
            argv.push("multi");
        }
        argv.extend(["--config", path.to_str().unwrap()]);
        let error = Cli::try_parse_from(argv)
            .err()
            .expect("invalid config accepted")
            .to_string();
        assert!(
            error.contains(path.to_str().unwrap()) && error.contains(field),
            "{error}"
        );
        assert!(!error.contains("PRIVATE_MARKER"), "{error}");
    }
    for name in ["PRIVATE/MARKER", "PRIVATE MARKER"] {
        let error = svpn::validate_tun_name(name).unwrap_err().to_string();
        assert!(!error.contains(name), "{error}");
    }
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn symlink_uses_its_directory_for_global_record_and_hook_paths() {
    use std::{fs, os::unix::fs::symlink};
    let base = std::env::temp_dir().join(format!("svpn config symlink {}", std::process::id()));
    let target = base.join("target");
    let alias = base.join("alias");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir(&alias).unwrap();
    let path = alias.join("config.toml");
    symlink("../target/config.toml", &path).unwrap();
    for (mode, multi) in [
        ("server = 'a.example'\n", false),
        (
            "[[servers]]\naddress = 'a.example'\nssh-identity = 'record key'\n",
            true,
        ),
    ] {
        fs::write(
            target.join("config.toml"),
            format!(
                "peer-tun-name = 'ok'\nssh-identity = 'global key'\n\
             up-script = 'up script'\ndown-script = 'down script'\n{mode}"
            ),
        )
        .unwrap();
        let args = load(&path, multi).unwrap();
        let params = resolve_servers(&args.server, &args.globals).unwrap();
        assert_eq!(args.globals.ssh_identity.unwrap(), alias.join("global key"));
        assert_eq!(args.hooks.up_script.unwrap(), alias.join("up script"));
        assert_eq!(args.hooks.down_script.unwrap(), alias.join("down script"));
        if multi {
            assert_eq!(
                params[0].identity.as_ref().unwrap(),
                &alias.join("record key")
            );
        }
    }
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn multi_cli_and_both_config_positions_produce_the_same_server_commands() {
    let base = std::env::temp_dir().join(format!("svpn config parity {}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("multi.toml");
    std::fs::write(
        &path,
        "peer-tun-name = 'svpn9'\nssh-user = 'vpn'\nssh-port = 2200\n\
         ssh-identity = '/keys/global'\nssh-remote-bin = \"/opt/svpn 'bin $HOME\"\n\
         tun-name = ''\ntun-addr = '10.88.0.2'\npeer-addr = '10.88.0.1'\n\
         mtu = 1300\nlog-level = 'debug'\nudp-port-range = '60000-60009'\n\
         mimic = ['mosh']\ntcp-port = 0\nstats-interval = 7\n\
         up-command = 'printf up'\ndown-script = 'hooks/down script'\n\
         [[servers]]\naddress = 'A.example'\nssh-port = 2222\nweight = 2\n\
         ssh-identity = 'keys/a'\nudp-port-range = '61000-61009'\n\
         [[servers]]\naddress = 'b.example'\nssh-user = 'other'\n\
         peer-tun-name = 'svpn8'\npeer-addr = '10.88.0.3'\n\
         ssh-remote-bin = '/other/bin'\nmimic = ['quic', 'mosh']\n\
         udp-port-range = '62000-62009'\n\
         ssh-host-key = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\n",
    )
    .unwrap();
    let first = format!(
        "A.example:2222,weight=2,identity={},udp-ports=61000-61009",
        base.join("keys/a").display()
    );
    let down = base.join("hooks/down script");
    let Mode::Client(cli) = Cli::try_parse_from([
        "svpn", "multi", "--server", &first,
        "--server", "b.example,user=other,peer-tun=svpn8,peer-addr=10.88.0.3,remote-bin=/other/bin,mimic=quic+mosh,udp-ports=62000-62009,hostkey=SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "--peer-tun-name", "svpn9", "--ssh-user", "vpn", "--ssh-port", "2200",
        "--ssh-identity", "/keys/global", "--ssh-remote-bin", "/opt/svpn 'bin $HOME",
        "--tun-name", "", "--tun-addr", "10.88.0.2", "--peer-addr", "10.88.0.1",
        "--mtu", "1300", "--log-level", "debug", "--udp-port-range", "60000-60009",
        "--mimic", "mosh", "--tcp-port", "0", "--stats-interval", "7",
        "--up-command", "printf up", "--down-script", down.to_str().unwrap(),
    ]).unwrap().command else { panic!("expected client") };
    fn resolved(args: &ClientArgs) -> Vec<(String, String)> {
        resolve_servers(&args.server, &args.globals)
            .unwrap()
            .iter()
            .map(|p| {
                (
                    format!("{p:?}"),
                    svpn::serve_command(
                        &p.remote_bin,
                        &p.peer_tun_name,
                        p.log_level,
                        p.udp_port_range,
                        &p.mimic,
                        p.tcp_port,
                    ),
                )
            })
            .collect()
    }
    let expected = resolved(&cli);
    assert!(expected[0].1.contains("--udp-port-range 61000-61009"));
    assert!(expected[1].1.contains("--udp-port-range 62000-62009"));
    for argv in [
        vec!["svpn", "--config", path.to_str().unwrap(), "multi"],
        vec!["svpn", "multi", "--config", path.to_str().unwrap()],
    ] {
        let Mode::Client(file) = Cli::try_parse_from(argv).unwrap().command else {
            panic!("expected client")
        };
        assert_eq!(resolved(&file), expected);
        assert_eq!(file.stats_interval, cli.stats_interval);
        assert_eq!(file.hooks.up_command, cli.hooks.up_command);
        assert_eq!(file.hooks.down_script, cli.hooks.down_script);
    }
    std::fs::remove_dir_all(base).unwrap();
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
