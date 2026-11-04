//! Config files on disk: size bounds, symlink resolution, error context, CLI parity.

use svpn::cli::{Cli, ClientArgs, Mode};
use svpn::config::{MAX_CONFIG, load};
use svpn::server_spec::resolve_servers;

const SINGLE: &str =
    "server \"main\" {\n  address = \"vpn.example\"\n}\ntunnel {\n  peer_name = \"svpn0\"\n}\n";
const MULTI: &str =
    "tunnel {\n  peer_name = \"svpn0\"\n}\nserver \"a\" {\n  address = \"vpn.example\"\n}\n";

// ── file loading ──

#[test]
fn bounded_regular_utf8_file_and_config_positions() {
    use std::{fs, os::unix::fs::symlink};
    let base = std::env::temp_dir().join(format!("svpn config test {}", std::process::id()));
    fs::create_dir(&base).unwrap();
    let path = base.join("config.hcl");
    fs::write(&path, SINGLE).unwrap();
    assert!(load(&path, false).is_ok());
    let link = base.join("link.hcl");
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
fn symlink_uses_its_directory_for_global_record_and_hook_paths() {
    use std::{fs, os::unix::fs::symlink};
    let base = std::env::temp_dir().join(format!("svpn config symlink {}", std::process::id()));
    let target = base.join("target");
    let alias = base.join("alias");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir(&alias).unwrap();
    let path = alias.join("config.hcl");
    symlink("../target/config.hcl", &path).unwrap();
    for (mode, multi) in [
        ("server \"main\" {\n  address = \"a.example\"\n}\n", false),
        (
            "server \"a\" {\n  address = \"a.example\"\n  ssh_identity = \"record key\"\n}\n",
            true,
        ),
    ] {
        fs::write(
            target.join("config.hcl"),
            format!(
                "ssh {{\n  identity = \"global key\"\n}}\n\
             hooks {{\n  up_script = \"up script\"\n  down_script = \"down script\"\n}}\n{mode}"
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

// ── error context ──

#[test]
fn semantic_errors_keep_file_and_field_but_not_raw_tun_values() {
    let base = std::env::temp_dir().join(format!("svpn config errors {}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("input.hcl");
    for (text, multi, field) in [
        (
            "server \"a\" {\n  address = \"a.example\"\n}\ntunnel {\n  peer_name = \"PRIVATE_MARKER_DO_NOT_LOG\"\n}",
            false,
            "peer_tun_name",
        ),
        (
            "server \"a\" {\n  address = \"a.example\"\n}\ntunnel {\n  name = \"PRIVATE_MARKER_DO_NOT_LOG\"\n}",
            false,
            "tun_name",
        ),
        (
            "server \"a\" {\n  address = \"a.example\"\n}\nserver \"b\" {\n  address = \"b.example\"\n  peer_tun_name = \"PRIVATE_MARKER_DO_NOT_LOG\"\n}",
            true,
            "peer_tun_name",
        ),
        // No addresses and no TUN names: valid — automatic assignment (#181).
        (
            "server \"a\" {\n  address = \"a.example\"\n}\ntunnel {\n  addr = \"10.77.0.2\"\n}",
            false,
            "set both tun_addr and peer_addr",
        ),
        (
            "server \"a\" {\n  address = \"a.example\"\n}\nserver \"b\" {\n  address = \"a.example\"\n}",
            true,
            "servers[1]",
        ),
        (
            "server \"a\" {\n  address = \"a.example\"\n}\ntunnel {\n  addr = \"10.77.0.1\"\n  peer_addr = \"10.77.0.1\"\n}",
            false,
            "point-to-point",
        ),
        (
            "server \"a\" {\n  address = \"a.example\"\n}\ntunnel {\n  peer_name = \"ok\"\n}\ntransport {\n  mimic = [\"ssh\"]\n}",
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

// ── CLI and file parity ──

#[test]
fn multi_cli_and_both_config_positions_produce_the_same_server_commands() {
    let base = std::env::temp_dir().join(format!("svpn config parity {}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("multi.hcl");
    std::fs::write(
        &path,
        "ssh {\n  user = \"vpn\"\n  port = 2200\n  identity = \"/keys/global\"\n  remote_bin = \"/opt/svpn 'bin $HOME\"\n}\n\
         tunnel {\n  name = \"\"\n  addr = \"10.88.0.2\"\n  peer_addr = \"10.88.0.1\"\n}\n\
         transport {\n  mtu = 1300\n  udp_ports = \"60000-60009\"\n  mimic = [\"mosh\"]\n  tcp_port = 0\n  stats = \"7s\"\n}\n\
         log_level = \"debug\"\n\
         hooks {\n  up_command = \"printf up\"\n  down_script = \"hooks/down script\"\n}\n\
         fallback_sticky {\n  strategy = \"sticky-asn\"\n  state = \"geo state.json\"\n}\n\
         geo {\n  db = \"geo db.csv\"\n}\n\
         server \"a\" {\n  address = \"A.example\"\n  ssh_port = 2222\n  weight = 2\n  ssh_identity = \"keys/a\"\n  udp_port_range = \"61000-61009\"\n}\n\
         server \"b\" {\n  address = \"b.example\"\n  ssh_user = \"other\"\n  peer_tun_name = \"svpn8\"\n  peer_addr = \"10.88.0.3\"\n  ssh_remote_bin = \"/other/bin\"\n  mimic = [\"quic\", \"mosh\"]\n  udp_port_range = \"62000-62009\"\n  ssh_host_key = \"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n}\n",
    )
    .unwrap();
    let Mode::Client(cli) = Cli::try_parse_from([
        "svpn", "multi", "--server", &format!("A.example:2222,weight=2,identity={},udp-ports=61000-61009", base.join("keys/a").display()),
        "--server", "b.example,user=other,peer-tun=svpn8,peer-addr=10.88.0.3,remote-bin=/other/bin,mimic=quic+mosh,udp-ports=62000-62009,hostkey=SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "--ssh-user", "vpn", "--ssh-port", "2200",
        "--ssh-identity", "/keys/global", "--ssh-remote-bin", "/opt/svpn 'bin $HOME",
        "--tun-name", "", "--tun-addr", "10.88.0.2", "--peer-addr", "10.88.0.1",
        "--mtu", "1300", "--log-level", "debug", "--udp-port-range", "60000-60009",
        "--mimic", "mosh", "--tcp-port", "0", "--stats-interval", "7",
        "--exit-policy", "sticky-asn", "--geo-db", base.join("geo db.csv").to_str().unwrap(),
        "--exit-state", base.join("geo state.json").to_str().unwrap(),
        "--up-command", "printf up", "--down-script", base.join("hooks/down script").to_str().unwrap(),
    ]).unwrap().command else { panic!("expected client") };
    fn resolved(args: &ClientArgs) -> Vec<(String, String)> {
        resolve_servers(&args.server, &args.globals)
            .unwrap()
            .iter()
            .map(|p| {
                let mut p = p.clone();
                p.label.clear();
                (
                    format!("{p:?}"),
                    svpn::serve_command(
                        &p.remote_bin,
                        p.peer_tun_name.as_deref(),
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
        assert_eq!(file.exit_policy, cli.exit_policy);
        assert_eq!(file.geo_db, cli.geo_db);
        assert_eq!(file.exit_state, cli.exit_state);
        assert_eq!(file.hooks.up_command, cli.hooks.up_command);
        assert_eq!(file.hooks.down_script, cli.hooks.down_script);
    }
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn advanced_multi_examples_parse_with_all_exit_features() {
    // Self-contained mirror of the ADVANCED multi example in HCL; the docs
    // examples are pinned by tests/docs.rs instead of parsed here.
    let example = "fallback_sticky {\n  strategy = \"sticky-asn\"\n  state = \"/etc/svpn/exits.json\"\n}\n\
         geo {\n  db = \"/etc/svpn/asn.csv\"\n}\n\
         country {\n  db = \"/etc/svpn/country.csv\"\n}\n\
         sticky \"claude\" {\n  names = [\"claude.ai\", \"anthropic.com\"]\n  via = [\"nl1\"]\n  every = \"5m\"\n}\n\
         sticky \"eu\" {\n  countries = [\"NL\", \"DE\"]\n  via = [\"de1\", \"nl1\"]\n}\n\
         server \"nl1\" {\n  address = \"nl1.example.com\"\n  weight = 3\n}\n\
         server \"de1\" {\n  address = \"de1.example.com\"\n  weight = 1\n}\n";
    let path = std::env::temp_dir().join(format!("svpn-readme-multi-{}.hcl", std::process::id()));
    std::fs::write(&path, example).unwrap();
    let args = load(&path, true).unwrap();
    assert!(args.geo_db.is_some());
    assert!(args.country_db.is_some());
    let servers = resolve_servers(&args.server, &args.globals).unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(args.stickies.len(), 2);
    std::fs::remove_file(path).unwrap();
}
