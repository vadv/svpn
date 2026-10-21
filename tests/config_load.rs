//! Config files on disk: size bounds, symlink resolution, error context, CLI parity.

use svpn::cli::{Cli, ClientArgs, Mode};
use svpn::config::{MAX_CONFIG, load};
use svpn::server_spec::resolve_servers;

const SINGLE: &str = "server = 'vpn.example'\npeer-tun-name = 'svpn0'\n";
const MULTI: &str = "peer-tun-name = 'svpn0'\n[[servers]]\naddress = 'vpn.example'\n";

// ── file loading ──

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

// ── error context ──

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
        // No addresses and no TUN names: valid — automatic assignment (#181).
        (
            "server = 'a.example'\ntun-addr = '10.77.0.2'",
            false,
            "set both tun-addr and peer-addr",
        ),
        (
            "peer-tun-name = 'ok'\n[[servers]]\naddress = 'a.example'\n[[servers]]\naddress = 'a.example'",
            true,
            "servers[1]",
        ),
        (
            "server = 'a.example'\npeer-tun-name = 'ok'\ntun-addr = '10.77.0.1'\npeer-addr = '10.77.0.1'",
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

// ── CLI and file parity ──

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
        assert_eq!(file.hooks.up_command, cli.hooks.up_command);
        assert_eq!(file.hooks.down_script, cli.hooks.down_script);
    }
    std::fs::remove_dir_all(base).unwrap();
}
