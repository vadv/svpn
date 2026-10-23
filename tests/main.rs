//! Binary entry: CLI mode resolution, early validation, port claiming, remote command building.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use svpn::control::Strategy;
use svpn::framing::Camouflage;
use svpn::server_spec::{resolve_perf, resolve_servers};
use svpn::*;

fn parse_cli(mode: &str, args: &[&str]) -> Cli {
    Cli::try_parse_from(["svpn", mode].into_iter().chain(args.iter().copied())).unwrap()
}

// ── cli mode resolution ──

#[test]
fn hook_options_belong_only_to_client() {
    for flag in [
        "--up-script",
        "--down-script",
        "--up-command",
        "--down-command",
    ] {
        assert!(
            Cli::try_parse_from([
                "svpn",
                "multi",
                "--server",
                "203.0.113.1,peer-tun=svpn0",
                flag,
                "value"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["svpn", "perf", "--server", "203.0.113.1", flag, "value"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["svpn", "serve", flag, "value"]).is_err());
    }
}

#[test]
fn legacy_client_and_perf_flags_resolve_identically() {
    let flags = [
        "--server",
        "203.0.113.10",
        "--ssh-user",
        "vpn",
        "--ssh-identity",
        "/keys/client",
        "--ssh-port",
        "2222",
        "--ssh-host-key",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "--ssh-remote-bin",
        "/opt/svpn",
        "--peer-tun-name",
        "svpn0",
        "--tun-name",
        "utun9",
        "--tun-addr",
        "10.9.0.2",
        "--peer-addr",
        "10.9.0.1",
        "--mtu",
        "1200",
        "--log-level",
        "debug",
        "--udp-port-range",
        "41000-42000",
        "--mimic",
        "mosh",
        "--tcp-port",
        "0",
    ];
    for mode in ["multi", "perf"] {
        let params = match parse_cli(mode, &flags).command {
            Mode::Client(svpn::cli::ClientArgs {
                server, globals, ..
            }) => resolve_servers(&server, &globals).unwrap().remove(0),
            Mode::Perf {
                server, globals, ..
            } => resolve_perf(&server, &globals).unwrap(),
            _ => unreachable!(),
        };
        assert_eq!(params.server, "203.0.113.10");
        assert_eq!(params.user.as_deref(), Some("vpn"));
        assert_eq!(
            params.identity.as_deref(),
            Some(std::path::Path::new("/keys/client"))
        );
        assert_eq!(params.ssh_port, 2222);
        assert_eq!(params.host_key.unwrap().to_string(), flags[9]);
        assert_eq!(params.remote_bin, "/opt/svpn");
        assert_eq!(params.peer_tun_name.as_deref(), Some("svpn0"));
        assert_eq!(params.tun_name.as_deref(), Some("utun9"));
        assert_eq!(params.tun_addr, Ipv4Addr::new(10, 9, 0, 2));
        assert_eq!(params.peer_addr, Ipv4Addr::new(10, 9, 0, 1));
        assert_eq!(params.mtu, 1200);
        assert_eq!(params.log_level, logging::Level::Debug);
        assert_eq!(params.udp_port_range, (41000, 42000));
        assert_eq!(params.mimic, [MimicArg::Mosh]);
        assert_eq!(params.tcp_port, Some(0));
    }
}

#[test]
fn client_stats_interval_defaults_to_thirty_and_accepts_zero() {
    for (extra, expected) in [
        (vec![], 30),
        (vec!["--stats-interval", "5"], 5),
        (vec!["--stats-interval", "0"], 0),
    ] {
        let mut args = vec!["svpn", "multi", "--server", "203.0.113.10,peer-tun=svpn0"];
        args.extend(extra);
        let Mode::Client(svpn::cli::ClientArgs { stats_interval, .. }) =
            Cli::try_parse_from(args).unwrap().command
        else {
            unreachable!()
        };
        assert_eq!(stats_interval, expected);
    }
    for value in ["-1", "1.5", "no", "4294967296"] {
        assert!(
            Cli::try_parse_from([
                "svpn",
                "multi",
                "--server",
                "203.0.113.10",
                "--stats-interval",
                value
            ])
            .is_err()
        );
    }
    assert!(
        Cli::try_parse_from([
            "svpn",
            "perf",
            "--server",
            "203.0.113.10",
            "--stats-interval",
            "5"
        ])
        .is_err()
    );
}

#[test]
fn preserves_perf_measurement_flags() {
    let cli = parse_cli(
        "perf",
        &[
            "--server",
            "203.0.113.10,peer-tun=svpn0,mimic=quic",
            "-t",
            "30",
            "-i",
            "5",
            "-P",
            "4",
            "-l",
            "16K",
            "-n",
            "2M",
            "-R",
            "-O",
            "2",
            "--json",
        ],
    );
    let Mode::Perf {
        server,
        globals,
        time,
        interval,
        parallel,
        len,
        bytes,
        reverse,
        omit,
        json,
    } = cli.command
    else {
        unreachable!()
    };
    let params = resolve_perf(&server, &globals).unwrap();
    assert_eq!(params.mimic, [MimicArg::Quic]);
    assert!(params.identity.is_none());
    assert_eq!(
        (time, interval, parallel, len, bytes, reverse, omit, json),
        (30, 5, 4, 16 << 10, Some(2 << 20), true, 2, true)
    );
}

#[test]
fn cli_enforces_server_cardinality_and_valid_syntax() {
    for mode in ["multi", "perf"] {
        for args in [
            vec![],
            vec!["--server", "203.0.113.10,unknown=x"],
            vec!["--server", "203.0.113.10,mimic=quic++mosh"],
            vec!["--server", "203.0.113.10:0"],
            vec!["--server", "203.0.113.10", "--ssh-port", "0"],
            vec!["--server", "203.0.113.10", "--udp-port-range", "0-1"],
            vec!["--server", "203.0.113.10", "--tcp-port", "65536"],
        ] {
            assert!(Cli::try_parse_from(["svpn", mode].into_iter().chain(args)).is_err());
        }
    }
    let args = [
        "--server",
        "203.0.113.10,peer-tun=tun0",
        "--server",
        "198.51.100.7,peer-tun=tun1",
    ];
    let Mode::Client(svpn::cli::ClientArgs {
        server, globals, ..
    }) = parse_cli("multi", &args).command
    else {
        unreachable!()
    };
    assert_eq!(resolve_servers(&server, &globals).unwrap().len(), 2);
    assert!(Cli::try_parse_from(["svpn", "perf"].into_iter().chain(args)).is_err());
}

#[test]
fn cli_merges_global_and_per_server_requirements() {
    for mode in ["multi", "perf"] {
        for (args, valid) in [
            // No TUN names or addresses: valid — automatic assignment (#181).
            (vec!["--server", "203.0.113.10", "--mimic", "mosh"], true),
            (
                vec![
                    "--server",
                    "203.0.113.10",
                    "--peer-tun-name",
                    "",
                    "--mimic",
                    "mosh",
                ],
                true,
            ),
            (
                vec!["--server", "203.0.113.10,peer-tun=tun0,mimic=mosh"],
                true,
            ),
            (vec!["--server", "203.0.113.10,peer-tun=,mimic=mosh"], false),
            (
                vec!["--server", "203.0.113.10,peer-tun=tun0"],
                mode == "multi",
            ),
            (
                vec!["--server", "203.0.113.10,peer-tun=tun0,mimic=quic+mosh"],
                mode == "multi",
            ),
            (
                vec!["--server", "203.0.113.10,peer-tun=tun0,mimic=mosh,weight=1"],
                mode == "multi",
            ),
            (
                vec![
                    "--server",
                    "203.0.113.10,peer-tun=tun0",
                    "--mimic",
                    "quic",
                    "--mimic",
                    "mosh",
                ],
                mode == "multi",
            ),
            (
                vec![
                    "--server",
                    "203.0.113.10,peer-tun=tun0,mimic=quic",
                    "--mimic",
                    "mosh",
                ],
                true,
            ),
        ] {
            let resolved =
                Cli::try_parse_from(["svpn", mode].into_iter().chain(args.iter().copied()))
                    .map_err(anyhow::Error::from)
                    .and_then(|cli| match cli.command {
                        Mode::Client(svpn::cli::ClientArgs {
                            server, globals, ..
                        }) => resolve_servers(&server, &globals).map(|_| ()),
                        Mode::Perf {
                            server, globals, ..
                        } => resolve_perf(&server, &globals).map(|_| ()),
                        _ => unreachable!(),
                    });
            assert_eq!(resolved.is_ok(), valid, "{mode} {args:?}: {resolved:?}");
        }
    }
}

// ── early validation before bootstrap ──

#[tokio::test]
async fn invalid_hooks_fail_before_ssh_bootstrap() {
    for flag in ["--up-command", "--down-command"] {
        let cli = Cli::try_parse_from([
            "svpn",
            "multi",
            "--server",
            "203.0.113.1",
            "--ssh-user",
            "root",
            "--peer-tun-name",
            "svpn0",
            flag,
            " ",
        ])
        .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), run(cli))
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("hook command is empty"));
    }
}

#[test]
fn invalid_server_fails_before_any_network_bootstrap() {
    let error = match Cli::try_parse_from([
        "svpn",
        "multi",
        "--server",
        "203.0.113.10,peer-tun=tun0",
        "--server",
        "198.51.100.7,peer-tun=bad/name",
    ]) {
        Ok(_) => panic!("invalid second server accepted"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("servers[1] (198.51.100.7)"));
    assert!(error.contains("TUN name"));
}

#[tokio::test]
async fn invalid_perf_measurements_fail_before_network_bootstrap() {
    for (flags, expected) in [
        (["-P", "0"], "--parallel: 1..=128"),
        (["-P", "129"], "--parallel: 1..=128"),
        (["-i", "0"], "--interval: >= 1 s"),
        (["-t", "0"], "specify --time or --bytes"),
        (["-l", "1"], "--len: >= 1024 bytes"),
    ] {
        let cli = parse_cli(
            "perf",
            &[
                "--server",
                "203.0.113.10,peer-tun=tun0,mimic=quic",
                flags[0],
                flags[1],
            ],
        );
        assert_eq!(run(cli).await.unwrap_err().to_string(), expected);
    }
    let cli = parse_cli(
        "perf",
        &[
            "--server",
            "203.0.113.10,peer-tun=tun0,mimic=quic",
            "-t",
            "0",
            "-n",
            "1M",
        ],
    );
    let Mode::Perf { time, bytes, .. } = cli.command else {
        unreachable!()
    };
    assert_eq!((time, bytes), (0, Some(1 << 20)));
}

// ── udp port claiming ──

#[tokio::test]
async fn final_udp_port_does_not_wrap() {
    let mut next = 65535;
    let result = claim_udp_port(Ipv4Addr::LOCALHOST, &mut next, 65535).await;
    // The port may already be occupied; neither case may wrap the cursor to zero.
    assert!(result.is_err() || result.unwrap() == 65535);
    assert_eq!(next, 65536);
    assert!(
        claim_udp_port(Ipv4Addr::LOCALHOST, &mut next, 65535)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn claims_sequential_ports_and_skips_busy() {
    // Hardcoded ports flake on shared CI runners (anything may hold 61000);
    // find a free base port and occupy its successor instead.
    let (base, guard) = free_adjacent_pair().await;
    let max = base + 10;
    let mut next = u32::from(base);
    let first = claim_udp_port(Ipv4Addr::LOCALHOST, &mut next, max)
        .await
        .unwrap();
    assert_eq!(first, base);
    let second = claim_udp_port(Ipv4Addr::LOCALHOST, &mut next, max)
        .await
        .unwrap();
    assert_eq!(second, base + 2, "busy port must be skipped");
    drop(guard);
}

/// Returns a free port whose successor is held by the returned socket.
async fn free_adjacent_pair() -> (u16, tokio::net::UdpSocket) {
    for base in 40000..60000u16 {
        let probe = tokio::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, base)).await;
        if probe.is_err() {
            continue;
        }
        drop(probe);
        if let Ok(guard) =
            tokio::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, base + 1)).await
        {
            return (base, guard);
        }
    }
    panic!("no adjacent UDP port pair available");
}

#[tokio::test]
async fn exhausts_port_range() {
    let mut next = 61001;
    let error = claim_udp_port(Ipv4Addr::LOCALHOST, &mut next, 61000)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exhausted"));
}

// ── remote serve command ──

#[test]
fn builds_remote_command_with_quoted_tun_name() {
    let command = serve_command(
        "/usr/local/bin/svpn",
        Some("my'tun"),
        logging::Level::Info,
        (60000, 60009),
        &[],
        None,
    );
    assert_eq!(
        command,
        "'/usr/local/bin/svpn' serve --log-level info --udp-port-range 60000-60009 --tun-name 'my'\\''tun'"
    );
}

#[test]
fn builds_remote_command_with_mimics() {
    let command = serve_command(
        "/usr/local/bin/svpn",
        Some("svpn0"),
        logging::Level::Debug,
        (41000, 42000),
        &[
            MimicArg::Quic,
            MimicArg::Mosh,
            MimicArg::WebRtc,
            MimicArg::Ssh,
        ],
        None,
    );
    assert!(
        command.ends_with("--mimic quic --mimic mosh --mimic webrtc --mimic ssh")
            && command.contains("--udp-port-range 41000-42000")
    );
}

#[test]
fn builds_remote_command_with_tcp_port() {
    let command = serve_command(
        "/usr/local/bin/svpn",
        Some("svpn0"),
        logging::Level::Info,
        (60000, 60009),
        &[MimicArg::Ssh],
        Some(45000),
    );
    assert!(command.ends_with("--mimic ssh --tcp-port 45000"));
}

#[test]
fn plans_mimic_variants() {
    // auto: empty list (serve applies the defaults) + ssh TCP fallback
    // with an ephemeral port.
    let plan = plan_mimic(&[], Option::None).unwrap();
    assert!(plan.strategies.is_empty());
    assert_eq!(plan.tcp, Some((Option::None, Camouflage::Ssh)));
    // Mosh only: UDP without a TCP fallback.
    let plan = plan_mimic(&[MimicArg::Mosh], Option::None).unwrap();
    assert_eq!(plan.strategies, [Strategy::Mosh]);
    assert_eq!(plan.tcp, Option::None);
    // mosh + ssh: fallback with the given port.
    let plan = plan_mimic(&[MimicArg::Mosh, MimicArg::Ssh], Some(41020)).unwrap();
    assert_eq!(plan.strategies, [Strategy::Mosh]);
    assert_eq!(plan.tcp, Some((Some(41020), Camouflage::Ssh)));
    // banner without UDP strategies and a port — an error.
    assert!(plan_mimic(&[MimicArg::Banner], Option::None).is_err());
    // Two TCP camouflage levels — an error.
    assert!(plan_mimic(&[MimicArg::Ssh, MimicArg::Banner], Some(41020)).is_err());
    // A duplicate strategy collapses.
    let plan = plan_mimic(&[MimicArg::Mosh, MimicArg::Mosh], Option::None).unwrap();
    assert_eq!(plan.strategies, [Strategy::Mosh]);
}

#[test]
fn quotes_remote_executable_without_shell_expansion() {
    assert_eq!(shell_quote("/opt/svpn"), "'/opt/svpn'");
    assert_eq!(
        shell_quote("x'; touch /tmp/bad; '"),
        "'x'\\''; touch /tmp/bad; '\\'''"
    );
}

#[test]
fn uses_ssh_destination_not_client_address_for_udp_bind() {
    assert_eq!(
        ssh_server_address("10.9.0.2 50000 72.56.22.122 22").unwrap(),
        Ipv4Addr::new(72, 56, 22, 122)
    );
    for value in [
        "",
        "a b",
        "1.2.3.4 50000 ::1 22",
        "1.2.3.4 50000 0.0.0.0 22",
    ] {
        assert!(ssh_server_address(value).is_err(), "{value}");
    }
}

// ── parsing and validation ──

#[test]
fn busy_tun_error_detected() {
    let busy = anyhow::Error::from(std::io::Error::from_raw_os_error(16))
        .context("create/configure TUN (requires network privileges)");
    assert!(is_busy_tun(&busy));
    let eperm = anyhow::Error::from(std::io::Error::from_raw_os_error(1))
        .context("create/configure TUN (requires network privileges)");
    assert!(!is_busy_tun(&eperm));
    assert!(!is_busy_tun(&anyhow::anyhow!("plain failure")));
}

#[test]
fn parses_byte_sizes() {
    assert_eq!(parse_byte_size("1M").unwrap(), 1 << 20);
    assert_eq!(parse_byte_size("512K").unwrap(), 512 << 10);
    assert_eq!(parse_byte_size("1G").unwrap(), 1 << 30);
    assert_eq!(parse_byte_size("2m").unwrap(), 2 << 20);
    assert_eq!(parse_byte_size("1048576").unwrap(), 1 << 20);
    for bad in ["", "M", "1X", "-1", "1.5M", "0", "2G", "9999999999999"] {
        assert!(parse_byte_size(bad).is_err(), "{bad}");
    }
}

#[test]
fn parses_udp_port_ranges() {
    assert_eq!(parse_port_range("60000-60009").unwrap(), (60000, 60009));
    assert_eq!(parse_port_range("1-1").unwrap(), (1, 1));
    for invalid in [
        "",
        "41000",
        "41000-",
        "-42000",
        "42000-41000",
        "0-41000",
        "65536-65536",
        "a-b",
        "41000-42000-1",
    ] {
        assert!(parse_port_range(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn validates_tun_configuration() {
    let local = Ipv4Addr::new(10, 77, 0, 2);
    let peer = Ipv4Addr::new(10, 77, 0, 1);
    assert!(validate_addresses(local, peer, 1280).is_ok());
    assert!(validate_addresses(local, local, 1280).is_err());
    assert!(validate_addresses(local, peer, 1500).is_err());
    assert!(validate_addresses(Ipv4Addr::UNSPECIFIED, peer, 1280).is_err());
}

#[test]
fn validates_tun_names() {
    for name in ["tun9", "svpn0", "a", "abcdefghijklmno", "15-characters-x"] {
        assert!(validate_tun_name(name).is_ok(), "{name}");
    }
    for name in ["", "abcdefghijklmnop", "a/b", "a b", "a\tb", "a\nb", "tün"] {
        assert!(validate_tun_name(name).is_err(), "{name:?}");
    }
}
