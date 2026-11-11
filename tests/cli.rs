//! CLI parsing: server cardinality and weights, config exclusivity, help and version.

use clap::error::ErrorKind;
use svpn::cli::*;
use svpn::server_spec::resolve_servers;

fn client(args: &[&str]) -> ClientArgs {
    match Cli::try_parse_from(["svpn"].into_iter().chain(args.iter().copied()))
        .unwrap()
        .command
    {
        Mode::Client(client) => client,
        _ => panic!("expected client"),
    }
}

// ── automatic ASN modes ──

#[test]
fn sticky_asn_mode_defaults_and_validation() {
    let base = [
        "multi",
        "--server",
        "vpn.example",
        "--exit-policy",
        "sticky-asn",
        "--geo-db",
        "asn.csv",
    ];
    assert_eq!(client(&base).sticky_asn_mode, StickyAsnMode::Hashed);
    for (value, mode) in [
        ("balanced", StickyAsnMode::Balanced),
        ("hashed", StickyAsnMode::Hashed),
    ] {
        let args: Vec<_> = base
            .into_iter()
            .chain(["--sticky-asn-mode", value])
            .collect();
        assert_eq!(client(&args).sticky_asn_mode, mode);
    }
    assert!(
        Cli::try_parse_from(
            ["svpn"]
                .into_iter()
                .chain(base)
                .chain(["--sticky-asn-mode", "typo"])
        )
        .is_err()
    );
    let error = Cli::try_parse_from([
        "svpn",
        "multi",
        "--server",
        "vpn.example",
        "--sticky-asn-mode",
        "balanced",
    ])
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("requires exit-policy sticky-asn")
    );
}

// ── dashboard address ──

#[test]
fn dashboard_address_comes_from_the_flag_or_the_config() {
    let args = client(&["--server", "203.0.113.1", "--web-listen", "127.0.0.1:8080"]);
    assert_eq!(args.web_listen, Some("127.0.0.1:8080".parse().unwrap()));
    assert_eq!(client(&["--server", "203.0.113.1"]).web_listen, None);

    let config = svpn::config::parse(
        "server \"main\" {\n  address = \"vpn.example\"\n}\n\
         dashboard {\n  listen = \"127.0.0.1:8080\"\n}\n",
        std::path::Path::new("."),
        false,
    )
    .expect("dashboard config");
    assert_eq!(config.web_listen, Some("127.0.0.1:8080".parse().unwrap()));

    let error = match svpn::config::parse(
        "server \"main\" {\n  address = \"vpn.example\"\n}\n\
         dashboard {\n  listen = \"nowhere\"\n}\n",
        std::path::Path::new("."),
        false,
    ) {
        Ok(_) => panic!("bad address must be refused"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("dashboard"), "{error:#}");
}

// ── cardinality and weights ──

#[test]
fn default_single_and_multi_have_separate_cardinality_and_weight_rules() {
    let single = client(&["--server", "VPN.example,peer-tun=svpn0"]);
    assert_eq!(
        resolve_servers(&single.server, &single.globals).unwrap()[0].server,
        "vpn.example"
    );
    assert_eq!(
        client(&["multi", "--server", "203.0.113.1,peer-tun=svpn0,weight=2"])
            .server
            .len(),
        1
    );
    assert_eq!(
        client(&[
            "multi",
            "--server",
            "203.0.113.1,peer-tun=svpn0",
            "--server",
            "203.0.113.2,peer-tun=svpn0"
        ])
        .server
        .len(),
        2
    );
    for args in [
        vec!["client", "--server", "203.0.113.1"],
        vec!["single", "--server", "203.0.113.1"],
        vec!["multi"],
        vec!["--server", "203.0.113.1,peer-tun=svpn0,weight=1"],
        vec![
            "--server",
            "203.0.113.1,peer-tun=svpn0",
            "--server",
            "203.0.113.2,peer-tun=svpn0",
        ],
        vec![
            "--mtu",
            "1280",
            "multi",
            "--server",
            "203.0.113.1,peer-tun=svpn0",
        ],
    ] {
        assert!(Cli::try_parse_from(["svpn"].into_iter().chain(args)).is_err());
    }
}

#[test]
fn sticky_asn_is_multi_only() {
    for args in [
        vec![
            "--server",
            "203.0.113.1",
            "--exit-policy",
            "sticky-asn",
            "--geo-db",
            "asn.csv",
        ],
        vec![
            "client",
            "--server",
            "203.0.113.1",
            "--exit-policy",
            "sticky-asn",
            "--geo-db",
            "asn.csv",
        ],
    ] {
        assert!(
            Cli::try_parse_from(["svpn"].into_iter().chain(args)).is_err(),
            "single mode must reject sticky-asn"
        );
    }
    // Multi accepts the flags; the geo-db requirement is enforced at runtime.
    let multi = client(&[
        "multi",
        "--server",
        "203.0.113.1",
        "--server",
        "203.0.113.2",
        "--exit-policy",
        "sticky-asn",
        "--geo-db",
        "asn.csv",
    ]);
    assert_eq!(multi.exit_policy, ExitPolicy::StickyAsn);
}

// ── geo country flags ──

#[test]
fn country_db_flag_parses_cwd_relative() {
    let multi = client(&[
        "multi",
        "--server",
        "203.0.113.1",
        "--country-db",
        "country.csv",
    ]);
    assert_eq!(
        multi.country_db.as_deref(),
        Some(std::path::Path::new("country.csv")),
        "CLI paths stay cwd-relative, unlike config-relative ones"
    );
}

// ── job commands ──

#[test]
fn job_commands_require_config() {
    for args in [
        vec!["svpn", "job", "run", "geo-update", "--config", "vpn.hcl"],
        vec!["svpn", "job", "list", "--config", "vpn.hcl"],
    ] {
        assert!(Cli::try_parse_from(args).is_ok());
    }
    // --config before the subcommand stays forbidden, as everywhere else.
    assert!(Cli::try_parse_from(["svpn", "--config", "vpn.hcl", "job", "list"]).is_err());
    for args in [
        vec!["svpn", "job", "run", "geo-update"], // no config
        vec!["svpn", "job", "frobnicate", "--config", "c"], // unknown subcommand
        vec!["svpn", "job"],                      // no subcommand
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

// ── config exclusivity ──

#[test]
fn every_explicit_client_setting_conflicts_with_config_even_at_default() {
    for (flag, value) in [
        ("--server", "203.0.113.1"),
        ("--ssh-user", "root"),
        ("--ssh-identity", "key"),
        ("--ssh-port", "22"),
        (
            "--ssh-host-key",
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("--ssh-remote-bin", "/usr/local/bin/svpn"),
        ("--peer-tun-name", ""),
        ("--tun-name", ""),
        ("--tun-addr", "10.77.0.2"),
        ("--peer-addr", "10.77.0.1"),
        ("--mtu", "1280"),
        ("--log-level", "info"),
        ("--udp-port-range", "60000-60009"),
        ("--mimic", "mosh"),
        ("--tcp-port", "0"),
        ("--stats-interval", "30"),
        ("--sticky-asn-mode", "hashed"),
        ("--web-listen", "127.0.0.1:8080"),
        ("--up-script", "up"),
        ("--down-script", "down"),
        ("--up-command", "true"),
        ("--down-command", "true"),
    ] {
        for prefix in [vec!["svpn"], vec!["svpn", "multi"]] {
            let result = Cli::try_parse_from(prefix.into_iter().chain([
                "--config",
                "/not/read/before/xor",
                flag,
                value,
            ]));
            let error = result.err().expect("mixed sources accepted");
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict, "{flag}: {error}");
        }
    }
}

#[test]
fn config_is_single_file_and_client_only() {
    for args in [
        vec!["--config", "a", "--config", "b"],
        vec!["multi", "--config", "a", "--config", "b"],
        vec!["--config", "a", "multi", "--config", "b"],
        vec!["perf", "--config", "a"],
        vec!["serve", "--config", "a"],
        vec!["--config", "a", "perf", "--server", "203.0.113.1"],
        vec!["--config", "a", "serve"],
    ] {
        let error = Cli::try_parse_from(["svpn"].into_iter().chain(args))
            .err()
            .unwrap();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::ArgumentConflict | ErrorKind::UnknownArgument
            ),
            "{error}"
        );
    }
}

// ── help and version ──

#[test]
fn help_and_version_do_not_read_config_or_require_a_server() {
    let no_args = Cli::try_parse_from(["svpn"]).err().unwrap();
    assert_eq!(
        no_args.kind(),
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    );
    assert_eq!(no_args.exit_code(), 2);
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["multi", "--help"],
        vec!["perf", "--help"],
        vec!["serve", "--help"],
        vec!["--config", "/missing", "--help"],
        vec!["multi", "--config", "/missing", "--help"],
    ] {
        let error = Cli::try_parse_from(["svpn"].into_iter().chain(args))
            .err()
            .unwrap();
        assert!(matches!(
            error.kind(),
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
        ));
        if error.kind() == ErrorKind::DisplayHelp {
            assert!(!error.to_string().contains("svpn client"));
        }
    }
}

// ── value normalization ──

#[test]
fn local_empty_tun_name_is_kernel_selected_and_stats_zero_is_off() {
    let args = client(&[
        "--server",
        "203.0.113.1,peer-tun=svpn0",
        "--tun-name",
        "",
        "--stats-interval",
        "0",
    ]);
    assert!(
        resolve_servers(&args.server, &args.globals).unwrap()[0]
            .tun_name
            .is_none()
    );
    assert_eq!(args.stats_interval, 0);
}
