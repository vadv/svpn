//! Config text: parsing, defaults, inheritance, sticky blocks, rejections.

use std::path::Path;

use svpn::MimicArg;
use svpn::cli::{Cli, Mode};
use svpn::config::parse;
use svpn::server_spec::resolve_servers;
use svpn::sticky::{Selector, Via};

const SINGLE: &str =
    "server \"main\" {\n  address = \"vpn.example\"\n}\ntunnel {\n  peer_name = \"svpn0\"\n}\n";
const MULTI: &str =
    "tunnel {\n  peer_name = \"svpn0\"\n}\nserver \"a\" {\n  address = \"vpn.example\"\n}\n";

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
    let strip = |args: &svpn::cli::ClientArgs| {
        resolve_servers(&args.server, &args.globals)
            .unwrap()
            .into_iter()
            .map(|mut p| {
                p.label.clear();
                format!("{p:?}")
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(strip(&file), strip(&cli));
    assert_eq!(file.stats_interval, 30);
    let disabled = parse(
        &format!("{SINGLE}transport {{\n  stats = \"0s\"\n}}\n"),
        Path::new("/config"),
        false,
    )
    .unwrap();
    assert_eq!(disabled.stats_interval, 0);
    let file = parse(
        "tunnel {\n  peer_name = \"\"\n}\nssh {\n  port = 2222\n}\ntransport {\n  mimic = [\"mosh\"]\n}\n\
         server \"a\" {\n  address = \"VPN.example\"\n  weight = 2\n}\n\
         server \"b\" {\n  address = \"203.0.113.2\"\n  ssh_port = 2200\n  mimic = []\n}\n",
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
        "server \"main\" {\n  address = \"vpn.example\"\n}\n\
         ssh {\n  identity = \"keys/client key\"\n  remote_bin = \"~/bin/$SVPN\"\n}\n\
         hooks {\n  up_script = \"scripts/up script\"\n  down_command = \"echo $HOME; ./down\"\n}\n",
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
        "ssh {\n  identity = \"global key\"\n}\n\
         server \"a\" {\n  address = \"a.example\"\n  ssh_identity = \"/absolute/key\"\n}\n\
         server \"b\" {\n  address = \"b.example\"\n  ssh_identity = \"~/relative/key\"\n}\n",
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
        "ssh {\n  port = 65535\n}\ntransport {\n  tcp_port = 0\n  mtu = 1400\n  udp_ports = \"1-65535\"\n}\n\
         server \"a\" {\n  address = \"a.example\"\n  weight = 4294967295\n}\n",
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
        "server \"a\" {\n  address = \"a:22\"\n}\n",
        "server \"a\" {\n  address = \"a\"\n  extra = 1\n}\n",
        "server \"a\" {\n  address = \"::1\"\n}\n",
        "server \"UPPER\" {\n  address = \"a\"\n}\n",
        "server \"a\" {\n  address = \"a\"\n}\nserver \"a\" {\n  address = \"b\"\n}\n",
        "server \"a\" {\n  address = \"a\"\n}\nunknown {\n}\n",
        "server \"a\" {\n  address = \"a\"\n}\nssh {\n  port = 22\n}\nssh {\n  port = 23\n}\n",
        "mystery = 1\nserver \"a\" {\n  address = \"a\"\n}\n",
        "server \"a\" {\n  address = \"a\"\n}\nserver \"b\" {\n  address = \"b\"\n}\n",
    ] {
        assert!(parse(text, Path::new("."), false).is_err(), "{text}");
    }
    for field in [
        "transport {\n  mtu = \"1280\"\n}\n",
        "transport {\n  mtu = -1\n}\n",
        "transport {\n  mtu = 1401\n}\n",
        "transport {\n  mtu = 1.5\n}\n",
        "ssh {\n  port = 0\n}\n",
        "ssh {\n  port = 65536\n}\n",
        "ssh {\n  port = -1\n}\n",
        "transport {\n  tcp_port = 65536\n}\n",
        "transport {\n  stats = \"-1s\"\n}\n",
        "log_level = \"verbose\"\n",
        "transport {\n  mimic = \"mosh\"\n}\n",
        "transport {\n  mimic = [\"auto\"]\n}\n",
        "transport {\n  mimic = [\"ssh\", \"banner\"]\n}\n",
        "transport {\n  udp_ports = \"0-1\"\n}\n",
        "transport {\n  udp_ports = \"2-1\"\n}\n",
        "ssh {\n  user = \"\"\n}\n",
        "ssh {\n  identity = \"\"\n}\n",
        "ssh {\n  remote_bin = \"\"\n}\n",
        "ssh {\n  host_key = \"bad\"\n}\n",
        "tunnel {\n  addr = \"::1\"\n}\n",
        "tunnel {\n  addr = \"0.0.0.0\"\n}\n",
        "hooks {\n  up_script = \"\"\n}\n",
        "hooks {\n  up_command = \" \"\n}\n",
        "hooks {\n  down_command = \"\"\n}\n",
        "hooks {\n  up_script = \"up\"\n  up_command = \"true\"\n}\n",
        "hooks {\n  down_script = \"down\"\n  down_command = \"true\"\n}\n",
    ] {
        let text = format!("{SINGLE}{field}");
        assert!(parse(&text, Path::new("."), false).is_err(), "{field}");
    }
    for text in [
        "server \"a\" {\n  address = \"a:22\"\n}\n",
        "server \"a\" {\n  weight = 0\n}\n",
        "server \"a\" {\n  weight = 4294967296\n}\n",
        "server \"a\" {\n  address = \"a\"\n  ssh_user = \"\"\n}\n",
        "server \"a\" {\n  address = \"a\"\n  up_command = \"true\"\n}\n",
        "server \"a\" {\n  address = \"a\"\n  tunnel {\n  }\n}\n",
    ] {
        assert!(parse(text, Path::new("."), true).is_err(), "{text}");
    }
}

#[test]
fn invalid_globals_cannot_be_hidden_by_valid_server_overrides() {
    for (global, local) in [
        ("ssh {\n  port = 0\n}\n", "ssh_port = 22"),
        ("ssh {\n  identity = \"\"\n}\n", "ssh_identity = \"/key\""),
        (
            "ssh {\n  host_key = \"bad\"\n}\n",
            "ssh_host_key = \"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
        ),
        ("ssh {\n  user = \"\"\n}\n", "ssh_user = \"root\""),
        (
            "ssh {\n  remote_bin = \"\"\n}\n",
            "ssh_remote_bin = \"/svpn\"",
        ),
        (
            "transport {\n  udp_ports = \"0-1\"\n}\n",
            "udp_port_range = \"1-2\"",
        ),
        (
            "tunnel {\n  peer_addr = \"0.0.0.0\"\n}\n",
            "peer_addr = \"10.77.0.1\"",
        ),
    ] {
        let text =
            format!("{global}{MULTI}server \"b\" {{\n  address = \"b.example\"\n  {local}\n}}\n");
        assert!(parse(&text, Path::new("."), true).is_err(), "{global}");
    }
}

#[test]
fn malformed_values_are_not_echoed_in_errors() {
    for field in ["port", "mimic"] {
        let text = format!("{SINGLE}ssh {{\n  {field} = \"PRIVATE_MARKER_DO_NOT_LOG\"\n}}\n");
        let error = parse(&text, Path::new("."), false)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("PRIVATE_MARKER"), "{error}");
        assert!(error.contains(field), "{error}");
    }
    // Syntax errors carry a sanitized line/column.
    let text = format!("{SINGLE}ssh {{\n  port = \n}}\n");
    let error = parse(&text, Path::new("."), false)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("line 8"), "{error}");
    assert!(error.contains("invalid config syntax"), "{error}");
}

// ── sticky blocks ──

#[test]
fn sticky_blocks_parse_with_all_selectors() {
    let args = parse(
        "fallback_sticky {\n  strategy = \"sticky-asn\"\n  state = \"exits.json\"\n}\n\
         geo {\n  db = \"asn.csv\"\n}\ncountry {\n  db = \"country.csv\"\n}\n\
         server \"nl1\" {\n  address = \"nl1.example\"\n  weight = 3\n}\n\
         server \"de1\" {\n  address = \"de1.example\"\n}\n\
         sticky \"claude\" {\n  names = [\"claude.ai\", \"anthropic.com\"]\n  via = [\"nl1\"]\n  every = \"5m\"\n}\n\
         sticky \"eu\" {\n  countries = [\"NL\", \"DE\"]\n  via = [\"de1\", \"nl1\"]\n}\n\
         sticky \"cf\" {\n  asn = [13335]\n  via = [\"de1\"]\n}\n\
         sticky \"legacy\" {\n  ips = [\"1.2.3.4\", \"5.6.0.0/16\"]\n  via = [\"nl1\"]\n}\n\
         sticky \"home\" {\n  names = [\"printer.lan\"]\n  via = local\n}\n\
         sticky \"printer2\" {\n  names = [\"printer2.lan\"]\n  via = local\n}\n",
        Path::new("/configs"),
        true,
    )
    .unwrap();
    assert_eq!(args.exit_policy, svpn::cli::ExitPolicy::StickyAsn);
    assert_eq!(
        args.exit_state,
        Some(std::path::PathBuf::from("/configs/exits.json"))
    );
    assert_eq!(args.geo_db.as_deref(), Some(Path::new("/configs/asn.csv")));
    assert_eq!(
        args.country_db.as_deref(),
        Some(Path::new("/configs/country.csv"))
    );
    let stickies = &args.stickies;
    assert_eq!(stickies.len(), 6);
    assert_eq!(stickies[0].label, "claude");
    assert_eq!(
        stickies[0].selector,
        Selector::Names(vec!["claude.ai".into(), "anthropic.com".into()])
    );
    assert_eq!(stickies[0].via, Via::Servers(vec!["nl1".into()]));
    assert_eq!(stickies[0].every, std::time::Duration::from_secs(300));
    assert_eq!(
        stickies[1].selector,
        Selector::Countries(vec!["NL".into(), "DE".into()])
    );
    assert_eq!(stickies[2].selector, Selector::Asn(vec![13335]));
    assert_eq!(stickies[3].via, Via::Servers(vec!["nl1".into()]));
    assert_eq!(stickies[4].via, Via::Local);
    assert_eq!(
        stickies[5].every,
        std::time::Duration::from_secs(300),
        "names default every"
    );
    // Config order is preserved: first match wins.
    assert_eq!(stickies[0].canonical_key(), "name:anthropic.com,claude.ai");
    assert_eq!(stickies[1].canonical_key(), "cc:DE,NL");
    assert_eq!(stickies[2].canonical_key(), "asn:13335");
}

#[test]
fn extra_block_labels_are_rejected() {
    let text = "server \"a\" \"b\" {\n  address = \"a.example\"\n}\n";
    assert!(parse(text, Path::new("."), false).is_err());
    let text = "server \"a\" {\n  address = \"a.example\"\n}\nsticky \"x\" \"y\" {\n  ips = [\"1.2.3.4\"]\n  via = [\"a\"]\n}\n";
    assert!(parse(text, Path::new("."), true).is_err());
}

#[test]
fn escaped_template_markers_are_literal_values() {
    let text = concat!(
        "server \"main\" {\n  address = \"vpn.example\"\n}\n",
        "hooks {\n  up_command = <<EOF\n",
        "echo literal $${HOME} and %%{var} here\n",
        "EOF\n}\n",
    );
    let args = parse(text, Path::new("."), false).unwrap();
    let command = args.hooks.up_command.unwrap();
    // HCL strips the escape: the hook sees one $ and one %.
    assert!(command.contains("${HOME}"), "{command}");
    assert!(command.contains("%{var}"), "{command}");
}

#[test]
fn sticky_errors_do_not_echo_values_in_the_chain() {
    let text = concat!(
        "server \"a\" {\n  address = \"a.example\"\n}\n",
        "sticky \"x\" {\n  ips = [\"PRIVATE.MARKER/16\"]\n  via = [\"a\"]\n}\n",
    );
    let error = format!("{:#}", parse(text, Path::new("."), true).err().unwrap());
    assert!(!error.contains("PRIVATE.MARKER"), "{error}");
    let text = concat!(
        "server \"a\" {\n  address = \"a.example\"\n}\n",
        "sticky \"x\" {\n  ips = [\"9.9.9.9\"]\n  via = [\"a\"]\n  every = \"PRIVATE\"\n}\n",
    );
    let error = format!("{:#}", parse(text, Path::new("."), true).err().unwrap());
    assert!(!error.contains("PRIVATE"), "{error}");
}

#[test]
fn sticky_blocks_reject_invalid_shapes() {
    let base = "server \"nl1\" {\n  address = \"nl1.example\"\n}\n";
    for sticky in [
        // no selector
        "sticky \"x\" {\n  via = [\"nl1\"]\n}\n",
        // two selectors
        "sticky \"x\" {\n  names = [\"a.example\"]\n  asn = [1]\n  via = [\"nl1\"]\n}\n",
        // unknown via label
        "sticky \"x\" {\n  ips = [\"1.2.3.4\"]\n  via = [\"ghost\"]\n}\n",
        // empty via list
        "sticky \"x\" {\n  ips = [\"1.2.3.4\"]\n  via = []\n}\n",
        // via missing
        "sticky \"x\" {\n  ips = [\"1.2.3.4\"]\n}\n",
        // every with a non-name selector
        "sticky \"x\" {\n  ips = [\"1.2.3.4\"]\n  via = [\"nl1\"]\n  every = \"5m\"\n}\n",
        // every below the minimum
        "sticky \"x\" {\n  names = [\"a.example\"]\n  via = [\"nl1\"]\n  every = \"1s\"\n}\n",
        // duplicate canonical key
        "sticky \"x\" {\n  ips = [\"1.2.3.4\"]\n  via = [\"nl1\"]\n}\n\
         sticky \"y\" {\n  ips = [\"1.2.3.4\"]\n  via = [\"nl1\"]\n}\n",
        // duplicate label
        "sticky \"x\" {\n  ips = [\"1.2.3.4\"]\n  via = [\"nl1\"]\n}\n\
         sticky \"x\" {\n  ips = [\"5.6.7.8\"]\n  via = [\"nl1\"]\n}\n",
        // host bits set
        "sticky \"x\" {\n  ips = [\"5.6.7.8/16\"]\n  via = [\"nl1\"]\n}\n",
        // uppercase name
        "sticky \"x\" {\n  names = [\"Claude.ai\"]\n  via = [\"nl1\"]\n  every = \"5m\"\n}\n",
        // bad country code
        "sticky \"x\" {\n  countries = [\"ZZZ\"]\n  via = local\n}\n",
        // asn out of range
        "sticky \"x\" {\n  asn = [4294967296]\n  via = [\"nl1\"]\n}\n",
        // block label problems
        "sticky \"Bad Label\" {\n  ips = [\"1.2.3.4\"]\n  via = [\"nl1\"]\n}\n",
        "sticky \"way_too_long_label_1234567890_abcdef\" {\n  ips = [\"1.2.3.4\"]\n  via = [\"nl1\"]\n}\n",
    ] {
        let text = format!("{base}{sticky}");
        assert!(parse(&text, Path::new("."), true).is_err(), "{sticky}");
    }
    for name in [
        "sticky \"x\" {\n  names = [\"\"]\n  via = local\n  every = \"5m\"\n}\n",
        "sticky \"x\" {\n  names = [\"a..b\"]\n  via = local\n  every = \"5m\"\n}\n",
    ] {
        let text = format!("{base}{name}");
        assert!(parse(&text, Path::new("."), true).is_err(), "{name}");
    }
}

#[test]
fn sticky_selectors_require_their_databases() {
    let servers = "server \"nl1\" {\n  address = \"nl1.example\"\n}\n";
    // countries selector without country db
    assert!(
        parse(
            &format!("{servers}sticky \"x\" {{\n  countries = [\"DE\"]\n  via = local\n}}\n"),
            Path::new("."),
            true
        )
        .is_err()
    );
    // asn selector without geo db
    assert!(
        parse(
            &format!("{servers}sticky \"x\" {{\n  asn = [13335]\n  via = [\"nl1\"]\n}}\n"),
            Path::new("."),
            true
        )
        .is_err()
    );
    // names + via local need no databases
    assert!(parse(
        &format!("{servers}sticky \"x\" {{\n  names = [\"printer.lan\"]\n  via = local\n  every = \"5m\"\n}}\n"),
        Path::new("."),
        true
    )
    .is_ok());
    // sticky-asn strategy without geo db
    assert!(
        parse(
            &format!("fallback_sticky {{\n  strategy = \"sticky-asn\"\n}}\n{servers}"),
            Path::new("."),
            true
        )
        .is_err()
    );
}

// ── job blocks ──

#[test]
fn job_blocks_parse_with_defaults() {
    let args = parse(
        concat!(
            "server \"main\" {\n  address = \"a.example\"\n}\n",
            "job \"geo-update\" {\n",
            "  every = \"24h\"\n",
            "  run = <<EOF\n",
            "curl -fL \"https://example/dbip-$(date +%Y-%m).csv.gz\"\n",
            "EOF\n",
            "  reload = [\"geo\", \"country\"]\n",
            "}\n",
            "job \"probe\" {\n",
            "  every = \"5m\"\n",
            "  timeout = \"30s\"\n",
            "  run = \"exit 0\"\n",
            "}\n",
        ),
        Path::new("/configs"),
        false,
    )
    .unwrap();
    let jobs = &args.jobs;
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0].label, "geo-update");
    assert_eq!(jobs[0].every, std::time::Duration::from_secs(86400));
    assert_eq!(
        jobs[0].timeout,
        std::time::Duration::from_secs(600),
        "default timeout"
    );
    assert!(
        jobs[0].run.contains("$(date +%Y-%m)"),
        "shell $( passes the sanitizer"
    );
    assert_eq!(
        jobs[0].reload,
        [svpn::job::Reload::Geo, svpn::job::Reload::Country]
    );
    assert_eq!(jobs[1].timeout, std::time::Duration::from_secs(30));
    assert!(jobs[1].reload.is_empty());
}

#[test]
fn job_blocks_reject_invalid_shapes() {
    let base = "server \"a\" {\n  address = \"a.example\"\n}\n";
    for job in [
        // every missing / below the floor
        "job \"x\" {\n  run = \"true\"\n}\n",
        "job \"x\" {\n  every = \"30s\"\n  run = \"true\"\n}\n",
        // run missing / blank
        "job \"x\" {\n  every = \"5m\"\n}\n",
        "job \"x\" {\n  every = \"5m\"\n  run = \" \"\n}\n",
        // timeout out of bounds
        "job \"x\" {\n  every = \"5m\"\n  timeout = \"0s\"\n  run = \"true\"\n}\n",
        "job \"x\" {\n  every = \"5m\"\n  timeout = \"25h\"\n  run = \"true\"\n}\n",
        // reload vocabulary and duplicates
        "job \"x\" {\n  every = \"5m\"\n  run = \"true\"\n  reload = [\"dns\"]\n}\n",
        "job \"x\" {\n  every = \"5m\"\n  run = \"true\"\n  reload = [\"geo\", \"geo\"]\n}\n",
        // labels: duplicate, invalid charset, extra
        "job \"x\" {\n  every = \"5m\"\n  run = \"true\"\n}\njob \"x\" {\n  every = \"5m\"\n  run = \"true\"\n}\n",
        "job \"Bad Label\" {\n  every = \"5m\"\n  run = \"true\"\n}\n",
        "job \"x\" \"y\" {\n  every = \"5m\"\n  run = \"true\"\n}\n",
    ] {
        let text = format!("{base}{job}");
        assert!(parse(&text, Path::new("."), false).is_err(), "{job}");
    }
}

// ── server hooks ──

#[test]
fn server_hooks_root_and_per_server_override() {
    let text = "server \"main\" {\n  address = \"vpn.example\"\n}\n\
                hooks {\n  server_up = \"echo root-up\"\n  server_down = \"echo root-down\"\n}\n";
    let args = parse(text, Path::new("/config"), false).unwrap();
    let params = resolve_servers(&args.server, &args.globals).unwrap();
    assert_eq!(params[0].server_up.as_deref(), Some("echo root-up"));
    assert_eq!(params[0].server_down.as_deref(), Some("echo root-down"));

    let text = "hooks {\n  server_up = \"echo root-up\"\n}\n\
                server \"a\" {\n  address = \"a.example\"\n}\n\
                server \"b\" {\n  address = \"b.example\"\n  server_up = \"echo b-up\"\n}\n";
    let args = parse(text, Path::new("/config"), true).unwrap();
    let params = resolve_servers(&args.server, &args.globals).unwrap();
    assert_eq!(params[0].server_up.as_deref(), Some("echo root-up"));
    assert_eq!(params[1].server_up.as_deref(), Some("echo b-up"));
    assert_eq!(params[1].server_down, None);
}

#[test]
fn server_hooks_empty_rejected() {
    for field in ["server_up", "server_down"] {
        let text = format!("{SINGLE}hooks {{\n  {field} = \"\"\n}}\n");
        let error = parse(&text, Path::new("."), false)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("must not be empty"), "{error}");
        assert!(error.contains(field), "{error}");
    }
    for field in ["server_up", "server_down"] {
        let text = format!("server \"a\" {{\n  address = \"a.example\"\n  {field} = \"  \"\n}}\n");
        let error = parse(&text, Path::new("."), true).err().unwrap();
        let error = format!("{error:#}");
        assert!(error.contains("must not be empty"), "{error}");
        assert!(error.contains(field), "{error}");
    }
}

#[test]
fn server_hooks_heredoc_and_cli_parity() {
    let text = "server \"main\" {\n  address = \"vpn.example\"\n  server_up = <<EOF\nsysctl -w net.ipv4.ip_forward=1\nEOF\n}\n";
    let args = parse(text, Path::new("/config"), false).unwrap();
    let params = resolve_servers(&args.server, &args.globals).unwrap();
    assert_eq!(
        params[0].server_up.as_deref(),
        Some("sysctl -w net.ipv4.ip_forward=1")
    );

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
