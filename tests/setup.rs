//! Setup CLI, embedded defaults and per-host report markers.

use svpn::{Cli, Mode, setup};

#[test]
fn setup_requires_exactly_one_of_config_or_server() {
    let cli = Cli::try_parse_from(["svpn", "setup", "--config", "client.hcl"]).unwrap();
    assert!(matches!(cli.command, Mode::Setup { .. }));
    let cli = Cli::try_parse_from(["svpn", "setup", "--server", "203.0.113.10"]).unwrap();
    let Mode::Setup { client } = cli.command else {
        unreachable!()
    };
    assert_eq!(client.server.len(), 1);
    assert!(Cli::try_parse_from(["svpn", "setup"]).is_err());
    assert!(
        Cli::try_parse_from([
            "svpn",
            "setup",
            "--config",
            "client.hcl",
            "--server",
            "203.0.113.10"
        ])
        .is_err()
    );
}

#[test]
fn absent_server_hooks_use_embedded_defaults_and_custom_commands_override() {
    assert_eq!(setup::up_or_default(None), setup::SERVER_UP);
    assert_eq!(setup::down_or_default(None), setup::SERVER_DOWN);
    assert_eq!(setup::up_or_default(Some("true".into())), "true");
    assert_eq!(setup::down_or_default(Some("true".into())), "true");
}

#[test]
fn example_command_prints_the_embedded_hook_text() {
    let cli = Cli::try_parse_from(["svpn", "example", "client-up"]).unwrap();
    assert!(matches!(cli.command, Mode::Example { .. }));
    assert_eq!(setup::example("client-up"), Some(svpn::client_routing::UP));
    assert_eq!(
        setup::example("client-down"),
        Some(svpn::client_routing::DOWN)
    );
    assert_eq!(setup::example("server-up"), Some(setup::SERVER_UP));
    assert_eq!(setup::example("server-down"), Some(setup::SERVER_DOWN));
    assert_eq!(setup::example("unknown"), None);
}

#[test]
fn report_markers_parse_from_installer_stdout() {
    let stdout = b"SVPN_SETUP_SELECTED=1.2.3\nnoise\nSVPN_SETUP_CHANGED=/usr/local/bin/svpn\n";
    assert_eq!(setup::changed_paths(stdout), vec!["/usr/local/bin/svpn"]);
    assert_eq!(setup::selected_version(stdout).unwrap(), "1.2.3");
    assert_eq!(setup::changed_paths(b"no markers\n"), Vec::<String>::new());
    assert!(setup::selected_version(b"").is_err());
    assert!(setup::selected_version(b"SVPN_SETUP_SELECTED=\n").is_err());
}

#[test]
fn downgrade_marker_parses_only_version_pairs() {
    let full = b"noise\nSVPN_SETUP_DOWNGRADE=1.0.0->0.9.6\n";
    assert_eq!(
        setup::downgrade_report(full).as_deref(),
        Some("1.0.0->0.9.6")
    );
    assert_eq!(setup::downgrade_report(b""), None);
    assert_eq!(
        setup::downgrade_report(b"SVPN_SETUP_DOWNGRADE=1.0.0\n"),
        None
    );
    assert_eq!(
        setup::downgrade_report(b"SVPN_SETUP_DOWNGRADE=->0.9.6\n"),
        None
    );
    assert_eq!(
        setup::downgrade_report(b"SVPN_SETUP_DOWNGRADE=a.b->c.d\n"),
        None
    );
    assert_eq!(
        setup::downgrade_report(b"SVPN_SETUP_DOWNGRADE=1.0.0->\n"),
        None
    );
}

#[test]
fn example_prints_job_templates() {
    for (name, label, table) in [
        ("job-geo-update", "geo-update", "geo"),
        ("job-country-update", "country-update", "country"),
    ] {
        let text = svpn::setup::example(name).unwrap();
        assert!(text.contains(&format!("job \"{label}\"")), "{name}");
        assert!(text.contains(&format!("reload  = [\"{table}\"]")), "{name}");
        // The template must survive our own config sanitizer: no live ${ or %{
        // sequences inside the heredocs.
        assert!(!text.contains("${") && !text.contains("%{"), "{name}");
        // And it must actually parse as a config fragment with a server.
        let dir = std::env::temp_dir().join(format!("svpn-example-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vpn.hcl");
        std::fs::write(
            &path,
            format!("{text}\nserver \"s1\" {{\n  address = \"a.example\"\n}}\n"),
        )
        .unwrap();
        let parsed = svpn::config::load(&path, true).unwrap();
        assert_eq!(parsed.jobs.len(), 1, "{name}");
        assert_eq!(parsed.jobs[0].label, label, "{name}");
        assert!(parsed.jobs[0].run_if.is_some(), "{name}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
