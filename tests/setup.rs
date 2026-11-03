//! Setup CLI and bounded embedded installer payload.

use sha2::{Digest, Sha256};
use svpn::{Cli, Mode, setup};

#[test]
fn setup_requires_exactly_one_of_config_or_server() {
    let cli = Cli::try_parse_from(["svpn", "setup", "--config", "client.toml"]).unwrap();
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
            "client.toml",
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
fn installer_frames_exact_embedded_hooks() {
    let input = setup::installer_input("0.9.6").unwrap();
    let text = String::from_utf8(input).unwrap();
    assert!(text.starts_with("SVPN_CLIENT_VERSION='0.9.6'\n"));
    assert!(text.contains(setup::SETUP_SCRIPT));
    assert!(text.contains(setup::SERVER_UP));
    assert!(text.contains(setup::SERVER_DOWN));
    assert!(text.ends_with("SVPN_SETUP_PAYLOAD\n"));
    for (name, script) in [
        ("server-up", setup::SERVER_UP),
        ("server-down", setup::SERVER_DOWN),
    ] {
        let hash = hex(&Sha256::digest(script.as_bytes()));
        assert!(text.contains(&format!("{name} {hash} {}\n", script.len())));
    }
    assert!(
        !String::from_utf8(setup::preflight_input())
            .unwrap()
            .contains("SVPN_SETUP_PAYLOAD")
    );
}

#[test]
fn report_markers_parse_from_installer_stdout() {
    let stdout = b"SVPN_SETUP_SELECTED=1.2.3\nnoise\nSVPN_SETUP_CHANGED=/usr/local/bin/svpn\nSVPN_SETUP_CHANGED=/usr/local/lib/svpn/server-up\n";
    assert_eq!(
        setup::changed_paths(stdout),
        vec!["/usr/local/bin/svpn", "/usr/local/lib/svpn/server-up"]
    );
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
fn payload_delimiter_as_a_line_is_rejected_anywhere() {
    assert!(setup::framing_safe(
        "#!/bin/sh\nsysctl -qw net.ipv4.ip_forward=1\n"
    ));
    assert!(!setup::framing_safe("SVPN_SETUP_PAYLOAD\ntrue\n"));
    assert!(!setup::framing_safe(
        "#!/bin/sh\nSVPN_SETUP_PAYLOAD\ntrue\n"
    ));
    assert!(!setup::framing_safe("#!/bin/sh\nSVPN_SETUP_PAYLOAD"));
    assert!(setup::framing_safe("#!/bin/sh\nSVPN_SETUP_PAYLOAD_EXTRA\n"));
    assert!(setup::framing_safe(""));
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
