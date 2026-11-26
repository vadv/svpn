//! The `dns` block of the config: exit mode and the resolvers of the local
//! exit.

use std::net::Ipv4Addr;
use std::path::Path;

use svpn::config::parse;
use svpn::dns::Settings;

const MULTI: &str =
    "tunnel {\n  peer_name = \"svpn0\"\n}\nserver \"a\" {\n  address = \"vpn.example\"\n}\n";

fn dns(text: &str) -> Result<Option<Settings>, String> {
    parse(&format!("{MULTI}{text}"), Path::new("/config"), true)
        .map(|args| args.dns)
        .map_err(|error| error.to_string())
}

// ── parsing ──

#[test]
fn without_the_mode_dns_is_left_alone() {
    assert_eq!(dns("").unwrap(), None);
    // An empty block says nothing: off, like every other block.
    assert_eq!(dns("dns {\n}\n").unwrap(), None);
}

#[test]
fn exit_mode_with_and_without_local_resolvers() {
    let off = dns("dns {\n  mode = \"exit\"\n}\n").unwrap();
    assert_eq!(off, Some(Settings { local: Vec::new() }));
    let local =
        dns("dns {\n  mode = \"exit\"\n  local = [\"77.88.8.8\", \"77.88.8.1\"]\n}\n").unwrap();
    assert_eq!(
        local,
        Some(Settings {
            local: vec![Ipv4Addr::new(77, 88, 8, 8), Ipv4Addr::new(77, 88, 8, 1)]
        })
    );
    // Three is resolv.conf's maximum.
    assert!(
        dns("dns {\n  mode = \"exit\"\n  local = [\"1.1.1.1\", \"8.8.8.8\", \"9.9.9.9\"]\n}\n")
            .is_ok()
    );
}

// ── rejections ──

#[test]
fn rejected_shapes() {
    for (text, reason) in [
        // A block without the mode does nothing; its resolvers would be unused.
        (
            "dns {\n  local = [\"77.88.8.8\"]\n}\n",
            "dns: local is only used with mode = \"exit\"",
        ),
        ("dns {\n  mode = \"off\"\n}\n", "dns: mode must be exit"),
        (
            "dns {\n  mode = true\n}\n",
            "dns: attribute mode must be a string",
        ),
        // The HCL parser itself refuses a repeated attribute.
        (
            "dns {\n  mode = \"exit\"\n  mode = \"exit\"\n}\n",
            "invalid config syntax",
        ),
        (
            "dns {\n  mode = \"exit\"\n  cache = true\n}\n",
            "dns: unknown attribute cache",
        ),
        (
            "dns {\n  mode = \"exit\"\n}\ndns {\n  mode = \"exit\"\n}\n",
            "config: duplicate block dns",
        ),
        (
            "dns \"main\" {\n}\n",
            "config: block dns must not have a label",
        ),
        // Resolvers: at least one, at most three, IPv4, never a loopback forwarder.
        (
            "dns {\n  mode = \"exit\"\n  local = []\n}\n",
            "dns: local must list 1..=3 resolvers",
        ),
        (
            "dns {\n  mode = \"exit\"\n  local = [\"1.1.1.1\", \"8.8.8.8\", \"9.9.9.9\", \"1.0.0.1\"]\n}\n",
            "dns: local must list 1..=3 resolvers",
        ),
        (
            "dns {\n  mode = \"exit\"\n  local = [\"77.88.8.8\", \"secret-value\"]\n}\n",
            "dns: local must list IPv4 WAN resolvers",
        ),
        (
            "dns {\n  mode = \"exit\"\n  local = [\"127.0.0.1\"]\n}\n",
            "dns: local must list IPv4 WAN resolvers",
        ),
        (
            "dns {\n  mode = \"exit\"\n  local = \"77.88.8.8\"\n}\n",
            "dns: attribute local must be a list of strings",
        ),
    ] {
        let error = dns(text).err().unwrap_or_default();
        assert!(error.contains(reason), "{text:?}: {error}");
    }
    // The rejected value itself never reaches the message.
    let error = dns("dns {\n  mode = \"exit\"\n  local = [\"77.88.8.8\", \"secret-value\"]\n}\n")
        .err()
        .unwrap();
    assert!(!error.contains("secret-value"));
    assert!(!error.contains("77.88.8.8"));
}
