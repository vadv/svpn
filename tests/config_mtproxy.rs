//! The `telegram_proxy` block of the config.

use std::path::{Path, PathBuf};

use svpn::config::parse;
use svpn::mtproxy::{Secret, Settings};

const MULTI: &str = r#"tunnel {
  peer_name = "svpn0"
}
server "a" {
  address = "vpn.example"
}
"#;
/// `ee`, the key 01 .. 10, and `www.example.com`.
const SECRET: &str = "ee0102030405060708090a0b0c0d0e0f107777772e6578616d706c652e636f6d";

/// A config directory with the secret in `name`.
fn base(name: &str, secret: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("svpn telegram proxy {}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let path = base.join(name);
    std::fs::write(&path, secret).unwrap();
    base
}

fn proxy(base: &Path, block: &str) -> Result<Option<Settings>, String> {
    let text = format!("{MULTI}telegram_proxy {{\n{block}}}\n");
    parse(&text, base, true)
        .map(|args| args.telegram_proxy)
        .map_err(|error| error.to_string())
}

// ── parsing ──

#[test]
fn without_the_block_the_proxy_is_off() {
    let base = Path::new("/config");
    assert!(parse(MULTI, base, true).unwrap().telegram_proxy.is_none());
    // An empty block says nothing: off, like every other block.
    assert_eq!(proxy(base, "").unwrap(), None);
}

#[test]
fn listen_and_a_secret_file_turn_it_on() {
    let base = base("telegram.secret", &format!(" {SECRET}\n"));
    let block = r#"  listen = "0.0.0.0:8081"
  secret_file = "telegram.secret"
"#;
    let settings = proxy(&base, block).unwrap().unwrap();
    assert_eq!(settings.listen.to_string(), "0.0.0.0:8081");
    assert_eq!(settings.secret, Secret::parse(SECRET).unwrap());
    // A relative path is the config directory's.
    let absolute = proxy(
        &base,
        &format!(
            "  listen = \"[::]:8081\"\n  secret_file = \"{}\"\n",
            base.join("telegram.secret").display()
        ),
    )
    .unwrap()
    .unwrap();
    assert_eq!(absolute.secret, settings.secret);
    assert_eq!(absolute.listen.to_string(), "[::]:8081");
}

#[test]
fn one_without_the_other_is_an_error() {
    let base = base("only.secret", SECRET);
    let error = proxy(&base, "  listen = \"0.0.0.0:8081\"\n").unwrap_err();
    assert_eq!(
        error,
        "telegram_proxy: listen and secret_file are both required"
    );
    let error = proxy(&base, "  secret_file = \"only.secret\"\n").unwrap_err();
    assert_eq!(
        error,
        "telegram_proxy: listen and secret_file are both required"
    );
}

// ── what is refused ──

#[test]
fn a_listen_address_that_is_not_one_is_an_error() {
    let base = base("address.secret", SECRET);
    for listen in ["8081", "0.0.0.0", "example.com:8081"] {
        let error = proxy(
            &base,
            &format!("  listen = \"{listen}\"\n  secret_file = \"address.secret\"\n"),
        )
        .unwrap_err();
        assert!(
            error.contains(&format!("telegram_proxy: invalid listen address {listen}")),
            "{error}"
        );
    }
}

#[test]
fn a_missing_secret_file_is_an_error_that_keeps_the_path() {
    let base = base("present.secret", SECRET);
    let error = proxy(
        &base,
        "  listen = \"0.0.0.0:8081\"\n  secret_file = \"missing.secret\"\n",
    )
    .unwrap_err();
    assert!(error.contains("telegram_proxy: read"), "{error}");
    assert!(error.contains("missing.secret"), "{error}");
}

#[test]
fn a_bad_secret_is_an_error_without_its_text() {
    let base = base(
        "bad.secret",
        "dd0102030405060708090a0b0c0d0e0f10 not hex at all",
    );
    let error = proxy(
        &base,
        "  listen = \"0.0.0.0:8081\"\n  secret_file = \"bad.secret\"\n",
    )
    .unwrap_err();
    assert!(error.contains("telegram_proxy: secret"), "{error}");
    assert!(!error.contains("not hex at all"), "{error}");
}

#[test]
fn unknown_attributes_are_refused() {
    let base = base("unknown.secret", SECRET);
    let error = proxy(
        &base,
        "  listen = \"0.0.0.0:8081\"\n  secret_file = \"unknown.secret\"\n  port = 443\n",
    )
    .unwrap_err();
    assert!(
        error.contains("telegram_proxy: unknown attribute port"),
        "{error}"
    );
}
