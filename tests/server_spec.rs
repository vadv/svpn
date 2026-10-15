use std::net::Ipv4Addr;
use std::path::PathBuf;

use svpn::MimicArg;
use svpn::logging;
use svpn::server_spec::*;

const PIN: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn local_tun_names_follow_the_client_platform() {
    for name in ["svpn0", "utun9", "a-b"] {
        assert!(validate_local_tun_name(name, false).is_ok());
    }
    for name in ["utun0", "utun9", "utun4294967294"] {
        assert!(validate_local_tun_name(name, true).is_ok());
    }
    for name in [
        "",
        "svpn0",
        "utun",
        "utun-1",
        "utun4294967295",
        "utun999999999999",
    ] {
        assert!(validate_local_tun_name(name, true).is_err(), "{name}");
    }
}

fn globals() -> Globals {
    let cli = svpn::Cli::try_parse_from([
        "svpn",
        "multi",
        "--server",
        "203.0.113.10",
        "--peer-tun-name",
        "svpn0",
    ])
    .unwrap();
    let svpn::Mode::Client(svpn::cli::ClientArgs { globals, .. }) = cli.command else {
        unreachable!()
    };
    globals
}

#[test]
fn parses_hosts_ports_and_numeric_boundaries() {
    let globals = globals();
    for (value, port, weight, tcp) in [
        ("203.0.113.10", 22, 1, None),
        ("203.0.113.10:1,weight=1,tcp-port=0", 1, 1, Some(0)),
        (
            "203.0.113.10:65535,weight=4294967295,tcp-port=65535",
            65535,
            u32::MAX,
            Some(65535),
        ),
    ] {
        let params = value
            .parse::<ServerSpec>()
            .unwrap()
            .resolve(&globals)
            .unwrap();
        assert_eq!(params.server, "203.0.113.10");
        assert_eq!(
            (params.ssh_port, params.weight, params.tcp_port),
            (port, weight, tcp)
        );
    }
    for value in [
        "",
        "::1",
        "[::1]:22",
        "203.0.113.256",
        "203.0.113.10:",
        "203.0.113.10:0",
        "203.0.113.10:65536",
        "203.0.113.10:abc",
        "203.0.113.10:22:23",
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
    ] {
        assert!(value.parse::<ServerSpec>().is_err(), "{value}");
    }
}

#[test]
fn hostnames_are_validated_and_normalized_without_dns() {
    let globals = globals();
    for (value, host, port) in [
        ("VPN.Example.invalid", "vpn.example.invalid", 22),
        ("vpn.example.invalid.:2222", "vpn.example.invalid.", 2222),
        ("localhost", "localhost", 22),
    ] {
        let params = value
            .parse::<ServerSpec>()
            .unwrap()
            .resolve(&globals)
            .unwrap();
        assert_eq!(params.server, host);
        assert_eq!(params.ssh_port, port);
    }
    for value in [
        "bad host",
        "vpn/name",
        "a..b",
        ".host",
        "host..",
        "-host",
        "host-",
        "host_name",
        "@host",
        "https://host",
        "хост.test",
        "123",
    ] {
        assert!(value.parse::<ServerSpec>().is_err(), "{value}");
    }
    assert!(
        format!("{}.test", "a".repeat(64))
            .parse::<ServerSpec>()
            .is_err()
    );
    let label = "a".repeat(63);
    assert!(
        format!("{label}.{label}.{label}.{label}")
            .parse::<ServerSpec>()
            .is_err()
    );
    let hosts = ["VPN.Example.invalid", "vpn.example.invalid:2222"]
        .map(|s| s.parse::<ServerSpec>().unwrap());
    assert!(
        resolve_servers(&hosts, &globals)
            .unwrap_err()
            .to_string()
            .contains("duplicate server host")
    );
}

#[tokio::test]
async fn ipv4_literals_do_not_require_dns() {
    assert_eq!(
        resolve_ipv4("203.0.113.10").await.unwrap(),
        Ipv4Addr::new(203, 0, 113, 10)
    );
}

#[test]
fn rejects_invalid_keys_values_and_separators() {
    for suffix in [
        "",
        "user",
        "=root",
        "wieght=2",
        "weight=0",
        "weight=-1",
        "weight=4294967296",
        "mimic=auto",
        "mimic=QUIC",
        "mimic=quic+",
        "mimic=+quic",
        "mimic=quic++mosh",
        "mimic=quic,mosh",
        "hostkey=garbage",
        "hostkey=SHA256:abc",
        "hostkey=MD5:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
        "peer-addr=::1",
        "peer-addr=hostname",
        "udp-ports=0-1",
        "udp-ports=1-0",
        "udp-ports=2-1",
        "udp-ports=1",
        "udp-ports=1-65536",
        "udp-ports=1-2-3",
        "tcp-port=-1",
        "tcp-port=65536",
        "tun-addr=10.0.0.1",
        "mtu=1280",
        "tun-name=tun0",
        "log-level=debug",
        "user=root,",
    ] {
        let value = format!("203.0.113.10,{suffix}");
        let error = value.parse::<ServerSpec>().unwrap_err().to_string();
        assert!(error.contains("--server (203.0.113.10)"), "{error}");
    }
    for (key, value) in [
        ("weight", "1"),
        ("user", "root"),
        ("identity", "/key"),
        ("hostkey", PIN),
        ("mimic", "quic"),
        ("remote-bin", "/svpn"),
        ("peer-tun", "tun0"),
        ("peer-addr", "10.1.0.1"),
        ("udp-ports", "1-65535"),
        ("tcp-port", "0"),
    ] {
        let empty = format!("203.0.113.10,{key}=");
        assert!(
            empty
                .parse::<ServerSpec>()
                .unwrap_err()
                .to_string()
                .contains("empty value")
        );
        let repeated = format!("203.0.113.10,{key}={value},{key}={value}");
        assert!(
            repeated
                .parse::<ServerSpec>()
                .unwrap_err()
                .to_string()
                .contains("repeated key")
        );
    }
}

#[test]
fn resolves_defaults_and_keeps_owned_retry_configuration() {
    let params = {
        let globals = globals();
        let spec: ServerSpec = "203.0.113.10".parse().unwrap();
        spec.resolve(&globals).unwrap()
    };
    let retry = params.clone();
    drop(params);
    assert_eq!(retry.weight, 1);
    assert_eq!(retry.ssh_port, 22);
    assert!(retry.identity.is_none());
    assert!(retry.user.is_none());
    assert!(retry.host_key.is_none());
    assert_eq!(retry.remote_bin, "/usr/local/bin/svpn");
    assert_eq!(retry.peer_tun_name, "svpn0");
    assert_eq!(retry.tun_addr, Ipv4Addr::new(10, 77, 0, 2));
    assert_eq!(retry.peer_addr, Ipv4Addr::new(10, 77, 0, 1));
    assert_eq!(retry.mtu, 1280);
    assert!(retry.tun_name.is_none());
    assert_eq!(retry.log_level, logging::Level::Info);
    assert_eq!(retry.udp_port_range, (60000, 60009));
    assert!(retry.mimic.is_empty());
    assert!(retry.tcp_port.is_none());
}

#[test]
fn per_server_values_override_all_link_defaults() {
    let mut globals = globals();
    globals.ssh_user = Some("global".into());
    globals.ssh_identity = Some("/global-key".into());
    globals.ssh_host_key = Some("invalid but overridden".into());
    globals.mimic = vec![MimicArg::Banner];
    globals.tcp_port = Some(41000);
    globals.tun_name = Some("utun9".into());
    globals.log_level = logging::Level::Debug;
    let value = format!(
        "198.51.100.7:2222,weight=3,user=override,identity=/key with space,hostkey={PIN},mimic=quic+mosh,remote-bin=/opt/svpn=dev,peer-tun=peer1,peer-addr=10.88.0.1,udp-ports=1-65535,tcp-port=0"
    );
    let params = value
        .parse::<ServerSpec>()
        .unwrap()
        .resolve(&globals)
        .unwrap();
    assert_eq!(params.server, "198.51.100.7");
    assert_eq!(params.weight, 3);
    assert_eq!(params.ssh_port, 2222);
    assert_eq!(params.user.as_deref(), Some("override"));
    assert_eq!(params.identity, Some(PathBuf::from("/key with space")));
    assert_eq!(params.host_key, Some(PIN.parse().unwrap()));
    assert_eq!(params.remote_bin, "/opt/svpn=dev");
    assert_eq!(params.peer_tun_name, "peer1");
    assert_eq!(params.peer_addr, Ipv4Addr::new(10, 88, 0, 1));
    assert_eq!(params.udp_port_range, (1, 65535));
    assert_eq!(params.tcp_port, Some(0));
    assert_eq!(params.mimic, [MimicArg::Quic, MimicArg::Mosh]);
    assert_eq!(params.tun_name.as_deref(), Some("utun9"));
    assert_eq!(params.log_level, logging::Level::Debug);
}

#[test]
fn validates_merged_configuration_before_bootstrap() {
    let mut globals = globals();
    for suffix in [
        "peer-addr=10.77.0.2",
        "peer-addr=0.0.0.0",
        "peer-addr=224.0.0.1",
        "peer-tun=too-long-tun-name",
        "peer-tun=bad/name",
        "peer-tun=bad name",
        "mimic=ssh",
        "mimic=ssh+banner,tcp-port=0",
    ] {
        let spec: ServerSpec = format!("203.0.113.10,{suffix}").parse().unwrap();
        assert!(spec.resolve(&globals).is_err(), "{suffix}");
    }
    let spec: ServerSpec = "203.0.113.10".parse().unwrap();
    globals.peer_tun_name = None;
    assert!(spec.resolve(&globals).is_err());
    assert!(
        "203.0.113.10,peer-tun=tun0"
            .parse::<ServerSpec>()
            .unwrap()
            .resolve(&globals)
            .is_ok()
    );
    globals.peer_tun_name = Some(String::new());
    assert_eq!(spec.resolve(&globals).unwrap().peer_tun_name, "");
    globals.mtu = 575;
    assert!(spec.resolve(&globals).is_err());
    globals.mtu = 1401;
    assert!(spec.resolve(&globals).is_err());
    globals.mtu = 1280;
    globals.tun_name = Some("bad/name".into());
    assert!(spec.resolve(&globals).is_err());
    globals.tun_name = None;
    globals.ssh_host_key = Some("invalid".into());
    assert!(spec.resolve(&globals).is_err());
}

#[test]
fn resolves_whole_pool_and_reports_server_index() {
    let mut globals = globals();
    let specs: Vec<ServerSpec> = ["203.0.113.10", "198.51.100.7,weight=2"]
        .map(|s| s.parse().unwrap())
        .into();
    let params = resolve_servers(&specs, &globals).unwrap();
    assert_eq!(params.len(), 2);
    assert_eq!(params[1].weight, 2);
    assert_eq!(params[0].peer_addr, params[1].peer_addr);
    assert!(resolve_servers(&[], &globals).is_err());
    let duplicate = [specs[0].clone(), "203.0.113.10:2222".parse().unwrap()];
    let error = resolve_servers(&duplicate, &globals)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "servers[1] (203.0.113.10): duplicate server host");
    let invalid = [
        specs[0].clone(),
        "198.51.100.7,peer-tun=bad/name".parse().unwrap(),
    ];
    let error = format!("{:#}", resolve_servers(&invalid, &globals).unwrap_err());
    assert!(error.contains("servers[1] (198.51.100.7)"));
    assert!(error.contains("TUN name"));
    globals.ssh_host_key = Some(PIN.into());
    assert!(resolve_servers(&specs[..1], &globals).is_ok());
    assert!(resolve_servers(&specs, &globals).is_err());
    let pinned = [
        format!("203.0.113.10,hostkey={PIN}"),
        format!("198.51.100.7,hostkey={PIN}"),
    ]
    .map(|s| s.parse().unwrap());
    assert!(resolve_servers(&pinned, &globals).is_err());
    globals.ssh_host_key = None;
    assert!(resolve_servers(&pinned, &globals).is_ok());
}

#[test]
fn perf_requires_one_effective_mimic_and_rejects_weight() {
    let mut globals = globals();
    for value in [
        "203.0.113.10",
        "203.0.113.10,mimic=quic+mosh",
        "203.0.113.10,mimic=quic+quic",
        "203.0.113.10,mimic=mosh,weight=1",
    ] {
        assert!(
            resolve_perf(&value.parse().unwrap(), &globals).is_err(),
            "{value}"
        );
    }
    for mimic in ["quic", "webrtc", "obfs", "mosh", "ssh", "banner", "none"] {
        let value = format!("203.0.113.10,mimic={mimic},tcp-port=0");
        assert!(
            resolve_perf(&value.parse().unwrap(), &globals).is_ok(),
            "{value}"
        );
    }
    let spec = "203.0.113.10".parse().unwrap();
    globals.mimic = vec![MimicArg::Mosh];
    assert!(resolve_perf(&spec, &globals).is_ok());
    let override_spec = "203.0.113.10,mimic=quic".parse().unwrap();
    assert_eq!(
        resolve_perf(&override_spec, &globals).unwrap().mimic,
        [MimicArg::Quic]
    );
    globals.mimic.push(MimicArg::Quic);
    assert!(resolve_perf(&spec, &globals).is_err());
    assert_eq!(
        resolve_perf(&override_spec, &globals).unwrap().mimic,
        [MimicArg::Quic]
    );
}
