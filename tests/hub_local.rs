//! Hub local-exit admission and reporting without privileged TUN fixtures.

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;

use svpn::geo::Geo;
use svpn::hub::*;
use svpn::link_io::Epoch;
use svpn::pool::Pool;
use svpn::server_spec::LinkParams;
use svpn::{session, stats};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
const RU_DEST: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const BY_DEST: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 35);

fn params() -> LinkParams {
    LinkParams {
        server: "server".to_owned(),
        weight: 1,
        countries: Vec::new(),
        identity: None,
        user: None,
        ssh_port: 22,
        host_key: None,
        remote_bin: "svpn".to_owned(),
        peer_tun_name: None,
        log_level: svpn::logging::Level::Info,
        udp_port_range: (0, 0),
        mimic: Vec::new(),
        remeasure_interval: None,
        tcp_port: None,
        tun_addr: CLIENT,
        peer_addr: Ipv4Addr::new(10, 77, 0, 1),
        addr_auto: false,
        mtu: 1280,
        tun_name: None,
        server_up: None,
        server_down: None,
    }
}

fn local_hub() -> Hub {
    let (events, incoming) = mpsc::channel(QUEUE);
    Hub {
        links: vec![Link {
            params: params(),
            outgoing: None,
            delivery: Arc::default(),
            epoch: Some(Epoch {
                link: 0,
                generation: 1,
            }),
            latest: None,
            stats: stats::Snapshot::default(),
            last_reason: String::new(),
            assigned: Arc::default(),
        }],
        pool: Pool::new([1]),
        geo: None,
        country: Some(Geo::from_ranges(vec![
            (
                RU_DEST.into(),
                RU_DEST.into(),
                svpn::geo::pack_country("RU").unwrap(),
            ),
            (
                BY_DEST.into(),
                BY_DEST.into(),
                svpn::geo::pack_country("BY").unwrap(),
            ),
        ])),
        local_exits: vec![
            svpn::geo::pack_country("RU").unwrap(),
            svpn::geo::pack_country("BY").unwrap(),
        ],
        local: None,
        local_task: None,
        nodes: Vec::new(),
        exit_owners: Default::default(),
        exit_state: None,
        sticky: StickyStats::default(),
        local_stats: LocalStats::default(),
        grace_until: None,
        tasks: JoinSet::new(),
        events,
        incoming,
        routes: Routes::default(),
        tombstones: session::Tombstones::default(),
        pair: watch::channel(None).0,
    }
}

fn packet_to(destination: Ipv4Addr) -> Vec<u8> {
    let mut bytes = common::tcp_packet(false);
    bytes[16..20].copy_from_slice(&destination.octets());
    bytes
}

#[tokio::test]
async fn local_exit_without_server_never_falls_back() {
    let mut hub = local_hub();
    let result = hub.dispatch(&packet_to(RU_DEST), CLIENT).unwrap();
    assert_eq!(result, None);
    assert!(hub.routes.by_key.is_empty());
    assert_eq!(hub.local_stats.failed, 1);
}

#[tokio::test]
async fn every_local_exit_country_uses_local_path() {
    let mut hub = local_hub();
    for destination in [RU_DEST, BY_DEST] {
        let result = hub.dispatch(&packet_to(destination), CLIENT).unwrap();
        assert!(result.is_none());
    }
    assert_eq!(hub.local_stats.failed, 2);
}

#[test]
fn report_calls_the_path_local_exit() {
    let mut hub = local_hub();
    let report = hub.stats_report(std::time::Duration::from_secs(1));
    assert!(report.contains("local-exit: opened 0 / failed 0 / closed 0"));
    assert!(!report.contains("direct:"));
}
