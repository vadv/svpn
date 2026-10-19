//! Hub: TCP reset synthesis, weighted reassignment, stats reports, bootstrap.

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use common::tcp_packet;
use svpn::control::Stats;
use svpn::hooks::Hooks;
use svpn::hub::*;
use svpn::link_io::{Epoch, Event};
use svpn::pool::Pool;
use svpn::server_spec::LinkParams;
use svpn::{packet, session, stats};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

fn link_params(server: Ipv4Addr) -> LinkParams {
    LinkParams {
        server: server.to_string(),
        weight: 1,
        identity: None,
        user: None,
        ssh_port: 22,
        host_key: None,
        remote_bin: "svpn".to_string(),
        peer_tun_name: "tun0".to_string(),
        log_level: svpn::logging::Level::Info,
        udp_port_range: (0, 0),
        mimic: Vec::new(),
        tcp_port: None,
        tun_addr: Ipv4Addr::new(10, 77, 0, 2),
        peer_addr: Ipv4Addr::new(10, 77, 0, 1),
        mtu: 1280,
        tun_name: None,
    }
}

fn test_hub(servers: [Ipv4Addr; 2]) -> Hub {
    let (events, incoming) = mpsc::channel(QUEUE);
    Hub {
        links: servers
            .into_iter()
            .enumerate()
            .map(|(link, server)| Link {
                params: link_params(server),
                outgoing: None,
                delivery: Arc::default(),
                epoch: Some(Epoch {
                    link,
                    generation: 1,
                }),
                latest: None,
                stats: stats::Snapshot::default(),
            })
            .collect(),
        pool: Pool::new([1, 1]),
        tasks: JoinSet::new(),
        events,
        incoming,
        routes: Routes::default(),
        tombstones: session::Tombstones::default(),
    }
}

// ── dispatch and ownership ──

#[tokio::test]
async fn closed_tcp_without_owner_gets_reset_but_live_owner_is_preserved() {
    let mut hub = test_hub([
        Ipv4Addr::new(203, 0, 113, 10),
        Ipv4Addr::new(198, 51, 100, 7),
    ]);
    let client_ip = Ipv4Addr::new(10, 77, 0, 2);
    let mut bytes = common::udp_packet(false);
    bytes.resize(40, 0);
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[9] = 6;
    bytes[32] = 0x50;
    bytes[33] = 0x10;
    let parsed = packet::parse(&bytes, true).unwrap();
    assert_eq!(
        hub.dispatch(&bytes, client_ip).unwrap(),
        packet::tcp_reset_for(&parsed),
        "resumed TCP traffic must not disappear after its owner is forgotten"
    );
    bytes[33] = 4;
    assert!(hub.dispatch(&bytes, client_ip).unwrap().is_none());
    bytes[33] = 2;
    assert!(hub.dispatch(&bytes, client_ip).unwrap().is_none());
    bytes[33] = 0x10;
    bytes[12] = 192;
    assert!(hub.dispatch(&bytes, client_ip).unwrap().is_none());
    bytes[12] = 10;
    assert!(hub.dispatch(&[0; 20], client_ip).unwrap().is_none());

    let epoch = Epoch {
        link: 0,
        generation: 1,
    };
    hub.pool.ready(epoch, Instant::now());
    let (outgoing, mut incoming) = mpsc::channel(2);
    hub.links[0].outgoing = Some(outgoing);
    hub.routes
        .by_key
        .insert(parsed.flow, Owner { epoch, id: 41 });
    assert!(hub.dispatch(&bytes, client_ip).unwrap().is_none());
    let forwarded = incoming.try_recv().unwrap();
    assert_eq!(forwarded.id, 41);
    assert_eq!(forwarded.bytes, bytes);
    // A non-serving owner is still owned, not permission to synthesize a reset.
    hub.routes
        .by_key
        .get_mut(&parsed.flow)
        .unwrap()
        .epoch
        .generation = 2;
    assert!(hub.dispatch(&bytes, client_ip).unwrap().is_none());
    assert!(incoming.try_recv().is_err());
    assert_eq!(hub.routes.by_key[&parsed.flow].id, 41);
}

#[tokio::test]
async fn retired_tcp_is_not_reassigned_between_ready_servers() {
    let mut hub = test_hub([
        Ipv4Addr::new(203, 0, 113, 10),
        Ipv4Addr::new(198, 51, 100, 7),
    ]);
    let first = hub.links[0].epoch.unwrap();
    let second = hub.links[1].epoch.unwrap();
    for epoch in [first, second] {
        assert!(hub.pool.ready(epoch, Instant::now()));
    }
    let (outgoing, mut from_first) = mpsc::channel(2);
    hub.links[0].outgoing = Some(outgoing);
    let (outgoing, mut from_second) = mpsc::channel(2);
    hub.links[1].outgoing = Some(outgoing);
    let params = hub.links[0].params.clone();
    let client_ip = params.tun_addr;
    let syn = tcp_packet(false);
    let key = packet::parse(&syn, true).unwrap().flow;
    assert!(hub.dispatch(&syn, client_ip).unwrap().is_none());
    let original = from_first.try_recv().unwrap();
    let owner = Owner {
        epoch: first,
        id: original.id,
    };
    assert_eq!(hub.routes.by_key[&key], owner);
    assert!(from_second.try_recv().is_err());

    let mut ack = syn.clone();
    ack[33] = 0x10;
    assert!(hub.dispatch(&ack, client_ip).unwrap().is_none());
    assert_eq!(from_first.try_recv().unwrap().id, owner.id);
    assert!(from_second.try_recv().is_err());

    let mut tun = None;
    let mut started = None;
    let mut hooks = Hooks::default();
    hub.handle_event(
        first,
        Event::Closed { id: owner.id, key },
        &mut tun,
        &params,
        &mut started,
        &mut hooks,
    )
    .await
    .unwrap();
    let expected = packet::tcp_reset_for(&packet::parse(&ack, true).unwrap());
    assert!(expected.is_some());
    for _ in 0..3 {
        assert_eq!(hub.dispatch(&ack, client_ip).unwrap(), expected);
    }
    assert!(hub.routes.by_key.is_empty());
    assert!(from_first.try_recv().is_err());
    assert!(from_second.try_recv().is_err());
    assert_eq!(hub.pool.ready_count(), 2);
    assert!(tun.is_none());

    // The rejected ACKs must not consume a weighted selection or a flow ID.
    assert!(hub.dispatch(&syn, client_ip).unwrap().is_none());
    let fresh = from_second.try_recv().unwrap();
    assert_eq!(fresh.id, owner.id + 1);
    assert_eq!(fresh.bytes, syn);
    assert!(from_first.try_recv().is_err());
    let fresh_owner = Owner {
        epoch: second,
        id: fresh.id,
    };
    assert_eq!(hub.routes.by_key[&key], fresh_owner);
    hub.handle_event(
        first,
        Event::Closed { id: owner.id, key },
        &mut tun,
        &params,
        &mut started,
        &mut hooks,
    )
    .await
    .unwrap();
    assert_eq!(hub.routes.by_key[&key], fresh_owner);
}

// ── stats reports ──

#[tokio::test]
async fn reports_cover_pool_single_server_and_unseen_links() {
    let mut hub = test_hub([
        Ipv4Addr::new(203, 0, 113, 10),
        Ipv4Addr::new(198, 51, 100, 7),
    ]);
    let epoch = Epoch {
        link: 0,
        generation: 1,
    };
    hub.pool.ready(epoch, Instant::now());
    hub.links[0].stats.observe(Stats {
        inner_rx_packets: 11,
        inner_rx_bytes: 12_000_000,
        inner_tx_packets: 7,
        active_flows: 3,
        ..Stats::default()
    });
    let output = hub.stats_report(Duration::from_secs(30));
    assert!(output.contains("servers ready 1/2"));
    assert!(output.contains("all servers | RX     3.20 Mbit/s"));
    assert!(output.contains("[203.0.113.10] ready | RX     3.20 Mbit/s"));
    assert!(output.contains("[198.51.100.7] connecting | RX     0.00 Mbit/s"));
    assert!(output.contains("flows 3 active"));
    hub.pool
        .failed(
            Epoch {
                link: 1,
                generation: 1,
            },
            Instant::now(),
        )
        .unwrap();
    assert!(
        hub.stats_report(Duration::from_secs(30))
            .contains("[198.51.100.7] backoff")
    );
    hub.links.truncate(1);
    let output = hub.stats_report(Duration::from_secs(30));
    assert!(output.contains("servers ready 1/1"));
    assert!(!output.contains("all servers"));
    assert!(output.contains("[203.0.113.10] ready | RX     0.00 Mbit/s"));
}

#[tokio::test]
async fn snapshots_are_isolated_between_generations() {
    let mut hub = test_hub([Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)]);
    let (old, latest) = watch::channel(Stats {
        inner_rx_bytes: 100,
        ..Stats::default()
    });
    hub.links[0].latest = Some(latest);
    hub.stats_report(Duration::from_secs(30));
    hub.links[0].stats.reset();
    let (_, latest) = watch::channel(Stats {
        inner_rx_bytes: 20,
        ..Stats::default()
    });
    hub.links[0].latest = Some(latest);
    old.send_replace(Stats {
        inner_rx_bytes: 1000,
        ..Stats::default()
    });
    hub.stats_report(Duration::from_secs(30));
    let (_, total) = hub.links[0].stats.sample();
    assert_eq!(total.inner_rx_bytes, 120);
}

#[tokio::test]
async fn startup_failure_is_not_reported_as_connecting() {
    let mut hub = test_hub([Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)]);
    let epoch = hub.links[0].epoch.take().unwrap();
    hub.pool.failed(epoch, Instant::now()).unwrap();
    let report = hub.stats_report(Duration::from_secs(1));
    assert!(report.contains("[127.0.0.1] failed"));
    assert!(report.contains("[127.0.0.2] connecting"));
}

#[tokio::test(start_paused = true)]
async fn report_timer_waits_a_full_period_and_does_not_catch_up_in_bursts() {
    assert!(report_timer(0).is_none());
    let start = Instant::now();
    let mut timer = report_timer(30).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(29), timer.tick())
            .await
            .is_err()
    );
    timer.tick().await;
    assert_eq!(Instant::now() - start, Duration::from_secs(30));
    tokio::time::advance(Duration::from_secs(100)).await;
    timer.tick().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(29), timer.tick())
            .await
            .is_err()
    );
    timer.tick().await;
    assert_eq!(Instant::now() - start, Duration::from_secs(160));
}

// ── bootstrap ──

#[tokio::test]
async fn parallel_bootstrap_failures_exit_without_creating_a_tun() {
    let cli = svpn::Cli::try_parse_from([
        "svpn",
        "multi",
        "--ssh-user",
        "root",
        "--server",
        "203.0.113.1,peer-tun=test0",
    ])
    .unwrap();
    let svpn::Mode::Client(svpn::cli::ClientArgs {
        server, globals, ..
    }) = cli.command
    else {
        unreachable!()
    };
    let mut params = svpn::server_spec::resolve_servers(&server, &globals)
        .unwrap()
        .remove(0);
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    params.server = Ipv4Addr::LOCALHOST.to_string();
    params.ssh_port = listener.local_addr().unwrap().port();
    let peer = async {
        // Do not close the first connection until both attempts have started.
        let first = listener.accept().await.unwrap();
        let second = listener.accept().await.unwrap();
        drop((first, second));
    };
    let test = async {
        let (_stop, shutdown) = watch::channel(false);
        let (result, ()) = tokio::join!(
            run(
                vec![params.clone(), params],
                None,
                0,
                Hooks::default(),
                shutdown
            ),
            peer
        );
        assert_eq!(result.unwrap_err().to_string(), "vpn: no server available");
    };
    tokio::time::timeout(Duration::from_secs(10), test)
        .await
        .unwrap();
}
