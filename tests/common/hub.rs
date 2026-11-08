//! Shared hub fixture for dashboard tests.

use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use svpn::{
    cli::ExitPolicy,
    hub::{Hub, JobStats, Link, Routes, StickyStats},
    link_io::Epoch,
    pool::Pool,
    session,
};
use tokio::sync::{mpsc, watch};

/// Two servers: the first is ready, the second has no epoch yet.
#[allow(dead_code)] // unused by some of the including test targets
pub fn dashboard_hub() -> Hub {
    let servers = [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)];
    let (events, incoming) = mpsc::channel(8);
    let mut pool = Pool::new([1, 1]);
    pool.ready(
        Epoch {
            link: 0,
            generation: 1,
        },
        tokio::time::Instant::now(),
    );
    // The live counters of the first session: the hub accumulates them once
    // per stats report, the dashboard adds the unreported delta. The sender
    // is dropped on purpose: the receiver keeps the last value.
    let (_, latest) = watch::channel(svpn::control::Stats {
        inner_rx_bytes: 4242,
        inner_rx_packets: 7,
        active_flows: 3,
        ..Default::default()
    });
    Hub {
        links: servers
            .iter()
            .enumerate()
            .map(|(link, &server)| Link {
                params: super::link_params(server, 1),
                outgoing: None,
                delivery: Arc::default(),
                epoch: (link == 0).then_some(Epoch {
                    link,
                    generation: 1,
                }),
                latest: (link == 0).then(|| latest.clone()),
                stats: svpn::stats::Snapshot::default(),
                last_reason: String::new(),
                assigned: Arc::default(),
            })
            .collect(),
        pool,
        geo: None,
        country: None,
        stickies: Vec::new(),
        sticky_via: Vec::new(),
        sticky_updates: None,
        sticky_task: None,
        job_events: None,
        job_task: None,
        job_stats: JobStats::default(),
        geo_path: None,
        country_path: None,
        geo_pending: None,
        country_pending: None,
        local: None,
        local_cleanup: None,
        nodes: servers
            .iter()
            .map(|server| (server.to_string(), 1))
            .collect(),
        policy: ExitPolicy::Balance,
        exit_owners: HashMap::new(),
        exit_state: None,
        sticky: StickyStats::default(),
        local_stats: Default::default(),
        grace_until: None,
        tasks: tokio::task::JoinSet::new(),
        events,
        incoming,
        routes: Routes::default(),
        tombstones: session::Tombstones::default(),
        pair: watch::channel(None).0,
    }
}
