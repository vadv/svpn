//! Job scheduler pieces: reload primitive, degraded honesty, counters.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use svpn::hub::*;
use svpn::job::{JobStatus, Reload};
use svpn::link_io::Epoch;
use svpn::pool::Pool;
use svpn::server_spec::LinkParams;
use svpn::{geo, session, stats};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

/// Write a valid ASN table with a chosen row count (≥ the MIN_ROWS floor);
/// a different count is a genuinely different table for reload assertions.
fn write_geo_csv(path: &std::path::Path, asn_first: u32, rows: u32) {
    use std::fmt::Write as _;
    let mut text = String::new();
    for row in 0u32..rows {
        let start = row << 15;
        let end = start | 0x7fff;
        let _ = writeln!(
            text,
            "\"{}\",\"{}\",{}",
            Ipv4Addr::from(start),
            Ipv4Addr::from(end),
            asn_first + row % 7
        );
    }
    std::fs::write(path, text).unwrap();
}

fn jobs_hub(geo_path: Option<std::path::PathBuf>) -> Hub {
    let (events, incoming) = mpsc::channel(QUEUE);
    Hub {
        policy: svpn::cli::ExitPolicy::StickyAsn,
        links: vec![Link {
            params: LinkParams {
                label: "s0".to_owned(),
                server: "a.example".to_owned(),
                weight: 1,
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
                tun_addr: Ipv4Addr::new(10, 77, 0, 2),
                peer_addr: Ipv4Addr::new(10, 77, 0, 1),
                addr_auto: false,
                mtu: 1280,
                tun_name: None,
                server_up: None,
                server_down: None,
            },
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
        country: None,
        stickies: Vec::new(),
        sticky_via: Vec::new(),
        sticky_updates: None,
        sticky_task: None,
        job_events: None,
        job_task: None,
        job_stats: JobStats::default(),
        geo_path,
        country_path: None,
        geo_pending: Some("geo-update".to_owned()),
        country_pending: None,
        local: None,
        local_cleanup: None,
        nodes: vec![("a.example".to_owned(), 1)],
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

#[test]
fn reload_geo_loads_the_table_and_clears_pending() {
    let dir = std::env::temp_dir().join(format!("svpn-jobs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("asn.csv");
    write_geo_csv(&csv, 64512, 131072);
    let mut hub = jobs_hub(Some(csv.clone()));
    assert!(hub.geo.is_none());
    hub.reload_geo("geo-update");
    assert!(hub.geo.is_some(), "the table is live after reload");
    assert!(hub.job_stats.geo.loaded_at.is_some());
    assert!(hub.job_stats.geo.error.is_empty());
    assert_eq!(hub.geo_pending, None, "degraded state is over");
    assert_eq!(
        geo::Geo::load(&csv).unwrap().rows(),
        hub.geo.as_ref().unwrap().rows()
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reload_geo_failure_keeps_the_previous_table() {
    let dir = std::env::temp_dir().join(format!("svpn-jobs-keep-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("asn.csv");
    write_geo_csv(&csv, 64512, 131072);
    let mut hub = jobs_hub(Some(csv.clone()));
    hub.reload_geo("geo-update");
    assert!(hub.geo.is_some());
    // The job "replaced" the file with garbage; reload must keep the old table.
    std::fs::write(&csv, "not,a,table\n").unwrap();
    hub.reload_geo("geo-update");
    assert!(hub.geo.is_some(), "a broken file never unloads the table");
    assert!(hub.job_stats.geo.loaded_at.is_some());
    assert!(hub.job_stats.geo.error.contains("previous table retained"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_file_reload_keeps_pending_state() {
    let mut hub = jobs_hub(Some(std::path::PathBuf::from("/nonexistent/asn.csv")));
    hub.reload_geo("geo-update");
    assert!(hub.geo.is_none());
    assert_eq!(hub.geo_pending.as_deref(), Some("geo-update"));
}

#[test]
fn report_is_honest_about_degraded_state_and_counters() {
    let dir = std::env::temp_dir().join(format!("svpn-jobs-report-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("asn.csv");
    write_geo_csv(&csv, 64512, 131072);
    let mut hub = jobs_hub(Some(csv));
    let report = hub.stats_report(Duration::from_secs(1));
    assert!(report.contains("geo: missing (job geo-update)"), "{report}");
    hub.job_stats.runs = 3;
    hub.job_stats.failures = 1;
    hub.job_stats.timeouts = 1;
    let report = hub.stats_report(Duration::from_secs(1));
    assert!(
        report.contains("jobs: runs 3 / failures 1 / timeouts 1"),
        "{report}"
    );
    hub.reload_geo("geo-update");
    let report = hub.stats_report(Duration::from_secs(1));
    assert!(!report.contains("geo: missing"), "{report}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_and_timed_out_jobs_never_reload_the_table() {
    let dir = std::env::temp_dir().join(format!("svpn-jobs-fail-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Two genuinely different tables: the hub serves good.csv; the job
    // "installed" swapped.csv and then failed. A failed or timed-out job
    // must not swap the in-memory table; only a successful one may.
    let good = dir.join("good.csv");
    let swapped = dir.join("swapped.csv");
    write_geo_csv(&good, 64512, 131072);
    write_geo_csv(&swapped, 100, 100500);
    let mut hub = jobs_hub(Some(good.clone()));
    hub.reload_geo("geo-update");
    let before = hub.geo.as_ref().unwrap().rows();
    // Point the reload source at the swapped file: if the handler reloaded
    // on failure, rows() would change to the swapped table's count.
    hub.geo_path = Some(swapped.clone());
    for build in [
        || JobStatus::Failed("exit 1".to_owned()),
        || JobStatus::Timeout,
    ] {
        let status = build();
        hub.handle_job_event(svpn::hub::JobEvent::Finished {
            label: "geo-update".to_owned(),
            status: status.clone(),
            next_at: 0,
            reload: vec![Reload::Geo],
        });
        assert_eq!(
            hub.geo.as_ref().unwrap().rows(),
            before,
            "a {status:?} job must not reload"
        );
    }
    assert_eq!(hub.job_stats.runs, 2);
    assert_eq!(hub.job_stats.failures, 1);
    assert_eq!(hub.job_stats.timeouts, 1);
    // Success reloads from the same source — this must swap the table.
    hub.handle_job_event(svpn::hub::JobEvent::Finished {
        label: "geo-update".to_owned(),
        status: JobStatus::Ok,
        next_at: 0,
        reload: vec![Reload::Geo],
    });
    assert_ne!(
        hub.geo.as_ref().unwrap().rows(),
        before,
        "a successful job must reload the swapped table"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
