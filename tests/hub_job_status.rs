//! Dashboard job progress: scheduling, skips, failures, reload status and privacy.

mod common;

use std::time::Duration;

use svpn::{
    hub::{JobContext, JobEvent, JobStats, jobs},
    job::{JobSpec, JobStatus, Reload},
    web,
};
use tokio::sync::watch;

// ── job and database status ──

#[test]
fn progress_has_initial_schedule_and_tracks_success_separately() {
    let mut hub = common::hub::dashboard_hub();
    let spec = spec("update");
    hub.job_stats = JobStats::new(&[spec], true, false);
    let initial = &hub.job_stats.details[0];
    assert_eq!(initial.state, "waiting");
    assert!(initial.next_at.is_some());
    assert!(hub.job_stats.geo.loaded_at.is_some());
    assert!(hub.job_stats.country.loaded_at.is_none());
    hub.handle_job_event(JobEvent::Started {
        label: "update".into(),
    });
    assert_eq!(hub.job_stats.details[0].state, "running");
    assert!(hub.job_stats.details[0].started_at.is_some());
    assert_eq!(hub.job_stats.details[0].next_at, None);
    hub.handle_job_event(finished(JobStatus::Ok, Vec::new()));
    let success = hub.job_stats.details[0].success_at;
    assert!(success.is_some());
    hub.handle_job_event(finished(
        JobStatus::Failed("exit status: 7".into()),
        vec![Reload::Country],
    ));
    let job = &hub.job_stats.details[0];
    assert_eq!(job.state, "failed");
    assert_eq!(job.success_at, success);
    assert_eq!(job.next_at, Some(1234));
    assert_eq!(job.reason, "exit status: 7");
    assert!(hub.job_stats.country.attempted_at.is_some());
    assert!(
        hub.job_stats
            .country
            .error
            .contains("previous table retained")
    );
    assert_eq!(
        (
            hub.job_stats.runs,
            hub.job_stats.failures,
            hub.job_stats.timeouts
        ),
        (2, 1, 0)
    );
}

#[test]
fn timeout_and_skip_are_distinct_and_skip_does_not_count_as_a_run() {
    let mut hub = common::hub::dashboard_hub();
    hub.job_stats = JobStats::new(&[spec("update")], false, false);
    hub.handle_job_event(finished(JobStatus::Timeout, vec![Reload::Geo]));
    assert_eq!(hub.job_stats.details[0].state, "timeout");
    assert_eq!(hub.job_stats.timeouts, 1);
    assert!(hub.job_stats.geo.error.contains("timed out"));
    hub.handle_job_event(JobEvent::Skipped {
        label: "update".into(),
        next_at: 4567,
        reason: "No update needed".into(),
    });
    assert_eq!(hub.job_stats.details[0].state, "skipped");
    assert_eq!(hub.job_stats.details[0].next_at, Some(4567));
    assert_eq!(hub.job_stats.runs, 1);
    assert_eq!(hub.job_stats.details[0].success_at, None);
}

#[test]
fn successful_script_with_broken_reload_is_not_a_successful_update() {
    let mut hub = common::hub::dashboard_hub();
    hub.geo_path = Some("/nonexistent/private-asn.csv".into());
    hub.country_path = Some("/nonexistent/private-country.csv".into());
    hub.geo_pending = Some("update".into());
    hub.job_stats = JobStats::new(&[spec("update")], false, false);
    hub.handle_job_event(finished(JobStatus::Ok, vec![Reload::Geo, Reload::Country]));
    assert_eq!(hub.job_stats.details[0].state, "reload_failed");
    assert_eq!(hub.job_stats.details[0].success_at, None);
    assert_eq!(hub.geo_pending.as_deref(), Some("update"));
    assert!(hub.job_stats.geo.attempted_at.is_some());
    assert!(
        hub.job_stats.country.attempted_at.is_some(),
        "every requested table is attempted"
    );
    let json = serde_json::to_string(&web::snapshot(&hub)).unwrap();
    assert!(!json.contains("private-asn.csv"));
    assert!(!json.contains("private-country.csv"));
    assert!(!json.contains("secret-payload"));
    assert!(json.contains("reload_failed"));
}

// ── scheduler events ──

#[tokio::test]
async fn scheduler_reports_run_if_skip_without_exposing_output_or_running_payload() {
    let mut spec = spec("update");
    spec.run_if = Some("printf secret-gate; exit 1".into());
    spec.run = "exit 99".into();
    let context = JobContext {
        specs: vec![spec],
        ..Default::default()
    };
    let (shutdown, mut stop) = watch::channel(false);
    let (events, task) = jobs::spawn_scheduler(&context, &mut stop);
    let mut events = events.unwrap();
    let task = task.unwrap();
    assert!(matches!(
        events.recv().await.unwrap(),
        JobEvent::Started { .. }
    ));
    let event = tokio::time::timeout(Duration::from_secs(3), events.recv())
        .await
        .unwrap()
        .unwrap();
    match event {
        JobEvent::Skipped {
            next_at, reason, ..
        } => {
            assert!(next_at > 0);
            assert!(!reason.contains("secret-gate"));
        }
        _ => panic!("expected a run_if skip"),
    }
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn scheduler_reports_completion_without_script_output() {
    let context = JobContext {
        specs: vec![spec("update")],
        ..Default::default()
    };
    let (shutdown, mut stop) = watch::channel(false);
    let (events, task) = jobs::spawn_scheduler(&context, &mut stop);
    let mut events = events.unwrap();
    assert!(matches!(
        events.recv().await.unwrap(),
        JobEvent::Started { .. }
    ));
    let event = tokio::time::timeout(Duration::from_secs(3), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        event,
        JobEvent::Finished {
            status: JobStatus::Ok,
            ..
        }
    ));
    shutdown.send(true).unwrap();
    task.unwrap().await.unwrap();
}

#[tokio::test]
async fn scheduler_reports_run_if_timeout_as_a_failed_update() {
    check_gate_failure("sleep 10", JobStatus::Timeout).await;
}

#[tokio::test]
async fn scheduler_reports_run_if_spawn_failure_as_a_failed_update() {
    // An embedded NUL fails spawn without changing the system shell or environment.
    check_gate_failure("\0", JobStatus::Failed("run_if: spawn failed".into())).await;
}

// ── helpers ──

async fn check_gate_failure(check: &str, expected: JobStatus) {
    let mut spec = spec("update");
    spec.run_if = Some(check.into());
    spec.run = "exit 99".into();
    spec.timeout = Duration::from_millis(100);
    spec.reload = vec![Reload::Geo, Reload::Country];
    let context = JobContext {
        specs: vec![spec],
        ..Default::default()
    };
    let mut hub = common::hub::dashboard_hub();
    hub.job_stats = JobStats::new(&context.specs, false, false);
    let (shutdown, mut stop) = watch::channel(false);
    let (events, task) = jobs::spawn_scheduler(&context, &mut stop);
    let mut events = events.unwrap();
    let started = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(started, JobEvent::Started { .. }));
    hub.handle_job_event(started);
    let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .unwrap()
        .unwrap();
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), task.unwrap())
        .await
        .unwrap()
        .unwrap();
    let JobEvent::Finished { status, reload, .. } = &event else {
        panic!("a broken gate must finish with an error, not skip");
    };
    assert_eq!(status, &expected, "the payload must not run");
    assert_eq!(reload, &[Reload::Geo, Reload::Country]);
    let timeout = expected == JobStatus::Timeout;
    hub.handle_job_event(event);
    let snapshot = web::snapshot(&hub);
    assert_eq!(snapshot.jobs.runs, 1);
    assert_eq!(snapshot.jobs.failures, u64::from(!timeout));
    assert_eq!(snapshot.jobs.timeouts, u64::from(timeout));
    let progress = &snapshot.jobs.details[0];
    assert_eq!(progress.state, if timeout { "timeout" } else { "failed" });
    assert!(progress.finished_at.is_some());
    assert!(progress.next_at.is_some());
    assert_eq!(progress.success_at, None);
    for database in &snapshot.databases {
        assert!(database.status.attempted_at.is_some());
        assert!(database.status.error.contains("previous table retained"));
    }
}

fn spec(label: &str) -> JobSpec {
    JobSpec {
        label: label.into(),
        every: Duration::from_secs(60),
        timeout: Duration::from_secs(2),
        run_if: None,
        run: "printf secret-payload".into(),
        reload: Vec::new(),
    }
}

fn finished(status: JobStatus, reload: Vec<Reload>) -> JobEvent {
    JobEvent::Finished {
        label: "update".into(),
        status,
        reload,
        next_at: 1234,
    }
}
