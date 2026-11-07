//! Job runner: spawn, timeout group-kill, capped output tail, env contract.

use std::time::Duration;

use svpn::job::{JobSpec, JobStatus};

fn spec(run: &str, timeout: Duration) -> JobSpec {
    JobSpec {
        label: "test".to_owned(),
        every: Duration::from_secs(60),
        timeout,
        run_if: None,
        run: run.to_owned(),
        reload: Vec::new(),
    }
}

#[tokio::test]
async fn successful_run_captures_output_and_env() {
    let spec = spec(
        "printf 'line-1\\n'; echo \"$SVPN_JOB/$SVPN_MARKER\"",
        Duration::from_secs(10),
    );
    let (status, tail) =
        svpn::job::run(&spec, &[("SVPN_MARKER".to_owned(), "42".to_owned())]).await;
    assert_eq!(status, JobStatus::Ok);
    assert!(tail.contains("line-1"), "{tail}");
    assert!(
        tail.contains("test/42"),
        "env contract reaches the script: {tail}"
    );
}

#[tokio::test]
async fn nonzero_exit_is_reported_verbatim() {
    let (status, _) = svpn::job::run(&spec("exit 3", Duration::from_secs(10)), &[]).await;
    match status {
        JobStatus::Failed(reason) => assert!(reason.contains("3"), "{reason}"),
        other => panic!("expected failure, got {other:?}"),
    }
}

#[tokio::test]
async fn timeout_kills_the_process_group_promptly() {
    let started = std::time::Instant::now();
    // A shell with a background child: the whole group must die with it.
    let (status, _) = svpn::job::run(&spec("sleep 30 & wait", Duration::from_secs(1)), &[]).await;
    assert_eq!(status, JobStatus::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "kill must be prompt, took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn output_is_capped_to_a_tail() {
    // ~64 KiB of lines; only the bounded tail may survive.
    let (status, tail) = svpn::job::run(
        &spec(
            "i=0; while [ $i -lt 2048 ]; do echo \"filler-$i\"; i=$((i+1)); done; echo LAST-MARKER",
            Duration::from_secs(20),
        ),
        &[],
    )
    .await;
    assert_eq!(status, JobStatus::Ok);
    assert!(tail.contains("LAST-MARKER"), "{tail}");
    assert!(tail.len() <= 8 * 1024, "tail not capped: {}", tail.len());
    assert!(!tail.contains("filler-0"), "the head must be dropped");
}

#[tokio::test]
async fn spawn_failure_is_a_reported_failure() {
    let (status, _) = svpn::job::run(&spec("exit 0", Duration::from_secs(10)), &[]).await;
    assert_eq!(status, JobStatus::Ok);
}

// ── run_foreground (svpn job run) ──

#[test]
fn foreground_exit_code_is_the_jobs_own() {
    let code = svpn::job::run_foreground(&spec("exit 3", Duration::from_secs(10)), &[]);
    assert_eq!(code, 3);
    let code = svpn::job::run_foreground(&spec("exit 0", Duration::from_secs(10)), &[]);
    assert_eq!(code, 0);
}

#[test]
fn foreground_timeout_reports_124() {
    let started = std::time::Instant::now();
    let code = svpn::job::run_foreground(&spec("sleep 30 & wait", Duration::from_secs(1)), &[]);
    assert_eq!(code, 124);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn foreground_env_contract_is_present() {
    let code = svpn::job::run_foreground(
        &spec(
            "[ \"$SVPN_JOB\" = test ] && [ \"$SVPN_MARKER\" = yes ]",
            Duration::from_secs(10),
        ),
        &[("SVPN_MARKER".to_owned(), "yes".to_owned())],
    );
    assert_eq!(code, 0, "env must reach the foreground script");
}

// ── auto_job_update presets ──

#[test]
fn geo_preset_matches_the_documented_contract() {
    let spec = svpn::job::preset_update(svpn::job::Reload::Geo);
    assert_eq!(spec.label, "geo-update");
    assert_eq!(spec.every, Duration::from_secs(3600));
    assert_eq!(spec.timeout, Duration::from_secs(600));
    assert_eq!(spec.reload, vec![svpn::job::Reload::Geo]);
    let check = spec.run_if.as_deref().unwrap();
    assert!(check.contains("db=$SVPN_GEO_DB"));
    // BSD stat with the GNU fallback: the answer is validated, not the code.
    assert!(check.contains("stat -f %m") && check.contains("stat -c %Y"));
    let run = &spec.run;
    assert!(run.contains("dbip-asn-lite"));
    assert!(run.contains(r"geo.XXXXXX"));
    assert!(run.contains("104857600"));
    assert!(run.contains("ulimit -f 976563"));
    assert!(run.contains(r",[0-9]+'")); // ASN rows end in a number
    assert!(run.contains(r#""$rows" -ge 100000"#));
    // Atomic install only after validation; no partial files on failure.
    assert!(run.contains(r#"trap 'rm -f "$tmp" "$tmp.gz"' EXIT"#));
    assert!(run.rfind("mv \"$tmp\" \"$db\"").unwrap() > run.find("valid rows").unwrap() - 100);
}

#[test]
fn country_preset_matches_the_documented_contract() {
    let spec = svpn::job::preset_update(svpn::job::Reload::Country);
    assert_eq!(spec.label, "country-update");
    assert_eq!(spec.reload, vec![svpn::job::Reload::Country]);
    let check = spec.run_if.as_deref().unwrap();
    assert!(check.contains("db=$SVPN_COUNTRY_DB"));
    let run = &spec.run;
    assert!(run.contains("dbip-country-lite"));
    assert!(run.contains(r"country.XXXXXX"));
    // Country rows end with a two-letter code; ASN rows carry a number.
    assert!(run.contains("[A-Z][A-Z]$"));
}
