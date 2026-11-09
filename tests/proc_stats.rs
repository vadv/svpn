//! Process resource sample: parsing, unit conversion, fallbacks and JSON shape.

mod common;

use svpn::{proc_stats, web};

const STATUS: &str = "Name:\tsvpn\nVmPeak:\t  120000 kB\nVmSize:\t  110000 kB\nVmHWM:\t   90000 kB\nVmRSS:\t   65536 kB\n";

// ── /proc parsing ──

#[test]
fn vm_rss_is_parsed_from_the_exact_field_in_kib() {
    assert_eq!(proc_stats::parse_vm_rss(STATUS), Some(65536 * 1024));
    assert_eq!(proc_stats::parse_vm_rss("VmRSS: 0 kB\n"), Some(0));
    assert_eq!(
        proc_stats::parse_vm_rss("VmRSS:\t2048 kB\r\nVmSwap: 0 kB\r\n"),
        Some(2048 * 1024)
    );
}

#[test]
fn missing_or_untrusted_vm_rss_is_not_guessed() {
    for status in [
        "Name:\tsvpn\nVmHWM: 90000 kB\n",
        "VmRSS: kB\n",
        "VmRSS: abc kB\n",
        "VmRSS: -1 kB\n",
        "VmRSS: 2048 MB\n",
        "VmRSS: 2048\n",
        "VmRSS: 18446744073709551615 kB\n",
        "",
    ] {
        assert_eq!(proc_stats::parse_vm_rss(status), None, "{status}");
    }
}

// ── unit conversion ──

#[test]
fn peak_rss_units_differ_between_linux_and_bsd() {
    assert_eq!(proc_stats::peak_bytes(2048, true), Some(2048 * 1024));
    assert_eq!(proc_stats::peak_bytes(2048, false), Some(2048));
    assert_eq!(proc_stats::peak_bytes(0, true), None);
    assert_eq!(proc_stats::peak_bytes(-1, false), None);
    assert_eq!(
        proc_stats::peak_bytes(i64::MAX, true),
        None,
        "KiB overflow stays unknown"
    );
}

#[test]
fn cpu_time_is_a_cumulative_counter_without_negative_or_overflowing_values() {
    assert_eq!(proc_stats::total_cpu_seconds(1_500_000, 500_000), Some(2.0));
    assert_eq!(proc_stats::total_cpu_seconds(0, 0), Some(0.0));
    assert_eq!(proc_stats::total_cpu_seconds(-1, 0), None);
    assert_eq!(proc_stats::total_cpu_seconds(0, -1), None);
    assert_eq!(proc_stats::total_cpu_seconds(i64::MAX, 1), None);
}

// ── fallback rule ──

#[test]
fn current_rss_wins_and_a_peak_fallback_is_explicitly_flagged() {
    let current = proc_stats::ProcessView {
        rss_bytes: Some(1024),
        peak_rss_bytes: Some(2048),
        ..Default::default()
    };
    assert_eq!(current.rss(), (Some(1024), false));

    let peak_only = proc_stats::ProcessView {
        peak_rss_bytes: Some(2048),
        ..Default::default()
    };
    assert_eq!(
        peak_only.rss(),
        (Some(2048), true),
        "macOS must not show a peak as live RSS"
    );

    assert_eq!(proc_stats::ProcessView::default().rss(), (None, false));
}

// ── live sample and snapshot ──

#[test]
fn a_real_sample_has_cpu_time_cores_and_some_memory_value() {
    let sample = proc_stats::sample();
    assert!(
        sample
            .cpu_seconds
            .is_some_and(|seconds| seconds.is_finite() && seconds >= 0.0)
    );
    assert!(sample.cpus.is_some_and(|cpus| cpus > 0));
    assert!(sample.peak_rss_bytes.is_some_and(|bytes| bytes > 0));
    let (rss, _) = sample.rss();
    assert!(
        rss.is_some_and(|bytes| bytes > 0),
        "the UI always has a memory number"
    );
    #[cfg(target_os = "linux")]
    assert!(
        sample.rss_bytes.is_some(),
        "Linux /proc/self/status is readable"
    );
    #[cfg(target_os = "macos")]
    assert!(
        sample.rss_bytes.is_none(),
        "macOS only reports peak RSS here"
    );
}

#[test]
fn snapshot_exposes_process_usage_as_nullable_json() {
    let hub = common::hub::dashboard_hub();
    let json = serde_json::to_value(web::snapshot(&hub)).expect("snapshot serializes");
    let process = &json["process"];
    for key in ["rss_bytes", "peak_rss_bytes", "cpu_seconds", "cpus"] {
        assert!(
            process.get(key).is_some(),
            "missing process key {key}: {process}"
        );
        assert!(
            process[key].is_null() || process[key].is_number(),
            "{key} must be a number or null: {process}"
        );
    }
}
