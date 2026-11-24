//! A database that cannot be written to. The file-size limit of a child
//! process stands in for a full disk: the store reports it and goes on
//! taking minutes, the process is none the worse.

use std::time::{Duration, Instant};

use svpn::history::{Kind, Query, Range, Recorder, Row, Series};

/// Set in the child that runs under the file-size limit.
const CHILD: &str = "SVPN_HISTORY_FULL_CHILD";
const TEST: &str = "a_full_disk_is_an_error_in_the_status_and_the_process_goes_on";
const MINUTE: u64 = 60;

// ── a full disk ──

#[test]
fn a_full_disk_is_an_error_in_the_status_and_the_process_goes_on() {
    if std::env::var_os(CHILD).is_none() {
        // Past the limit a write fails, and the limit raises a signal that
        // would end the process instead. The shell leaves that signal
        // ignored; both are inherited across exec. A real full disk sends none.
        // 256 KiB is room for the empty database, none for a minute of rows.
        let blocks = 256 * 1024 / 512;
        let script =
            format!("trap '' XFSZ; ulimit -f {blocks}; exec \"$1\" --exact {TEST} --nocapture");
        let output = std::process::Command::new("sh")
            .args(["-c", &script, "sh"])
            .arg(std::env::current_exe().unwrap())
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "the limited child failed\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let dir = std::env::temp_dir().join(format!("svpn history full {}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let recorder = Recorder::spawn(dir.join("stats.sqlite"));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut minute = 1_792_886_400;
    let status = loop {
        recorder.record(minute, rows());
        minute += MINUTE;
        let status = recorder.status();
        if status.state == "error" || Instant::now() > deadline {
            break status;
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    assert_eq!(status.state, "error", "the full disk must reach the status");
    // A full disk says so; where the file-size limit bites first is the
    // platform's choice, and it says "disk I/O error" instead.
    assert!(status.error.contains("disk"), "{}", status.error);
    // Still here, and still taking minutes without a wait.
    let started = Instant::now();
    recorder.record(minute, rows());
    assert!(started.elapsed() < Duration::from_millis(50));
    // A query is still answered — with the data or with the reason — which
    // is what "the thread is alive" means. Behind a slow disk the channel to
    // it can be full for a moment, so asking is retried until the deadline.
    let query = || Query {
        range: Range::Day,
        kind: Kind::Link,
        link: None,
        top: 8,
    };
    let answer = loop {
        match recorder.query(query()) {
            Ok(answer) => break answer,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "the history thread does not take queries: {error}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let answered = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), answer)
            .await
            .expect("the history thread answers")
    });
    // The reply itself may be the data or the reason; a dropped one means the thread is gone.
    assert!(answered.is_ok(), "the history thread dropped the reply");
    // The shutdown does not hang on the disk either.
    let started = Instant::now();
    recorder.close();
    assert!(started.elapsed() < Duration::from_secs(10));
}

// ── helpers ──

/// One minute of four thousand networks and a server: far more than the
/// child's file-size limit holds.
fn rows() -> Vec<Row> {
    (0..4000u32)
        .map(|asn| Row {
            series: Series::Network {
                link: "a.example:22".to_owned(),
                asn,
            },
            rx_bytes: 1 << 20,
            tx_bytes: 1 << 20,
            ..zero()
        })
        .chain([Row {
            series: Series::Link {
                link: "a.example:22".to_owned(),
            },
            rx_bytes: 1 << 30,
            ..zero()
        }])
        .collect()
}

fn zero() -> Row {
    Row {
        series: Series::Local,
        rx_bytes: 0,
        tx_bytes: 0,
        rx_packets: 0,
        tx_packets: 0,
        opened: 0,
        closed: 0,
        failed: 0,
        drops: 0,
        active: 0,
    }
}
