//! Logging: record formatting and level filtering.

use std::sync::atomic::Ordering;

use svpn::logging::*;

// ── record formatting ──

#[test]
fn every_record_ends_with_one_newline() {
    for text in [
        "[server] stats: received 1 packet",
        "[server] stats: received 1 packet\n",
        "[server] stats: received 1 packet\r\n",
    ] {
        assert_eq!(
            format_record(1.0, text),
            "t+    1.000s [server] stats: received 1 packet\n"
        );
    }
    assert_eq!(
        format!(
            "{}{}",
            format_record(1.0, "first"),
            format_record(2.0, "second")
        ),
        "t+    1.000s first\nt+    2.000s second\n"
    );
}

// ── level filtering ──

#[test]
fn level_order_filters_output() {
    assert!(Level::Error < Level::Info && Level::Info < Level::Debug);
    MAX_LEVEL.store(Level::Error.as_u8(), Ordering::Relaxed);
    assert!(enabled(Level::Error) && !enabled(Level::Info) && !enabled(Level::Debug));
    MAX_LEVEL.store(Level::Debug.as_u8(), Ordering::Relaxed);
    assert!(enabled(Level::Error) && enabled(Level::Info) && enabled(Level::Debug));
    MAX_LEVEL.store(Level::Info.as_u8(), Ordering::Relaxed);
}
