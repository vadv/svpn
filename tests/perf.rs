use std::net::Ipv4Addr;
use std::time::Duration;

use svpn::perf::*;
use tokio::io::AsyncReadExt;

fn get(size: &str) -> String {
    format!("GET /seg?{size} HTTP/1.1\r\nHost: 10.77.0.1\r\n\r\n")
}

#[test]
fn parse_get_segment() {
    assert!(matches!(parse(&get("size=1024")), Request::Segment(1024)));
    assert!(matches!(parse(&get("size=1")), Request::Segment(1)));
}

#[test]
fn parse_get_rejects_bad_size() {
    for query in ["size=0", "size=abc", "size=", "size=-1", "foo=1&size=5"] {
        assert!(matches!(parse(&get(query)), Request::Bad), "{query}");
    }
}

#[test]
fn parse_get_rejects_oversize() {
    assert!(matches!(
        parse(&get(&format!("size={}", (1 << 30) + 1))),
        Request::Bad
    ));
    assert!(matches!(
        parse(&get("size=1073741824")),
        Request::Segment(_)
    ));
}

#[test]
fn parse_get_without_size() {
    assert!(matches!(
        parse("GET /seg HTTP/1.1\r\nHost: x\r\n\r\n"),
        Request::Bad
    ));
    assert!(matches!(
        parse("GET /seg? HTTP/1.1\r\nHost: x\r\n\r\n"),
        Request::Bad
    ));
}

#[test]
fn parse_post_uses_content_length() {
    let request = "POST /seg HTTP/1.1\r\nContent-Length: 4096\r\n\r\n";
    assert!(matches!(parse(request), Request::Upload(4096)));
    let request = "POST /seg HTTP/1.1\r\ncontent-length: 8\r\n\r\n";
    assert!(matches!(parse(request), Request::Upload(8)));
}

#[test]
fn parse_post_rejects_missing_or_bad_length() {
    assert!(matches!(
        parse("POST /seg HTTP/1.1\r\nHost: x\r\n\r\n"),
        Request::Bad
    ));
    assert!(matches!(
        parse("POST /seg HTTP/1.1\r\nContent-Length: abc\r\n\r\n"),
        Request::Bad
    ));
    assert!(matches!(
        parse(&format!(
            "POST /seg HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            (1 << 30) + 1
        )),
        Request::Bad
    ));
}

#[test]
fn parse_rejects_other_methods_and_paths() {
    assert!(matches!(
        parse("DELETE /seg HTTP/1.1\r\n\r\n"),
        Request::Bad
    ));
    assert!(matches!(parse("GET /admin HTTP/1.1\r\n\r\n"), Request::Bad));
    assert!(matches!(parse("garbage\r\n\r\n"), Request::Bad));
    assert!(matches!(parse(""), Request::Bad));
}

#[test]
fn head_declares_size() {
    assert_eq!(
        head(7),
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: keep-alive\r\n\r\n"
    );
}

#[test]
fn summary_stats() {
    let s = summary(&[10.0, 20.0, 30.0, 40.0]).expect("non-empty");
    assert_eq!(s.min, 10.0);
    // Upper median (nearest-rank): ceil(0.5*3)=2 → sorted[2].
    assert_eq!(s.median, 30.0);
    assert_eq!(s.mean, 25.0);
    assert_eq!(s.p95, 40.0);
    assert!((s.cv - 0.447_213_6).abs() < 1e-6, "cv={}", s.cv);
    assert!(summary(&[]).is_none());
    assert_eq!(summary(&[7.5]).unwrap().cv, 0.0);
}

#[test]
fn rows_drop_partial_tail_and_omit() {
    let outcome = Outcome {
        reverse: false,
        interval_secs: 5,
        omit_secs: 5,
        ready_ms: 0,
        // 12.9 s: two full intervals (0-5, 5-10) + a partial tail.
        elapsed: Duration::from_millis(12_900),
        buckets: vec![
            vec![StreamAgg {
                bytes: 1_000_000,
                rtts: vec![],
            }],
            vec![StreamAgg {
                bytes: 2_000_000,
                rtts: vec![Duration::from_millis(40)],
            }],
            vec![StreamAgg {
                bytes: 500_000,
                rtts: vec![],
            }],
        ],
    };
    let table = rows(&outcome);
    // Interval 0 (0-5 s) dropped as -O 5; the partial tail did not make it in.
    assert_eq!(table.len(), 1);
    assert_eq!(table[0].start, 5);
    // 2_000_000 bytes in 5 s = 3.2 Mbps.
    assert!((table[0].sum_mbit - 3.2).abs() < 1e-9);
    assert_eq!(table[0].rtt_p50_ms, Some(40.0));
}

#[tokio::test]
async fn measure_deadline_bounds_stalled_transfers() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, PORT))
        .await
        .unwrap();
    let server = tokio::spawn(async move {
        let (ready, _) = listener.accept().await.unwrap();
        drop(ready);
        let mut peers = Vec::new();
        for _ in 0..4 {
            peers.push(listener.accept().await.unwrap().0);
        }
        // Accept requests but never send HTTP responses.
        for mut peer in peers {
            let mut request = Vec::new();
            peer.read_to_end(&mut request).await.unwrap();
            assert!(!request.is_empty());
        }
    });
    let args = MeasureArgs {
        peer: Ipv4Addr::LOCALHOST,
        duration: 1,
        interval: 1,
        streams: 4,
        segment: 1024,
        total: None,
        reverse: false,
        omit: 0,
    };
    let outcome = tokio::time::timeout(Duration::from_secs(3), measure(&args))
        .await
        .expect("perf -t hangs on a stalled response")
        .unwrap();
    assert!(outcome.elapsed >= Duration::from_secs(1));
    assert!(outcome.buckets.iter().flatten().all(|agg| agg.bytes == 0));
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("perf left a worker connection open")
        .unwrap();
}

#[test]
fn mbit_converts_bytes() {
    assert!((mbit(1_048_576, 1) - 8.388_608).abs() < 1e-9);
}
