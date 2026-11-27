//! Dashboard HTTP: loopback only, GET only, JSON and HTML.

mod common;

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use svpn::{
    history::{Recorder, Row, Series},
    web,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

/// Start the dashboard on an ephemeral port and return its address.
async fn start() -> std::net::SocketAddr {
    start_with(None).await
}

async fn start_with(history: Option<Arc<Recorder>>) -> std::net::SocketAddr {
    let hub = common::hub::dashboard_hub();
    let (tx, rx) = watch::channel(web::snapshot(&hub));
    let listener = web::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind dashboard");
    let addr = listener.local_addr().expect("dashboard addr");
    tokio::spawn(async move {
        let _sender = tx;
        let _ = web::serve(listener, rx, None, history).await;
    });
    addr
}

/// Send one request and read the whole answer.
async fn request(addr: std::net::SocketAddr, raw: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(raw.as_bytes()).await.expect("write");
    stream.flush().await.expect("flush");
    let mut answer = String::new();
    stream
        .read_to_string(&mut answer)
        .await
        .expect("read answer");
    answer
}

/// GET with a loopback Host header.
async fn get(addr: std::net::SocketAddr, path: &str) -> String {
    request(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n\r\n"),
    )
    .await
}

/// Send a head in separate TCP writes, so the terminator arrives in a later read.
async fn request_parts(addr: std::net::SocketAddr, parts: &[&str]) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    for part in parts {
        stream.write_all(part.as_bytes()).await.expect("write");
        stream.flush().await.expect("flush");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut answer = String::new();
    stream
        .read_to_string(&mut answer)
        .await
        .expect("read answer");
    answer
}

fn head_of(length: usize) -> String {
    let prefix = "GET / HTTP/1.1\r\nHost: localhost\r\nX: ";
    let suffix = "\r\n\r\n";
    assert!(length >= prefix.len() + suffix.len());
    format!(
        "{prefix}{}{suffix}",
        "a".repeat(length - prefix.len() - suffix.len())
    )
}

#[tokio::test]
async fn json_endpoint_serves_the_snapshot() {
    let addr = start().await;
    let answer = get(addr, "/api/state").await;
    assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
    assert!(
        answer.contains("content-type: application/json"),
        "{answer}"
    );
    let body = answer.split("\r\n\r\n").nth(1).expect("body");
    let json: serde_json::Value = serde_json::from_str(body).expect("json body");
    assert_eq!(json["servers"].as_array().map(Vec::len), Some(2));
}

#[tokio::test]
async fn root_serves_html() {
    let addr = start().await;
    let answer = get(addr, "/").await;
    assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
    assert!(answer.contains("content-type: text/html"), "{answer}");
    assert!(answer.contains("<h1>svpn</h1>"), "{answer}");
    for section in [
        "Servers",
        "Rules",
        "Pinned groups",
        "Flows",
        "Traffic",
        "Diagnostics",
    ] {
        assert!(answer.contains(section), "missing section {section}");
    }
    assert!(
        answer.contains("/api/state"),
        "the page must poll the json endpoint"
    );
}

#[tokio::test]
async fn modules_are_embedded_javascript_and_cannot_be_framed_or_loaded_remotely() {
    let addr = start().await;
    for path in ["/dashboard.mjs", "/state.mjs"] {
        let answer = get(addr, path).await;
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
        assert!(answer.contains("content-type: text/javascript"), "{answer}");
        assert!(answer.contains("script-src 'self'"), "{answer}");
        assert!(answer.contains("frame-ancestors 'none'"), "{answer}");
        assert!(answer.contains("cache-control: no-store"), "{answer}");
        let foreign = request(
            addr,
            &format!("GET {path} HTTP/1.1\r\nHost: evil.example\r\n\r\n"),
        )
        .await;
        assert!(foreign.starts_with("HTTP/1.1 403"), "{foreign}");
    }
}

#[tokio::test]
async fn other_paths_are_not_found() {
    let addr = start().await;
    let answer = get(addr, "/nope").await;
    assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
}

#[tokio::test]
async fn other_methods_are_rejected() {
    let addr = start().await;
    let answer = request(
        addr,
        &format!("POST /api/state HTTP/1.1\r\nHost: {addr}\r\n\r\n"),
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 405"), "{answer}");
    assert!(answer.contains("allow: GET"), "{answer}");
}

#[tokio::test]
async fn foreign_host_header_is_rejected() {
    let addr = start().await;
    let answer = request(
        addr,
        "GET /api/state HTTP/1.1\r\nHost: evil.example\r\n\r\n",
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
}

/// A browser sends more headers before Host: the check must find Host and
/// not the first header with a colon.
#[tokio::test]
async fn browser_headers_are_accepted() {
    let addr = start().await;
    let answer = request(
        addr,
        &format!(
            "GET /api/state HTTP/1.1\r\nAccept-Encoding: identity\r\nUser-Agent: Mozilla/5.0\r\n\
             Host: {addr}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
}

#[tokio::test]
async fn dashboard_refuses_a_public_address() {
    let error = web::bind("0.0.0.0:8080".parse().unwrap()).await;
    assert!(error.is_err(), "public bind must be refused");
}

// ── History ──

#[tokio::test]
async fn history_is_refused_while_it_is_off() {
    let addr = start().await;

    let answer = get(addr, "/api/history?range=24h&kind=link").await;

    assert!(
        answer.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{answer}"
    );
    assert!(answer.ends_with("history is off"), "{answer}");
}

#[tokio::test]
async fn history_rejects_a_query_it_does_not_understand() {
    let addr = start().await;
    for query in [
        "range=1y",
        "kind=country",
        "top=0",
        "top=33",
        "link=a%20b",
        "range=1h&range=24h",
        "x=1",
    ] {
        let answer = get(addr, &format!("/api/history?{query}")).await;
        assert!(
            answer.starts_with("HTTP/1.1 400 Bad Request"),
            "{query}: {answer}"
        );
    }
}

#[tokio::test]
async fn history_answers_from_the_thread_that_owns_the_database() {
    let dir = std::env::temp_dir().join(format!("svpn history http {}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let recorder = Recorder::spawn(dir.join("stats.sqlite"), None);
    let addr = start_with(Some(Arc::clone(&recorder))).await;
    let minute = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 60
        * 60;
    for (ago, bytes) in [(2, 4096), (1, 2048)] {
        recorder.record(
            minute - ago * 60,
            vec![Row {
                series: Series::Link {
                    link: "192.0.2.1".to_owned(),
                },
                rx_bytes: bytes,
                ..zero()
            }],
        );
    }

    // The thread writes on its own time; the answer follows within the request timeout.
    let deadline = Duration::from_secs(5);
    let started = std::time::Instant::now();
    let json = loop {
        let answer = get(addr, "/api/history?range=1h&kind=link").await;
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
        let json: serde_json::Value =
            serde_json::from_str(answer.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        if json["series"][0]["rx_bytes"] == 6144 || started.elapsed() > deadline {
            break json;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(json["range"], "1h");
    assert_eq!(json["kind"], "link");
    assert_eq!(json["step"], 60);
    assert_eq!(json["series"][0]["link"], "192.0.2.1");
    assert_eq!(json["series"][0]["rx_bytes"], 6144);
    assert_eq!(
        json["series"][0]["points"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        json["series"][0]["points"][1],
        serde_json::json!([minute - 60, 2048, 0])
    );

    recorder.close();
    let answer = get(addr, "/api/history?range=1h&kind=link").await;
    assert!(
        answer.starts_with("HTTP/1.1 503 Service Unavailable"),
        "{answer}"
    );
}

#[tokio::test]
async fn the_snapshot_says_that_history_is_off() {
    let addr = start().await;

    let answer = get(addr, "/api/state").await;
    let json: serde_json::Value =
        serde_json::from_str(answer.split("\r\n\r\n").nth(1).unwrap()).unwrap();

    assert_eq!(
        json["history"],
        serde_json::json!({ "enabled": false, "state": "", "error": "", "bytes": 0 })
    );
}

// ── Host and head parsing ──

#[tokio::test]
async fn host_in_the_body_is_not_a_header() {
    let addr = start().await;
    let answer = request(
        addr,
        "GET /api/state HTTP/1.1\r\nContent-Length: 17\r\n\r\nHost: localhost\r\n",
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
}

#[tokio::test]
async fn missing_or_duplicate_host_is_rejected() {
    let addr = start().await;
    for raw in [
        "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: localhost\r\nHost: evil.example\r\n\r\n",
    ] {
        let answer = request(addr, raw).await;
        assert!(answer.starts_with("HTTP/1.1 403"), "{raw}: {answer}");
    }
}

#[tokio::test]
async fn every_loopback_host_spelling_is_accepted() {
    let addr = start().await;
    for host in [
        "127.0.0.1",
        "127.0.0.2:8080",
        "[::1]",
        "[::1]:8080",
        "localhost",
        "LOCALHOST:8080",
    ] {
        let answer = request(addr, &format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{host}: {answer}");
    }
}

#[tokio::test]
async fn head_at_the_limit_is_accepted() {
    let addr = start().await;
    let raw = head_of(web::MAX_HEAD);
    assert_eq!(raw.len(), web::MAX_HEAD);
    let answer = request(addr, &raw).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
}

#[tokio::test]
async fn oversized_head_is_rejected_when_the_terminator_arrives_later() {
    let addr = start().await;
    let raw = head_of(web::MAX_HEAD + 1);
    let split = raw.len() - 3;
    let answer = request_parts(addr, &[&raw[..split], &raw[split..]]).await;
    assert!(!answer.contains("200 OK"), "{answer}");
}

// ── resource limits ──

/// A peer that never finishes its head must not hold the listener forever.
#[tokio::test]
async fn incomplete_request_is_closed_after_timeout() {
    let addr = start().await;
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: ")
        .await
        .expect("write");
    stream.flush().await.expect("flush");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(
        web::REQUEST_TIMEOUT + Duration::from_secs(2),
        stream.read(&mut byte),
    )
    .await
    .expect("stalled request must be closed");
    assert_eq!(read.expect("read"), 0);
}

#[tokio::test]
async fn every_answer_is_no_store() {
    let addr = start().await;
    let answer = get(addr, "/api/state").await;
    assert!(answer.contains("cache-control: no-store"), "{answer}");
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
