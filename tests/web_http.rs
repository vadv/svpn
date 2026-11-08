//! Dashboard HTTP: loopback only, GET only, JSON and HTML.

mod common;

use std::time::Duration;

use svpn::web;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

/// Start the dashboard on an ephemeral port and return its address.
async fn start() -> std::net::SocketAddr {
    let hub = common::hub::dashboard_hub();
    let (tx, rx) = watch::channel(web::snapshot(&hub));
    let listener = web::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind dashboard");
    let addr = listener.local_addr().expect("dashboard addr");
    tokio::spawn(async move {
        let _sender = tx;
        let _ = web::serve(listener, rx).await;
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
    for section in ["Servers", "Rules", "Pinned groups", "Flows", "Counters"] {
        assert!(answer.contains(section), "missing section {section}");
    }
    assert!(
        answer.contains("/api/state"),
        "the page must poll the json endpoint"
    );
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
