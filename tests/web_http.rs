//! Dashboard HTTP: loopback only, GET only, JSON and HTML.

mod common;

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

#[tokio::test]
async fn dashboard_refuses_a_public_address() {
    let error = web::bind("0.0.0.0:8080".parse().unwrap()).await;
    assert!(error.is_err(), "public bind must be refused");
}

#[tokio::test]
async fn every_answer_is_no_store() {
    let addr = start().await;
    let answer = get(addr, "/api/state").await;
    assert!(answer.contains("cache-control: no-store"), "{answer}");
}
