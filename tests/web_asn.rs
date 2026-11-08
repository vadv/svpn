//! ASN CSV download: no parsing/cache in the server, bounded async transfers.

mod common;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use svpn::{geo::Geo, web};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    task::JoinHandle,
};

// ── CSV and HTTP boundaries ──

#[tokio::test]
async fn csv_is_raw_uncached_and_only_uses_the_configured_path() {
    let csv = common::csv::Csv::new("1.0.0.0,1.0.0.255,13335,Cloudflare\n");
    let (addr, _server) = start(Some(csv.0.clone()), true).await;
    let first = get(addr, "/api/asn.csv?path=/etc/passwd").await;
    assert!(first.starts_with("HTTP/1.1 200"));
    assert!(first.contains("content-type: text/csv"));
    assert!(first.contains("cache-control: no-store"));
    assert_eq!(body(&first), "1.0.0.0,1.0.0.255,13335,Cloudflare\n");
    std::fs::write(&csv.0, "not parsed on the router\n").unwrap();
    assert_eq!(
        body(&get(addr, "/api/asn.csv").await),
        "not parsed on the router\n"
    );
    let state = get(addr, "/api/state").await;
    assert!(
        !state.contains("asn_names"),
        "organizations are browser-only state"
    );
    assert!(
        get(addr, "/api/asn-names")
            .await
            .starts_with("HTTP/1.1 404")
    );
}

#[tokio::test]
async fn missing_or_unloaded_databases_do_not_expose_files() {
    let csv = common::csv::Csv::new("names");
    for (path, loaded) in [(None, true), (Some(csv.0.clone()), false)] {
        let (addr, _server) = start(path, loaded).await;
        assert!(get(addr, "/api/asn.csv").await.starts_with("HTTP/1.1 404"));
    }
    let (addr, _server) = start(Some(csv.0.clone()), true).await;
    std::fs::remove_file(&csv.0).unwrap();
    assert!(get(addr, "/api/asn.csv").await.starts_with("HTTP/1.1 503"));
}

#[tokio::test]
async fn csv_keeps_host_and_method_guards() {
    let csv = common::csv::Csv::new("names");
    let (addr, _server) = start(Some(csv.0.clone()), true).await;
    let foreign = request(
        addr,
        "GET /api/asn.csv HTTP/1.1\r\nHost: evil.example\r\n\r\n",
    )
    .await;
    assert!(foreign.starts_with("HTTP/1.1 403"));
    let post = request(
        addr,
        &format!("POST /api/asn.csv HTTP/1.1\r\nHost: {addr}\r\n\r\n"),
    )
    .await;
    assert!(post.starts_with("HTTP/1.1 405"));
}

#[tokio::test]
async fn csv_rejects_directories_and_oversized_files() {
    let csv = common::csv::Csv::new("");
    let (addr, _server) = start(csv.0.parent().map(PathBuf::from), true).await;
    assert!(get(addr, "/api/asn.csv").await.starts_with("HTTP/1.1 503"));
    std::fs::File::options()
        .write(true)
        .open(&csv.0)
        .unwrap()
        .set_len(128 * 1024 * 1024 + 1)
        .unwrap();
    let (addr, _server) = start(Some(csv.0.clone()), true).await;
    assert!(get(addr, "/api/asn.csv").await.starts_with("HTTP/1.1 503"));
}

// ── concurrency and cleanup ──

#[tokio::test]
async fn stalled_csv_does_not_block_snapshots_and_shutdown_closes_its_socket() {
    let csv = common::csv::Csv::new("");
    std::fs::File::options()
        .write(true)
        .open(&csv.0)
        .unwrap()
        .set_len(32 * 1024 * 1024)
        .unwrap();
    let (addr, server) = start(Some(csv.0.clone()), true).await;
    let mut download = TcpStream::connect(addr).await.unwrap();
    download
        .write_all(format!("GET /api/asn.csv HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut byte = [0];
    download.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte[0], b'H');
    let state = tokio::time::timeout(Duration::from_secs(2), get(addr, "/api/state"))
        .await
        .expect("snapshot must not wait for the CSV transfer");
    assert!(state.starts_with("HTTP/1.1 200"));
    server.abort();
    let _ = server.await;
    let mut partial = Vec::new();
    let _result = tokio::time::timeout(Duration::from_secs(2), download.read_to_end(&mut partial))
        .await
        .expect("shutdown must close the download socket");
    assert!(
        partial.len() < 32 * 1024 * 1024,
        "shutdown cancels, not drains, the transfer"
    );
}

#[tokio::test]
async fn connections_are_bounded_and_released() {
    let (addr, _server) = start(None, false).await;
    let mut peers = Vec::new();
    for _ in 0..web::MAX_CONNECTIONS {
        let mut peer = TcpStream::connect(addr).await.unwrap();
        peer.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        peers.push(peer);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut extra = TcpStream::connect(addr).await.unwrap();
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(2), extra.read(&mut byte))
        .await
        .expect("excess connection is closed promptly");
    assert!(
        !matches!(result, Ok(1..)),
        "excess client must not be served"
    );
    drop(peers);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(get(addr, "/api/state").await.starts_with("HTTP/1.1 200"));
}

// ── helpers ──

async fn start(path: Option<PathBuf>, loaded: bool) -> (SocketAddr, JoinHandle<()>) {
    let mut hub = common::hub::dashboard_hub();
    hub.geo = loaded.then(|| Geo::from_ranges(vec![(0, u32::MAX, 13335)]));
    let (tx, rx) = watch::channel(web::snapshot(&hub));
    let listener = web::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let _sender = tx;
        web::serve(listener, rx, path).await.unwrap();
    });
    (addr, task)
}

async fn request(addr: SocketAddr, text: &str) -> String {
    let mut peer = TcpStream::connect(addr).await.unwrap();
    peer.write_all(text.as_bytes()).await.unwrap();
    let mut response = String::new();
    peer.read_to_string(&mut response).await.unwrap();
    response
}

async fn get(addr: SocketAddr, path: &str) -> String {
    request(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n\r\n"),
    )
    .await
}

fn body(response: &str) -> &str {
    response.split_once("\r\n\r\n").unwrap().1
}
