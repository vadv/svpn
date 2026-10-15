//! Benchmark client: segments over N TCP connections to the perf server on
//! the TUN-IP, tallying bytes and probe RTTs per interval.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::PORT;

/// Benchmark: segments over N TCP connections to the perf server on the TUN-IP.
pub struct MeasureArgs {
    pub peer: Ipv4Addr,
    /// Duration, seconds; used when `total` is not set.
    pub duration: u64,
    pub interval: u64,
    pub streams: usize,
    pub segment: u64,
    /// Total volume, bytes (-n); overrides duration (iperf3).
    pub total: Option<u64>,
    /// Upload (POST) instead of download (GET).
    pub reverse: bool,
    /// Drop the first N seconds from the report.
    pub omit: u64,
}

#[derive(Default, Clone)]
pub struct StreamAgg {
    pub bytes: u64,
    pub rtts: Vec<Duration>,
}

pub struct Outcome {
    pub reverse: bool,
    pub interval_secs: u64,
    pub omit_secs: u64,
    pub ready_ms: u128,
    pub elapsed: Duration,
    /// Interval → stream → aggregate.
    pub buckets: Vec<Vec<StreamAgg>>,
}

struct Shared {
    peer: Ipv4Addr,
    start: Instant,
    cap: Duration,
    interval_ms: u64,
    segment: u64,
    total: Option<u64>,
    reverse: bool,
    done: AtomicU64,
    buckets: Vec<Mutex<Vec<StreamAgg>>>,
}

impl Shared {
    /// Counts bytes at the moment of actual I/O — not per segment but in chunks:
    /// a segment interrupted by the deadline keeps its progress, and the interval
    /// is chosen by the time the bytes arrive.
    fn tally(&self, stream_idx: usize, bytes: u64) {
        self.done.fetch_add(bytes, Ordering::Relaxed);
        let idx = Instant::now().duration_since(self.start).as_millis() as u64 / self.interval_ms;
        if let Some(bucket) = self.buckets.get(idx as usize) {
            bucket.lock().expect("perf bucket poisoned")[stream_idx].bytes += bytes;
        }
    }
}

pub async fn measure(args: &MeasureArgs) -> Result<Outcome> {
    ensure!(
        args.streams >= 1 && args.streams <= 128,
        "--parallel: 1..=128"
    );
    ensure!(args.interval >= 1, "--interval: >= 1 s");
    ensure!(
        args.duration >= 1 || args.total.is_some(),
        "specify --time or --bytes"
    );
    ensure!(args.segment >= 1024, "--len: >= 1024 bytes");
    let addr = std::net::SocketAddr::V4(SocketAddrV4::new(args.peer, PORT));
    let boot = Instant::now();
    wait_ready(addr, Duration::from_secs(60)).await?;
    let ready_ms = boot.elapsed().as_millis();
    crate::debug!("perf ready after {ready_ms} ms");

    // -n overrides -t; for -n the fallback ceiling is an hour, so we don't hang.
    let cap_secs = match args.total {
        Some(_) => 3600,
        None => args.duration,
    };
    let count = cap_secs / args.interval + 2;
    let shared = Arc::new(Shared {
        peer: args.peer,
        start: Instant::now(),
        cap: Duration::from_secs(cap_secs),
        interval_ms: args.interval * 1000,
        segment: args.segment,
        total: args.total,
        reverse: args.reverse,
        done: AtomicU64::new(0),
        buckets: (0..count)
            .map(|_| Mutex::new(vec![StreamAgg::default(); args.streams]))
            .collect(),
    });
    let deadline = tokio::time::Instant::from_std(shared.start + shared.cap);
    let mut streams = tokio::task::JoinSet::new();
    for idx in 0..args.streams {
        let shared = Arc::clone(&shared);
        streams.spawn(async move { run_stream(&shared, idx).await });
    }
    let result: Result<()> = async {
        while !streams.is_empty() {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    break;
                }
                Some(stream) = streams.join_next() => {
                    stream.context("perf stream task")??;
                }
            }
        }
        Ok(())
    }
    .await;
    // Cancel unfinished connect/IO and wait for all sockets to be released.
    streams.shutdown().await;
    // The -n total is checked once after stopping: exiting via join_next or the
    // timer must not bypass the volume check.
    if let Some(total) = shared.total {
        ensure!(
            shared.done.load(Ordering::Relaxed) >= total,
            "perf --bytes: volume not transferred within the allotted time"
        );
    }
    result?;
    let elapsed = shared.start.elapsed();
    let buckets = shared
        .buckets
        .iter()
        .map(|bucket| bucket.lock().expect("perf bucket poisoned").clone())
        .collect();
    Ok(Outcome {
        reverse: args.reverse,
        interval_secs: args.interval,
        omit_secs: args.omit,
        ready_ms,
        elapsed,
        buckets,
    })
}

/// Waits for the channel to be ready: connections do not bypass the channel, so
/// retrying until the first successful connect is a sufficient readiness criterion.
async fn wait_ready(addr: std::net::SocketAddr, budget: Duration) -> Result<()> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => return Ok(()),
            _ => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    bail!("channel not ready within {budget:?}: check --mimic and server reachability")
}

async fn run_stream(shared: &Shared, stream_idx: usize) -> Result<()> {
    let addr = std::net::SocketAddr::V4(SocketAddrV4::new(shared.peer, PORT));
    let mut conn = TcpStream::connect(addr)
        .await
        .context("perf stream connect")?;
    conn.set_nodelay(true).ok();
    let mut buf = vec![0u8; 64 * 1024];
    let mut last_probe: i64 = -1;
    loop {
        let now = Instant::now();
        if now.duration_since(shared.start) >= shared.cap {
            break;
        }
        if let Some(total) = shared.total
            && shared.done.load(Ordering::Relaxed) >= total
        {
            break;
        }
        let idx = now.duration_since(shared.start).as_millis() as u64 / shared.interval_ms;
        // The first segment of an interval is a small RTT probe (1 KiB).
        let small = idx as i64 > last_probe;
        let size = if small { 1024 } else { shared.segment };
        let t0 = Instant::now();
        if shared.reverse {
            conn.write_all(post_head(size).as_bytes()).await?;
            write_body(&mut conn, size, shared, stream_idx).await?;
            let len = read_head(&mut conn).await?;
            ensure!(len == 0, "perf upload: unexpected response body {len}");
        } else {
            conn.write_all(get_head(size).as_bytes()).await?;
            let len = read_head(&mut conn).await?;
            ensure!(len == size, "perf segment: {len} != {size}");
            read_body(&mut conn, &mut buf, size, shared, stream_idx).await?;
        }
        // Bytes are counted in chunks inside read/write_body; here only the probe's
        // RTT is recorded when the segment completes.
        if small {
            last_probe = idx as i64;
            let done_idx =
                Instant::now().duration_since(shared.start).as_millis() as u64 / shared.interval_ms;
            if let Some(bucket) = shared.buckets.get(done_idx as usize) {
                bucket.lock().expect("perf bucket poisoned")[stream_idx]
                    .rtts
                    .push(t0.elapsed());
            }
        }
    }
    Ok(())
}

fn get_head(size: u64) -> String {
    format!("GET /seg?size={size} HTTP/1.1\r\nHost: svpn-perf\r\nConnection: keep-alive\r\n\r\n")
}

fn post_head(len: u64) -> String {
    format!(
        "POST /seg HTTP/1.1\r\nHost: svpn-perf\r\nContent-Length: {len}\r\nConnection: keep-alive\r\n\r\n"
    )
}

/// Reads the response header; returns Content-Length; the status must be 200.
async fn read_head(conn: &mut TcpStream) -> Result<u64> {
    let mut head: Vec<u8> = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        ensure!(
            conn.read(&mut byte).await? > 0,
            anyhow::anyhow!("perf response cut short")
        );
        head.push(byte[0]);
        if head.len() > 4 * 1024 {
            bail!("perf response header too large");
        }
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .context("perf response without a status")?;
    ensure!(status == "200", "perf status {status}");
    head.split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<u64>().ok())
                .flatten()
        })
        .context("perf response without Content-Length")
}

async fn read_body(
    conn: &mut TcpStream,
    buf: &mut [u8],
    mut left: u64,
    shared: &Shared,
    stream_idx: usize,
) -> Result<()> {
    while left > 0 {
        let take = (left as usize).min(buf.len());
        let read = conn.read(&mut buf[..take]).await?;
        ensure!(read > 0, anyhow::anyhow!("perf body cut short"));
        left -= read as u64;
        shared.tally(stream_idx, read as u64);
    }
    Ok(())
}

async fn write_body(
    conn: &mut TcpStream,
    mut left: u64,
    shared: &Shared,
    stream_idx: usize,
) -> Result<()> {
    let chunk = [b'B'; 64 * 1024];
    while left > 0 {
        let take = (left as usize).min(chunk.len());
        conn.write_all(&chunk[..take]).await?;
        left -= take as u64;
        shared.tally(stream_idx, take as u64);
    }
    Ok(())
}
