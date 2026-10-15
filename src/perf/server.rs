//! Server side of the perf benchmark: a minimal HTTP listener on the TUN-IP.
//! Answers `GET /seg?size=N` with N bytes and drains `POST /seg` bodies.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::PORT;

/// Upper bound for the segment and the request header.
const MAX_SEGMENT: u64 = 1 << 30;
const MAX_HEADER: usize = 4 * 1024;

pub enum Request {
    Segment(u64),
    Upload(u64),
    Bad,
}

/// Starts the listener after the TUN is created. A bind failure does not kill serve:
/// the benchmark is auxiliary, the VPN session matters more.
pub fn spawn(bind: Ipv4Addr) {
    tokio::spawn(async move {
        let listener = match crate::tcp::bind_listener(std::net::SocketAddr::from(
            SocketAddrV4::new(bind, PORT),
        ))
        .await
        {
            Ok(listener) => listener,
            Err(error) => {
                crate::error!("perf: bind {bind}:{PORT} failed — {error}");
                return;
            }
        };
        crate::debug!("perf listener on {bind}:{PORT}");
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let _ = serve_connection(stream).await;
            });
        }
    });
}

async fn serve_connection(mut stream: tokio::net::TcpStream) -> io::Result<()> {
    stream.set_nodelay(true).ok();
    // keep-alive: the client transfers segments over one connection per stream.
    loop {
        let Some(header) = read_header(&mut stream).await? else {
            return Ok(()); // EOF: the client closed the connection
        };
        match parse(&header) {
            Request::Segment(size) => {
                stream.write_all(head(size).as_bytes()).await?;
                let chunk = [b'A'; 64 * 1024];
                let mut left = size;
                while left > 0 {
                    let take = (left as usize).min(chunk.len());
                    stream.write_all(&chunk[..take]).await?;
                    left -= take as u64;
                }
            }
            Request::Upload(len) => {
                drain(&mut stream, len).await?;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                    )
                    .await?;
            }
            Request::Bad => {
                stream
                    .write_all(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await?;
                return Ok(());
            }
        }
    }
}

/// Reads the header up to CRLFCRLF byte by byte — we never cross the header
/// boundary: the POST body is read separately in `drain`.
async fn read_header(stream: &mut tokio::net::TcpStream) -> io::Result<Option<String>> {
    let mut header = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte).await? == 0 {
            return Ok(None); // EOF: connection closed (empty or truncated header)
        }
        header.push(byte[0]);
        if header.len() > MAX_HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "perf header too large",
            ));
        }
        if header.ends_with(b"\r\n\r\n") {
            return Ok(Some(String::from_utf8_lossy(&header).into_owned()));
        }
    }
}

pub fn parse(header: &str) -> Request {
    let Some(request_line) = header.split("\r\n").next() else {
        return Request::Bad;
    };
    let mut parts = request_line.split(' ');
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(path)) => parse_get(path),
        (Some("POST"), Some(path)) => parse_post(header, path),
        _ => Request::Bad,
    }
}

fn parse_get(path: &str) -> Request {
    let Some((path, query)) = path.split_once('?') else {
        return Request::Bad;
    };
    if path != "/seg" {
        return Request::Bad;
    }
    let size = query
        .split_whitespace()
        .find_map(|pair| pair.strip_prefix("size="))
        .and_then(|value| value.parse::<u64>().ok());
    match size {
        Some(size) if (1..=MAX_SEGMENT).contains(&size) => Request::Segment(size),
        _ => Request::Bad,
    }
}

fn parse_post(header: &str, path: &str) -> Request {
    if path != "/seg" {
        return Request::Bad;
    }
    let len = header.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<u64>().ok())
            .flatten()
    });
    match len {
        Some(len) if len <= MAX_SEGMENT => Request::Upload(len),
        _ => Request::Bad,
    }
}

pub fn head(size: u64) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: keep-alive\r\n\r\n")
}

/// Reads exactly `len` body bytes, storing nothing.
async fn drain(stream: &mut tokio::net::TcpStream, mut len: u64) -> io::Result<()> {
    let mut sink = [0u8; 64 * 1024];
    while len > 0 {
        let take = (len as usize).min(sink.len());
        let read = stream.read(&mut sink[..take]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "perf upload body cut short",
            ));
        }
        len -= read as u64;
    }
    Ok(())
}
