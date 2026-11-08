//! Stream the configured CSV to the browser; no organization parsing or cache.

use std::{path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Total transfer budget, independent of the short header/idle-write deadline.
pub const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CSV_BYTES: u64 = 128 * 1024 * 1024;

pub async fn serve_csv(stream: &mut TcpStream, path: &Path) -> Result<()> {
    tokio::time::timeout(TRANSFER_TIMEOUT, transfer(stream, path))
        .await
        .context("ASN CSV transfer timeout")?
}

async fn transfer(stream: &mut TcpStream, path: &Path) -> Result<()> {
    let mut file = match File::open(path).await {
        Ok(file) => file,
        Err(error) => {
            crate::warn!("dashboard ASN CSV open: {error}");
            return super::respond(
                stream,
                503,
                "text/plain; charset=utf-8",
                b"ASN CSV unavailable",
            )
            .await;
        }
    };
    let metadata = file.metadata().await.context("ASN CSV metadata")?;
    if !metadata.is_file() || metadata.len() > MAX_CSV_BYTES {
        return super::respond(
            stream,
            503,
            "text/plain; charset=utf-8",
            b"ASN CSV is not a supported regular file",
        )
        .await;
    }
    write(
        stream,
        super::response_head(200, "text/csv; charset=utf-8", metadata.len()).as_bytes(),
    )
    .await?;
    // Bound memory and capture this open inode/length across atomic DB updates.
    let mut remaining = metadata.len();
    let mut buffer = [0u8; 16 * 1024];
    while remaining != 0 {
        let limit = remaining.min(buffer.len() as u64) as usize;
        let read = file
            .read(&mut buffer[..limit])
            .await
            .context("read ASN CSV")?;
        ensure!(read != 0, "ASN CSV truncated during transfer");
        write(stream, &buffer[..read]).await?;
        remaining -= read as u64;
    }
    tokio::time::timeout(super::REQUEST_TIMEOUT, stream.flush())
        .await
        .context("ASN CSV flush timeout")??;
    Ok(())
}

async fn write(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(super::REQUEST_TIMEOUT, stream.write_all(bytes))
        .await
        .context("ASN CSV write timeout")?
        .context("write ASN CSV")
}
