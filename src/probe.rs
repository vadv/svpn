//! UDP channel establishment: protected challenge/response
//! A → echo-A+B → echo-B and a size probe up to the wire cap inside the
//! AEAD channel. Each call verifies only a data-plane fact
//! it checked itself; peer reports travel as session control messages.
//! `flow_id=0` is reserved: channel service records.
#![allow(dead_code)]

use anyhow::{Result, bail, ensure};
use std::time::Instant as StdInstant;
use tokio::time::Instant;

use crate::channel::{self, Channel, Record};
use crate::crypto::MAX_PLAINTEXT;
use crate::drivers::{Command, Event, Io};

/// Client side of establishment: initiates and verifies the echo in both directions.
pub async fn client(
    io: &mut Io,
    channel: &mut Channel,
    cap: usize,
    deadline: Instant,
) -> Result<()> {
    let a = channel::challenge()?;
    exchange(io, channel, &Record::ProbeA { challenge: a }).await?;
    let b = match next_record(io, channel, deadline).await? {
        Record::ProbeAb { echo, challenge } => {
            ensure!(echo == a, "probe echo mismatch");
            challenge
        }
        _ => bail!("unexpected record before PROBE_AB"),
    };
    exchange(io, channel, &Record::ProbeB { echo: b }).await?;
    size_probe(io, channel, cap, deadline).await
}

/// Server side of establishment: replies to A, verifies echo-B.
pub async fn server(
    io: &mut Io,
    channel: &mut Channel,
    cap: usize,
    deadline: Instant,
) -> Result<()> {
    let a = match next_record(io, channel, deadline).await? {
        Record::ProbeA { challenge } => challenge,
        _ => bail!("unexpected record before PROBE_A"),
    };
    let b = channel::challenge()?;
    exchange(
        io,
        channel,
        &Record::ProbeAb {
            echo: a,
            challenge: b,
        },
    )
    .await?;
    match next_record(io, channel, deadline).await? {
        Record::ProbeB { echo } => ensure!(echo == b, "probe echo mismatch"),
        _ => bail!("unexpected record before PROBE_B"),
    }
    size_echo(io, channel, cap, deadline).await
}

/// Brings the size-probe record up to the wire cap and waits for the echo (client).
async fn size_probe(
    io: &mut Io,
    channel: &mut Channel,
    cap: usize,
    deadline: Instant,
) -> Result<()> {
    // sealed = plain + 24 (seq 8 + tag 16); plain = kind 1 + zeros 8 + padding.
    let padding_len = cap.saturating_sub(33).min(MAX_PLAINTEXT - 9);
    let mut padding = vec![0u8; padding_len];
    getrandom::fill(&mut padding).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
    exchange(io, channel, &Record::SizeProbe { padding }).await?;
    match next_record(io, channel, deadline).await? {
        Record::SizeProbe { .. } => Ok(()),
        _ => bail!("unexpected record before SIZE_PROBE echo"),
    }
}

/// The server checks the size against its own cap and echoes the size probe back.
async fn size_echo(
    io: &mut Io,
    channel: &mut Channel,
    cap: usize,
    deadline: Instant,
) -> Result<()> {
    let padding = match next_record(io, channel, deadline).await? {
        Record::SizeProbe { padding } => {
            ensure!(padding.len() + 33 <= cap, "size probe exceeds cap");
            padding
        }
        _ => bail!("unexpected record before SIZE_PROBE"),
    };
    exchange(io, channel, &Record::SizeProbe { padding }).await
}

/// Channel record exchange: seal → driver command; events → open.
async fn exchange(io: &mut Io, channel: &mut Channel, record: &Record) -> Result<()> {
    let sealed = channel.seal(record)?;
    io.command
        .send(Command::Send(sealed))
        .await
        .map_err(|_| anyhow::anyhow!("transport task closed"))?;
    Ok(())
}

/// Next channel record: event → AEAD-open. The deadline covers the whole attempt.
async fn next_record(io: &mut Io, channel: &mut Channel, deadline: Instant) -> Result<Record> {
    let now = Instant::now();
    ensure!(now < deadline, "probe deadline exceeded");
    let event = tokio::time::timeout_at(deadline, io.events.recv())
        .await
        .map_err(|_| anyhow::anyhow!("probe deadline exceeded"))?
        .ok_or_else(|| anyhow::anyhow!("transport task closed"))?;
    match event {
        Event::Wire(bytes) => channel
            .open(&bytes, StdInstant::now())?
            .ok_or_else(|| anyhow::anyhow!("replayed channel record")),
        Event::Failed(reason) => bail!("transport failed: {reason}"),
    }
}
