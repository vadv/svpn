//! TCP flow transport (EPIC-003): one listening port per session, every
//! connection is initiated by the client. The binding token correlates a
//! connection with a flow, then `framing` frames (including the Ssh layer)
//! carry packets sealed by `Cipher::seal`.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, tcp::OwnedWriteHalf},
    sync::{mpsc, oneshot},
};

use crate::crypto::Cipher;
use crate::framing::{self, Camouflage, TOKEN_BYTES};
use crate::link_io::is_probe_flow;
use crate::udp::Incoming;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_CHUNK: usize = 4096;
/// Periodic small L2 frame while the flow is idle (T02, requirement 6).
const SSH_KEEPALIVE: Duration = Duration::from_secs(30);

/// TCP mode configuration of the session (one port for all flows).
#[derive(Clone, Copy)]
pub struct Mode {
    pub port: u16,
    pub camouflage: Camouflage,
}

/// Event from the transport background task to the session loop.
pub enum Event {
    /// A decrypted IP packet of a flow.
    Packet(Incoming),
    /// Client: binding sent (preflight also verified a reply). Server: binding authenticated.
    Connected { id: u64 },
    /// Connect/binding failed: the selector must learn about the refusal
    /// (auto mode bans the TCP candidate and decides whether the list is exhausted).
    Failed { id: u64 },
    /// Clean stream EOF; the session classifies it using the inner flow state.
    Closed { id: u64 },
    /// An incoming connection presented a binding token; the session matches
    /// the token to a flow.
    Bound {
        token: [u8; TOKEN_BYTES],
        conn: oneshot::Sender<Result<Bound>>,
    },
}

/// Session reply to `Event::Bound`: flow parameters and the outgoing packet channel.
pub struct Bound {
    pub id: u64,
    pub key: [u8; 16],
    pub outgoing: mpsc::Receiver<Vec<u8>>,
}

/// Binds the mimic TCP listener. SO_REUSEADDR: a session restart must
/// rebind the fixed port while accepted connections of the old session
/// still sit in TIME_WAIT. Server-side only: on macOS this flag would let
/// a second live process steal the port, so client code must not reuse it.
pub async fn bind_listener(addr: SocketAddr) -> Result<TcpListener> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
        .context("create TCP listener socket")?;
    socket
        .set_reuse_address(true)
        .context("set SO_REUSEADDR on TCP listener")?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("bind TCP flow listener on {addr}"))?;
    socket.listen(1024).context("listen TCP flow listener")?;
    socket
        .set_nonblocking(true)
        .context("TCP listener nonblocking")?;
    TcpListener::from_std(socket.into())
        .with_context(|| format!("bind TCP flow listener on {addr}"))
}

pub async fn bind(port: u16) -> Result<TcpListener> {
    bind_listener((std::net::Ipv4Addr::UNSPECIFIED, port).into()).await
}

/// Accepts one connection; without a listener (client role) it never completes.
pub async fn accept(
    listener: Option<&mut TcpListener>,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

/// Server side of a connection: camouflage hello, binding frame, packet pump.
pub async fn serve(
    mut stream: TcpStream,
    camouflage: Camouflage,
    events: mpsc::Sender<Event>,
) -> Result<()> {
    // Interactive mimic: Nagle would delay probe answers and fragment pacing
    // the same way it delays an SSH keystroke.
    stream.set_nodelay(true).context("set TCP_NODELAY")?;
    let mut decoder = decoder(camouflage, true);
    write_hello(&mut stream, camouflage, true).await?;
    // Exactly one frame is allowed before token matching — the binding frame.
    let payload = loop {
        if let Some(payload) = decoder.next(None)? {
            break payload;
        }
        let mut chunk = [0u8; READ_CHUNK];
        let read = stream
            .read(&mut chunk)
            .await
            .context("read TCP binding frame")?;
        ensure!(read != 0, "TCP connection closed before binding frame");
        decoder.push(&chunk[..read]);
    };
    let (token, first) = framing::split_binding(&payload)?;
    let token: [u8; TOKEN_BYTES] = token.try_into().expect("split_binding yields 16 bytes");
    let (reply, resolve) = oneshot::channel();
    events
        .send(Event::Bound { token, conn: reply })
        .await
        .context("session stopped while binding TCP connection")?;
    let bound = resolve
        .await
        .context("session dropped TCP binding resolver")??;
    let mut cipher = Cipher::new(bound.key, bound.id, false);
    let packet = cipher
        .open(first)
        .context("TCP binding frame authentication failed")?;
    if camouflage == Camouflage::Ssh {
        // kex-reply/NEWKEYS/auth frames mean "kex complete"; AEAD-lookalike frames follow.
        stream.write_all(&framing::ssh_server_tail()).await?;
    }
    if is_probe_flow(bound.id) && packet.is_empty() {
        // Plain-TCP plane preflight: answer the empty binding with an empty
        // frame — the handshake round-trip is the verdict.
        let response = encode_frame(&mut cipher, camouflage, &[])?;
        stream.write_all(&response).await?;
        return Ok(());
    }
    events.send(Event::Connected { id: bound.id }).await?;
    if !packet.is_empty() {
        events
            .send(Event::Packet(Incoming {
                id: bound.id,
                channel: None,
                packet,
            }))
            .await?;
    }
    pump(
        stream,
        &mut cipher,
        bound.id,
        bound.outgoing,
        decoder,
        camouflage,
        events,
    )
    .await
}

/// Client side: connect, banner, binding frame carrying the first packet, pump.
pub async fn connect(
    remote: SocketAddr,
    camouflage: Camouflage,
    id: u64,
    key: [u8; 16],
    token: [u8; TOKEN_BYTES],
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    events: mpsc::Sender<Event>,
) -> Result<()> {
    let first = outgoing
        .recv()
        .await
        .context("flow closed before TCP connect")?;
    if is_probe_flow(id) && first.is_empty() {
        // Plain-TCP plane: an empty binding — the handshake itself is the probe.
        preflight(remote, camouflage, id, key, token).await?;
        events
            .send(Event::Connected { id })
            .await
            .context("session stopped during TCP preflight")?;
        return Ok(());
    }
    let (stream, mut cipher, decoder) =
        connect_bound(remote, camouflage, id, key, token, &first).await?;
    events.send(Event::Connected { id }).await.ok();
    pump(
        stream,
        &mut cipher,
        id,
        outgoing,
        decoder,
        camouflage,
        events,
    )
    .await
}

/// Verify an authenticated round trip before admitting the server to a pool.
/// The caller allocates and retires the technical flow over the control channel.
pub async fn preflight(
    remote: SocketAddr,
    camouflage: Camouflage,
    id: u64,
    key: [u8; 16],
    token: [u8; TOKEN_BYTES],
) -> Result<()> {
    ensure!(is_probe_flow(id), "invalid TCP preflight ID");
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        let (mut stream, mut cipher, mut decoder) =
            connect_bound(remote, camouflage, id, key, token, &[]).await?;
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            if let Some(payload) = decoder.next(Some(&mut cipher))? {
                let packet = cipher
                    .open(&payload)
                    .context("TCP probe authentication failed")?;
                ensure!(packet.is_empty(), "unexpected TCP probe payload");
                return Ok(());
            }
            let read = stream
                .read(&mut chunk)
                .await
                .context("read TCP probe reply")?;
            ensure!(
                read != 0,
                "TCP probe closed without confirmation; update the server binary"
            );
            decoder.push(&chunk[..read]);
        }
    })
    .await
    .context("TCP probe timed out; server must support authenticated probe replies")?
}

pub async fn pump(
    stream: TcpStream,
    cipher: &mut Cipher,
    id: u64,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    mut decoder: framing::Decoder,
    camouflage: Camouflage,
    events: mpsc::Sender<Event>,
) -> Result<()> {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        // The binding read can also contain data; never wait for a second read.
        while let Some(payload) = decoder.next(Some(&mut *cipher))? {
            let packet = cipher
                .open(&payload)
                .context("TCP frame authentication failed")?;
            if !packet.is_empty() {
                events
                    .send(Event::Packet(Incoming {
                        id,
                        channel: None,
                        packet,
                    }))
                    .await?;
            }
        }
        tokio::select! {
            packet = outgoing.recv() => {
                let Some(packet) = packet else { return Ok(()) };
                write_frame(&mut write_half, cipher, camouflage, &packet).await?;
            }
            _ = tokio::time::sleep(SSH_KEEPALIVE), if matches!(camouflage, Camouflage::Ssh) => {
                // Small frame while idle (T02 §6); empty payload is a keepalive.
                write_frame(&mut write_half, cipher, camouflage, &[]).await?;
            }
            read = read_half.read(&mut chunk) => {
                let read = read.context("read TCP flow stream")?;
                if read == 0 {
                    decoder.finish()?;
                    events.send(Event::Closed { id }).await?;
                    return Ok(());
                }
                decoder.push(&chunk[..read]);
            }
        }
    }
}

pub fn encode_frame(cipher: &mut Cipher, camouflage: Camouflage, packet: &[u8]) -> Result<Vec<u8>> {
    match camouflage {
        Camouflage::Ssh => framing::ssh_frame(cipher, packet),
        _ => framing::frame(&cipher.seal(packet)?),
    }
}

async fn connect_bound(
    remote: SocketAddr,
    camouflage: Camouflage,
    id: u64,
    key: [u8; 16],
    token: [u8; TOKEN_BYTES],
    first: &[u8],
) -> Result<(TcpStream, Cipher, framing::Decoder)> {
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(remote))
        .await
        .context("TCP flow connect timeout")?
        .with_context(|| format!("connect TCP flow {remote}"))?;
    // Interactive mimic (see `serve`): answers and fragments must not wait
    // for Nagle coalescing.
    stream.set_nodelay(true).context("set TCP_NODELAY")?;
    let mut cipher = Cipher::new(key, id, true);
    let decoder = decoder(camouflage, false);
    write_hello(&mut stream, camouflage, false).await?;
    let sealed = cipher.seal(first)?;
    let binding = match camouflage {
        Camouflage::Ssh => {
            let mut bytes = framing::ssh_binding_frame(&token, &sealed)?;
            bytes.extend(framing::ssh_client_tail());
            bytes
        }
        _ => framing::frame(&framing::binding_payload(&token, &sealed))?,
    };
    stream.write_all(&binding).await?;
    Ok((stream, cipher, decoder))
}

async fn write_frame(
    half: &mut OwnedWriteHalf,
    cipher: &mut Cipher,
    camouflage: Camouflage,
    packet: &[u8],
) -> Result<()> {
    half.write_all(&encode_frame(cipher, camouflage, packet)?)
        .await?;
    Ok(())
}

/// Decoder for the peer's stream; the peer is the client when we are the server.
fn decoder(camouflage: Camouflage, server: bool) -> framing::Decoder {
    match camouflage {
        Camouflage::Ssh => framing::Decoder::new_ssh(server),
        _ => framing::Decoder::new(camouflage),
    }
}

/// Hello bytes of our role: banner, or the SSH banner+kexinit.
async fn write_hello(stream: &mut TcpStream, camouflage: Camouflage, server: bool) -> Result<()> {
    match camouflage {
        Camouflage::None => {}
        Camouflage::Banner => stream.write_all(framing::banner()).await?,
        Camouflage::Ssh => {
            let hello = if server {
                framing::ssh_server_hello()
            } else {
                framing::ssh_client_hello()
            };
            stream.write_all(&hello).await?;
        }
    }
    Ok(())
}
