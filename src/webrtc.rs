//! WebRTC strategy (EPIC-005 I06): ICE/DTLS/SCTP data channel (RFC 8831).
//!
//! A real WebRTC stack (str0m, sans-I/O): channel hardening with ICE, a
//! DTLS 1.2 handshake with fingerprint verification, an SCTP association
//! with a DATA channel `unordered, maxRetransmits=0` — the UDP-like mode of
//! RFC 8831. One UDP socket per side: STUN/DTLS/SCTP are multiplexed inside
//! str0m.
//!
//! Signaling without SDP or third-party servers: `Hello` (ICE credentials,
//! DTLS fingerprint, host candidate) travels over the SSH control channel
//! (wired up in I07/I08). The server is ICE-lite with a public address, the
//! client is controlling; str0m handles Nomination and consent freshness as
//! long as the `recv`/`wait_ready` pump keeps running.
//!
//! Limitations (deliberate, within the epic's scope):
//! - A client behind NAT does not know its external address: its
//!   `Hello.candidate` is None; the server discovers the peer-reflexive
//!   candidate from incoming STUN.
//! - Channel readiness does not mean the SVPN path is passable:
//!   "DTLS connected" alone does not allow emitting IP packets (that
//!   decision belongs to session).
//! - The interop check is two independent `Rtc` instances over real OS
//!   sockets; a browser peer is outside the epic's scope.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceCreds, Input, Output, Rtc};

use crate::pcap::PcapBuilder;

/// Data channel label; the server accepts only this one.
pub const LABEL: &str = "svpn";
/// IP record budget in the data channel: SCTP DATA (~16 B) + DTLS record
/// (13 B header + 16 B tag) on top of a UDP datagram ≤1200 B.
pub const FRAGMENT_BUDGET: usize = 1200 - 60;

// The default 128 KiB would cap SCTP at roughly 26 Mbit/s at 40 ms RTT even
// before overhead; 1 MiB keeps the window from being the bottleneck.
pub const SCTP_SEND_BUFFER_SIZE: usize = 1024 * 1024;

/// A side's signaling message: sent over the SSH control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub ufrag: String,
    pub pass: String,
    /// DTLS fingerprint in SDP format `"sha-256 AA:BB:…"`.
    pub fingerprint: String,
    /// The side's host candidate; None if the address is unknown (for a
    /// client behind NAT the server learns the peer-reflexive one from incoming STUN).
    #[serde(default)]
    pub candidate: Option<SocketAddr>,
}

/// One side of the WebRTC connection: a sans-I/O engine + a dedicated UDP socket.
pub struct Peer {
    pub rtc: Rtc,
    pub socket: tokio::net::UdpSocket,
    /// The controlling side: DTLS/SCTP client, creates the data channel.
    dtls_client: bool,
    pub channel: Option<ChannelId>,
    /// One UDP packet can yield several ChannelData; we keep every record.
    pending: VecDeque<Vec<u8>>,
    pub wire: Option<PcapBuilder>,
}

/// One-time background warmup of the lazily initialized crypto. The first
/// peer in the process pays tens of milliseconds (up to ~350 ms on a
/// router) for it, later peers cost microseconds; a round that builds the
/// first peer synchronously stalls every other candidate behind it. Call
/// once at startup; the built peer is discarded.
pub fn prewarm() {
    std::thread::spawn(|| {
        let _ = Peer::client(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)));
    });
}

impl Peer {
    /// Server side: ICE-lite, DTLS/SCTP passive. `public` is the address
    /// for the client (the socket may listen on 0.0.0.0); None — use the
    /// socket's address.
    pub fn server(bind: SocketAddr, public: Option<SocketAddr>) -> Result<(Peer, Hello)> {
        let socket = UdpSocket::bind(bind).context("bind WebRTC server socket")?;
        let candidate = match public {
            Some(addr) => SocketAddr::new(addr.ip(), socket.local_addr()?.port()),
            None => socket.local_addr()?,
        };
        let mut rtc = Rtc::builder()
            .set_sctp_max_buffered_amount(SCTP_SEND_BUFFER_SIZE)
            .build(Instant::now());
        rtc.direct_api().set_ice_lite(true);
        rtc.direct_api().set_ice_controlling(false);
        let candidate_value = Candidate::host(candidate, "udp").context("host candidate")?;
        ensure!(
            rtc.add_local_candidate(candidate_value).is_some(),
            "local candidate rejected"
        );
        let hello_value = hello(&mut rtc, Some(candidate));
        Ok((Peer::from_parts(rtc, socket, false)?, hello_value))
    }

    /// Client side: controlling, DTLS/SCTP active, sends the first packet.
    /// `bind` with an unspecified address is allowed (the candidate is then None).
    pub fn client(bind: SocketAddr) -> Result<(Peer, Hello)> {
        let socket = UdpSocket::bind(bind).context("bind WebRTC client socket")?;
        let local = socket.local_addr()?;
        let candidate = (!local.ip().is_unspecified()).then_some(local);
        let mut rtc = Rtc::builder()
            .set_sctp_max_buffered_amount(SCTP_SEND_BUFFER_SIZE)
            .build(Instant::now());
        rtc.direct_api().set_ice_controlling(true);
        if let Some(addr) = candidate {
            let host = Candidate::host(addr, "udp").context("host candidate")?;
            ensure!(
                rtc.add_local_candidate(host).is_some(),
                "local candidate rejected"
            );
        }
        let hello_value = hello(&mut rtc, candidate);
        Ok((Peer::from_parts(rtc, socket, true)?, hello_value))
    }

    fn from_parts(rtc: Rtc, socket: UdpSocket, dtls_client: bool) -> Result<Peer> {
        // The default UDP buffer dropped packets during SCTP traffic bursts (W01).
        socket2::SockRef::from(&socket)
            .set_recv_buffer_size(1024 * 1024)
            .context("WebRTC receive buffer")?;
        socket
            .set_nonblocking(true)
            .context("nonblocking WebRTC socket")?;
        let socket = tokio::net::UdpSocket::from_std(socket).context("async WebRTC socket")?;
        Ok(Peer {
            rtc,
            socket,
            dtls_client,
            channel: None,
            pending: VecDeque::new(),
            wire: None,
        })
    }

    /// Wires up the other side's signaling and starts DTLS/SCTP.
    /// The client side creates the data channel; the server side opens it via DCEP.
    pub fn configure(&mut self, hello: &Hello) -> Result<()> {
        let mut d = self.rtc.direct_api();
        d.set_remote_ice_credentials(IceCreds {
            ufrag: hello.ufrag.clone(),
            pass: hello.pass.clone(),
        });
        let fingerprint: str0m::crypto::Fingerprint = hello
            .fingerprint
            .parse()
            .map_err(|e: String| anyhow::anyhow!("fingerprint: {e}"))?;
        d.set_remote_fingerprint(fingerprint);
        if let Some(addr) = hello.candidate {
            // A socket bound to 0.0.0.0 yields no local candidate, and
            // without one ICE starts no checks. Connecting to the peer's
            // address reveals the egress IP.
            if self.socket.local_addr()?.ip().is_unspecified() {
                let probe = std::net::UdpSocket::bind("0.0.0.0:0").context("bind egress probe")?;
                probe.connect(addr).context("egress probe connect")?;
                let local = probe.local_addr().context("egress probe addr")?;
                let host = Candidate::host(local, "udp").context("host candidate")?;
                ensure!(
                    self.rtc.add_local_candidate(host).is_some(),
                    "local candidate rejected"
                );
            }
            let host = Candidate::host(addr, "udp").context("host candidate")?;
            self.rtc.add_remote_candidate(host);
        }
        // The roles mirror connect_l_r from str0m's tests: the controlling
        // side is the DTLS and SCTP client, the ICE-lite server is passive.
        self.rtc
            .direct_api()
            .start_dtls(self.dtls_client)
            .context("start dtls")?;
        self.rtc.direct_api().start_sctp(self.dtls_client);
        if self.dtls_client {
            // The channel counts as open only after Event::ChannelOpen
            // (DCEP acknowledgment) — the event reaches both sides.
            self.rtc.direct_api().create_data_channel(ChannelConfig {
                label: LABEL.to_owned(),
                ordered: false,
                reliability: Reliability::MaxRetransmits { retransmits: 0 },
                ..ChannelConfig::default()
            });
        }
        Ok(())
    }

    /// ICE+DTLS+SCTP are up and the data channel is open.
    pub fn is_ready(&self) -> bool {
        self.channel.is_some() && self.rtc.is_connected()
    }

    /// Queues a record into SCTP; false means the buffer is full, retry after incoming ACKs.
    pub fn write(&mut self, data: &[u8]) -> Result<bool> {
        let id = self.channel.context("data channel is not open")?;
        self.rtc
            .channel(id)
            .context("data channel vanished")?
            .write(true, data)
            .context("sctp write")
    }

    /// Waits for ICE/DTLS/SCTP + DCEP readiness, advancing input and timers.
    pub async fn wait_ready(&mut self, deadline: Instant) -> Result<()> {
        loop {
            let next = self.poll().await?;
            if self.is_ready() {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "WebRTC handshake deadline exceeded"
            );
            self.input(next.min(deadline)).await?;
        }
    }

    pub fn take_received(&mut self) -> Option<Vec<u8>> {
        self.pending.pop_front()
    }

    /// Receives a record; None means the deadline has expired.
    pub async fn recv(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>> {
        loop {
            let next = self.poll().await?;
            if let Some(data) = self.take_received() {
                return Ok(Some(data));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            self.input(next.min(deadline)).await?;
        }
    }

    /// Enables recording wire datagrams (both sides) into the pcap artifact.
    pub fn record_wire(&mut self, pcap: PcapBuilder) {
        self.wire = Some(pcap);
    }

    /// Stashes a datagram for the pcap artifact (active only after `record_wire`).
    fn note_wire(&mut self, bytes: &[u8]) {
        if let Some(pcap) = self.wire.as_mut() {
            pcap.add_datagram(bytes);
        }
    }

    /// Receives one UDP packet or advances str0m's nearest timer.
    /// Cancellation is safe: there is no other await point between the
    /// select and handle_input.
    pub async fn input(&mut self, deadline: Instant) -> Result<()> {
        let mut buf = vec![0u8; 65_535];
        let input = tokio::select! {
            packet = self.socket.recv_from(&mut buf) => {
                let (len, from) = packet.context("udp recv")?;
                crate::debug!("webrtc receive <- {from} ({len}b)");
                let contents = (&buf[..len])
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("datagram parse: {e:?}"))?;
                self.note_wire(&buf[..len]);
                Input::Receive(
                    Instant::now(),
                    Receive {
                        proto: Protocol::Udp,
                        source: from,
                        destination: self.socket.local_addr()?,
                        contents,
                    },
                )
            }
            _ = tokio::time::sleep_until(deadline.into()) => Input::Timeout(Instant::now()),
        };
        self.rtc.handle_input(input).context("rtc input")
    }

    /// Fully drains str0m's output until Timeout. Called outside select so
    /// that cancelling a command wait does not lose an already polled Transmit.
    pub async fn poll(&mut self) -> Result<Instant> {
        loop {
            match self.rtc.poll_output().context("rtc poll")? {
                Output::Timeout(at) => return Ok(at),
                Output::Transmit(transmit) => {
                    crate::debug!(
                        "webrtc transmit -> {} ({}b)",
                        transmit.destination,
                        transmit.contents.len()
                    );
                    self.socket
                        .send_to(&transmit.contents, transmit.destination)
                        .await
                        .context("udp send")?;
                    self.note_wire(&transmit.contents);
                }
                Output::Event(Event::ChannelOpen(id, label)) if label == LABEL => {
                    self.channel = Some(id);
                }
                Output::Event(Event::ChannelData(data)) if Some(data.id) == self.channel => {
                    self.pending.push_back(data.data);
                }
                Output::Event(_) => {}
            }
        }
    }
}

/// A side's Hello from its engine: credentials + fingerprint in SDP format.
fn hello(rtc: &mut Rtc, candidate: Option<SocketAddr>) -> Hello {
    let creds = rtc.direct_api().local_ice_credentials();
    let fingerprint = rtc.direct_api().local_dtls_fingerprint().to_string();
    Hello {
        ufrag: creds.ufrag,
        pass: creds.pass,
        fingerprint,
        candidate,
    }
}
