//! QUIC/H3 strategy: a MASQUE-like tunnel per RFC 9298.
//!
//! Real QUIC/TLS 1.3 (quinn, ALPN `h3`) + HTTP/3 extended CONNECT
//! (`:protocol connect-udp`, RFC 9298) as the controlling stream; channel
//! IP-records travel as unreliable QUIC datagrams (RFC 9297), not streams.
//!
//! HTTP datagram format: `[quarter_stream_id=0x00][context_id=0x00][udp]`
//! (our tunnel is the only extended CONNECT on the connection, stream 0;
//! context 0 is assigned to the stream implicitly, RFC 9298 §5).
//!
//! Limitations (deliberate, within the epic's scope):
//! - Only the fixed destination (target) set by the server is proxied;
//!   `:authority` is checked against it — this is not an open proxy.
//! - The stream capsule protocol (REGISTER/CLOSE, RFC 9293) is not
//!   implemented: closing the tunnel means closing the QUIC connection.
//!   Not compatible with third-party MASQUE proxies; such compatibility
//!   is not required.
//! - Certificate pin = SHA-256 of the whole end-entity certificate DER
//!   (not SPKI): the pair is self-signed and lives within a single session;
//!   regenerating the certificate without changing the key is unsupported.
//!
//! shortcut: no capsule framing or REGISTER_CAPSULE, revisit when
//! integrating with third-party MASQUE clients (outside the current epic).
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use bytes::{Bytes, BytesMut};
use http::{Method, StatusCode, Uri};
use quinn::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use quinn::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use quinn::{Connection, Endpoint};
use sha2::{Digest, Sha256};

/// SNI of the server's self-signed certificate (the same on both sides).
pub const SNI: &str = "cdn-lookalike.example";

/// HTTP/3 ALPN.
pub const ALPN: &[u8] = b"h3";
/// Extended CONNECT pseudo-header (RFC 9298).
pub const PROTOCOL: &str = "connect-udp";
/// Datagram UDP payload budget: QUIC guarantees delivery of packets
/// ≤1200 B; the QUIC+AEAD+frame header is ≤ 60 B and the [0x00 0x00] prefix is 2 B.
pub const FRAGMENT_BUDGET: usize = 1200 - 62;
/// UDP relay receive buffer, in bytes.
pub const RELAY_BUFFER: usize = 65_535;
/// Raised kernel receive buffer for the QUIC socket: TUN bursts overflow the
/// kernel default and drop datagrams before quinn reads them (same rationale
/// as the WebRTC socket, W01).
const UDP_RCVBUF: usize = 1024 * 1024;
/// HTTP datagram prefix: quarter_stream_id + context_id.
pub const DATAGRAM_PREFIX: [u8; 2] = [0x00, 0x00];

/// Stripped-down verifier: we trust only the certificate with the known pin.
#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, quinn::rustls::Error> {
        if cert_pin(end_entity) != self.pin {
            return Err(quinn::rustls::Error::General(
                "certificate pin mismatch".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    // The handshake is already authenticated by the pin; CERTIFICATE_VERIFY
    // signatures are checked by rustls inside its own stack.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &quinn::rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, quinn::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &quinn::rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, quinn::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
        vec![
            quinn::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            quinn::rustls::SignatureScheme::ED25519,
            quinn::rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// Client tunnel: UDP semantics over HTTP datagrams.
pub struct Tunnel {
    endpoint: Endpoint,
    quic: Connection,
    /// The CONNECT stream keeps the tunnel open.
    _stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
}

impl Tunnel {
    /// Maximum UDP payload size (without the prefix) as negotiated by QUIC.
    pub fn max_payload(&self) -> Option<usize> {
        self.quic
            .max_datagram_size()
            .map(|limit| limit.saturating_sub(DATAGRAM_PREFIX.len()))
    }

    pub fn send(&self, udp: &[u8]) -> Result<()> {
        ensure!(
            udp.len() + DATAGRAM_PREFIX.len() <= self.max_payload().context("datagrams off")?,
            "datagram {} exceeds budget",
            udp.len()
        );
        let mut frame = BytesMut::with_capacity(udp.len() + DATAGRAM_PREFIX.len());
        frame.extend_from_slice(&DATAGRAM_PREFIX);
        frame.extend_from_slice(udp);
        self.quic
            .send_datagram(frame.freeze())
            .map_err(|e| anyhow::anyhow!("send datagram: {e}"))
    }

    pub async fn recv(&self) -> Result<Bytes> {
        loop {
            let datagram = self.quic.read_datagram().await.context("read datagram")?;
            // A foreign quarter stream id (not 0) is not our tunnel; skip it.
            if let Some(udp) = decode_datagram(&datagram).ok().filter(|u| !u.is_empty()) {
                return Ok(Bytes::copy_from_slice(udp));
            }
        }
    }

    /// Closes the tunnel and the endpoint; no reconnect semantics.
    pub fn close(&self) {
        self.quic.close(0u32.into(), b"tunnel closed");
        self.endpoint.close(0u32.into(), b"tunnel closed");
    }
}

/// SHA-256 of the certificate DER: the pin value passed over the control channel.
pub fn cert_pin(cert: &CertificateDer<'_>) -> [u8; 32] {
    Sha256::digest(cert.as_ref()).into()
}

/// Server endpoint: listens on `bind`, serves a single tunnel to `target`
/// per connection.
pub fn server_endpoint(
    bind: SocketAddr,
    cert: CertificateDer<'static>,
    key: quinn::rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Endpoint> {
    let mut crypto = quinn::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("server certificate")?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).context("quinn server crypto")?,
    ));
    config.transport_config(Arc::new(datagram_transport()));
    let socket = udp_socket(bind)?;
    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("create QUIC server endpoint")
}

/// Accepts exactly one connection and relays its UDP datagrams to `target`.
/// The QUIC strategy channel registers its loopback socket as the target
/// and waits for the client to connect; concurrent accepts on one endpoint
/// are safe (quinn hands out connections one at a time).
pub async fn accept_relay(endpoint: &Endpoint, target: SocketAddr) -> Result<()> {
    let incoming = endpoint.accept().await.context("QUIC listener closed")?;
    let conn = incoming.await.context("QUIC handshake")?;
    let quic = conn.clone();
    let mut h3 = h3::server::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build::<h3_quinn::Connection, Bytes>(h3_quinn::Connection::new(conn))
        .await
        .context("H3 handshake")?;
    // One tunnel per connection: a CONNECT with a foreign :authority gets 403.
    let resolver = h3
        .accept()
        .await
        .context("H3 accept")?
        .context("H3 closed before CONNECT")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    if request.method() != Method::CONNECT
        || request.extensions().get::<h3::ext::Protocol>() != Some(&h3::ext::Protocol::CONNECT_UDP)
        || request.uri() != &connect_uri(target)
    {
        stream
            .send_response(
                http::Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(())
                    .unwrap(),
            )
            .await
            .ok();
        // FIN, then the normal H3 shutdown (GoAway), so the client manages
        // to read the 403 before the connection closes.
        stream.finish().await.ok();
        let _ = h3.accept().await;
        return Ok(());
    }
    stream
        .send_response(
            http::Response::builder()
                .status(StatusCode::OK)
                .body(())
                .unwrap(),
        )
        .await
        .context("CONNECT response")?;
    relay(quic, target).await
}

/// Connects to the QUIC/H3 server and opens a CONNECT-UDP tunnel to `target`.
/// `sni` is the name for the ClientHello; `pin` is the SHA-256 of the server certificate DER.
pub async fn connect(
    server: SocketAddr,
    sni: &str,
    pin: [u8; 32],
    target: SocketAddr,
) -> Result<Tunnel> {
    ServerName::try_from(sni).map_err(|_| anyhow::anyhow!("invalid SNI {sni}"))?;
    let verifier = Arc::new(PinVerifier { pin });
    let mut crypto = quinn::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    config.transport_config(Arc::new(datagram_transport()));
    let mut endpoint = client_endpoint()?;
    endpoint.set_default_client_config(config);
    let conn = endpoint
        .connect(server, sni)
        .context("QUIC connect")?
        .await
        .context("QUIC handshake")?;
    let quic = conn.clone();
    let (mut h3, mut request) = h3::client::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
        .await
        .context("H3 handshake")?;
    let _ = &mut h3;
    let connect = http::Request::builder()
        .method(Method::CONNECT)
        .uri(connect_uri(target))
        .extension(h3::ext::Protocol::CONNECT_UDP)
        .body(())
        .context("build CONNECT request")?;
    let mut stream = request
        .send_request(connect)
        .await
        .context("send CONNECT")?;
    let response = stream.recv_response().await.map_err(|e| {
        let full = format!("{e:#}");
        anyhow::anyhow!("CONNECT response: {full}")
    })?;
    ensure!(
        response.status() == StatusCode::OK,
        "tunnel rejected: {}",
        response.status()
    );
    Ok(Tunnel {
        endpoint,
        quic,
        _stream: stream,
    })
}

/// Decodes an HTTP datagram: `[quarter=0][ctx=0][udp]`.
pub fn decode_datagram(datagram: &Bytes) -> Result<&[u8]> {
    ensure!(
        datagram.len() > DATAGRAM_PREFIX.len() && datagram.starts_with(&DATAGRAM_PREFIX),
        "unexpected datagram prefix {:?}",
        &datagram[..DATAGRAM_PREFIX.len().min(datagram.len())]
    );
    Ok(&datagram[DATAGRAM_PREFIX.len()..])
}

/// Negotiated fragment budget after record and encryption overhead.
pub fn fragment_budget(tunnel: &Tunnel) -> Result<usize> {
    let limit = tunnel.max_payload().context("datagrams off")?;
    Ok((limit.min(FRAGMENT_BUDGET)).saturating_sub(crate::channel::DATA_HEADER + 24))
}

fn datagram_transport() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(1 << 16));
    // Traffic with pauses (paced) must not tear down the connection via
    // the standard 30s idle timeout.
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(2)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(120)).expect("idle timeout"),
    ));
    transport
}

/// Binds the QUIC UDP socket with a raised receive buffer (see `UDP_RCVBUF`)
/// and hands it to quinn in non-blocking mode.
fn udp_socket(bind: SocketAddr) -> Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(bind).context("bind QUIC socket")?;
    socket2::SockRef::from(&socket)
        .set_recv_buffer_size(UDP_RCVBUF)
        .context("QUIC receive buffer")?;
    socket
        .set_nonblocking(true)
        .context("QUIC socket nonblocking")?;
    Ok(socket)
}

/// The connection is occupied by the tunnel; relay until closed.
async fn relay(quic: Connection, target: SocketAddr) -> Result<()> {
    // Both directions belong to this future: cancellation must release the socket.
    let inbound = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .context("relay socket")?;
    let upstream = async {
        while let Ok(datagram) = quic.read_datagram().await {
            let Ok(payload) = decode_datagram(&datagram) else {
                continue;
            };
            inbound
                .send_to(payload, target)
                .await
                .context("relay send")?;
        }
        Ok(())
    };
    let downstream = async {
        let mut buffer = vec![0u8; RELAY_BUFFER];
        loop {
            let (len, _) = inbound.recv_from(&mut buffer).await?;
            let mut frame = BytesMut::with_capacity(len + DATAGRAM_PREFIX.len());
            frame.extend_from_slice(&DATAGRAM_PREFIX);
            frame.extend_from_slice(&buffer[..len]);
            if quic.send_datagram(frame.freeze()).is_err() {
                return Ok(());
            }
        }
    };
    tokio::select! {
        result = upstream => result,
        result = downstream => result,
    }
}

/// Client endpoint: outbound only, no listener.
fn client_endpoint() -> Result<Endpoint> {
    let socket = udp_socket("0.0.0.0:0".parse().unwrap())?;
    Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("create QUIC client endpoint")
}

fn connect_uri(target: SocketAddr) -> Uri {
    Uri::builder()
        .scheme("https")
        .authority(target.to_string())
        .path_and_query("/")
        .build()
        .unwrap()
}
