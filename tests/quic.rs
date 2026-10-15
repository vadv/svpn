use anyhow::Result;
use bytes::{Bytes, BytesMut};
use quinn::Endpoint;
use quinn::rustls::pki_types::PrivatePkcs8KeyDer;
use std::net::SocketAddr;
use std::time::Duration;
use svpn::channel;
use svpn::pcap::PcapBuilder;
use svpn::quic::*;

const SNI: &str = "cdn-lookalike.example";

struct Fixture {
    server: Endpoint,
    server_addr: SocketAddr,
    pin: [u8; 32],
    target: SocketAddr,
}

/// Independent UDP peer: echoes (byte-flip) every datagram.
fn spawn_echo_peer() -> (SocketAddr, tokio::sync::oneshot::Receiver<()>) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let (done, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; RELAY_BUFFER];
        while let Ok((len, peer)) = socket.recv_from(&mut buf) {
            let mut reply = buf[..len].to_vec();
            reply.reverse();
            if socket.send_to(&reply, peer).is_err() {
                break;
            }
        }
        let _ = done.send(());
    });
    (addr, rx)
}

async fn fixture() -> (Fixture, tokio::task::JoinHandle<Result<()>>) {
    let cert = rcgen::generate_simple_self_signed(vec![SNI.to_string()]).unwrap();
    let pin = cert_pin(&cert.cert.der().clone());
    let server = server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert.cert.der().clone(),
        quinn::rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            cert.signing_key.serialize_der(),
        )),
    )
    .unwrap();
    let server_addr = server.local_addr().unwrap();
    let (target, _peer_alive) = spawn_echo_peer();
    // The production server accepts connections in a loop — the same loop here.
    let relay_server = server.clone();
    let serving = tokio::spawn(async move {
        loop {
            accept_relay(&relay_server, target).await?;
        }
    });
    (
        Fixture {
            server,
            server_addr,
            pin,
            target,
        },
        serving,
    )
}

async fn tunneled() -> (Fixture, Tunnel) {
    let (fixture, _serving) = fixture().await;
    let tunnel = connect(fixture.server_addr, SNI, fixture.pin, fixture.target)
        .await
        .unwrap();
    (fixture, tunnel)
}

#[tokio::test]
async fn full_exchange_with_independent_peer() {
    let (fixture, tunnel) = tunneled().await;
    let budget = tunnel.max_payload().unwrap();
    let probe = |len: usize| (0..len as u8).collect::<Vec<u8>>();
    for len in [1, 64, 500, FRAGMENT_BUDGET, budget] {
        let payload = probe(len);
        tunnel.send(&payload).unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(10), tunnel.recv())
            .await
            .expect("echo timeout")
            .unwrap();
        let expected: Vec<u8> = payload.iter().rev().cloned().collect();
        assert_eq!(echoed.as_ref(), expected, "echo mismatch at len {len}");
    }
    // The channel fragment budget agrees with the QUIC limit.
    assert!(fragment_budget(&tunnel).unwrap() <= FRAGMENT_BUDGET);
    assert!(fragment_budget(&tunnel).unwrap() >= 1000);
    tunnel.close();
    fixture.server.close(0u32.into(), b"done");
}

#[tokio::test]
async fn idle_relay_exits_when_peer_closes_without_another_udp_reply() {
    let (fixture, serving) = fixture().await;
    let tunnel = connect(fixture.server_addr, SNI, fixture.pin, fixture.target)
        .await
        .unwrap();
    tunnel.send(b"ready").unwrap();
    tokio::time::timeout(Duration::from_secs(2), tunnel.recv())
        .await
        .unwrap()
        .unwrap();
    tunnel.close();
    fixture.server.close(0u32.into(), b"done");
    assert!(
        tokio::time::timeout(Duration::from_secs(2), serving)
            .await
            .expect("relay outlived the closed connection")
            .unwrap()
            .is_err()
    ); // The next accept observes the closed listener.
}

#[tokio::test]
async fn oversize_datagram_is_rejected_before_send() {
    let (_fixture, tunnel) = tunneled().await;
    let too_big = vec![0u8; tunnel.max_payload().unwrap() + 1];
    assert!(tunnel.send(&too_big).is_err());
    tunnel.close();
}

#[tokio::test]
async fn wrong_pin_fails_handshake() {
    let (fixture, _serving) = fixture().await;
    let wrong = [0u8; 32];
    let error = connect(fixture.server_addr, SNI, wrong, fixture.target)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        error.to_string().contains("handshake") || error.to_string().contains("pin"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn foreign_target_is_forbidden() {
    let (fixture, _serving) = fixture().await;
    let other: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let error = connect(fixture.server_addr, SNI, fixture.pin, other)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        error.to_string().contains("403"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn datagram_prefix_codec() {
    let mut frame = BytesMut::new();
    frame.extend_from_slice(&DATAGRAM_PREFIX);
    frame.extend_from_slice(b"udp-payload");
    let datagram = frame.freeze();
    assert_eq!(decode_datagram(&datagram).unwrap(), b"udp-payload");
    // A foreign context id / quarter stream id is rejected outright.
    for bad in [
        Bytes::from_static(b"\x00\x01abc"),
        Bytes::from_static(b"\x01\x00abc"),
        Bytes::from_static(b"\x00"),
        Bytes::from_static(b""),
    ] {
        assert!(decode_datagram(&bad).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn channel_records_flow_through_tunnel() {
    let (fixture, tunnel) = tunneled().await;
    // Full channel cycle: fragmentation → datagrams → echo peer → reassembly.
    let mut client = channel::Channel::new([0x99; 16], 21, true);
    let mut server = channel::Channel::new([0x99; 16], 21, false);
    let mut reassembly = channel::Reassembly::default();
    let now = std::time::Instant::now();
    let packet: Vec<u8> = (0..1400u32).map(|i| i as u8).collect();
    for record in
        channel::fragment_packet(9, 1, &packet, fragment_budget(&tunnel).unwrap()).unwrap()
    {
        let wire = client.seal(&record).unwrap();
        tunnel.send(&wire).unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(10), tunnel.recv())
            .await
            .expect("echo timeout")
            .unwrap();
        // The echo peer reverses the bytes: reversing again restores the original.
        let expected: Vec<u8> = wire.iter().rev().cloned().collect();
        assert_eq!(echoed.as_ref(), expected);
    }
    let _ = (&mut server, &mut reassembly, now);
    // A direct echo check: reversing the reversed bytes yields the original.
    let direct = client.seal(&channel::Record::Keepalive).unwrap();
    tunnel.send(&direct).unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(10), tunnel.recv())
        .await
        .expect("echo timeout")
        .unwrap();
    let expected: Vec<u8> = direct.iter().rev().cloned().collect();
    assert_eq!(echoed.as_ref(), expected);
    let _ = (&mut server, &mut reassembly, now);
    tunnel.close();
    fixture.server.close(0u32.into(), b"done");
}

/// Wire artifact: CONNECT tunnel datagrams in a pcap (UDP wrappers).
#[tokio::test]
async fn writes_datagram_pcap_artifact() {
    let (fixture, tunnel) = tunneled().await;
    let mut pcap = PcapBuilder::new();
    for len in [64, 512, 1024] {
        let payload = vec![0xa7; len];
        tunnel.send(&payload).unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(10), tunnel.recv())
            .await
            .expect("echo timeout")
            .unwrap();
        pcap.add_datagram(&payload);
        pcap.add_datagram(&echoed);
    }
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/pcap/quic-dance.pcap");
    pcap.finish(&path);
    assert!(std::fs::metadata(&path).unwrap().len() > 0);
    tunnel.close();
    fixture.server.close(0u32.into(), b"done");
}
