use anyhow::ensure;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use str0m::channel::Reliability;
use svpn::pcap::PcapBuilder;
use svpn::webrtc::*;

fn deadline(secs: u64) -> Instant {
    Instant::now() + Duration::from_secs(secs)
}

/// Write + drain Transmit — what the driver does in production.
async fn send(peer: &mut Peer, data: &[u8]) -> anyhow::Result<()> {
    ensure!(peer.write(data)?, "sctp send buffer full");
    peer.poll().await?;
    Ok(())
}

/// A real UDP exchange of two independent Rtc instances over OS loopback sockets.
async fn pair() -> (Peer, Peer) {
    let (mut server, server_hello) = Peer::server("127.0.0.1:0".parse().unwrap(), None).unwrap();
    let (mut client, client_hello) = Peer::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.configure(&server_hello).unwrap();
    server.configure(&client_hello).unwrap();
    let (client_ready, server_ready) = tokio::join!(
        client.wait_ready(deadline(5)),
        server.wait_ready(deadline(5)),
    );
    client_ready.unwrap();
    server_ready.unwrap();
    (server, client)
}

#[tokio::test]
async fn sctp_send_buffers_are_large_and_bounded() {
    let (mut server, mut client) = pair().await;
    for peer in [&mut server, &mut client] {
        let mut buffered = 0;
        let mut blocked = false;
        for _ in 0..=2 * SCTP_SEND_BUFFER_SIZE / FRAGMENT_BUDGET {
            if !peer.write(&[0; FRAGMENT_BUDGET]).unwrap() {
                blocked = true;
                break;
            }
            buffered += FRAGMENT_BUDGET;
            peer.poll().await.unwrap();
        }
        assert!(blocked, "SCTP buffer must be bounded without ACKs");
        assert!(buffered >= SCTP_SEND_BUFFER_SIZE - FRAGMENT_BUDGET);
        assert!(buffered <= SCTP_SEND_BUFFER_SIZE);
    }
}

/// Fill the real SCTP send buffer with no incoming ACKs.
async fn congested_driver() -> (Peer, svpn::drivers::Io, SocketAddr) {
    let (server, mut client) = pair().await;
    let addr = client.socket.local_addr().unwrap();
    let mut blocked = false;
    for _ in 0..1024 {
        if !client.write(&[0; FRAGMENT_BUDGET]).unwrap() {
            blocked = true;
            break;
        }
        client.poll().await.unwrap();
    }
    assert!(blocked, "test must reach actual SCTP backpressure");
    assert!(client.is_ready());
    let io = svpn::drivers::webrtc_channel(client);
    for _ in 0..128 {
        io.command
            .send(svpn::drivers::Command::Send(vec![0; FRAGMENT_BUDGET]))
            .await
            .expect("congestion must not close the driver");
    }
    (server, io, addr)
}

#[tokio::test]
async fn active_sctp_congestion_recovers_after_queue_overflow() {
    // congested_driver must fit the deadline: if a regression makes the
    // driver stop reading commands, the test must fail rather than hang.
    let (mut server, mut io, _) = tokio::time::timeout(Duration::from_secs(5), congested_driver())
        .await
        .expect("congestion setup must not hang");
    let marker = b"after-congestion";
    let commands = io.command.clone();
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            _ = async {
                loop {
                    if server.recv(deadline(1)).await.unwrap().as_deref() == Some(marker.as_slice()) {
                        break;
                    }
                }
            } => {}
            _ = async {
                // The channel is unreliable: the marker can also be tail-dropped.
                loop {
                    commands.send(svpn::drivers::Command::Send(marker.to_vec()))
                        .await.expect("congestion closed the driver");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            } => unreachable!(),
            event = io.events.recv() => panic!("unexpected congestion event: {event:?}"),
        }
    })
    .await
    .expect("driver must resume after SCTP ACKs");
}

#[tokio::test]
async fn active_sctp_congestion_does_not_block_close_or_drop() {
    for explicit_close in [true, false] {
        // congested_driver and send(Close) must also fit the deadline:
        // a hang during setup is as much a failure as a hang during close.
        tokio::time::timeout(Duration::from_secs(10), async {
            let (_server, mut io, addr) = congested_driver().await;
            if explicit_close {
                io.command
                    .send(svpn::drivers::Command::Close)
                    .await
                    .unwrap();
                assert_eq!(io.events.recv().await, None);
            }
            drop(io);
            loop {
                if UdpSocket::bind(addr).is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("congested driver must close and release its UDP socket");
    }
}

#[tokio::test]
async fn handshake_and_exchange_over_real_sockets() {
    let (mut server, mut client) = pair().await;
    assert!(client.is_ready() && server.is_ready());
    assert!(client.rtc.is_connected() && server.rtc.is_connected());

    // The channel is indeed unordered with no retransmissions.
    let config = client
        .rtc
        .channel(client.channel.unwrap())
        .unwrap()
        .config()
        .cloned()
        .unwrap();
    assert!(!config.ordered);
    assert_eq!(
        config.reliability,
        Reliability::MaxRetransmits { retransmits: 0 }
    );

    // A full fragment and a minimal payload in both directions.
    let big = vec![0xA5; FRAGMENT_BUDGET];
    send(&mut client, &big).await.unwrap();
    assert_eq!(server.recv(deadline(10)).await.unwrap(), Some(big));
    let small = b"svpn".to_vec();
    send(&mut server, &small).await.unwrap();
    assert_eq!(client.recv(deadline(10)).await.unwrap(), Some(small));
}

#[tokio::test]
async fn wrong_fingerprint_fails_handshake() {
    let (mut server, mut server_hello) =
        Peer::server("127.0.0.1:0".parse().unwrap(), None).unwrap();
    // Corrupt the last byte of the pin: DTLS with a foreign certificate will fail.
    let mut parts: Vec<&str> = server_hello.fingerprint.split(':').collect();
    let last = parts.pop().unwrap();
    parts.push(if last == "FF" { "00" } else { "FF" });
    server_hello.fingerprint = parts.join(":");

    let (mut client, client_hello) = Peer::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.configure(&server_hello).unwrap();
    server.configure(&client_hello).unwrap();
    let (ready, _) = tokio::join!(
        client.wait_ready(deadline(3)),
        server.wait_ready(deadline(3)),
    );
    assert!(ready.is_err() && !client.is_ready());
}

#[tokio::test]
async fn oversize_write_is_rejected() {
    let (_server, mut client) = pair().await;
    let huge = vec![0u8; 300_000];
    assert!(send(&mut client, &huge).await.is_err());
}

#[tokio::test]
async fn writes_webrtc_pcap_artifact() {
    let (mut server, server_hello) = Peer::server("127.0.0.1:0".parse().unwrap(), None).unwrap();
    let (mut client, client_hello) = Peer::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.record_wire(PcapBuilder::new());
    client.configure(&server_hello).unwrap();
    server.configure(&client_hello).unwrap();
    let (client_ready, server_ready) = tokio::join!(
        client.wait_ready(deadline(5)),
        server.wait_ready(deadline(5)),
    );
    client_ready.unwrap();
    server_ready.unwrap();
    send(&mut client, b"pcap").await.unwrap();
    assert_eq!(
        server.recv(deadline(10)).await.unwrap(),
        Some(b"pcap".to_vec())
    );
    let path = std::path::Path::new("target/pcap/webrtc-dance.pcap");
    client.wire.take().expect("wire recorder").finish(path);
    assert!(path.exists() && std::fs::metadata(path).unwrap().len() > 0);
}
