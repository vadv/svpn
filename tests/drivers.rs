//! Transport drivers: rebind budgets, datagram sockets, QUIC relay, WebRTC channels.

use std::time::Duration;

use svpn::drivers::*;
use svpn::profile::Profile;
use svpn::{quic, webrtc};
use tokio::net::UdpSocket;

/// Waits for the next transport task event.
async fn next(io: &mut Io) -> Event {
    tokio::time::timeout(Duration::from_secs(5), io.events.recv())
        .await
        .expect("event within 5s")
        .expect("driver alive")
}

async fn udp() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

// Inject binding to check OS errors and late completion without exhausting host FDs.
async fn rebind_until<F>(
    deadline: tokio::time::Instant,
    mut bind: impl FnMut() -> F,
) -> std::io::Result<UdpSocket>
where
    F: std::future::Future<Output = std::io::Result<UdpSocket>>,
{
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let result = tokio::time::timeout_at(deadline, bind())
            .await
            .map_err(|_| std::io::ErrorKind::TimedOut)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        match result {
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                tokio::time::sleep_until(
                    deadline.min(tokio::time::Instant::now() + Duration::from_millis(1)),
                )
                .await;
            }
            result => return result,
        }
    }
}

// ── rebind ──

#[tokio::test]
async fn rebind_rejects_held_sockets_expired_budgets_and_other_errors() {
    let held = udp().await;
    let addr = held.local_addr().unwrap();
    let error = rebind_until(
        tokio::time::Instant::now() + Duration::from_millis(20),
        || UdpSocket::bind(addr),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    drop(held);
    assert_eq!(
        rebind_until(tokio::time::Instant::now(), || UdpSocket::bind(addr))
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut,
    );
    rebind_until(tokio::time::Instant::now() + Duration::from_secs(1), || {
        UdpSocket::bind(addr)
    })
    .await
    .unwrap();
    let mut attempts = 0;
    let error = rebind_until(tokio::time::Instant::now() + Duration::from_secs(1), || {
        attempts += 1;
        std::future::ready(Err(std::io::ErrorKind::PermissionDenied.into()))
    })
    .await
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(attempts, 1, "unexpected OS errors must not be retried");
}

#[tokio::test]
async fn rebind_rejects_success_observed_after_deadline() {
    let mut socket = Some(udp().await);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let error = rebind_until(deadline, || {
        // Model descheduling during bind; timeout polls an already-ready result first.
        std::thread::sleep(deadline.saturating_duration_since(tokio::time::Instant::now()));
        std::future::ready(Ok(socket.take().unwrap()))
    })
    .await
    .unwrap_err();
    assert!(socket.is_none(), "the bind attempt must have completed");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

// ── datagram ──

#[tokio::test]
async fn datagram_round_trips_plain_and_learn_peer() {
    let server_socket = udp().await;
    let server_addr = server_socket.local_addr().unwrap();
    let mut server = datagram(server_socket, Profile::Plain, None);
    let client_socket = udp().await;
    let mut client = datagram(client_socket, Profile::Plain, Some(server_addr));
    // The server does not know the peer yet — the client speaks first.
    client
        .command
        .send(Command::Send(b"sealed-record-A-0123456789abcdef".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        next(&mut server).await,
        Event::Wire(b"sealed-record-A-0123456789abcdef".to_vec())
    );
    server
        .command
        .send(Command::Send(b"sealed-record-B-0123456789abcdef".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        next(&mut client).await,
        Event::Wire(b"sealed-record-B-0123456789abcdef".to_vec())
    );
    // The server ignores a foreign source, the channel lives.
    let alien = udp().await;
    alien.send_to(b"junk", server_addr).await.unwrap();
    server
        .command
        .send(Command::Send(b"after-alien-0123456789abcdef".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        next(&mut client).await,
        Event::Wire(b"after-alien-0123456789abcdef".to_vec())
    );
}

#[tokio::test]
async fn cancelling_datagram_owner_closes_receiver_and_releases_socket() {
    let socket = udp().await;
    let addr = socket.local_addr().unwrap();
    let peer = udp().await;
    let mut io = datagram(socket, Profile::Plain, Some(peer.local_addr().unwrap()));
    let record = vec![0xAB; 64];
    peer.send_to(&record, addr).await.unwrap();
    assert_eq!(next(&mut io).await, Event::Wire(record));

    // Keep a sender alive so channel closure alone cannot stop the driver.
    let command = io.command.clone();
    let owner = tokio::spawn(async move { next(&mut io).await });
    tokio::task::yield_now().await;
    assert!(!command.is_closed());
    owner.abort();
    assert!(owner.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(1), command.closed())
        .await
        .expect("cancelled owner must stop the driver while the runtime stays alive");
    UdpSocket::bind(addr)
        .await
        .expect("cancelled driver must release its UDP socket");
}

#[tokio::test]
async fn close_releases_socket_before_returning() {
    let socket = udp().await;
    let addr = socket.local_addr().unwrap();
    let mut io = datagram(socket, Profile::Plain, None);
    // An outstanding sender must not delay explicit shutdown.
    let command = io.command.clone();
    tokio::time::timeout(Duration::from_secs(1), io.close())
        .await
        .unwrap();
    assert!(command.is_closed());
    UdpSocket::bind(addr)
        .await
        .expect("close must release the fixed UDP port before returning");
}

#[tokio::test]
async fn datagram_mosh_wraps_wire_bytes() {
    let server_socket = udp().await;
    let server_addr = server_socket.local_addr().unwrap();
    let mut server = datagram(server_socket, Profile::Mosh, None);
    let client_socket = udp().await;
    let client = datagram(client_socket, Profile::Mosh, Some(server_addr));
    // A sniffer sees the mosh camouflage: an LE u64 prefix over the record.
    let record = vec![0xABu8; 64];
    client
        .command
        .send(Command::Send(record.clone()))
        .await
        .unwrap();
    assert_eq!(next(&mut server).await, Event::Wire(record));
}

#[tokio::test]
async fn datagram_garbage_before_peer_learned_is_dropped() {
    let server_socket = udp().await;
    let server_addr = server_socket.local_addr().unwrap();
    let mut server = datagram(server_socket, Profile::Mosh, None);
    // Scanner junk before the first valid packet: the channel lives,
    // the peer address is not taken by the scanner, a valid client continues.
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(b"garbage-not-mosh", server_addr)
        .unwrap();
    let client_socket = udp().await;
    let client = datagram(client_socket, Profile::Mosh, Some(server_addr));
    client
        .command
        .send(Command::Send(vec![0xABu8; 64]))
        .await
        .unwrap();
    assert_eq!(next(&mut server).await, Event::Wire(vec![0xABu8; 64]));
    // After the peer is learned, junk from a foreign address still misses.
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(b"garbage-not-mosh", server_addr)
        .unwrap();
    client
        .command
        .send(Command::Send(vec![0xCDu8; 32]))
        .await
        .unwrap();
    assert_eq!(next(&mut server).await, Event::Wire(vec![0xCDu8; 32]));
}

#[tokio::test]
async fn malformed_datagram_from_current_peer_does_not_close_driver() {
    for profile in [Profile::Plain, Profile::Mosh, Profile::Obfs] {
        let socket = udp().await;
        let target = socket.local_addr().unwrap();
        let peer = udp().await;
        let mut driver = datagram(socket, profile, Some(peer.local_addr().unwrap()));
        peer.send_to(&[0], target).await.unwrap();
        if profile == Profile::Obfs {
            peer.send_to(&[15; 32], target).await.unwrap();
        }
        let record = vec![0xAB; 64];
        let mut wire = record.clone();
        profile.wrap_in_place(&mut wire).unwrap();
        peer.send_to(&wire, target).await.unwrap();
        assert_eq!(next(&mut driver).await, Event::Wire(record));
        driver.close().await;
    }
}

#[tokio::test]
async fn terminal_failure_releases_driver_with_a_full_event_queue() {
    let socket = udp().await;
    let target = socket.local_addr().unwrap();
    let driver = datagram(socket, Profile::Plain, None);
    let sender = udp().await;
    tokio::time::timeout(Duration::from_secs(3), async {
        for queued in 1..=EVENTS_QUEUE {
            sender.send_to(&[0; 28], target).await.unwrap();
            while driver.events.len() != queued {
                tokio::task::yield_now().await;
            }
        }
    })
    .await
    .expect("fill event queue");
    driver.command.send(Command::Send(vec![0])).await.unwrap();
    tokio::time::timeout(Duration::from_millis(100), driver.command.closed())
        .await
        .expect("terminal failure blocked behind Wire events");
    assert_eq!(driver.events.len(), EVENTS_QUEUE);
}

#[tokio::test]
async fn datagram_event_queue_is_bounded_and_survives_backlog() {
    // The session does not read events while the peer floods >1024
    // records: the excess is lost, the transport task lives and keeps delivering.
    let server_socket = udp().await;
    let server_addr = server_socket.local_addr().unwrap();
    let mut server = datagram(server_socket, Profile::Mosh, None);
    let client_socket = udp().await;
    let client = datagram(client_socket, Profile::Mosh, Some(server_addr));
    for i in 0..1400u32 {
        let mut record = vec![0u8; 28];
        record[..4].copy_from_slice(&i.to_be_bytes());
        client.command.send(Command::Send(record)).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut seen = 0;
    while let Ok(event) =
        tokio::time::timeout(Duration::from_millis(100), server.events.recv()).await
    {
        if matches!(event, Some(Event::Wire(_))) {
            seen += 1;
        }
    }
    assert_eq!(seen, 1024, "the queue yields exactly its capacity");
    // After degradation the queue accepts records again.
    let marker = vec![0xEE; 28];
    client
        .command
        .send(Command::Send(marker.clone()))
        .await
        .unwrap();
    // The old backlog leaves first; we wait for the marker itself.
    loop {
        match next(&mut server).await {
            Event::Wire(bytes) if bytes == marker => break,
            Event::Wire(_) => continue,
            other => panic!("expected Wire, got {other:?}"),
        }
    }
}

// ── quic ──

#[tokio::test]
async fn quic_server_drop_aborts_pending_relay_and_releases_sockets() {
    let cert = rcgen::generate_simple_self_signed(vec!["cdn.example".to_string()]).unwrap();
    let endpoint = quic::server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert.cert.der().clone(),
        quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let server_addr = endpoint.local_addr().unwrap();
    let loopback = udp().await;
    let target = loopback.local_addr().unwrap();
    let io = quic_server(endpoint, loopback);
    let command = io.command.clone();
    tokio::task::yield_now().await;
    drop(io);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    tokio::time::timeout_at(deadline, command.closed())
        .await
        .expect("dropped QUIC driver must close its command receiver");
    rebind_until(deadline, || UdpSocket::bind(target))
        .await
        .expect("dropped QUIC driver must release its loopback socket within the same deadline");
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if UdpSocket::bind(server_addr).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("aborted accept_relay must release its endpoint");
}

#[tokio::test]
async fn quic_drivers_carry_records_through_relay() {
    use quinn::rustls::pki_types::PrivatePkcs8KeyDer;
    // Server: certificate + endpoint + loopback channel behind the relay.
    let cert = rcgen::generate_simple_self_signed(vec!["cdn.example".to_string()]).unwrap();
    let pin = quic::cert_pin(cert.cert.der());
    let endpoint = quic::server_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        cert.cert.der().clone(),
        quinn::rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            cert.signing_key.serialize_der(),
        )),
    )
    .unwrap();
    let server_addr = endpoint.local_addr().unwrap();
    let loopback = udp().await;
    let target = loopback.local_addr().unwrap();
    let mut server = quic_server(endpoint, loopback);
    // The client connects to the listener, target is the channel loopback.
    let tunnel = quic::connect(server_addr, "cdn.example", pin, target)
        .await
        .unwrap();
    let mut client = quic_client(tunnel);
    client
        .command
        .send(Command::Send(b"quic-record-1-0123456789abcdef".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        next(&mut server).await,
        Event::Wire(b"quic-record-1-0123456789abcdef".to_vec())
    );
    server
        .command
        .send(Command::Send(b"quic-record-2-0123456789abcdef".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        next(&mut client).await,
        Event::Wire(b"quic-record-2-0123456789abcdef".to_vec())
    );
}

// ── webrtc ──

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webrtc_outbound_burst_does_not_wait_for_receive_ticks() {
    let (mut server_peer, server_hello) =
        webrtc::Peer::server("127.0.0.1:0".parse().unwrap(), None).unwrap();
    let (mut client_peer, client_hello) =
        webrtc::Peer::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_peer.configure(&server_hello).unwrap();
    server_peer.configure(&client_hello).unwrap();
    let mut server = webrtc_channel(server_peer);
    let client = webrtc_channel(client_peer);
    client
        .command
        .send(Command::Send(vec![0xFF]))
        .await
        .unwrap();
    assert_eq!(next(&mut server).await, Event::Wire(vec![0xFF]));

    // 64 small records fit into the SCTP window; waiting 50 ms per
    // outbound command is not allowed even with a silent peer app.
    for id in 0..64u8 {
        client
            .command
            .send(Command::Send(vec![id; 64]))
            .await
            .unwrap();
    }
    let mut received = [false; 64];
    tokio::time::timeout(Duration::from_secs(1), async {
        for _ in 0..64 {
            let Event::Wire(bytes) = next(&mut server).await else {
                panic!("WebRTC driver failed");
            };
            assert_eq!(bytes.len(), 64);
            let id = usize::from(bytes[0]);
            assert!(id < 64 && !received[id], "invalid or repeated record {id}");
            received[id] = true;
        }
    })
    .await
    .expect("outbound burst must not take 64 receive ticks (3.2s)");
    assert!(received.into_iter().all(|value| value));
}

#[tokio::test]
async fn webrtc_drop_releases_socket_with_full_pre_handshake_queue() {
    let (peer, hello) = webrtc::Peer::server("127.0.0.1:0".parse().unwrap(), None).unwrap();
    let addr = hello.candidate.unwrap();
    let io = webrtc_channel(peer);
    // No configure: DCEP will not open. Fill the outbox.
    tokio::time::timeout(Duration::from_secs(1), async {
        for _ in 0..64 {
            io.command.send(Command::Send(vec![0; 64])).await.unwrap();
        }
    })
    .await
    .unwrap();
    drop(io);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if UdpSocket::bind(addr).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropped driver must release its UDP socket");
}

#[tokio::test]
async fn webrtc_full_queue_does_not_block_close_or_sender_drop() {
    for explicit_close in [true, false] {
        let (peer, hello) = webrtc::Peer::server("127.0.0.1:0".parse().unwrap(), None).unwrap();
        let addr = hello.candidate.unwrap();
        let Io {
            command,
            mut events,
            mut tasks,
        } = webrtc_channel(peer);
        tokio::time::timeout(Duration::from_secs(1), async {
            for _ in 0..128 {
                command.send(Command::Send(vec![0; 64])).await.unwrap();
            }
            if explicit_close {
                command.send(Command::Close).await.unwrap();
            }
        })
        .await
        .unwrap();
        drop(command);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            tokio::time::timeout_at(deadline, events.recv())
                .await
                .unwrap(),
            None,
            "full queue must not mask shutdown",
        );
        // Event EOF is not the task-completion barrier for all owned resources.
        tokio::time::timeout_at(deadline, tasks.join_next())
            .await
            .expect("driver must finish after event EOF")
            .expect("driver task exists")
            .expect("driver task must not panic");
        assert!(tasks.is_empty());
        rebind_until(deadline, || UdpSocket::bind(addr))
            .await
            .expect("closed driver must release its socket within the same deadline");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webrtc_driver_exchanges_records() {
    let (mut server_peer, server_hello) =
        webrtc::Peer::server("127.0.0.1:0".parse().unwrap(), None).unwrap();
    let (mut client_peer, client_hello) =
        webrtc::Peer::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_peer.configure(&server_hello).unwrap();
    server_peer.configure(&client_hello).unwrap();
    let mut server = webrtc_channel(server_peer);
    let mut client = webrtc_channel(client_peer);
    // ICE/DTLS/SCTP handshake inside the drivers; then data both ways.
    client
        .command
        .send(Command::Send(b"rtc-record-1-0123456789abcdef".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        next(&mut server).await,
        Event::Wire(b"rtc-record-1-0123456789abcdef".to_vec())
    );
    server
        .command
        .send(Command::Send(b"rtc-record-2-0123456789abcdef".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        next(&mut client).await,
        Event::Wire(b"rtc-record-2-0123456789abcdef".to_vec())
    );
    for io in [&mut client, &mut server] {
        io.command.send(Command::Close).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), io.events.recv())
                .await
                .unwrap(),
            None
        );
    }
}
