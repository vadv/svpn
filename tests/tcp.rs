//! TCP transport: fixed-port rebind, frame pump, preflight, and flow binding.

use std::net::SocketAddr;
use std::time::Duration;

use svpn::crypto::{Cipher, random};
use svpn::framing::{self, Camouflage, TOKEN_BYTES};
use svpn::link_io::PREFLIGHT_ID;
use svpn::tcp::*;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

const FLOW_TEST_QUEUE: usize = 8;

async fn spawn_serve(camouflage: Camouflage) -> (SocketAddr, mpsc::Receiver<Event>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (events, incoming) = mpsc::channel(16);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve(stream, camouflage, events).await.unwrap();
    });
    (address, incoming)
}

// ── listener ──

#[tokio::test]
async fn fixed_port_rebinds_despite_time_wait() {
    // SO_REUSEADDR regression: a session restart must rebind the fixed
    // mimic port while old accepted connections sit in TIME_WAIT. The
    // server side closes first to force that state on the listener port.
    let first = bind_listener("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let port = first.local_addr().unwrap().port();
    let client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (server, _) = first.accept().await.unwrap();
    drop(server);
    drop(client);
    drop(first);
    bind_listener(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .expect("rebind fixed port while TIME_WAIT lingers");
}

// ── pump ──

#[tokio::test]
async fn pump_drains_buffered_frames_without_another_socket_read() {
    for camouflage in [Camouflage::None, Camouflage::Banner, Camouflage::Ssh] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        let key = [7; 16];
        let id = 42;
        let mut sender = Cipher::new(key, id, false);
        let mut decoder = server_decoder(camouflage);
        decoder.push(&encode_frame(&mut sender, camouflage, &[]).unwrap());
        decoder.push(&encode_frame(&mut sender, camouflage, b"buffered packet").unwrap());
        let (_send, outgoing) = mpsc::channel(1);
        let (events, mut incoming) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            pump(
                stream,
                &mut Cipher::new(key, id, true),
                (id, 1),
                outgoing,
                decoder,
                camouflage,
                events,
            )
            .await
        });
        let received = timeout(Duration::from_secs(1), incoming.recv()).await;
        task.abort();
        let _ = task.await;
        let Event::Packet(packet) = received
            .expect("buffered frame waited for a socket read")
            .unwrap()
        else {
            panic!("expected buffered packet");
        };
        assert_eq!((packet.id, packet.generation), (id, 1));
        assert_eq!(packet.packet, b"buffered packet");
    }
}

#[tokio::test]
async fn pump_distinguishes_clean_eof_from_truncated_frames() {
    for camouflage in [Camouflage::None, Camouflage::Banner, Camouflage::Ssh] {
        for truncated in [false, true] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (peer, _) = listener.accept().await.unwrap();
            let (key, id) = ([7; 16], 42);
            let mut decoder = server_decoder(camouflage);
            let frame =
                encode_frame(&mut Cipher::new(key, id, false), camouflage, b"packet").unwrap();
            decoder.push(&frame[..frame.len() - usize::from(truncated)]);
            let (_send, outgoing) = mpsc::channel(1);
            let (events, mut incoming) = mpsc::channel(4);
            drop(peer);
            let result = timeout(
                Duration::from_secs(1),
                pump(
                    stream,
                    &mut Cipher::new(key, id, true),
                    (id, 1),
                    outgoing,
                    decoder,
                    camouflage,
                    events,
                ),
            )
            .await
            .unwrap();
            if truncated {
                assert!(result.unwrap_err().to_string().contains("inside a frame"));
                assert!(incoming.recv().await.is_none());
            } else {
                result.unwrap();
                assert!(matches!(incoming.recv().await, Some(Event::Packet(_))));
                assert!(matches!(
                    incoming.recv().await,
                    Some(Event::Closed {
                        id: 42,
                        generation: 1
                    })
                ));
                assert!(incoming.recv().await.is_none());
            }
        }
    }
}

// ── preflight ──

#[tokio::test]
async fn preflight_authenticates_both_directions_without_ip_data() {
    for camouflage in [Camouflage::None, Camouflage::Banner, Camouflage::Ssh] {
        let (address, mut events) = spawn_serve(camouflage).await;
        let key = random().unwrap();
        let (send, outgoing) = mpsc::channel(1);
        send.send(Vec::new()).await.unwrap();
        let (connected, mut received) = mpsc::channel(1);
        let probe = tokio::spawn(connect(
            address,
            camouflage,
            (PREFLIGHT_ID, 1),
            key,
            [8; TOKEN_BYTES],
            outgoing,
            connected,
        ));
        let Event::Bound { token, conn } = events.recv().await.unwrap() else {
            panic!("expected binding");
        };
        assert_eq!(token, [8; TOKEN_BYTES]);
        let (_send, outgoing) = mpsc::channel(1);
        conn.send(Ok(Bound {
            id: PREFLIGHT_ID,
            generation: 1,
            key,
            outgoing,
            cancel: None,
        }))
        .ok();
        timeout(Duration::from_secs(3), probe)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(
            received.recv().await,
            Some(Event::Connected {
                id: PREFLIGHT_ID,
                generation: 1
            })
        ));
        assert!(
            received.recv().await.is_none(),
            "preflight must not start the packet pump"
        );
        assert!(
            events.recv().await.is_none(),
            "probe must not enter the IP plane"
        );
    }
}

#[tokio::test]
async fn preflight_does_not_accept_a_tcp_connect_as_readiness() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0; 1024];
        let _ = stream.read(&mut buf).await;
        // An old server or a filter can accept the socket without confirming binding.
    });
    assert!(
        preflight(
            address,
            Camouflage::None,
            PREFLIGHT_ID,
            [1; 16],
            [2; TOKEN_BYTES]
        )
        .await
        .is_err()
    );
    peer.await.unwrap();
}

#[tokio::test]
async fn preflight_rejects_an_unauthenticated_reply() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0; 1024];
        let _ = stream.read(&mut buf).await;
        let mut wrong_key = Cipher::new([9; 16], PREFLIGHT_ID, false);
        stream
            .write_all(&framing::frame(&wrong_key.seal(&[]).unwrap()).unwrap())
            .await
            .unwrap();
    });
    assert!(
        preflight(
            address,
            Camouflage::None,
            PREFLIGHT_ID,
            [1; 16],
            [2; TOKEN_BYTES]
        )
        .await
        .is_err()
    );
    peer.await.unwrap();
}

// ── flow binding ──

#[tokio::test]
async fn binds_by_token_and_transfers_both_directions() {
    let (address, mut server_events) = spawn_serve(Camouflage::Banner).await;
    let key = random().unwrap();
    let (client_send, client_outgoing) = mpsc::channel(FLOW_TEST_QUEUE);
    let (client_events, mut client_incoming) = mpsc::channel(16);
    let client = tokio::spawn(connect(
        address,
        Camouflage::Banner,
        (1, 1),
        key,
        [9u8; TOKEN_BYTES],
        client_outgoing,
        client_events,
    ));
    client_send.send(vec![1, 2, 3]).await.unwrap();
    // Server: binding → the first flow packet.
    let event = timeout(Duration::from_secs(3), server_events.recv())
        .await
        .unwrap()
        .unwrap();
    let conn = match event {
        Event::Bound { token, conn } => {
            assert_eq!(token, [9u8; TOKEN_BYTES]);
            conn
        }
        Event::Packet(_)
        | Event::Connected { .. }
        | Event::Failed { .. }
        | Event::Closed { .. } => {
            panic!("expected binding event first")
        }
    };
    let (server_send, server_outgoing) = mpsc::channel(FLOW_TEST_QUEUE);
    let _ = conn.send(Ok(Bound {
        id: 1,
        generation: 1,
        key,
        outgoing: server_outgoing,
        cancel: None,
    }));
    assert!(matches!(
        timeout(Duration::from_secs(3), server_events.recv())
            .await
            .unwrap()
            .unwrap(),
        Event::Connected {
            id: 1,
            generation: 1
        }
    ));
    let event = timeout(Duration::from_secs(3), server_events.recv())
        .await
        .unwrap()
        .unwrap();
    match event {
        Event::Packet(packet) => {
            assert_eq!((packet.id, packet.generation), (1, 1));
            assert_eq!(packet.packet, vec![1, 2, 3]);
        }
        Event::Bound { .. }
        | Event::Connected { .. }
        | Event::Failed { .. }
        | Event::Closed { .. } => {
            panic!("expected packet event")
        }
    }
    // Reverse direction: server → client over the same connection.
    server_send.send(vec![7, 7]).await.unwrap();
    let event = loop {
        let event = timeout(Duration::from_secs(3), client_incoming.recv())
            .await
            .unwrap()
            .unwrap();
        // Connected arrives before the first packet — skip it.
        if !matches!(event, Event::Connected { .. }) {
            break event;
        }
    };
    match event {
        Event::Packet(packet) => {
            assert_eq!((packet.id, packet.generation), (1, 1));
            assert_eq!(packet.packet, vec![7, 7]);
        }
        Event::Bound { .. } => panic!("client must not receive bindings"),
        Event::Connected { .. } => unreachable!(),
        Event::Failed { .. } | Event::Closed { .. } => unreachable!(),
    }
    client.abort();
}

#[tokio::test]
async fn bound_cancellation_preserves_generation_on_peer_eof() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (server_events, mut server_incoming) = mpsc::channel(8);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve(stream, Camouflage::None, server_events).await
    });
    let (client_send, client_outgoing) = mpsc::channel(1);
    let (client_events, mut client_incoming) = mpsc::channel(8);
    let client = tokio::spawn(connect(
        address,
        Camouflage::None,
        (42, 7),
        [1; 16],
        [9; TOKEN_BYTES],
        client_outgoing,
        client_events,
    ));
    client_send.send(vec![1, 2, 3]).await.unwrap();
    let Event::Bound { conn, .. } = timeout(Duration::from_secs(3), server_incoming.recv())
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("expected binding");
    };
    let (server_send, outgoing) = mpsc::channel(1);
    let (cancel, cancelled) = oneshot::channel();
    assert!(
        conn.send(Ok(Bound {
            id: 42,
            generation: 7,
            key: [1; 16],
            outgoing,
            cancel: Some(cancelled),
        }))
        .is_ok()
    );
    assert!(matches!(
        timeout(Duration::from_secs(3), server_incoming.recv())
            .await
            .unwrap(),
        Some(Event::Connected {
            id: 42,
            generation: 7
        })
    ));
    assert!(matches!(
        timeout(Duration::from_secs(3), server_incoming.recv()).await.unwrap(),
        Some(Event::Packet(packet))
            if (packet.id, packet.generation) == (42, 7) && packet.packet == [1, 2, 3]
    ));
    cancel.send(()).unwrap();
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(3), client)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(server_send.is_closed());
    assert!(client_send.is_closed());
    assert!(
        server_incoming.recv().await.is_none(),
        "cancellation is not a transport failure"
    );
    assert!(matches!(
        client_incoming.recv().await,
        Some(Event::Connected {
            id: 42,
            generation: 7
        })
    ));
    assert!(matches!(
        client_incoming.recv().await,
        Some(Event::Closed {
            id: 42,
            generation: 7
        })
    ));
    assert!(client_incoming.recv().await.is_none());
}

#[tokio::test]
async fn unknown_token_closes_connection() {
    let (address, mut server_events) = spawn_serve(Camouflage::None).await;
    let (_send, outgoing) = mpsc::channel(FLOW_TEST_QUEUE);
    let (events, mut incoming) = mpsc::channel(16);
    let client = tokio::spawn(connect(
        address,
        Camouflage::None,
        (1, 1),
        random().unwrap(),
        [9u8; TOKEN_BYTES],
        outgoing,
        events,
    ));
    // The binding frame goes out with the first flow packet.
    _send.send(vec![1]).await.unwrap();
    let event = timeout(Duration::from_secs(3), server_events.recv())
        .await
        .unwrap()
        .unwrap();
    if let Event::Bound { conn, .. } = event {
        let _ = conn.send(Err(anyhow::anyhow!("unknown TCP binding token")));
    }
    // Rejection may be an EOF or reset, but must never deliver data.
    let result = timeout(Duration::from_secs(3), client)
        .await
        .unwrap()
        .unwrap();
    let mut closed = result.is_err();
    while let Some(event) = incoming.recv().await {
        match event {
            Event::Closed {
                id: 1,
                generation: 1,
            } => closed = true,
            Event::Connected {
                id: 1,
                generation: 1,
            } => {}
            _ => panic!("rejected binding delivered data or another flow event"),
        }
    }
    assert!(closed);
}

#[tokio::test]
async fn wrong_key_fails_authentication() {
    let (address, mut server_events) = spawn_serve(Camouflage::None).await;
    let (_send, outgoing) = mpsc::channel(FLOW_TEST_QUEUE);
    let (events, mut incoming) = mpsc::channel(16);
    let client = tokio::spawn(connect(
        address,
        Camouflage::None,
        (1, 1),
        [1u8; 16],
        [9u8; TOKEN_BYTES],
        outgoing,
        events,
    ));
    _send.send(vec![1]).await.unwrap();
    let event = timeout(Duration::from_secs(3), server_events.recv())
        .await
        .unwrap()
        .unwrap();
    if let Event::Bound { conn, .. } = event {
        let (_, server_outgoing) = mpsc::channel(FLOW_TEST_QUEUE);
        let _ = conn.send(Ok(Bound {
            id: 1,
            generation: 1,
            key: [2u8; 16],
            outgoing: server_outgoing,
            cancel: None,
        }));
    }
    // The server rejects authentication; EOF/reset must not deliver data.
    let result = timeout(Duration::from_secs(3), client)
        .await
        .unwrap()
        .unwrap();
    let mut closed = result.is_err();
    while let Some(event) = incoming.recv().await {
        match event {
            Event::Closed {
                id: 1,
                generation: 1,
            } => closed = true,
            Event::Connected {
                id: 1,
                generation: 1,
            } => {}
            _ => panic!("rejected key delivered data or another flow event"),
        }
    }
    assert!(closed);
    assert!(matches!(
        timeout(Duration::from_secs(3), server_events.recv())
            .await
            .unwrap(),
        Some(Event::Failed {
            id: 1,
            generation: 1
        })
    ));
    assert!(server_events.recv().await.is_none());
}

fn server_decoder(camouflage: Camouflage) -> framing::Decoder {
    match camouflage {
        Camouflage::Ssh => {
            let mut decoder = framing::Decoder::new_ssh(false);
            decoder.push(&framing::ssh_server_hello());
            decoder.push(&framing::ssh_server_tail());
            decoder
        }
        _ => {
            let mut decoder = framing::Decoder::new(camouflage);
            if camouflage == Camouflage::Banner {
                decoder.push(framing::banner());
            }
            decoder
        }
    }
}
