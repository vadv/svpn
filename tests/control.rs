//! Control channel: stats counters, JSONL framing, message wire format, send/recv.

use svpn::control::*;
use svpn::packet::FlowKey;
use svpn::selector::Reason;
use tokio::io::{AsyncWriteExt, BufReader};

// ── stats ──

#[test]
fn count_drop_names_the_reason() {
    let mut stats = Stats::default();
    stats.count_drop("drop:", "pending buffer full");
    stats.count_drop("drop[h1]:", "TUN write timeout");
    assert_eq!(stats.dropped_packets, 2);
    assert_eq!(stats.inner_tx_packets, 0);
}

// ── framing ──

#[tokio::test]
async fn reads_split_and_coalesced_messages() {
    let (mut write, read) = tokio::io::duplex(128);
    let task = tokio::spawn(async move {
        write.write_all(b"{\"type\":\"rea").await.unwrap();
        tokio::task::yield_now().await;
        write
            .write_all(b"dy\",\"version\":1}\n{\"type\":\"close\",\"id\":2}\n")
            .await
            .unwrap();
    });
    let mut reader = BufReader::new(read);
    assert!(matches!(
        read_message(&mut reader).await.unwrap(),
        Message::Ready { version: 1 }
    ));
    assert!(matches!(
        read_message(&mut reader).await.unwrap(),
        Message::Close { id: 2 }
    ));
    assert!(read_message(&mut reader).await.is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn rejects_oversized_incomplete_and_invalid_messages() {
    for input in [
        vec![b'x'; MAX_LINE + 1],
        b"{\"type\":\"ready\",\"version\":1}".to_vec(),
        b"not JSON\n".to_vec(),
        b"{\"type\":\"ready\",\"version\":1,\"unknown\":true}\n".to_vec(),
    ] {
        let mut reader = BufReader::new(input.as_slice());
        assert!(read_message(&mut reader).await.is_err());
    }
}

// ── message wire format ──

#[tokio::test]
async fn opened_token_round_trip() {
    let value = Message::Opened {
        id: 5,
        port: 41000,
        key: [7; 16],
        token: Some([9; 16]),
    };
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(matches!(
        serde_json::from_slice::<Message>(&bytes).unwrap(),
        Message::Opened { token: Some(t), .. } if t == [9; 16]
    ));
    let udp_value = Message::Opened {
        id: 5,
        port: 41000,
        key: [7; 16],
        token: None,
    };
    let bytes = serde_json::to_vec(&udp_value).unwrap();
    assert!(!bytes.windows(6).any(|w| w == b"token"));
}

#[tokio::test]
async fn v2_messages_round_trip_with_wire_names() {
    // Exact JSON names: one line, no unknown fields.
    let cases: Vec<(Message, &str)> = vec![
        (
            Message::Endpoints {
                udp: vec![Endpoint {
                    strategy: Strategy::Quic,
                    port: 41000,
                }],
                tcp: Some(41010),
                pin: None,
            },
            "{\"type\":\"endpoints\",\"udp\":[{\"strategy\":\"quic\",\"port\":41000}],\"tcp\":41010}",
        ),
        (
            Message::ChannelPrepare {
                attempt: 7,
                strategy: Strategy::Obfs,
                hello: None,
            },
            "{\"type\":\"channel_prepare\",\"attempt\":7,\"strategy\":\"obfs\"}",
        ),
        (
            Message::ChannelReady {
                attempt: 7,
                channel: 3,
                port: 41002,
                key: [1; 16],
                max_wire: 1380,
                hello: None,
                relay: None,
            },
            "{\"type\":\"channel_ready\",\"attempt\":7,\"channel\":3,\"port\":41002,\"key\":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],\"max_wire\":1380}",
        ),
        (
            Message::ChannelFailed {
                attempt: None,
                channel: Some(3),
                reason: Reason::ChannelFailed,
            },
            "{\"type\":\"channel_failed\",\"attempt\":null,\"channel\":3,\"reason\":\"channel_failed\"}",
        ),
        (
            Message::ChannelVerified { channel: 3 },
            "{\"type\":\"channel_verified\",\"channel\":3}",
        ),
        (
            Message::FlowOpen {
                flow_id: 9,
                flow: FlowKey {
                    protocol: 6,
                    source: "10.77.0.2".parse().unwrap(),
                    source_port: 5,
                    destination: "10.77.0.1".parse().unwrap(),
                    destination_port: 80,
                },
                channel: Some(3),
            },
            "{\"type\":\"flow_open\",\"flow_id\":9,\"flow\":{\"protocol\":6,\"source\":\"10.77.0.2\",\"destination\":\"10.77.0.1\",\"source_port\":5,\"destination_port\":80},\"channel\":3}",
        ),
        (
            Message::Commit {
                flow_id: 9,
                attempt: 11,
            },
            "{\"type\":\"commit\",\"flow_id\":9,\"attempt\":11}",
        ),
        (
            Message::Committed { flow_id: 9 },
            "{\"type\":\"committed\",\"flow_id\":9}",
        ),
        (
            Message::FlowClose { flow_id: 9 },
            "{\"type\":\"flow_close\",\"flow_id\":9}",
        ),
        (
            Message::FlowReject {
                flow_id: 9,
                reason: Reason::EndpointUnavailable,
            },
            "{\"type\":\"flow_reject\",\"flow_id\":9,\"reason\":\"endpoint_unavailable\"}",
        ),
    ];
    for (message, json) in cases {
        let line = serde_json::to_string(&message).unwrap();
        assert_eq!(line, json);
        assert!(line.len() < MAX_LINE, "line budget: {line}");
        // Message lacks Debug/PartialEq (it holds keys): compare via reverse serialization.
        let back = serde_json::to_string(&serde_json::from_str::<Message>(json).unwrap()).unwrap();
        assert_eq!(back, json, "round trip {json}");
    }
}

#[tokio::test]
async fn v2_rejects_unknown_strategy_reason_and_fields() {
    for bad in [
        "{\"type\":\"channel_prepare\",\"attempt\":1,\"strategy\":\"tcp\"}",
        "{\"type\":\"channel_prepare\",\"attempt\":1,\"strategy\":\"wireguard\"}",
        "{\"type\":\"channel_failed\",\"attempt\":null,\"channel\":null,\"reason\":\"dpi\"}",
        "{\"type\":\"committed\",\"flow_id\":1,\"extra\":true}",
    ] {
        assert!(serde_json::from_str::<Message>(bad).is_err(), "{bad}");
    }
}

#[tokio::test]
async fn endpoints_tcp_null_round_trip() {
    let message = Message::Endpoints {
        udp: Vec::new(),
        tcp: None,
        pin: None,
    };
    let json = serde_json::to_string(&message).unwrap();
    assert_eq!(json, "{\"type\":\"endpoints\",\"udp\":[],\"tcp\":null}");
    let back = serde_json::to_string(&serde_json::from_str::<Message>(&json).unwrap()).unwrap();
    assert_eq!(back, json);
}

#[tokio::test]
async fn server_hooks_round_trip() {
    let message = Message::ServerHooks {
        up: Some("echo up".to_string()),
        down: Some("echo down".to_string()),
    };
    let json = serde_json::to_string(&message).unwrap();
    assert_eq!(
        json,
        "{\"type\":\"server_hooks\",\"up\":\"echo up\",\"down\":\"echo down\"}"
    );
    let back = serde_json::to_string(&serde_json::from_str::<Message>(&json).unwrap()).unwrap();
    assert_eq!(back, json);

    let message = Message::HookResult {
        ok: true,
        stdout: "out".to_string(),
        stderr: "err".to_string(),
    };
    let json = serde_json::to_string(&message).unwrap();
    assert_eq!(
        json,
        "{\"type\":\"hook_result\",\"ok\":true,\"stdout\":\"out\",\"stderr\":\"err\"}"
    );
    let back = serde_json::to_string(&serde_json::from_str::<Message>(&json).unwrap()).unwrap();
    assert_eq!(back, json);
}

#[tokio::test]
async fn server_hooks_and_hook_result_fit_control_line() {
    let max = "x".repeat(svpn::config::MAX_SERVER_HOOK);
    let message = Message::ServerHooks {
        up: Some(max.clone()),
        down: Some(max),
    };
    let line = serde_json::to_string(&message).unwrap();
    assert!(
        line.len() < MAX_LINE,
        "ServerHooks line budget: {}",
        line.len()
    );

    let max = "x".repeat(1500);
    let message = Message::HookResult {
        ok: true,
        stdout: max.clone(),
        stderr: max,
    };
    let line = serde_json::to_string(&message).unwrap();
    assert!(
        line.len() < MAX_LINE,
        "HookResult line budget: {}",
        line.len()
    );
}

// ── control send/recv ──

#[tokio::test]
async fn close_burst_waits_for_writer_then_delivers_heartbeat() {
    let (left, right) = tokio::io::duplex(1);
    let (read, write) = tokio::io::split(left);
    let control = Control::new(read, write);
    let reader = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let (read, write) = tokio::io::split(right);
        let mut peer = Control::new(read, write);
        for expected in 0..=QUEUE as u64 {
            assert!(matches!(peer.recv().await.unwrap(), Message::Close { id } if id == expected));
        }
        assert!(matches!(
            peer.recv().await.unwrap(),
            Message::Heartbeat { .. }
        ));
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        for id in 0..=QUEUE as u64 {
            control.send(Message::Close { id }).await.unwrap();
        }
        control
            .send(Message::Heartbeat {
                stats: Stats::default(),
            })
            .await
            .unwrap();
        reader.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn control_round_trip() {
    let (left, right) = tokio::io::duplex(1024);
    let (lr, lw) = tokio::io::split(left);
    let (rr, rw) = tokio::io::split(right);
    let mut client = Control::new(lr, lw);
    let mut server = Control::new(rr, rw);
    client.send(Message::Close { id: 7 }).await.unwrap();
    assert!(matches!(
        server.recv().await.unwrap(),
        Message::Close { id: 7 }
    ));
    server
        .send(Message::Ready { version: VERSION })
        .await
        .unwrap();
    assert!(matches!(
        client.recv().await.unwrap(),
        Message::Ready { version: VERSION }
    ));
}

// ── address assignment (#181) ──

#[test]
fn address_assignment_messages_round_trip() {
    let cases: Vec<(Message, &str)> = vec![
        (
            Message::Hello {
                version: VERSION,
                client_ip: "10.77.3.2".parse().unwrap(),
                server_ip: "10.77.3.1".parse().unwrap(),
                mtu: 1400,
                addr_auto: true,
            },
            "{\"type\":\"hello\",\"version\":2,\"client_ip\":\"10.77.3.2\",\"server_ip\":\"10.77.3.1\",\"mtu\":1400,\"addr_auto\":true}",
        ),
        (
            Message::Assigned {
                server_ip: "10.77.3.1".parse().unwrap(),
                client_ip: "10.77.3.2".parse().unwrap(),
            },
            "{\"type\":\"assigned\",\"server_ip\":\"10.77.3.1\",\"client_ip\":\"10.77.3.2\"}",
        ),
        (Message::AcceptAddr, "{\"type\":\"accept_addr\"}"),
        (Message::DeclineAddr, "{\"type\":\"decline_addr\"}"),
    ];
    for (message, json) in cases {
        assert_eq!(serde_json::to_string(&message).unwrap(), json);
        let back = serde_json::to_string(&serde_json::from_str::<Message>(json).unwrap()).unwrap();
        assert_eq!(back, json, "round trip {json}");
    }
    // A Hello without addr_auto (a pre-#181 client) must fail to parse.
    assert!(
        serde_json::from_str::<Message>(
            "{\"type\":\"hello\",\"version\":2,\"client_ip\":\"10.77.3.2\",\"server_ip\":\"10.77.3.1\",\"mtu\":1400}"
        )
        .is_err()
    );
}
