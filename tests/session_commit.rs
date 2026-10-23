//! Server commit requires the current live, authenticated binding in either arrival order.

mod common;

use std::time::Duration;

use common::session::{link_session_with, test_key};
use svpn::control::{Control, Message};
use svpn::selector::{Candidate, Reason};
use svpn::session::{ChannelHandle, Plane, Session, TaskEvent};
use tokio::io::{AsyncBufReadExt, BufReader, DuplexStream, Lines};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

// ── independent control / transport ordering ──

#[tokio::test]
async fn tcp_commit_waits_for_authentication_in_either_arrival_order() {
    for fixed in [false, true] {
        for commit_first in [false, true] {
            let (writer, reader) = tokio::io::duplex(4096);
            let (mut server, _events) =
                link_session_with(fixed, Control::new(tokio::io::empty(), writer));
            server_role(&mut server);
            let mut lines = BufReader::new(reader).lines();
            let token = open_tcp(&mut server).await;
            assert!(matches!(message(&mut lines).await, Message::Opened { .. }));
            if commit_first {
                server.commit(1, 1).await.unwrap();
                assert!(!active(&server));
                assert_no_message(&mut lines).await;
            }
            let _bound = server.resolve_binding(&token).unwrap();
            if commit_first {
                // Resolving the token is not authentication of the binding frame.
                server.commit(1, 1).await.unwrap();
                assert!(!active(&server));
                assert_no_message(&mut lines).await;
            }
            server.tcp_connected(1, 1).await.unwrap();
            if !commit_first {
                assert!(!active(&server));
                assert_no_message(&mut lines).await;
                server.commit(1, 1).await.unwrap();
            }
            assert!(active(&server));
            assert_committed(message(&mut lines).await);
            server.commit(1, 1).await.unwrap();
            assert_committed(message(&mut lines).await);
            for generation in [0, 2] {
                server.commit(1, generation).await.unwrap();
            }
            assert_no_message(&mut lines).await;
        }
    }
}

#[tokio::test]
async fn delayed_commit_cannot_reactivate_a_failed_tcp_binding() {
    for fixed in [false, true] {
        let (writer, reader) = tokio::io::duplex(4096);
        let (mut server, _events) =
            link_session_with(fixed, Control::new(tokio::io::empty(), writer));
        server_role(&mut server);
        let mut lines = BufReader::new(reader).lines();
        let token = open_tcp(&mut server).await;
        assert!(matches!(message(&mut lines).await, Message::Opened { .. }));
        let bound = server.resolve_binding(&token).unwrap();
        server.tcp_connected(1, 1).await.unwrap();
        server.commit(1, 1).await.unwrap();
        assert_committed(message(&mut lines).await);
        drop(bound);
        server.tcp_failed(1, 1).await.unwrap();
        assert!(matches!(
            message(&mut lines).await,
            Message::FlowReject { generation: 1, .. }
        ));
        assert!(!active(&server));
        server.commit(1, 1).await.unwrap();
        server.tcp_connected(1, 1).await.unwrap();
        assert!(!active(&server));
        assert_no_message(&mut lines).await;
    }
}

#[tokio::test]
async fn replacement_binding_forgets_old_commit_and_authentication() {
    for fixed in [false, true] {
        let (writer, reader) = tokio::io::duplex(4096);
        let (mut server, _events) =
            link_session_with(fixed, Control::new(tokio::io::empty(), writer));
        server_role(&mut server);
        let mut lines = BufReader::new(reader).lines();
        let old_token = open_tcp(&mut server).await;
        let Message::Opened { key: old_key, .. } = message(&mut lines).await else {
            panic!("expected TCP binding");
        };
        server.commit(1, 1).await.unwrap();
        if fixed {
            server.tcp_open_server(1, 2, test_key()).await.unwrap();
        } else {
            server.channels_tcp_open(1, 2, test_key()).await.unwrap();
        }
        let Message::Opened {
            key,
            token: Some(token),
            generation: 2,
            ..
        } = message(&mut lines).await
        else {
            panic!("expected replacement TCP binding");
        };
        assert_ne!(key, old_key);
        assert_ne!(token, old_token);
        assert!(server.resolve_binding(&old_token).is_err());
        let _bound = server.resolve_binding(&token).unwrap();
        server.tcp_connected(1, 1).await.unwrap();
        server.commit(1, 1).await.unwrap();
        assert!(!active(&server));
        assert_no_message(&mut lines).await;
        server.tcp_connected(1, 2).await.unwrap();
        assert!(!active(&server));
        assert_no_message(&mut lines).await;
        server.commit(1, 2).await.unwrap();
        assert!(active(&server));
        assert!(matches!(
            message(&mut lines).await,
            Message::Committed {
                flow_id: 1,
                generation: 2
            }
        ));
    }
}

// ── datagram recovery ──

#[tokio::test]
async fn datagram_commit_waits_for_channel_establishment() {
    let (writer, reader) = tokio::io::duplex(4096);
    let (mut server, _events) = link_session_with(false, Control::new(tokio::io::empty(), writer));
    server_role(&mut server);
    let mut lines = BufReader::new(reader).lines();
    let Plane::Channels(plane) = &mut server.plane else {
        unreachable!()
    };
    let (command, _commands) = mpsc::channel(4);
    plane.channels.insert(
        10,
        ChannelHandle {
            candidate: Candidate::Mosh,
            key: [7; 16],
            established: false,
            command,
            task: tokio::spawn(std::future::pending()),
            cancel: None,
            relay: None,
        },
    );
    server
        .flow_open(1, 1, test_key(), Some(10), false)
        .await
        .unwrap();
    assert!(matches!(
        message(&mut lines).await,
        Message::FlowOpened { .. }
    ));
    server.commit(1, 1).await.unwrap();
    assert!(!active(&server));
    assert_no_message(&mut lines).await;
    server
        .dispatch_task_event(TaskEvent::Established { channel: 10 })
        .await
        .unwrap();
    assert!(matches!(
        message(&mut lines).await,
        Message::ChannelVerified { channel: 10 }
    ));
    assert_committed(message(&mut lines).await);
    assert!(active(&server));
}

#[tokio::test]
async fn delayed_commit_cannot_clear_a_dead_channels_recovery_deadline() {
    let (writer, reader) = tokio::io::duplex(4096);
    let (mut server, _events) = link_session_with(false, Control::new(tokio::io::empty(), writer));
    server_role(&mut server);
    let mut lines = BufReader::new(reader).lines();
    let Plane::Channels(plane) = &mut server.plane else {
        unreachable!()
    };
    let (command, _commands) = mpsc::channel(4);
    plane.channels.insert(
        10,
        ChannelHandle {
            candidate: Candidate::Mosh,
            key: [7; 16],
            established: true,
            command,
            task: tokio::spawn(std::future::pending()),
            cancel: None,
            relay: None,
        },
    );
    server
        .flow_open(1, 1, test_key(), Some(10), false)
        .await
        .unwrap();
    assert!(matches!(
        message(&mut lines).await,
        Message::FlowOpened { .. }
    ));
    server.commit(1, 1).await.unwrap();
    assert_committed(message(&mut lines).await);
    if let Plane::Channels(plane) = &mut server.plane {
        plane.flows.get_mut(&1).unwrap().data_started = true;
    }
    server
        .channel_failed(None, Some(10), Reason::ChannelFailed)
        .await
        .unwrap();
    assert!(matches!(
        message(&mut lines).await,
        Message::FlowReject { .. }
    ));
    let started = recovery_start(&server);
    server.commit(1, 1).await.unwrap();
    assert!(!active(&server));
    assert_eq!(recovery_start(&server), started);
    assert_no_message(&mut lines).await;
    server
        .expire_flows(started + svpn::selector::RECOVERY_BUDGET)
        .await
        .unwrap();
    assert!(!server.has_flow(1));
}

// ── helpers ──

fn server_role(server: &mut Session) {
    match &mut server.plane {
        Plane::Channels(plane) => {
            plane.server_ip = None;
            plane.selector = None;
            plane.tcp_port = Some(9000);
        }
        Plane::Tcp(plane) => plane.server_ip = None,
    }
}

async fn open_tcp(server: &mut Session) -> [u8; 16] {
    if matches!(&server.plane, Plane::Tcp(_)) {
        server.tcp_open_server(1, 1, test_key()).await.unwrap();
    } else {
        server.channels_tcp_open(1, 1, test_key()).await.unwrap();
    }
    match &server.plane {
        Plane::Channels(plane) => plane.flows[&1].tcp.as_ref().unwrap().token.unwrap(),
        Plane::Tcp(plane) => plane.flows[&1].tcp_token.unwrap(),
    }
}

fn active(server: &Session) -> bool {
    match &server.plane {
        Plane::Channels(plane) => plane.flows[&1].active,
        Plane::Tcp(plane) => plane.flows[&1].active,
    }
}

fn recovery_start(server: &Session) -> Instant {
    let Plane::Channels(plane) = &server.plane else {
        unreachable!()
    };
    plane.flows[&1].recovery.as_ref().unwrap().started
}

async fn message(lines: &mut Lines<BufReader<DuplexStream>>) -> Message {
    let line = timeout(Duration::from_secs(1), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str(&line).unwrap()
}

async fn assert_no_message(lines: &mut Lines<BufReader<DuplexStream>>) {
    assert!(
        timeout(Duration::from_millis(2), lines.next_line())
            .await
            .is_err()
    );
}

fn assert_committed(message: Message) {
    assert!(matches!(
        message,
        Message::Committed {
            flow_id: 1,
            generation: 1
        }
    ));
}
