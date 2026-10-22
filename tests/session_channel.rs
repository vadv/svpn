//! Session channels: replay guard, failure handling, task cleanup, negotiation.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use std::time::Instant as StdInstant;

use common::session::{link_session, link_session_with, test_key, test_plane};
use svpn::control::{Control, Message, Strategy};
use svpn::link_io;
use svpn::selector::{Action, Allowed, Candidate, Reason, Selector};
use svpn::session::*;
use svpn::{channel, drivers, probe, webrtc};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

// ── replay guard ──

#[tokio::test]
async fn replay_cannot_keep_a_channel_ready() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client_addr = client.local_addr().unwrap();
    let mut server_io = drivers::datagram(server, svpn::profile::Profile::Plain, Some(client_addr));
    let mut client_io = drivers::datagram(client, svpn::profile::Profile::Plain, Some(server_addr));
    let mut peer = channel::Channel::new([7; 16], 9, true);
    let (events, mut established) = mpsc::channel(4);
    let (incoming, _incoming) = mpsc::channel(4);
    let (_command, mut commands) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        let mut channel = channel::Channel::new([7; 16], 9, false);
        let ctx = ChannelCtx {
            events,
            incoming,
            client: false,
            channel_id: 9,
            max_wire: 1200,
        };
        pump(&mut server_io, &mut channel, &mut commands, &ctx).await
    });
    tokio::time::timeout(
        Duration::from_secs(2),
        probe::client(
            &mut client_io,
            &mut peer,
            1200,
            tokio::time::Instant::now() + Duration::from_secs(2),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        established.recv().await,
        Some(TaskEvent::Established { channel: 9 })
    ));
    let replay = peer
        .seal(&channel::Record::FlowProbe {
            flow_id: 1,
            challenge: [5; 16],
        })
        .unwrap();
    client_io
        .command
        .send(drivers::Command::Send(replay.clone()))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let Some(drivers::Event::Wire(bytes)) = client_io.events.recv().await else {
                panic!("peer transport closed");
            };
            if matches!(peer.open(&bytes, StdInstant::now()).unwrap(), Some(channel::Record::FlowEcho { flow_id: 1, echo }) if echo == [5; 16]) {
                break;
            }
        }
    }).await.unwrap();
    client_io
        .command
        .send(drivers::Command::Send(replay))
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    client_io.close().await;
    assert!(
        error.to_string().contains("replayed or expired UDP packet"),
        "{error:#}"
    );
}

// ── failure handling ──

#[tokio::test]
async fn last_channel_loss_signals_checking() {
    let (mut session, mut events) = link_session(false);
    session.readiness = Some(Readiness::Ready);
    // One selected channel, no flows riding it.
    let (command, _commands) = mpsc::channel(1);
    let task = tokio::spawn(async {});
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane
        .selector
        .as_mut()
        .unwrap()
        .adopt(Candidate::Mosh, Some(5));
    plane.channels.insert(
        5,
        ChannelHandle {
            candidate: svpn::selector::Candidate::Mosh,
            key: [7; 16],
            established: true,
            cancel: None,
            command,
            task,
            relay: None,
        },
    );
    session
        .channel_failed(None, Some(5), svpn::selector::Reason::ChannelFailed)
        .await
        .unwrap();
    let (epoch, event) = events
        .try_recv()
        .expect("channel failure must publish Checking");
    assert_eq!(epoch.link, 2);
    assert!(matches!(event, link_io::Event::Checking));
}

#[tokio::test]
async fn peer_channel_failure_unblocks_tcp_fallback() {
    let now = StdInstant::now();
    let key = test_key();
    let mut selector = Selector::new_proactive(Allowed {
        mosh: true,
        tcp: true,
        ..Allowed::default()
    });
    assert_eq!(
        selector.request(1, key, b"syn", now).unwrap(),
        vec![Action::PrepareChannel {
            candidate: Candidate::Mosh,
            attempt: 1
        }]
    );
    selector.channel_ready(Candidate::Mosh, 1, 10, now);
    let mut plane = test_plane(Some(selector));
    plane
        .flows
        .insert(1, Flow::new(key, tokio::time::Instant::now()));
    let (command, _) = mpsc::channel(1);
    let task = tokio::spawn(std::future::pending());
    let aborted = task.abort_handle();
    plane.channels.insert(
        10,
        ChannelHandle {
            candidate: Candidate::Mosh,
            key: [7; 16],
            established: true,
            command,
            task,
            cancel: None,
            relay: None,
        },
    );

    // The peer may report failure before the local probe timer.
    assert_eq!(
        plane.channel_failed(None, Some(10), Reason::ChannelFailed, now),
        vec![Action::TryTcp {
            flow_id: 1,
            attempt: 2
        }]
    );
    assert!(plane.channels.is_empty());
    tokio::task::yield_now().await;
    assert!(aborted.is_finished());
    // A late local failure of the same channel does not cancel the TCP bind.
    assert!(
        plane
            .channel_failed(None, Some(10), Reason::ChannelFailed, now)
            .is_empty()
    );
    let selector = plane.selector.as_mut().unwrap();
    assert_eq!(
        selector.bind_succeeded(1, now),
        vec![Action::Commit {
            flow_id: 1,
            candidate: Candidate::Tcp,
            attempt: 2,
        }]
    );
    assert!(selector.committed(1).is_empty());
}

#[test]
fn stale_failure_does_not_consume_current_attempt() {
    let now = StdInstant::now();
    let key = test_key();
    let mut selector = Selector::new_proactive(Allowed {
        mosh: true,
        tcp: true,
        ..Allowed::default()
    });
    selector.request(1, key, b"syn", now).unwrap();
    let mut plane = test_plane(Some(selector));
    plane.attempt = Some((1, Candidate::Mosh, None, None));
    assert!(
        plane
            .channel_failed(Some(0), None, Reason::Unsupported, now)
            .is_empty()
    );
    assert_eq!(plane.attempt.as_ref().map(|pending| pending.0), Some(1));
    assert_eq!(
        plane.channel_failed(Some(1), None, Reason::Unsupported, now),
        vec![Action::TryTcp {
            flow_id: 1,
            attempt: 2
        }]
    );
    assert!(plane.attempt.is_none());
}

#[tokio::test]
async fn server_channel_failure_closes_only_its_flows() {
    let key = test_key();
    let mut plane = test_plane(None);
    for (id, channel) in [(1, Some(10)), (2, Some(20)), (3, None)] {
        let mut flow = Flow::new(key, tokio::time::Instant::now());
        flow.channel = channel;
        plane.flows.insert(id, flow);
    }
    let (command, _) = mpsc::channel(1);
    let task = tokio::spawn(std::future::pending());
    plane.channels.insert(
        10,
        ChannelHandle {
            candidate: Candidate::Mosh,
            key: [7; 16],
            established: true,
            command,
            task,
            cancel: None,
            relay: None,
        },
    );
    assert_eq!(
        plane.channel_failed(None, Some(10), Reason::ChannelFailed, StdInstant::now()),
        vec![Action::CloseFlow { flow_id: 1 }]
    );
    assert!(
        plane
            .channel_failed(None, Some(10), Reason::ChannelFailed, StdInstant::now())
            .is_empty()
    );
}

// ── task cleanup ──

#[tokio::test]
async fn channel_removal_aborts_its_relay() {
    let mut plane = test_plane(None);
    let task = tokio::spawn(std::future::pending());
    let channel_abort = task.abort_handle();
    let relay = tokio::spawn(std::future::pending::<()>());
    plane.channels.insert(
        1,
        ChannelHandle {
            candidate: Candidate::Quic,
            key: [7; 16],
            established: true,
            cancel: None,
            command: mpsc::channel(1).0,
            task,
            relay: Some(relay.abort_handle()),
        },
    );
    plane.channel_failed(None, Some(1), Reason::ChannelFailed, StdInstant::now());
    assert!(relay.await.unwrap_err().is_cancelled());
    assert!(channel_abort.is_finished());
}

#[tokio::test]
async fn session_drop_aborts_flow_channel_and_handshake_tasks() {
    for tcp in [false, true] {
        let (mut session, _events) = link_session(tcp);
        session
            .handle_tun_packet(&common::udp_packet(false), Some(1))
            .await
            .unwrap();
        let task = tokio::spawn(std::future::pending());
        let flow_abort = task.abort_handle();
        let mut aborts = vec![flow_abort];
        match &mut session.plane {
            Plane::Channels(plane) => {
                plane.flows.get_mut(&1).unwrap().tcp = Some(FlowTcp {
                    key: [0; 16],
                    token: None,
                    out: None,
                    receiver: None,
                    task: Some(task),
                });
                let task = tokio::spawn(std::future::pending());
                aborts.push(task.abort_handle());
                let relay = session.tasks.spawn(std::future::pending());
                aborts.push(relay.clone());
                plane.channels.insert(
                    1,
                    ChannelHandle {
                        candidate: Candidate::Mosh,
                        key: [7; 16],
                        established: true,
                        command: mpsc::channel(1).0,
                        task,
                        cancel: None,
                        relay: Some(relay),
                    },
                );
            }
            Plane::Tcp(plane) => plane.flows.get_mut(&1).unwrap().task = Some(task),
        }
        aborts.push(session.tasks.spawn(std::future::pending()));
        drop(session);
        tokio::task::yield_now().await;
        assert!(aborts.iter().all(tokio::task::AbortHandle::is_finished));
    }
}

// ── prepare and negotiation ──

#[tokio::test]
async fn webrtc_channel_uses_ssh_address_and_negotiated_port() {
    for advertised in [
        Some("127.0.0.2:9".parse().unwrap()),
        Some("10.0.0.5:9".parse().unwrap()),
        None,
        Some("0.0.0.0:0".parse().unwrap()),
    ] {
        let (mut server, mut hello) =
            webrtc::Peer::server(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), None).unwrap();
        let port = hello.candidate.unwrap().port();
        hello.candidate = advertised;
        let (client, client_hello) =
            webrtc::Peer::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).unwrap();
        server.configure(&client_hello).unwrap();

        let (mut session, _events) = link_session(false);
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        let mut selector = Selector::new_proactive(Allowed {
            webrtc: true,
            ..Allowed::default()
        });
        assert_eq!(
            selector
                .request(1, test_key(), b"syn", StdInstant::now())
                .unwrap(),
            vec![Action::PrepareChannel {
                candidate: Candidate::WebRtc,
                attempt: 1,
            }]
        );
        plane.selector = Some(selector);
        plane.server_ip = Some(Ipv4Addr::LOCALHOST);
        plane.attempt = Some((1, Candidate::WebRtc, None, Some(client)));
        session
            .channel_ready(ChannelReadyParams {
                attempt: 1,
                channel: 7,
                port,
                key: [3; 16],
                max_wire: strategy_max_wire(Strategy::WebRtc),
                hello: Some(serde_json::to_string(&hello).unwrap()),
                relay: None,
            })
            .await
            .unwrap();

        server
            .wait_ready(StdInstant::now() + Duration::from_secs(3))
            .await
            .unwrap_or_else(|error| panic!("advertised {advertised:?}: {error:#}"));
        assert!(server.is_ready());
    }
}

#[tokio::test]
async fn occupied_candidate_port_reports_failure_without_ending_session() {
    for strategy in [
        Strategy::Mosh,
        Strategy::Obfs,
        Strategy::Plain,
        Strategy::WebRtc,
    ] {
        let occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let (mut session, _events) = link_session(false);
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        plane.selector = None;
        plane.bind = Ipv4Addr::LOCALHOST;
        plane.ports.insert(strategy, port);
        let (local, remote) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(local);
        session.control = Control::new(reader, writer);
        let (reader, writer) = tokio::io::split(remote);
        let mut peer = Control::new(reader, writer);

        session.channel_prepare(7, strategy, None).await.unwrap();
        assert!(matches!(
            peer.recv().await.unwrap(),
            Message::ChannelFailed {
                attempt: Some(7),
                channel: None,
                reason: Reason::ChannelFailed,
            }
        ));
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        assert!(plane.channels.is_empty());
        // Use an ephemeral socket only for this allocation test, not a public UDP mode.
        plane.ports.insert(Strategy::Mosh, 0);
        session
            .channel_prepare(8, Strategy::Mosh, None)
            .await
            .unwrap();
        assert!(matches!(
            peer.recv().await.unwrap(),
            Message::ChannelReady { attempt: 8, .. }
        ));
        let Plane::Channels(plane) = &session.plane else {
            unreachable!()
        };
        assert_eq!(plane.channels.len(), 1);
        assert!(plane.prepared.contains_key(&8));
    }
}

#[tokio::test]
async fn channel_prepare_reuses_a_live_datagram_channel() {
    let (client_half, mut wire) = tokio::io::duplex(4096);
    let control = Control::new(tokio::io::empty(), client_half);
    let (mut session, _events) = link_session_with(false, control);
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.selector = None;
    plane.bind = Ipv4Addr::UNSPECIFIED;
    plane.ports.insert(Strategy::Mosh, 60002);
    plane.next_channel_id = 5;
    let (command, _commands) = mpsc::channel(1);
    let (cancel, _cancelled) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async { std::future::pending::<()>().await });
    plane.channels.insert(
        5,
        ChannelHandle {
            candidate: Candidate::Mosh,
            key: [9; 16],
            established: true,
            command,
            cancel: Some(cancel),
            task,
            relay: None,
        },
    );
    session
        .channel_prepare(99, Strategy::Mosh, None)
        .await
        .unwrap();
    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(&mut wire);
    let mut line = String::new();
    lines.read_line(&mut line).await.unwrap();
    let ready: Message = serde_json::from_str(line.trim()).unwrap();
    let Message::ChannelReady {
        attempt,
        channel,
        port,
        key,
        ..
    } = ready
    else {
        panic!("expected ChannelReady");
    };
    assert_eq!((attempt, channel, port), (99, 5, 60002));
    assert_eq!(key, [9; 16]);
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    // Borrowed, not owned: an attempt-only ChannelFailed must not resolve
    // to the live channel, so the attempt is absent from `prepared`.
    assert!(!plane.prepared.contains_key(&99));
    assert_eq!(
        plane.next_channel_id, 5,
        "reuse must not allocate a channel id"
    );
    assert_eq!(
        plane.channels.len(),
        1,
        "no fresh channel bound on top of the live one"
    );
}

#[tokio::test]
async fn channel_ready_reuses_a_live_channel_without_clobbering_it() {
    let (mut session, _events) = link_session(false);
    // A live channel id=5 already exists (e.g. draining after a switch).
    let (command, _commands) = mpsc::channel(1);
    let (cancel, _cancelled) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async { std::future::pending::<()>().await });
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.channels.insert(
        5,
        ChannelHandle {
            candidate: Candidate::Mosh,
            key: [9; 16],
            established: true,
            command,
            cancel: Some(cancel),
            task,
            relay: None,
        },
    );
    // A challenge probe targets the same strategy; the server reuses id 5.
    session.challenge = Some(challenge::Challenge {
        attempts: std::collections::HashMap::from([(
            99,
            challenge::Challenger {
                candidate: Candidate::Mosh,
                channel: None,
                owned: true,
                peer: None,
                burst: None,
            },
        )]),
        measured: Vec::new(),
        incumbent: None,
        deadline: tokio::time::Instant::now() + Duration::from_secs(30),
    });
    session
        .channel_ready(ChannelReadyParams {
            attempt: 99,
            channel: 5,
            port: 60002,
            key: [8; 16],
            max_wire: 1200,
            hello: None,
            relay: None,
        })
        .await
        .unwrap();
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    assert_eq!(
        plane.channels.len(),
        1,
        "reuse must not spawn a fresh channel"
    );
    let handle = plane.channels.get(&5).unwrap();
    assert_eq!(
        handle.key, [9; 16],
        "the live handle must survive unchanged (no clobber)"
    );
    assert!(
        !handle.task.is_finished(),
        "the live channel task was aborted"
    );
}

// ── borrowed channels: reuse must never resurrect cipher state ──

#[tokio::test]
async fn late_reuse_reply_after_retirement_fails_the_attempt() {
    let (mut session, _events) = link_session(false);
    let (command, _commands) = mpsc::channel(1);
    let (cancel, _cancelled) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async { std::future::pending::<()>().await });
    {
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        plane.channels.insert(
            5,
            ChannelHandle {
                candidate: Candidate::Mosh,
                key: [9; 16],
                established: true,
                command,
                cancel: Some(cancel),
                task,
                relay: None,
            },
        );
        // The channel dies and retires before the reuse reply arrives.
        plane.retire(5);
    }
    session.challenge = Some(challenge::Challenge {
        attempts: std::collections::HashMap::from([(
            99,
            challenge::Challenger {
                candidate: Candidate::Mosh,
                channel: None,
                owned: true,
                peer: None,
                burst: None,
            },
        )]),
        measured: Vec::new(),
        incumbent: None,
        deadline: tokio::time::Instant::now() + Duration::from_secs(30),
    });
    session
        .channel_ready(ChannelReadyParams {
            attempt: 99,
            channel: 5,
            port: 60002,
            key: [9; 16],
            max_wire: 1200,
            hello: None,
            relay: None,
        })
        .await
        .unwrap();
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    assert!(
        plane.channels.is_empty(),
        "a retired id must not be resurrected with fresh cipher state"
    );
    assert!(
        session
            .challenge
            .as_ref()
            .is_none_or(|challenge| !challenge.attempts.contains_key(&99)),
        "the attempt fails instead of waiting forever"
    );
}

#[tokio::test]
async fn reused_established_channel_opens_probe_and_expiry_spares_it() {
    let (client_half, mut wire) = tokio::io::duplex(4096);
    let control = Control::new(tokio::io::empty(), client_half);
    let (mut session, _events) = link_session_with(false, control);
    let (command, _commands) = mpsc::channel(1);
    let (cancel, _cancelled) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async { std::future::pending::<()>().await });
    {
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        plane.channels.insert(
            5,
            ChannelHandle {
                candidate: Candidate::Mosh,
                key: [9; 16],
                established: true,
                command,
                cancel: Some(cancel),
                task,
                relay: None,
            },
        );
    }
    session.challenge = Some(challenge::Challenge {
        attempts: std::collections::HashMap::from([(
            99,
            challenge::Challenger {
                candidate: Candidate::Mosh,
                channel: None,
                owned: true,
                peer: None,
                burst: None,
            },
        )]),
        measured: Vec::new(),
        incumbent: None,
        deadline: tokio::time::Instant::now() + Duration::from_secs(30),
    });
    session
        .channel_ready(ChannelReadyParams {
            attempt: 99,
            channel: 5,
            port: 60002,
            key: [9; 16],
            max_wire: 1200,
            hello: None,
            relay: None,
        })
        .await
        .unwrap();
    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(&mut wire);
    let mut line = String::new();
    lines.read_line(&mut line).await.unwrap();
    let open: Message = serde_json::from_str(line.trim()).unwrap();
    let Message::FlowOpen {
        flow_id, channel, ..
    } = open
    else {
        panic!("expected FlowOpen for the reused channel");
    };
    assert_eq!((flow_id, channel), (99, Some(5)));
    // The probe never answers: expiry must fail the attempt without
    // stopping the borrowed channel.
    session.finish_challenge(true).await.unwrap();
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    let handle = plane.channels.get(&5).unwrap();
    assert!(
        !handle.task.is_finished(),
        "the borrowed channel outlives the attempt"
    );
    let mut line = String::new();
    lines.read_line(&mut line).await.unwrap();
    let closed: Message = serde_json::from_str(line.trim()).unwrap();
    assert!(
        matches!(closed, Message::FlowClose { .. }),
        "the expired probe flow is closed"
    );
    let mut line = String::new();
    lines.read_line(&mut line).await.unwrap();
    let failed: Message = serde_json::from_str(line.trim()).unwrap();
    let Message::ChannelFailed {
        attempt, channel, ..
    } = failed
    else {
        panic!("expected ChannelFailed");
    };
    assert_eq!(
        (attempt, channel),
        (Some(99), None),
        "a borrowed channel is never reported as the attempt's own failure"
    );
}

#[tokio::test]
async fn borrowed_attempt_cancellation_spares_the_server_channel() {
    let (client_half, mut wire) = tokio::io::duplex(4096);
    let control = Control::new(tokio::io::empty(), client_half);
    let (mut session, _events) = link_session_with(false, control);
    {
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        plane.selector = None;
        plane.bind = Ipv4Addr::UNSPECIFIED;
        plane.ports.insert(Strategy::Mosh, 60002);
        plane.next_channel_id = 5;
    }
    let (command, _commands) = mpsc::channel(1);
    let (cancel, _cancelled) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async { std::future::pending::<()>().await });
    {
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        plane.channels.insert(
            5,
            ChannelHandle {
                candidate: Candidate::Mosh,
                key: [9; 16],
                established: true,
                command,
                cancel: Some(cancel),
                task,
                relay: None,
            },
        );
    }
    session
        .channel_prepare(99, Strategy::Mosh, None)
        .await
        .unwrap();
    use tokio::io::AsyncBufReadExt;
    let mut lines = tokio::io::BufReader::new(&mut wire);
    let mut line = String::new();
    lines.read_line(&mut line).await.unwrap();
    // The client cancels the attempt: the borrowed channel must stay.
    session
        .channel_failed(Some(99), None, Reason::ChannelFailed)
        .await
        .unwrap();
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    let handle = plane.channels.get(&5).unwrap();
    assert!(
        !handle.task.is_finished(),
        "the server channel survives the borrowed attempt's cancellation"
    );
}
