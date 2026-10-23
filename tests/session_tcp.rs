//! Session TCP transport: EOF/FIN/reset events, close backpressure, TUN preflight.

mod common;

use std::net::Ipv4Addr;
use std::time::Duration;
use std::time::Instant as StdInstant;

use common::session::{assert_closed, link_session, link_session_cap, tcp_packet};
use svpn::control::{Control, Message};
use svpn::link_io::{self, PREFLIGHT_ID};
use svpn::packet;
use svpn::selector::{Allowed, Candidate, Reason, Selector};
use svpn::session::*;
use svpn::udp::Incoming;
use tokio::sync::mpsc;

// ── opening fallback ──

#[tokio::test]
async fn failed_tcp_binding_keeps_owner_and_queue_on_a_verified_datagram_path() {
    let (mut session, mut events) = link_session_cap(false, 8);
    session.readiness = Some(Readiness::Ready);
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    let mut selector = Selector::new_proactive(Allowed {
        quic: true,
        tcp: true,
        ..Allowed::default()
    });
    selector.adopt(Candidate::Quic, Some(10));
    selector.adopt(Candidate::Tcp, None);
    plane.selector = Some(selector);
    let bytes = common::udp_packet(false);
    let key = packet::parse(&bytes, true).unwrap().flow;
    session.handle_tun_packet(&bytes, Some(41)).await.unwrap();
    session.tcp_failed(41, 1).await.unwrap();
    session.tcp_failed(41, 1).await.unwrap();
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    let flow = &plane.flows[&41];
    assert_eq!(flow.generation, 2);
    assert_eq!(flow.channel, Some(10));
    assert!(!flow.active);
    assert!(!flow.data_started);
    assert_eq!(plane.by_key[&key], 41);
    let selector = plane.selector.as_ref().unwrap();
    assert_eq!(
        selector.banned,
        vec![(Candidate::Tcp, Reason::ChannelFailed)]
    );
    assert!(selector.has_queued(41));
    assert_eq!(selector.queued_bytes(), bytes.len());
    assert_eq!(session.stats.open_failed_flows, 0);
    assert_eq!(session.readiness, Some(Readiness::Ready));
    assert!(session.round.is_none());
    assert!(events.try_recv().is_err(), "retry released the Hub owner");
}

// ── EOF/FIN behavior ──

#[tokio::test]
async fn idle_tcp_eof_does_not_check_or_retire_other_flows() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 8);
        let first = tcp_packet(2);
        let mut second = first.clone();
        second[20..22].copy_from_slice(&4321u16.to_be_bytes());
        session.handle_tun_packet(&first, Some(41)).await.unwrap();
        session.handle_tun_packet(&second, Some(42)).await.unwrap();
        let idle = tokio::time::Instant::now() - TCP_IDLE;
        match &mut session.plane {
            Plane::Channels(plane) => {
                let flow = plane.flows.get_mut(&41).unwrap();
                flow.active = true;
                flow.data_started = true;
                flow.last_seen = idle;
            }
            Plane::Tcp(plane) => {
                let flow = plane.flows.get_mut(&41).unwrap();
                flow.active = true;
                flow.data_started = true;
                flow.binding_deadline = None;
                flow.last_seen = idle;
            }
        }
        session.readiness = Some(Readiness::Ready);
        session.tcp_closed(41, 1).await.unwrap();
        assert!(!session.has_flow(41));
        assert!(session.has_flow(42));
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Closed { id: 41, .. }
        ));
        assert_eq!(
            session.readiness,
            Some(Readiness::Ready),
            "idle EOF started Checking"
        );
        assert!(session.round.is_none());
        session.tcp_closed(41, 1).await.unwrap();
        assert!(events.try_recv().is_err());
    }
}

#[tokio::test]
async fn fin_then_eof_keeps_ready_but_reset_or_unexplained_eof_checks() {
    for legacy in [false, true] {
        for finish in [true, false] {
            for reset in [false, true] {
                let (mut session, mut events) = link_session_cap(legacy, 8);
                if let Plane::Channels(plane) = &mut session.plane {
                    plane.selector = Some(Selector::new_proactive(Allowed {
                        tcp: true,
                        ..Allowed::default()
                    }));
                }
                let syn = tcp_packet(2);
                let mut second = syn.clone();
                second[20..22].copy_from_slice(&4321u16.to_be_bytes());
                session.handle_tun_packet(&syn, Some(41)).await.unwrap();
                session.handle_tun_packet(&second, Some(42)).await.unwrap();
                let mut outgoing = Vec::new();
                match &mut session.plane {
                    Plane::Channels(plane) => {
                        let selector = plane.selector.as_mut().unwrap();
                        for (&id, flow) in &mut plane.flows {
                            selector.bind_succeeded(id, 1, StdInstant::now());
                            selector.committed(id, 1);
                            selector.take_queue(id);
                            flow.active = true;
                            flow.data_started = true;
                            let (send, receive) = mpsc::channel(8);
                            outgoing.push(receive);
                            flow.tcp = Some(FlowTcp {
                                key: [1; 16],
                                token: None,
                                out: Some(send),
                                receiver: None,
                                task: None,
                                cancel: None,
                            });
                        }
                    }
                    Plane::Tcp(plane) => {
                        for flow in plane.flows.values_mut() {
                            flow.active = true;
                            flow.data_started = true;
                            flow.pending.clear();
                            flow.binding_deadline = None;
                            let (send, receive) = mpsc::channel(8);
                            outgoing.push(receive);
                            flow.outgoing = Some(send);
                        }
                    }
                }
                session.readiness = Some(Readiness::Ready);
                let mut reply = tcp_packet(0x11);
                reply[12..16].copy_from_slice(&syn[16..20]);
                reply[16..20].copy_from_slice(&syn[12..16]);
                reply[20..22].copy_from_slice(&syn[22..24]);
                reply[22..24].copy_from_slice(&syn[20..22]);
                if finish {
                    session
                        .deliver_to_tun(Incoming {
                            generation: 1,
                            id: 41,
                            channel: None,
                            packet: reply.clone(),
                        })
                        .await
                        .unwrap();
                    assert!(matches!(
                        events.try_recv().unwrap().1,
                        link_io::Event::Packet(_)
                    ));
                    session
                        .handle_tun_packet(&tcp_packet(0x11), Some(41))
                        .await
                        .unwrap();
                    let fin_end = packet::parse(&syn, true)
                        .unwrap()
                        .tcp
                        .unwrap()
                        .seq
                        .wrapping_add(1);
                    let mut ack = tcp_packet(0x10);
                    ack[28..32].copy_from_slice(&fin_end.to_be_bytes());
                    session.handle_tun_packet(&ack, Some(41)).await.unwrap();
                    let mut ack = reply.clone();
                    ack[33] = 0x10;
                    ack[28..32].copy_from_slice(&fin_end.to_be_bytes());
                    session
                        .deliver_to_tun(Incoming {
                            generation: 1,
                            id: 41,
                            channel: None,
                            packet: ack,
                        })
                        .await
                        .unwrap();
                    assert!(matches!(
                        events.try_recv().unwrap().1,
                        link_io::Event::Packet(_)
                    ));
                }
                if reset {
                    session.tcp_failed(41, 1).await.unwrap();
                } else {
                    session.tcp_closed(41, 1).await.unwrap();
                }
                assert!(!session.has_flow(41));
                assert!(session.has_flow(42));
                assert!(matches!(
                    events.try_recv().unwrap().1,
                    link_io::Event::Closed { id: 41, .. }
                ));
                if finish && !reset {
                    assert_eq!(session.readiness, Some(Readiness::Ready));
                    assert!(session.round.is_none());
                    assert!(events.try_recv().is_err());
                    reply[33] = 0x10;
                    reply[22..24].copy_from_slice(&4321u16.to_be_bytes());
                    session
                        .deliver_to_tun(Incoming {
                            generation: 1,
                            id: 42,
                            channel: None,
                            packet: reply,
                        })
                        .await
                        .unwrap();
                    assert!(matches!(
                        events.try_recv().unwrap().1,
                        link_io::Event::Packet(link_io::Packet { id: 42, .. })
                    ));
                } else {
                    assert_eq!(session.readiness, Some(Readiness::Probing));
                    assert!(session.round.is_some());
                    assert!(matches!(
                        events.try_recv().unwrap().1,
                        link_io::Event::Checking
                    ));
                }
            }
        }
    }
}

#[tokio::test]
async fn failed_fixed_tcp_flow_starts_checking_without_retiring_other_flows() {
    let (mut session, mut events) = link_session_cap(true, 8);
    session.readiness = Some(Readiness::Ready);
    let first = common::udp_packet(false);
    let mut second = first.clone();
    second[20..22].copy_from_slice(&4321u16.to_be_bytes());
    session.handle_tun_packet(&first, Some(41)).await.unwrap();
    session.handle_tun_packet(&second, Some(42)).await.unwrap();
    let Plane::Tcp(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.flows.get_mut(&41).unwrap().active = true;
    plane.flows.get_mut(&41).unwrap().data_started = true;
    session.tcp_failed(41, 1).await.unwrap();
    assert!(!session.has_flow(41));
    assert!(session.has_flow(42));
    assert!(matches!(
        events.try_recv().unwrap().1,
        link_io::Event::Closed { id: 41, .. }
    ));
    assert!(matches!(
        events.try_recv().unwrap().1,
        link_io::Event::Checking
    ));
    assert_eq!(session.readiness, Some(Readiness::Probing));
    assert!(session.round.is_some());
}

// ── close and drop ──

#[tokio::test]
async fn close_waits_for_capacity_and_obeys_heartbeat_deadline() {
    let (mut session, mut events) = link_session(true);
    let bytes = common::udp_packet(false);
    let key = packet::parse(&bytes, true).unwrap().flow;
    session.handle_tun_packet(&bytes, Some(11)).await.unwrap();
    let PacketIo::Link(io) = &session.io else {
        unreachable!()
    };
    io.events
        .try_send((io.epoch, link_io::Event::Ready))
        .unwrap();
    let close = session.tcp_close(11);
    tokio::pin!(close);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut close)
            .await
            .is_err()
    );
    let (_, event) = events.recv().await.unwrap();
    assert!(matches!(event, link_io::Event::Ready));
    close.await.unwrap();
    assert_closed(events.recv().await.unwrap(), 11, key);

    let (mut session, _events) = link_session(true);
    session.handle_tun_packet(&bytes, Some(11)).await.unwrap();
    let PacketIo::Link(io) = &session.io else {
        unreachable!()
    };
    io.events
        .try_send((io.epoch, link_io::Event::Ready))
        .unwrap();
    let result = with_heartbeat_deadline(
        tokio::time::Instant::now() + Duration::from_millis(10),
        async {
            session.tcp_close(11).await?;
            Ok(false)
        },
    )
    .await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("control heartbeat timeout")
    );
}

#[tokio::test]
async fn legacy_tcp_failure_closes_and_notifies_both_owners() {
    let (mut session, mut events) = link_session(true);
    let (local, remote) = tokio::io::duplex(8192);
    let (reader, writer) = tokio::io::split(local);
    session.control = Control::new(reader, writer);
    let (reader, writer) = tokio::io::split(remote);
    let mut peer = Control::new(reader, writer);
    let bytes = common::udp_packet(false);
    let key = packet::parse(&bytes, true).unwrap().flow;
    session.handle_tun_packet(&bytes, Some(11)).await.unwrap();
    assert!(matches!(
        peer.recv().await.unwrap(),
        Message::Open {
            generation: 1,
            id: 11,
            ..
        }
    ));
    let Plane::Tcp(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.flows.get_mut(&11).unwrap().active = true;
    plane.flows.get_mut(&11).unwrap().data_started = true;
    session.tcp_failed(11, 1).await.unwrap();
    assert_closed(events.recv().await.unwrap(), 11, key);
    assert!(matches!(
        peer.recv().await.unwrap(),
        Message::Close {
            generation: 1,
            id: 11
        }
    ));
    assert_eq!(session.flow_count(), 0);
}

#[tokio::test]
async fn session_drop_closes_real_tcp_flow_connections() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for legacy in [false, true] {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (bound, binding) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            assert!(stream.read(&mut bytes).await.unwrap() > 0);
            bound.send(()).unwrap();
            loop {
                match stream.read(&mut bytes).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                    Err(error) => panic!("{error}"),
                }
            }
            let _ = stream.shutdown().await;
        });
        let (mut session, _events) = link_session(legacy);
        match &mut session.plane {
            Plane::Tcp(plane) => plane.server_ip = Some(Ipv4Addr::LOCALHOST),
            Plane::Channels(plane) => {
                plane.server_ip = Some(Ipv4Addr::LOCALHOST);
                plane.selector = Some(Selector::new(Allowed {
                    tcp: true,
                    ..Allowed::default()
                }));
            }
        }
        session
            .handle_tun_packet(&common::udp_packet(false), Some(1))
            .await
            .unwrap();
        if legacy {
            session
                .tcp_opened_client(1, 1, port, [1; 16], Some([2; 16]))
                .await
                .unwrap();
        } else {
            session
                .channels_tcp_opened(1, 1, port, [1; 16], Some([2; 16]))
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), binding)
            .await
            .unwrap()
            .unwrap();
        drop(session);
        tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }
}

// ── server preflight over TUN ──

#[tokio::test]
async fn server_tcp_preflight_uses_the_tun_only_after_authenticated_binding() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session(legacy);
        match &mut session.plane {
            Plane::Channels(plane) => {
                plane.selector = None;
                plane.tcp_port = Some(9000);
            }
            Plane::Tcp(plane) => plane.server_ip = None,
        }
        let request = packet::icmp_echo_request(
            session.client_ip,
            Ipv4Addr::new(10, 77, 0, 1),
            123,
            7,
            b"kernel-only",
        );
        let key = packet::parse(&request, true).unwrap().flow;
        let token = if legacy {
            session.tcp_open_server(PREFLIGHT_ID, 1, key).await.unwrap();
            let Plane::Tcp(plane) = &session.plane else {
                unreachable!()
            };
            plane.flows[&PREFLIGHT_ID].tcp_token.unwrap()
        } else {
            session
                .channels_tcp_open(PREFLIGHT_ID, 1, key)
                .await
                .unwrap();
            let Plane::Channels(plane) = &session.plane else {
                unreachable!()
            };
            plane.flows[&PREFLIGHT_ID]
                .tcp
                .as_ref()
                .unwrap()
                .token
                .unwrap()
        };
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: PREFLIGHT_ID,
                channel: None,
                packet: request.clone(),
            })
            .await
            .unwrap();
        assert!(events.try_recv().is_err(), "unbound TCP probe reached TUN");
        let mut bound = session.resolve_binding(&token).unwrap();
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: PREFLIGHT_ID,
                channel: None,
                packet: request.clone(),
            })
            .await
            .unwrap();
        assert!(
            events.try_recv().is_err(),
            "unauthenticated TCP probe reached TUN"
        );
        session.tcp_connected(PREFLIGHT_ID, 1).await.unwrap();
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: PREFLIGHT_ID,
                channel: None,
                packet: request.clone(),
            })
            .await
            .unwrap();
        assert!(
            matches!(events.try_recv(), Ok((_, link_io::Event::Packet(packet)))
            if packet.id == PREFLIGHT_ID && packet.bytes == request)
        );
        let reply = common::echo_reply(&request);
        session.handle_tun_packet(&reply, None).await.unwrap();
        assert_eq!(bound.outgoing.try_recv().unwrap(), reply);
    }
}

#[tokio::test]
async fn server_preflight_uses_the_tun_path_and_relays_the_kernel_reply() {
    let (mut session, mut events) = link_session(false);
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.selector = None; // server side
    let (command, mut commands) = mpsc::channel(4);
    plane.channels.insert(
        5,
        ChannelHandle {
            candidate: Candidate::Mosh,
            key: [7; 16],
            established: true,
            command,
            task: tokio::spawn(async {}),
            cancel: None,
            relay: None,
        },
    );

    let request = packet::icmp_echo_request(
        Ipv4Addr::new(10, 77, 0, 2),
        Ipv4Addr::new(10, 77, 0, 1),
        0x1234,
        7,
        &[0xa5; 16],
    );
    let key = packet::parse(&request, true).unwrap().flow;
    session
        .flow_open(PREFLIGHT_ID, 1, key, Some(5), false)
        .await
        .unwrap();
    // Model the completed FlowEcho/Commit exchange.
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.flows.get_mut(&PREFLIGHT_ID).unwrap().active = true;
    assert!(matches!(commands.try_recv(), Ok(TaskCommand::Record(_))));

    session
        .deliver_to_tun(Incoming {
            generation: 1,
            id: PREFLIGHT_ID,
            channel: Some(5),
            packet: request.clone(),
        })
        .await
        .unwrap();

    assert!(matches!(
        events.try_recv(),
        Ok((_, link_io::Event::Packet(packet)))
            if packet.id == PREFLIGHT_ID && packet.bytes == request
    ));
    assert!(
        commands.try_recv().is_err(),
        "server fabricated an echo reply"
    );
    let reply = common::echo_reply(&request);
    session.handle_tun_packet(&reply, None).await.unwrap();
    assert!(matches!(
        commands.try_recv(),
        Ok(TaskCommand::Data { flow_id: id, generation: 1, packet: bytes }) if id == PREFLIGHT_ID && bytes == reply
    ));
    assert!(packet::icmp_echo_reply_matches(
        &reply,
        0x1234,
        7,
        &[0xa5; 16]
    ));
}
