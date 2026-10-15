mod common;

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use std::time::Instant as StdInstant;

use svpn::control::{Control, Message, Stats, Strategy};
use svpn::link_io::{self, FIRST_PROBE_ID, LinkIo, PREFLIGHT_ID};
use svpn::packet::{self, FlowKey};
use svpn::selector::{Action, Allowed, Candidate, Reason, Selector};
use svpn::session::*;
use svpn::udp::Incoming;
use svpn::{channel, drivers, probe, webrtc};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

#[test]
fn prefixed_line_is_unchanged_without_a_tag_and_names_the_server_in_a_pool() {
    assert_eq!(prefixed("", "channel"), "channel:");
    assert_eq!(prefixed("[h1]", "channel"), "channel[h1]:");
    assert_eq!(prefixed("[203.0.113.10]", "flow"), "flow[203.0.113.10]:");
}

fn link_session(tcp: bool) -> (Session, mpsc::Receiver<(link_io::Epoch, link_io::Event)>) {
    link_session_cap(tcp, 1)
}

fn link_session_cap(
    tcp: bool,
    events_capacity: usize,
) -> (Session, mpsc::Receiver<(link_io::Epoch, link_io::Event)>) {
    let (events, returned) = mpsc::channel(events_capacity);
    let (_, packets) = mpsc::channel(1);
    let server_ip = Some(Ipv4Addr::new(10, 77, 0, 1));
    let plane = if tcp {
        Plane::Tcp(TcpPlane {
            mode: svpn::tcp::Mode {
                port: 9000,
                camouflage: svpn::framing::Camouflage::None,
            },
            server_ip,
            token_index: HashMap::new(),
            flows: HashMap::new(),
            by_key: HashMap::new(),
            next_flow_id: 1,
        })
    } else {
        let mut plane = test_plane(Some(Selector::new(Allowed {
            mosh: true,
            ..Allowed::default()
        })));
        plane.server_ip = server_ip;
        Plane::Channels(Box::new(plane))
    };
    (
        Session {
            control: Control::new(tokio::io::empty(), tokio::io::sink()),
            io: PacketIo::Link(LinkIo {
                epoch: link_io::Epoch {
                    link: 2,
                    generation: 7,
                },
                peer_ip: Ipv4Addr::new(10, 77, 0, 1),
                tag: String::new(),
                packets,
                events,
                stats: tokio::sync::watch::channel(Stats::default()).0,
                delivery: std::sync::Arc::default(),
            }),
            last_link_id: 0,
            readiness: None,
            client_ip: Ipv4Addr::new(10, 77, 0, 2),
            drop_prefix: String::new(),
            mtu: 1400,
            plane,
            tcp_listener: None,
            tasks: JoinSet::new(),
            task_events: mpsc::channel(64),
            incoming: mpsc::channel(CHANNEL_QUEUE),
            tcp_events: mpsc::channel(CHANNEL_QUEUE),
            tombstones: Tombstones::default(),
            stats: Stats::default(),
            round: None,
            next_round_attempt: u64::MAX / 2,
        },
        returned,
    )
}

fn assert_closed(event: (link_io::Epoch, link_io::Event), id: u64, key: FlowKey) {
    assert_eq!(
        event.0,
        link_io::Epoch {
            link: 2,
            generation: 7
        }
    );
    let link_io::Event::Closed {
        id: closed,
        key: closed_key,
    } = event.1
    else {
        panic!("expected close event");
    };
    assert_eq!((closed, closed_key), (id, key));
}

fn tcp_packet(flags: u8) -> Vec<u8> {
    let mut bytes = common::udp_packet(false);
    bytes.resize(40, 0);
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[9] = 6;
    bytes[32] = 0x50;
    bytes[33] = flags;
    bytes
}

#[tokio::test]
async fn explicit_id_is_native_and_stale_rst_cannot_close_reused_tuple() {
    for tcp in [false, true] {
        let (mut session, mut events) = link_session(tcp);
        let syn = tcp_packet(2);
        let key = packet::parse(&syn, true).unwrap().flow;
        session.handle_tun_packet(&syn, Some(41)).await.unwrap();
        assert!(session.has_flow(41));
        assert!(!session.has_flow(1));
        session
            .handle_tun_packet(&tcp_packet(4), Some(40))
            .await
            .unwrap();
        assert!(session.has_flow(41));
        assert!(events.try_recv().is_err());
        assert_eq!(session.stats.dropped_packets, 1);

        let rst = tcp_packet(4);
        session.handle_tun_packet(&rst, Some(41)).await.unwrap();
        assert!(session.has_flow(41));
        assert!(events.try_recv().is_err());
        assert_eq!(session.stats.dropped_packets, 1);
        if let Plane::Tcp(plane) = &session.plane {
            assert_eq!(plane.flows[&41].pending, VecDeque::from([syn.clone(), rst]));
        }
        // The peer closes after delivery; an old close cannot retire the next ID.
        session.close_flow(41, false).await.unwrap();
        assert_closed(events.try_recv().unwrap(), 41, key);
        assert!(!session.has_flow(41));
        session.handle_tun_packet(&syn, Some(42)).await.unwrap();
        session.close_flow(41, false).await.unwrap();
        assert!(session.has_flow(42));
        assert!(events.try_recv().is_err());
    }
}

#[tokio::test]
async fn client_rst_reaches_transport_before_retiring_flow() {
    // Legacy TCP can send before the Connected event reaches the session.
    for (legacy, fallback, active) in [
        (false, false, true),
        (false, true, true),
        (true, false, true),
        (true, false, false),
    ] {
        for (full, ending) in [
            (true, "control"),
            (true, "eof"),
            (true, "error"),
            (false, "control"),
            (false, "eof"),
            (false, "error"),
        ] {
            let (mut session, mut events) = link_session(legacy);
            let syn = tcp_packet(2);
            let key = packet::parse(&syn, true).unwrap().flow;
            session.handle_tun_packet(&syn, Some(41)).await.unwrap();
            session.readiness = Some(Readiness::Ready);
            let (out, mut outgoing) = mpsc::channel(1);
            let (command, mut commands) = mpsc::channel(1);
            if full {
                out.try_send(vec![0]).unwrap();
                command.try_send(TaskCommand::Data(0, vec![0])).unwrap();
            }
            match &mut session.plane {
                Plane::Channels(plane) => {
                    let flow = plane.flows.get_mut(&41).unwrap();
                    flow.active = active;
                    if fallback {
                        flow.tcp = Some(FlowTcp {
                            key: [0; 16],
                            token: None,
                            out: Some(out),
                            receiver: None,
                            task: None,
                        });
                    } else {
                        flow.channel = Some(5);
                        plane.channels.insert(
                            5,
                            ChannelHandle {
                                candidate: Candidate::Mosh,
                                command,
                                task: tokio::spawn(async {}),
                                cancel: None,
                                relay: None,
                            },
                        );
                    }
                }
                Plane::Tcp(plane) => {
                    let flow = plane.flows.get_mut(&41).unwrap();
                    flow.active = active;
                    flow.outgoing = Some(out);
                }
            }
            let rst = tcp_packet(4);
            session.handle_tun_packet(&rst, Some(41)).await.unwrap();
            assert!(session.has_flow(41), "RST closed the flow before delivery");
            assert!(events.try_recv().is_err());
            if full {
                assert_eq!(session.stats.dropped_packets, 1);
            } else if legacy || fallback {
                assert_eq!(outgoing.try_recv().unwrap(), rst);
            } else {
                assert!(
                    matches!(commands.try_recv(), Ok(TaskCommand::Data(41, bytes)) if bytes == rst)
                );
            }
            // EOF/reset can overtake Close on the independent SSH channel.
            match ending {
                "eof" if legacy || fallback => session.tcp_closed(41).await.unwrap(),
                "error" if legacy || fallback => session.tcp_failed(41).await.unwrap(),
                _ => session
                    .dispatch_control(if legacy {
                        Message::Close { id: 41 }
                    } else {
                        Message::FlowClose { flow_id: 41 }
                    })
                    .await
                    .unwrap(),
            }
            assert_closed(events.try_recv().unwrap(), 41, key);
            assert!(!session.has_flow(41));
            // The other ordering: transport completion arrives after Close.
            session.tcp_closed(41).await.unwrap();
            session.tcp_failed(41).await.unwrap();
            assert_eq!(session.readiness, Some(Readiness::Ready));
            assert!(events.try_recv().is_err());
        }
    }
}

#[tokio::test]
async fn closed_tcp_after_idle_replies_to_target_without_reopening_flow() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session(legacy);
        let syn = tcp_packet(2);
        let key = packet::parse(&syn, true).unwrap().flow;
        session.handle_tun_packet(&syn, Some(41)).await.unwrap();
        match &mut session.plane {
            Plane::Channels(plane) => plane.selector = None,
            Plane::Tcp(plane) => plane.server_ip = None,
        }
        let target_packet = packet::tcp_probe(key, 123);
        // A pre-commit owner still owns its tuple: do not synthesize a reset.
        session
            .handle_tun_packet(&target_packet, None)
            .await
            .unwrap();
        assert!(session.has_flow(41));
        assert!(events.try_recv().is_err());
        match &mut session.plane {
            Plane::Channels(plane) => plane.flows.get_mut(&41).unwrap().active = true,
            Plane::Tcp(plane) => plane.flows.get_mut(&41).unwrap().active = true,
        }
        session
            .expire_flows(tokio::time::Instant::now() + FLOW_IDLE + Duration::from_secs(1))
            .await
            .unwrap();
        assert_closed(events.try_recv().unwrap(), 41, key);
        assert!(!session.has_flow(41));
        session
            .handle_tun_packet(&target_packet, None)
            .await
            .unwrap();
        let (_, link_io::Event::Packet(reset)) =
            events.try_recv().expect("idle target must get a TCP reset")
        else {
            panic!("expected a local TCP reset");
        };
        let expected =
            packet::tcp_reset_for(&packet::parse(&target_packet, true).unwrap()).unwrap();
        assert_eq!(reset.bytes, expected);
        assert_eq!(packet::parse(&reset.bytes, true).unwrap().flow, key);
        assert!(!session.has_flow(41));
        assert!(events.try_recv().is_err());
        // Never answer a reset or invent a TCP response for UDP.
        session
            .handle_tun_packet(&packet::tcp_reset_seq(key, 123), None)
            .await
            .unwrap();
        session
            .handle_tun_packet(&common::udp_packet(true), None)
            .await
            .unwrap();
        assert!(events.try_recv().is_err());
    }
}

#[tokio::test]
async fn server_rst_retires_flow_only_after_tun_delivery() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 2);
        let syn = tcp_packet(2);
        let key = packet::parse(&syn, true).unwrap().flow;
        session.handle_tun_packet(&syn, Some(41)).await.unwrap();
        match &mut session.plane {
            Plane::Channels(plane) => plane.selector = None,
            Plane::Tcp(plane) => plane.server_ip = None,
        }
        let rst = tcp_packet(4);
        // An inactive flow cannot deliver a reset or retire its mapping.
        session
            .deliver_to_tun(Incoming {
                id: 41,
                channel: None,
                packet: rst.clone(),
            })
            .await
            .unwrap();
        assert!(session.has_flow(41));
        assert!(events.try_recv().is_err());
        match &mut session.plane {
            Plane::Channels(plane) => plane.flows.get_mut(&41).unwrap().active = true,
            Plane::Tcp(plane) => plane.flows.get_mut(&41).unwrap().active = true,
        }
        for id in [40, 42] {
            session
                .deliver_to_tun(Incoming {
                    id,
                    channel: None,
                    packet: rst.clone(),
                })
                .await
                .unwrap();
            assert!(session.has_flow(41));
            assert!(events.try_recv().is_err());
        }
        let mut wrong_tuple = rst.clone();
        wrong_tuple[20] ^= 1;
        session
            .deliver_to_tun(Incoming {
                id: 41,
                channel: None,
                packet: wrong_tuple,
            })
            .await
            .unwrap();
        assert!(session.has_flow(41));
        assert!(events.try_recv().is_err());
        // Failed packet delivery must not turn into a successful close.
        let PacketIo::Link(io) = &session.io else {
            unreachable!()
        };
        for _ in 0..2 {
            io.events
                .try_send((io.epoch, link_io::Event::Checking))
                .unwrap();
        }
        session
            .deliver_to_tun(Incoming {
                id: 41,
                channel: None,
                packet: rst.clone(),
            })
            .await
            .unwrap();
        assert!(session.has_flow(41));
        for _ in 0..2 {
            events.try_recv().unwrap();
        }
        session
            .deliver_to_tun(Incoming {
                id: 41,
                channel: None,
                packet: rst.clone(),
            })
            .await
            .unwrap();
        assert!(
            matches!(events.try_recv(), Ok((_, link_io::Event::Packet(packet)))
            if packet.id == 41 && packet.bytes == rst)
        );
        assert_closed(events.try_recv().unwrap(), 41, key);
        assert!(!session.has_flow(41));
    }
}

#[tokio::test]
async fn explicit_ids_are_nonzero_never_reused_and_do_not_wrap() {
    for tcp in [false, true] {
        let (mut session, mut events) = link_session(tcp);
        let bytes = common::udp_packet(false);
        let key = packet::parse(&bytes, true).unwrap().flow;
        session.handle_tun_packet(&bytes, Some(0)).await.unwrap();
        assert_closed(events.recv().await.unwrap(), 0, key);
        assert_eq!(session.flow_count(), 0);
        session.handle_tun_packet(&bytes, Some(7)).await.unwrap();
        session.close_flow(7, false).await.unwrap();
        assert_closed(events.recv().await.unwrap(), 7, key);
        session.handle_tun_packet(&bytes, Some(7)).await.unwrap();
        assert_closed(events.recv().await.unwrap(), 7, key);
        assert_eq!(session.flow_count(), 0);
        assert!(
            session
                .handle_tun_packet(&bytes, Some(PREFLIGHT_ID))
                .await
                .is_err()
        );
        assert!(!session.has_flow(PREFLIGHT_ID));
        assert_eq!(session.last_link_id, 7);
        assert!(
            session
                .handle_tun_packet(&bytes, Some(FIRST_PROBE_ID))
                .await
                .is_err()
        );
        session
            .handle_tun_packet(&bytes, Some(FIRST_PROBE_ID - 1))
            .await
            .unwrap();
        assert!(session.has_flow(FIRST_PROBE_ID - 1));
    }
}

#[tokio::test]
async fn ids_rejected_while_probing_stay_retired_after_ready() {
    for tcp in [false, true] {
        for malformed in [false, true] {
            let (mut session, mut events) = link_session(tcp);
            let bytes = common::udp_packet(false);
            let key = packet::parse(&bytes, true).unwrap().flow;
            session.readiness = Some(Readiness::Probing);
            let rejected = if malformed { &[0][..] } else { &bytes };
            session.handle_tun_packet(rejected, Some(7)).await.unwrap();
            if !malformed {
                assert_closed(events.try_recv().unwrap(), 7, key);
            }
            assert_eq!(session.last_link_id, 7);
            assert_eq!(session.flow_count(), 0);

            session.readiness = Some(Readiness::Ready);
            session.handle_tun_packet(&bytes, Some(7)).await.unwrap();
            assert_closed(events.try_recv().unwrap(), 7, key);
            assert!(!session.has_flow(7));
            session.handle_tun_packet(&bytes, Some(8)).await.unwrap();
            assert!(session.has_flow(8));
        }
    }
}

#[tokio::test]
async fn queued_packets_cannot_reopen_closed_ids_or_close_another_tuple() {
    for tcp in [false, true] {
        let (mut session, mut events) = link_session(tcp);
        let bytes = common::udp_packet(false);
        let key = packet::parse(&bytes, true).unwrap().flow;
        session.handle_tun_packet(&bytes, Some(7)).await.unwrap();
        session.close_flow(7, false).await.unwrap();
        assert_closed(events.try_recv().unwrap(), 7, key);

        let mut other = bytes.clone();
        other[21] ^= 1;
        session.handle_tun_packet(&other, Some(8)).await.unwrap();
        session.handle_tun_packet(&bytes, Some(7)).await.unwrap();
        assert_closed(events.try_recv().unwrap(), 7, key);
        assert!(!session.has_flow(7));
        assert!(session.has_flow(8));
        assert_eq!(session.last_link_id, 8);

        // A genuinely conflicting ID must not retire its existing tuple.
        session.handle_tun_packet(&bytes, Some(8)).await.unwrap();
        assert_closed(events.try_recv().unwrap(), 8, key);
        assert!(session.has_flow(8));
        assert_eq!(session.stats.dropped_packets, 2);

        session.handle_tun_packet(&bytes, Some(9)).await.unwrap();
        assert!(session.has_flow(9));
        assert_eq!(session.last_link_id, 9);
    }
}

#[tokio::test]
async fn rejected_new_packets_release_their_owner_without_admission() {
    for tcp in [false, true] {
        let (mut session, mut events) = link_session(tcp);
        let bytes = common::udp_packet(false);
        let key = packet::parse(&bytes, true).unwrap().flow;
        session.mtu = 20;
        session.handle_tun_packet(&bytes, Some(1)).await.unwrap();
        assert_closed(events.recv().await.unwrap(), 1, key);
        session.mtu = 1400;
        let ack = tcp_packet(0x10);
        session.handle_tun_packet(&ack, Some(2)).await.unwrap();
        assert_closed(
            events.recv().await.unwrap(),
            2,
            packet::parse(&ack, true).unwrap().flow,
        );
        session.handle_tun_packet(&[0], Some(3)).await.unwrap();
        assert!(events.try_recv().is_err());
        session.handle_tun_packet(&bytes, Some(3)).await.unwrap();
        assert_closed(events.recv().await.unwrap(), 3, key);
        assert_eq!(session.flow_count(), 0);
        assert_eq!(session.stats.dropped_packets, 4);
    }
}

#[tokio::test]
async fn committed_packets_are_counted_once_on_both_sides_and_transports() {
    for client in [false, true] {
        for tcp in [false, true] {
            for accepted in [false, true] {
                let (mut session, _events) = link_session(false);
                let bytes = common::udp_packet(false);
                let key = packet::parse(&bytes, true).unwrap().flow;
                let Plane::Channels(plane) = &mut session.plane else {
                    unreachable!()
                };
                let now = StdInstant::now();
                if client {
                    let selector = plane.selector.as_mut().unwrap();
                    selector.request(1, key, &bytes, now).unwrap();
                    selector.enqueue(1, &bytes).unwrap();
                    selector.channel_ready(Candidate::Mosh, 1, 10, now);
                    selector.probes_passed(Candidate::Mosh, 10, now);
                    selector.peer_verified(Candidate::Mosh, 10, now);
                    selector.bind_succeeded(1, now);
                } else {
                    plane.selector = None;
                }
                let mut flow = Flow::new(key, tokio::time::Instant::now());
                flow.channel = Some(10);
                if !client {
                    flow.pending = VecDeque::from([bytes.clone(), bytes.clone()]);
                }
                let (send, received) = mpsc::channel(4);
                let (command, commands) = mpsc::channel(4);
                let mut received = Some(received);
                let mut commands = Some(commands);
                if !accepted {
                    received.take();
                    commands.take();
                }
                if tcp {
                    flow.tcp = Some(FlowTcp {
                        key: [0; 16],
                        token: None,
                        out: Some(send),
                        receiver: None,
                        task: None,
                    });
                }
                plane.flows.insert(1, flow);
                plane.channels.insert(
                    10,
                    ChannelHandle {
                        candidate: Candidate::Mosh,
                        command,
                        task: tokio::spawn(std::future::pending()),
                        cancel: None,
                        relay: None,
                    },
                );
                for _ in 0..2 {
                    if client {
                        session.committed(1).await.unwrap();
                    } else {
                        session.commit(1).await.unwrap();
                    }
                }
                assert_eq!(session.stats.inner_tx_packets, if accepted { 2 } else { 0 });
                assert_eq!(
                    session.stats.inner_tx_bytes,
                    if accepted { 2 * bytes.len() as u64 } else { 0 }
                );
                assert_eq!(session.stats.dropped_packets, if accepted { 0 } else { 2 });
                if accepted {
                    for _ in 0..2 {
                        if tcp {
                            assert_eq!(received.as_mut().unwrap().try_recv().unwrap(), bytes);
                        } else {
                            assert!(
                                matches!(commands.as_mut().unwrap().try_recv().unwrap(), TaskCommand::Data(1, packet) if packet == bytes)
                            );
                        }
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn flow_probe_overload_closes_only_the_opening_flow() {
    for rebind in [false, true] {
        let (mut session, mut events) = link_session(false);
        let bytes = common::udp_packet(false);
        let key = packet::parse(&bytes, true).unwrap().flow;
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        plane.selector = None;
        if rebind {
            plane
                .flows
                .insert(1, Flow::new(key, tokio::time::Instant::now()));
            plane.by_key.insert(key, 1);
        }
        let (command, mut commands) = mpsc::channel(1);
        assert!(command.try_send(TaskCommand::Data(2, bytes)).is_ok());
        plane.channels.insert(
            10,
            ChannelHandle {
                candidate: Candidate::Mosh,
                command,
                task: tokio::spawn(std::future::pending()),
                cancel: None,
                relay: None,
            },
        );
        tokio::time::timeout(Duration::from_millis(100), async {
            if rebind {
                session.flow_channel(1, 10).await
            } else {
                session.flow_open(1, key, Some(10)).await
            }
        })
        .await
        .expect("FlowProbe blocked the session loop")
        .unwrap();
        assert!(!session.has_flow(1));
        assert_closed(events.try_recv().unwrap(), 1, key);
        let Plane::Channels(plane) = &session.plane else {
            unreachable!()
        };
        assert!(plane.channels.contains_key(&10));
        assert!(matches!(commands.try_recv(), Ok(TaskCommand::Data(2, _))));
    }
}

#[tokio::test]
async fn borrowed_channel_failure_closes_its_flows_but_probe_timeout_does_not() {
    for transport_failed in [false, true] {
        let (mut session, mut events) = link_session_cap(false, 8);
        let bytes = common::udp_packet(false);
        let key = packet::parse(&bytes, true).unwrap().flow;
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        let mut selector = Selector::new_proactive(Allowed {
            mosh: true,
            tcp: true,
            ..Allowed::default()
        });
        selector.adopt(Candidate::Mosh, Some(10));
        selector.request(1, key, &bytes, StdInstant::now()).unwrap();
        selector.bind_succeeded(1, StdInstant::now());
        selector.committed(1);
        plane.selector = Some(selector);
        let mut flow = Flow::new(key, tokio::time::Instant::now());
        flow.channel = Some(10);
        flow.active = true;
        plane.flows.insert(1, flow);
        plane.by_key.insert(key, 1);
        let (command, _commands) = mpsc::channel(1);
        plane.channels.insert(
            10,
            ChannelHandle {
                candidate: Candidate::Mosh,
                command,
                task: tokio::spawn(std::future::pending()),
                cancel: None,
                relay: None,
            },
        );
        session.begin_preflight().await.unwrap();
        let (&attempt, candidate) = session
            .round
            .as_ref()
            .unwrap()
            .pending
            .iter()
            .next()
            .unwrap();
        assert!(!candidate.owned);
        assert_eq!(candidate.channel, Some(10));
        if transport_failed {
            session
                .dispatch_task_event(TaskEvent::Failed {
                    channel: 10,
                    reason: "transport failed".into(),
                })
                .await
                .unwrap();
            assert_closed(events.try_recv().unwrap(), 1, key);
        } else {
            session
                .round_attempt_failed(attempt, Reason::PathTimeout)
                .await
                .unwrap();
            assert!(events.try_recv().is_err());
        }
        session.round_won(None).await.unwrap();
        assert_eq!(session.readiness, Some(Readiness::Verified(None)));
        assert_eq!(session.has_flow(1), !transport_failed);
        let Plane::Channels(plane) = &session.plane else {
            unreachable!()
        };
        assert_eq!(plane.channels.contains_key(&10), !transport_failed);
        assert_eq!(plane.by_key.contains_key(&key), !transport_failed);
    }
}

#[tokio::test]
async fn udp_commit_does_not_wait_for_a_full_shared_command_queue() {
    let (mut session, _events) = link_session(false);
    let bytes = common::udp_packet(false);
    let key = packet::parse(&bytes, true).unwrap().flow;
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    let mut flow = Flow::new(key, tokio::time::Instant::now());
    flow.channel = Some(10);
    plane.flows.insert(1, flow);
    let (command, mut commands) = mpsc::channel(1);
    assert!(
        command
            .try_send(TaskCommand::Data(2, bytes.clone()))
            .is_ok()
    );
    plane.channels.insert(
        10,
        ChannelHandle {
            candidate: Candidate::Mosh,
            command,
            task: tokio::spawn(std::future::pending()),
            cancel: None,
            relay: None,
        },
    );
    tokio::time::timeout(
        Duration::from_millis(100),
        session.send_pending(1, VecDeque::from([bytes])),
    )
    .await
    .expect("commit blocked the session loop")
    .unwrap();
    assert_eq!(session.stats.dropped_packets, 1);
    assert_eq!(session.stats.inner_tx_packets, 0);
    assert!(session.has_flow(1));
    assert!(matches!(commands.try_recv(), Ok(TaskCommand::Data(2, _))));
}

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

#[tokio::test]
async fn legacy_tcp_counts_first_and_queued_packets_on_transport_admission() {
    let (mut session, _events) = link_session(true);
    let bytes = common::udp_packet(false);
    for _ in 0..3 {
        session.handle_tun_packet(&bytes, Some(1)).await.unwrap();
    }
    assert_eq!(session.stats.inner_tx_packets, 0);
    session
        .tcp_opened_client(1, 9000, [1; 16], Some([2; 16]))
        .await
        .unwrap();
    assert_eq!(session.stats.inner_tx_packets, 3);
    session.handle_tun_packet(&bytes, Some(1)).await.unwrap();
    assert_eq!(session.stats.inner_tx_packets, 4);
    assert_eq!(session.stats.inner_tx_bytes, 4 * bytes.len() as u64);
}

#[tokio::test]
async fn tcp_fallback_keeps_user_packets_until_commit() {
    let (mut session, _events) = link_session(false);
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.selector = Some(Selector::new_proactive(Allowed {
        tcp: true,
        ..Allowed::default()
    }));
    let bytes = common::udp_packet(false);
    for _ in 0..3 {
        session.handle_tun_packet(&bytes, Some(1)).await.unwrap();
    }
    assert_eq!(session.stats.inner_tx_packets, 0);
    session
        .channels_tcp_opened(1, 9000, [1; 16], Some([2; 16]))
        .await
        .unwrap();
    assert_eq!(session.stats.inner_tx_packets, 0);
    session.tcp_connected(1).await.unwrap();
    assert_eq!(session.stats.inner_tx_packets, 0);
    session.committed(1).await.unwrap();
    assert_eq!(session.stats.inner_tx_packets, 3);
    session.handle_tun_packet(&bytes, Some(1)).await.unwrap();
    assert_eq!(session.stats.inner_tx_packets, 4);
    assert_eq!(session.stats.inner_tx_bytes, 4 * bytes.len() as u64);
}

/// N3 unit helper: the OS-style echo reply for a round's request
/// (type 0, recomputed ICMP checksum — id/seq/payload intact).
fn echo_reply_for(request: &[u8]) -> Vec<u8> {
    let mut reply = request.to_vec();
    reply[12..16].copy_from_slice(&request[16..20]);
    reply[16..20].copy_from_slice(&request[12..16]);
    reply[20] = 0; // echo reply
    reply[22] = 0;
    reply[23] = 0; // clear the old checksum
    let mut sum: u32 = 0;
    for pair in reply[20..].as_chunks::<2>().0 {
        sum += u16::from_be_bytes(*pair) as u32;
    }
    if reply.len() % 2 == 1 {
        sum += u32::from(reply[reply.len() - 1]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    reply[22..24].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    reply
}

#[tokio::test]
async fn retired_tcp_probe_events_do_not_kill_ready_session() {
    for tcp in [false, true] {
        let (mut session, _events) = link_session(tcp);
        session.readiness = Some(Readiness::Ready);
        // Cancellation cannot remove Connected/Failed already in the event queue.
        assert!(session.tcp_connected(PREFLIGHT_ID).await.is_ok());
        assert!(session.tcp_failed(PREFLIGHT_ID).await.is_ok());
        if tcp {
            session
                .tcp_opened_client(PREFLIGHT_ID, 9000, [0; 16], None)
                .await
                .unwrap();
            session.tcp_close(PREFLIGHT_ID).await.unwrap();
        } else {
            session
                .channels_tcp_opened(PREFLIGHT_ID, 9000, [0; 16], None)
                .await
                .unwrap();
            session.committed(PREFLIGHT_ID).await.unwrap();
            session.close_flow(PREFLIGHT_ID, false).await.unwrap();
        }
        assert_eq!(session.readiness, Some(Readiness::Ready));
        assert!(session.round.is_none());
    }
}

#[tokio::test]
async fn round_failure_waits_for_pool_event_capacity() {
    let (mut session, mut events) = link_session(false);
    session.begin_preflight().await.unwrap();
    let PacketIo::Link(io) = &session.io else {
        unreachable!()
    };
    io.events
        .send((io.epoch, link_io::Event::Ready))
        .await
        .unwrap();
    let (result, ()) = tokio::join!(session.round_failed(), async {
        assert!(matches!(
            events.recv().await.unwrap().1,
            link_io::Event::Ready
        ));
        let event = tokio::time::timeout(Duration::from_millis(100), events.recv())
            .await
            .expect("round verdict was lost")
            .unwrap();
        assert!(matches!(event.1, link_io::Event::RoundFailed));
    });
    result.unwrap();
}

#[tokio::test]
async fn retry_round_announces_checking_to_pool() {
    let (mut session, mut events) = link_session(false);
    session.begin_preflight().await.unwrap();
    while events.try_recv().is_ok() {}
    session.round_failed().await.unwrap();
    assert!(matches!(
        events.try_recv().unwrap().1,
        link_io::Event::RoundFailed
    ));
    session.arm_round().await.unwrap();
    assert!(matches!(
        events.try_recv().unwrap().1,
        link_io::Event::Checking
    ));
}

#[test]
fn liveness_payload_spans_the_agreed_mtu_bound() {
    for mtu in [60, 64, 576, 1400, 1428] {
        let max = usize::from(mtu).saturating_sub(28).min(1400);
        assert_eq!(probe_payload_len(mtu, 0).unwrap(), 32);
        assert_eq!(probe_payload_len(mtu, (max - 32) as u16).unwrap(), max);
        for sample in 0..=u16::MAX {
            assert!((32..=max).contains(&probe_payload_len(mtu, sample).unwrap()));
        }
    }
    for mtu in [0, 27, 28, 59] {
        assert!(probe_payload_len(mtu, 0).is_err());
    }
}

#[tokio::test]
async fn round_probes_every_udp_candidate_and_keys_preflight_by_icmp_identity() {
    let (mut session, _events) = link_session(false);
    if let Plane::Channels(plane) = &mut session.plane {
        plane.selector = Some(Selector::new_proactive(Allowed {
            mosh: true,
            obfs: true,
            ..Allowed::default()
        }));
    }
    session.begin_preflight().await.unwrap();
    let round = session.round.as_ref().expect("round armed");
    // Both candidates entered the same round at once — the startup race
    // (Connecting) is the same parallel path as re-checking, never serial.
    let mut candidates: Vec<_> = round.pending.values().map(|rc| rc.candidate).collect();
    candidates.sort();
    assert_eq!(candidates.len(), 2);
    assert!(candidates.contains(&Candidate::Mosh));
    assert!(candidates.contains(&Candidate::Obfs));
    assert!(round.pending.values().all(|rc| rc.channel.is_none()));
    assert!(round.retry_at.is_none());
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    let flow = plane.flows.get(&PREFLIGHT_ID).expect("preflight flow");
    assert_eq!(flow.key.protocol, 1);
    assert_eq!(flow.key.source, session.client_ip);
    assert_eq!(flow.key.source_port, round.id);
}

#[tokio::test]
async fn parallel_candidates_have_independent_tun_verdicts() {
    let (mut session, _events) = link_session(false);
    let (local, remote) = tokio::io::duplex(8192);
    let (reader, writer) = tokio::io::split(local);
    session.control = Control::new(reader, writer);
    let (reader, writer) = tokio::io::split(remote);
    let mut peer = Control::new(reader, writer);
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.selector = Some(Selector::new_proactive(Allowed {
        mosh: true,
        obfs: true,
        tcp: true,
        ..Allowed::default()
    }));
    session.begin_preflight().await.unwrap();
    // All three start before any candidate receives a reply.
    let mut prepares = 0;
    let mut tcp = false;
    for _ in 0..3 {
        match tokio::time::timeout(Duration::from_secs(1), peer.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Message::Open { id, .. } => {
                assert_eq!(Some(id), session.round.as_ref().unwrap().tcp_id);
                tcp = true;
            }
            Message::ChannelPrepare { .. } => prepares += 1,
            _ => panic!("unexpected round start message"),
        }
    }
    assert!(tcp);
    assert_eq!(prepares, 2);
    let round = session.round.as_mut().unwrap();
    let mut probes: Vec<_> = round
        .pending
        .iter_mut()
        .map(|(&id, rc)| {
            let channel = if rc.candidate == Candidate::Mosh {
                100
            } else {
                101
            };
            rc.channel = Some(channel);
            (id, channel, rc.candidate, rc.icmp_id, rc.request.clone())
        })
        .collect();
    probes.sort_by_key(|probe| probe.1);
    assert_ne!(probes[0].3, probes[1].3);
    assert!(probes.iter().all(|probe| probe.3 != round.id));
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    for (id, channel, candidate, _, _) in &probes {
        let flow = plane.flows.get_mut(id).unwrap();
        flow.channel = Some(*channel);
        flow.active = true;
        plane.channels.insert(
            *channel,
            ChannelHandle {
                candidate: *candidate,
                command: mpsc::channel(1).0,
                cancel: None,
                task: tokio::spawn(std::future::pending()),
                relay: None,
            },
        );
    }
    // A reply from the faster handshake cannot prove another candidate's TUN path.
    session
        .deliver_to_tun(Incoming {
            id: probes[1].0,
            channel: Some(101),
            packet: echo_reply_for(&probes[0].4),
        })
        .await
        .unwrap();
    assert!(session.round.is_some());
    // Even matching ICMP bytes cannot prove B when delivered by channel A.
    session
        .deliver_to_tun(Incoming {
            id: probes[1].0,
            channel: Some(100),
            packet: echo_reply_for(&probes[1].4),
        })
        .await
        .unwrap();
    assert!(
        session.round.is_some(),
        "another channel supplied the verdict"
    );
    // The second candidate completes its own TUN check and wins immediately.
    session
        .deliver_to_tun(Incoming {
            id: probes[1].0,
            channel: Some(101),
            packet: echo_reply_for(&probes[1].4),
        })
        .await
        .unwrap();
    assert!(session.round.is_none());
    assert_eq!(session.readiness, Some(Readiness::Verified(Some(101))));
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    assert!(!plane.channels.contains_key(&100));
    assert!(plane.channels.contains_key(&101));
    assert!(plane.flows.is_empty());
    assert_eq!(
        plane
            .selector
            .as_ref()
            .unwrap()
            .ready_channel(Candidate::Obfs),
        Some(101)
    );
}

#[tokio::test]
async fn round_verdict_reply_wins_and_noise_is_ignored() {
    let (mut session, _events) = link_session(false);
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.selector = Some(Selector::new_proactive(Allowed {
        tcp: true,
        ..Allowed::default()
    }));
    session.begin_preflight().await.unwrap();
    let round = session.round.as_ref().expect("round armed");
    let request = round.request.clone();
    let id = round.tcp_id.unwrap();
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.flows.get_mut(&id).unwrap().active = true;
    // Unrelated packet on the preflight flow: no verdict, round stands.
    session
        .deliver_to_tun(Incoming {
            id,
            channel: None,
            packet: vec![0u8; 40],
        })
        .await
        .unwrap();
    assert!(session.round.is_some());
    assert_eq!(session.readiness, Some(Readiness::Probing));
    // The matching echo reply wins: round retired, flow closed, Verified.
    session
        .deliver_to_tun(Incoming {
            id,
            channel: None,
            packet: echo_reply_for(&request),
        })
        .await
        .unwrap();
    assert!(session.round.is_none());
    assert_eq!(session.readiness, Some(Readiness::Verified(None)));
    assert!(!session.has_flow(PREFLIGHT_ID));
}

#[tokio::test]
async fn round_failure_emits_event_schedules_backoff_and_rearms() {
    let (mut session, mut events) = link_session(false);
    session.begin_preflight().await.unwrap();
    let attempt = *session
        .round
        .as_ref()
        .expect("round armed")
        .pending
        .keys()
        .next()
        .unwrap();
    session
        .channel_failed(Some(attempt), None, Reason::PathTimeout)
        .await
        .unwrap();
    let round = session.round.as_ref().expect("round retained for retry");
    assert!(round.pending.is_empty());
    assert!(round.retry_at.is_some());
    assert_eq!(round.backoff_step, 1);
    assert_eq!(session.readiness, Some(Readiness::Probing));
    assert!(matches!(
        events.recv().await,
        Some((_, link_io::Event::RoundFailed))
    ));
    // Re-arm keeps the escalated backoff but probes with a fresh identity.
    let old_id = round.id;
    session.arm_round().await.unwrap();
    let round = session.round.as_ref().expect("round rearmed");
    assert!(round.retry_at.is_none());
    assert_eq!(round.pending.len(), 1);
    assert_eq!(round.backoff_step, 1);
    assert_ne!(round.id, old_id);
}

#[tokio::test]
async fn tcp_round_winner_is_first_for_new_user_flows() {
    let (mut session, _events) = link_session(false);
    if let Plane::Channels(plane) = &mut session.plane {
        plane.selector = Some(Selector::new_proactive(Allowed {
            mosh: true,
            tcp: true,
            ..Allowed::default()
        }));
    }
    session.begin_preflight().await.unwrap();
    let attempt = *session
        .round
        .as_ref()
        .unwrap()
        .pending
        .keys()
        .next()
        .unwrap();
    session
        .round_attempt_failed(attempt, Reason::PathTimeout)
        .await
        .unwrap();
    session.round_won(None).await.unwrap();
    assert!(
        session
            .announce_ready(Some(tokio::time::Instant::now()), None)
            .await
            .unwrap()
    );
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    let actions = plane
        .selector
        .as_mut()
        .unwrap()
        .request(1, test_key(), b"syn", StdInstant::now())
        .unwrap();
    assert!(matches!(
        actions.as_slice(),
        [Action::TryTcp { flow_id: 1, .. }]
    ));
}

#[tokio::test]
async fn tcp_probe_ids_isolate_late_events_across_retries() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session(legacy);
        if let Plane::Channels(plane) = &mut session.plane {
            plane.selector = Some(Selector::new_proactive(Allowed {
                tcp: true,
                ..Allowed::default()
            }));
        }
        let (local, remote) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(local);
        session.control = Control::new(reader, writer);
        let (reader, writer) = tokio::io::split(remote);
        let mut peer = Control::new(reader, writer);
        session.begin_preflight().await.unwrap();
        let Message::Open { id: first, .. } = peer.recv().await.unwrap() else {
            panic!("missing TCP probe Open");
        };
        assert!(
            (FIRST_PROBE_ID..PREFLIGHT_ID).contains(&first),
            "TCP still reuses the marker"
        );
        let reply = echo_reply_for(&session.round.as_ref().unwrap().request);
        session.round_failed().await.unwrap();
        assert!(matches!(
            events.recv().await.unwrap().1,
            link_io::Event::RoundFailed
        ));
        let at = session.round.as_ref().unwrap().retry_at.unwrap();
        session.poll_round(at).await.unwrap();
        assert!(matches!(
            events.recv().await.unwrap().1,
            link_io::Event::Checking
        ));
        let second = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Message::Open { id, .. } = peer.recv().await.unwrap() {
                    break id;
                }
            }
        })
        .await
        .unwrap();
        assert_ne!(first, second);
        assert!(second < PREFLIGHT_ID);
        assert!(!session.has_flow(first));
        assert!(session.has_flow(second));
        assert_eq!(session.flow_count(), 0);
        session
            .dispatch_control(Message::Opened {
                id: first,
                port: 9000,
                key: [1; 16],
                token: Some([2; 16]),
            })
            .await
            .unwrap();
        session.tcp_connected(first).await.unwrap();
        session.tcp_failed(first).await.unwrap();
        session
            .deliver_to_tun(Incoming {
                id: first,
                channel: None,
                packet: reply,
            })
            .await
            .unwrap();
        if legacy {
            session
                .dispatch_control(Message::Close { id: first })
                .await
                .unwrap();
        } else {
            for message in [
                Message::FlowOpened {
                    flow_id: first,
                    flow: test_key(),
                    channel: 99,
                },
                Message::Committed { flow_id: first },
                Message::FlowClose { flow_id: first },
                Message::FlowReject {
                    flow_id: first,
                    reason: Reason::ChannelFailed,
                },
            ] {
                session.dispatch_control(message).await.unwrap();
            }
        }
        assert!(session.round.as_ref().unwrap().retry_at.is_none());
        assert_eq!(session.readiness, Some(Readiness::Probing));
        match &session.plane {
            Plane::Channels(plane) => {
                assert!(!plane.flows[&second].active);
                assert!(plane.flows[&second].tcp.is_none());
            }
            Plane::Tcp(plane) => {
                assert!(!plane.flows[&second].active);
                assert!(plane.flows[&second].task.is_none());
            }
        }
        assert!(events.try_recv().is_err());
    }
}

#[tokio::test]
async fn late_round_failure_cannot_restart_a_successful_tcp_round() {
    let (mut session, mut events) = link_session(false);
    if let Plane::Channels(plane) = &mut session.plane {
        plane.selector = Some(Selector::new_proactive(Allowed {
            mosh: true,
            tcp: true,
            ..Allowed::default()
        }));
    }
    session.begin_preflight().await.unwrap();
    let attempt = *session
        .round
        .as_ref()
        .unwrap()
        .pending
        .keys()
        .next()
        .unwrap();
    session
        .round_attempt_failed(attempt, Reason::PathTimeout)
        .await
        .unwrap();
    session.round_won(None).await.unwrap();
    session
        .channel_failed(Some(attempt), None, Reason::PathTimeout)
        .await
        .unwrap();
    assert!(session.round.is_none());
    assert_eq!(session.readiness, Some(Readiness::Verified(None)));
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn round_deadline_beats_resends_for_udp_and_tcp() {
    for tcp in [false, true] {
        let (mut session, mut events) = link_session(false);
        if let Plane::Channels(plane) = &mut session.plane {
            plane.selector = Some(Selector::new_proactive(Allowed {
                mosh: !tcp,
                tcp,
                ..Allowed::default()
            }));
        }
        session.begin_preflight().await.unwrap();
        let now = tokio::time::Instant::now();
        let round = session.round.as_mut().unwrap();
        round.deadline = now;
        for rc in round.pending.values_mut() {
            rc.deadline = now;
            rc.resend_at = Some(now);
        }
        session.poll_round(now).await.unwrap();
        assert!(session.round.as_ref().unwrap().retry_at.is_some());
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::RoundFailed
        ));
        // Backoff does not keep resending a retired request or repeat the event.
        session.poll_round(now).await.unwrap();
        assert!(events.try_recv().is_err());
    }
}

#[tokio::test]
async fn round_with_only_tcp_starts_immediately() {
    let (mut session, _events) = link_session(false);
    if let Plane::Channels(plane) = &mut session.plane {
        plane.selector = Some(Selector::new_proactive(Allowed {
            tcp: true,
            ..Allowed::default()
        }));
    }
    session.begin_preflight().await.unwrap();
    let round = session.round.as_ref().expect("round armed");
    assert!(round.pending.is_empty());
    assert!(round.tcp_id.is_some());
}

#[tokio::test]
async fn tcp_preflight_does_not_count_as_ip_traffic() {
    for legacy in [false, true] {
        let (mut session, _events) = link_session(legacy);
        if let Plane::Channels(plane) = &mut session.plane {
            plane.selector = Some(Selector::new_proactive(Allowed {
                tcp: true,
                ..Allowed::default()
            }));
        }
        session.begin_preflight().await.unwrap();
        let id = session.round.as_ref().unwrap().tcp_id.unwrap();
        if legacy {
            session
                .tcp_opened_client(id, 9000, [1; 16], Some([2; 16]))
                .await
                .unwrap();
        } else {
            session
                .channels_tcp_opened(id, 9000, [1; 16], Some([2; 16]))
                .await
                .unwrap();
        }
        assert_eq!(session.stats, Stats::default());
        let request = session.round.as_ref().unwrap().request.clone();
        session.tcp_connected(id).await.unwrap();
        assert_eq!(session.readiness, Some(Readiness::Probing));
        session
            .deliver_to_tun(Incoming {
                id,
                channel: None,
                packet: request.clone(),
            })
            .await
            .unwrap();
        assert_eq!(session.readiness, Some(Readiness::Probing));
        session
            .deliver_to_tun(Incoming {
                id,
                channel: None,
                packet: echo_reply_for(&request),
            })
            .await
            .unwrap();
        assert_eq!(session.readiness, Some(Readiness::Verified(None)));
    }
}

#[tokio::test]
async fn fixed_tcp_round_failure_retries_without_transport_only_readiness() {
    let (mut session, mut events) = link_session(true);
    session.begin_preflight().await.unwrap();
    let now = tokio::time::Instant::now();
    session.round.as_mut().unwrap().deadline = now;
    session.poll_round(now).await.unwrap();
    assert!(matches!(
        events.try_recv().unwrap().1,
        link_io::Event::RoundFailed
    ));
    assert_eq!(session.readiness, Some(Readiness::Probing));
    assert!(session.has_flow(PREFLIGHT_ID));
    let retry = session.round.as_ref().unwrap().retry_at.unwrap();
    session.tcp_close(PREFLIGHT_ID).await.unwrap();
    session.tcp_failed(PREFLIGHT_ID).await.unwrap();
    assert!(events.try_recv().is_err());
    session.poll_round(retry).await.unwrap();
    assert!(session.round.as_ref().unwrap().retry_at.is_none());
    assert!(session.round.as_ref().unwrap().tcp_id.is_some());
    assert_eq!(session.readiness, Some(Readiness::Probing));
}

#[tokio::test]
async fn idle_tcp_eof_does_not_check_or_retire_other_flows() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 8);
        let first = tcp_packet(2);
        let mut second = first.clone();
        second[20..22].copy_from_slice(&4321u16.to_be_bytes());
        session.handle_tun_packet(&first, Some(41)).await.unwrap();
        session.handle_tun_packet(&second, Some(42)).await.unwrap();
        let idle = tokio::time::Instant::now() - FLOW_IDLE;
        match &mut session.plane {
            Plane::Channels(plane) => plane.flows.get_mut(&41).unwrap().last_seen = idle,
            Plane::Tcp(plane) => plane.flows.get_mut(&41).unwrap().last_seen = idle,
        }
        session.readiness = Some(Readiness::Ready);
        session.tcp_closed(41).await.unwrap();
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
        session.tcp_closed(41).await.unwrap();
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
                match &mut session.plane {
                    Plane::Channels(plane) => {
                        let selector = plane.selector.as_mut().unwrap();
                        for (&id, flow) in &mut plane.flows {
                            selector.bind_succeeded(id, StdInstant::now());
                            selector.committed(id);
                            selector.take_queue(id);
                            flow.active = true;
                        }
                    }
                    Plane::Tcp(plane) => {
                        for flow in plane.flows.values_mut() {
                            flow.active = true;
                            flow.outgoing = Some(mpsc::channel(1).0);
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
                    // The final ACK must not erase the FIN-dwell state.
                    session
                        .handle_tun_packet(&tcp_packet(0x10), Some(41))
                        .await
                        .unwrap();
                }
                if reset {
                    session.tcp_failed(41).await.unwrap();
                } else {
                    session.tcp_closed(41).await.unwrap();
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
    session.tcp_failed(41).await.unwrap();
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

#[tokio::test]
async fn legacy_binding_token_does_not_activate_flow_until_authenticated() {
    for authenticated in [false, true] {
        let (mut session, _events) = link_session(true);
        let bytes = common::udp_packet(false);
        let key = packet::parse(&bytes, true).unwrap().flow;
        session.tcp_open_server(1, key).await.unwrap();
        let Plane::Tcp(plane) = &session.plane else {
            unreachable!()
        };
        let token = plane.flows[&1].tcp_token.unwrap();
        let _bound = session.resolve_binding(&token).unwrap();
        let Plane::Tcp(plane) = &session.plane else {
            unreachable!()
        };
        assert!(!plane.flows[&1].active);
        if authenticated {
            session.tcp_connected(1).await.unwrap();
        }
        session.close_flow(1, false).await.unwrap();
        assert_eq!(session.stats.open_failed_flows, u64::from(!authenticated));
    }
}

#[tokio::test]
async fn failed_open_counts_once_but_active_close_is_not_an_open_failure() {
    for tcp in [false, true] {
        for active in [false, true] {
            let (mut session, _events) = link_session(tcp);
            let bytes = common::udp_packet(false);
            session.handle_tun_packet(&bytes, Some(1)).await.unwrap();
            match &mut session.plane {
                Plane::Channels(plane) => plane.flows.get_mut(&1).unwrap().active = active,
                Plane::Tcp(plane) => plane.flows.get_mut(&1).unwrap().active = active,
            }
            session.close_flow(1, false).await.unwrap();
            session.close_flow(1, false).await.unwrap();
            assert_eq!(session.stats.open_failed_flows, u64::from(!active));
            assert_eq!(session.stats.closed_flows, 1);
        }
    }
    let (mut session, _events) = link_session(false);
    let bytes = common::udp_packet(false);
    session.handle_tun_packet(&bytes, Some(1)).await.unwrap();
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    let actions = plane
        .selector
        .as_mut()
        .unwrap()
        .poll(StdInstant::now() + Duration::from_secs(31));
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::FailFlow { flow_id: 1, .. }))
    );
    session.execute_actions(actions).await.unwrap();
    assert_eq!(session.stats.open_failed_flows, 1);
}

#[tokio::test]
async fn selector_admission_failure_notifies_owner() {
    let (mut session, mut events) = link_session(false);
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    let selector = plane.selector.as_mut().unwrap();
    for id in 1..=svpn::selector::PENDING_FLOWS as u64 {
        selector
            .request(id, test_key(), b"syn", StdInstant::now())
            .unwrap();
    }
    let bytes = common::udp_packet(false);
    let key = packet::parse(&bytes, true).unwrap().flow;
    session.handle_tun_packet(&bytes, Some(100)).await.unwrap();
    assert_closed(events.recv().await.unwrap(), 100, key);
    assert_eq!(session.flow_count(), 0);
    assert_eq!(session.stats.open_failed_flows, 1);
}

#[tokio::test]
async fn return_packets_are_validated_before_bounded_delivery() {
    for tcp in [false, true] {
        let (mut session, mut events) = link_session(tcp);
        let outgoing = common::udp_packet(false);
        session.handle_tun_packet(&outgoing, Some(9)).await.unwrap();
        let bytes = common::udp_packet(true);
        session
            .deliver_to_tun(Incoming {
                id: 9,
                channel: None,
                packet: bytes.clone(),
            })
            .await
            .unwrap();
        assert!(events.try_recv().is_err()); // Not active yet.
        match &mut session.plane {
            Plane::Channels(plane) => plane.flows.get_mut(&9).unwrap().active = true,
            Plane::Tcp(plane) => {
                let flow = plane.flows.get_mut(&9).unwrap();
                flow.outgoing = Some(mpsc::channel(1).0);
                flow.active = true;
            }
        }
        for (id, packet) in [(10, bytes.clone()), (9, vec![0]), (9, outgoing)] {
            session
                .deliver_to_tun(Incoming {
                    id,
                    channel: None,
                    packet,
                })
                .await
                .unwrap();
            assert!(events.try_recv().is_err());
        }
        session
            .deliver_to_tun(Incoming {
                id: 9,
                channel: None,
                packet: bytes.clone(),
            })
            .await
            .unwrap();
        session
            .deliver_to_tun(Incoming {
                id: 9,
                channel: None,
                packet: bytes.clone(),
            })
            .await
            .unwrap();
        assert_eq!(session.stats.inner_rx_packets, 0); // Still queued, not delivered.
        assert_eq!(session.stats.dropped_packets, 5);
        let (epoch, event) = events.recv().await.unwrap();
        assert_eq!(
            epoch,
            link_io::Epoch {
                link: 2,
                generation: 7
            }
        );
        let link_io::Event::Packet(packet) = event else {
            panic!("expected packet")
        };
        assert_eq!(packet.id, 9);
        assert_eq!(packet.bytes, bytes);
        let PacketIo::Link(io) = &session.io else {
            unreachable!()
        };
        io.delivery.received(packet.bytes.len());
        io.delivery.apply(&mut session.stats);
        assert_eq!(session.stats.inner_rx_packets, 1);
    }
}

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
        Message::Open { id: 11, .. }
    ));
    session.tcp_failed(11).await.unwrap();
    assert_closed(events.recv().await.unwrap(), 11, key);
    assert!(matches!(
        peer.recv().await.unwrap(),
        Message::Close { id: 11 }
    ));
    assert_eq!(session.flow_count(), 0);
}

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
                .tcp_opened_client(1, port, [1; 16], Some([2; 16]))
                .await
                .unwrap();
        } else {
            session
                .channels_tcp_opened(1, port, [1; 16], Some([2; 16]))
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

#[test]
fn fmt_bytes_is_human_readable() {
    assert_eq!(fmt_bytes(0), "0 B");
    assert_eq!(fmt_bytes(512), "512 B");
    assert_eq!(fmt_bytes(4096), "4.0 KB");
    assert_eq!(fmt_bytes(3 * 1024 * 1024), "3.0 MB");
}

fn test_key() -> FlowKey {
    FlowKey {
        protocol: 6,
        source: Ipv4Addr::new(10, 77, 0, 2),
        destination: Ipv4Addr::new(10, 77, 0, 1),
        source_port: 12345,
        destination_port: 9000,
    }
}

fn test_plane(selector: Option<Selector>) -> ChannelsPlane {
    ChannelsPlane {
        prepared: HashMap::new(),
        selector,
        server_ip: None,
        quic_pin: None,
        tcp_port: None,
        token_index: HashMap::new(),
        ports: HashMap::new(),
        bind: Ipv4Addr::UNSPECIFIED,
        quic: None,
        channels: HashMap::new(),
        next_channel_id: 0,
        attempt: None,
        flows: HashMap::new(),
        by_key: HashMap::new(),
        next_client_flow_id: 1,
    }
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

#[tokio::test]
async fn heartbeat_guard_preserves_readiness_result() {
    let deadline = tokio::time::Instant::now() + HEARTBEAT_TIMEOUT;
    assert!(
        with_heartbeat_deadline(deadline, async { Ok(true) })
            .await
            .unwrap()
    );
    assert!(
        !with_heartbeat_deadline(deadline, async { Ok(false) })
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn ready_work_cannot_revive_an_expired_heartbeat() {
    let mut last_heartbeat = tokio::time::Instant::now() - HEARTBEAT_TIMEOUT * 2;
    let expired = last_heartbeat + HEARTBEAT_TIMEOUT;
    assert!(
        with_heartbeat_deadline(expired, async {
            last_heartbeat = tokio::time::Instant::now();
            Ok(false)
        })
        .await
        .is_err()
    );
    assert!(last_heartbeat > expired);
}

#[test]
fn max_wire_covers_transport_overhead() {
    for strategy in [
        Strategy::Plain,
        Strategy::Mosh,
        Strategy::WebRtc,
        Strategy::Quic,
        Strategy::Obfs,
    ] {
        let cap = strategy_max_wire(strategy);
        assert!(cap >= 576, "{strategy:?} cap {cap}");
        assert!(
            usize::from(cap).saturating_sub(45) >= 512,
            "{strategy:?} fragment budget"
        );
    }
}

#[test]
fn candidate_and_strategy_maps_are_inverse() {
    for strategy in [
        Strategy::Quic,
        Strategy::WebRtc,
        Strategy::Obfs,
        Strategy::Mosh,
    ] {
        let candidate = candidate_strategy_from(strategy);
        assert_eq!(candidate_strategy(candidate), strategy);
    }
}

#[test]
fn tombstones_answer_by_closed_rules_and_rate_limit() {
    let mut tombstones = Tombstones::default();
    let t0 = StdInstant::now();
    let key = test_key();
    assert!(!tombstones.active(&key, t0));
    tombstones.insert(key, t0);
    assert!(tombstones.active(&key, t0 + TOMBSTONE_TTL - Duration::from_millis(1)));

    // Incoming ACK → RST with seq = its ack.
    let mut ack_segment = tcp_packet(0x10);
    ack_segment[24..28].copy_from_slice(&5u32.to_be_bytes());
    ack_segment[28..32].copy_from_slice(&900u32.to_be_bytes());
    let ack_packet = packet::parse(&ack_segment, true).unwrap();
    let reset = tombstones.respond(&key, &ack_packet, t0).unwrap();
    assert_eq!(reset[33], 0x04);
    assert_eq!(&reset[24..28], &900u32.to_be_bytes());

    // Within the minimum interval: silent drop.
    assert!(
        tombstones
            .respond(&key, &ack_packet, t0 + Duration::from_millis(100))
            .is_none()
    );
    // After it: answers again.
    assert!(
        tombstones
            .respond(&key, &ack_packet, t0 + Duration::from_millis(250))
            .is_some()
    );

    // SYN (no ACK) → RST|ACK acknowledging seq + 1.
    let mut syn = tcp_packet(0x02);
    syn[24..28].copy_from_slice(&1234u32.to_be_bytes());
    let syn_packet = packet::parse(&syn, true).unwrap();
    let reset = tombstones
        .respond(&key, &syn_packet, t0 + Duration::from_millis(500))
        .unwrap();
    assert_eq!(reset[33], 0x14);
    assert_eq!(&reset[28..32], &1235u32.to_be_bytes());

    // An incoming RST is never answered.
    let rst_packet = packet::parse(&tcp_packet(0x04), true).unwrap();
    assert!(
        tombstones
            .respond(&key, &rst_packet, t0 + Duration::from_millis(600))
            .is_none()
    );

    // TTL expiry frees the tuple for normal admission.
    assert!(!tombstones.active(&key, t0 + TOMBSTONE_TTL));
}

#[test]
fn tombstone_table_is_bounded_and_evicts_oldest() {
    let mut tombstones = Tombstones::default();
    let t0 = StdInstant::now();
    let first = FlowKey {
        source_port: 1,
        ..test_key()
    };
    for i in 0..(TOMBSTONE_CAP + 3) as u16 {
        tombstones.insert(
            FlowKey {
                source_port: i + 1,
                ..test_key()
            },
            t0,
        );
    }
    assert_eq!(tombstones.entries.len(), TOMBSTONE_CAP);
    assert!(!tombstones.active(&first, t0));
    assert!(tombstones.active(
        &FlowKey {
            source_port: TOMBSTONE_CAP as u16 + 2,
            ..test_key()
        },
        t0
    ));
}

#[tokio::test]
async fn retire_resets_tcp_flows_with_known_ack_and_drops_the_rest() {
    for tcp in [false, true] {
        let (mut session, _events) = link_session(tcp);
        // TCP flow with a known last client ACK.
        let syn = tcp_packet(0x02);
        let key = packet::parse(&syn, true).unwrap().flow;
        session.handle_tun_packet(&syn, Some(41)).await.unwrap();
        let mut data = tcp_packet(0x10);
        data[24..28].copy_from_slice(&100u32.to_be_bytes());
        data[28..32].copy_from_slice(&777u32.to_be_bytes());
        session.handle_tun_packet(&data, Some(41)).await.unwrap();
        // TCP flow without any ACK: respond-on-arrival covers it.
        let mut orphan_syn = tcp_packet(0x02);
        orphan_syn[20..22].copy_from_slice(&40001u16.to_be_bytes());
        session
            .handle_tun_packet(&orphan_syn, Some(42))
            .await
            .unwrap();
        // A UDP flow: retired silently, no tombstone, no reset.
        let udp_key = FlowKey {
            protocol: 17,
            ..key
        };
        if let Plane::Channels(plane) = &mut session.plane {
            plane
                .flows
                .insert(7, Flow::new(udp_key, tokio::time::Instant::now()));
            plane.by_key.insert(udp_key, 7);
        }
        assert!(session.has_flow(41) && session.has_flow(42));

        let retired = session.retire_flows_of();
        // Exactly one RST + one probe, for the acked flow.
        assert_eq!(retired.len(), 2);
        let (id, reset) = retired[0];
        assert_eq!(id, 41);
        let parsed = packet::parse(&reset, false).unwrap();
        assert_eq!(parsed.flow, key);
        assert_eq!(parsed.tcp.as_ref().unwrap().flags, 0x04);
        assert_eq!(parsed.tcp.as_ref().unwrap().seq, 777);
        let (_, probe) = retired[1];
        let parsed = packet::parse(&probe, false).unwrap();
        assert_eq!(parsed.tcp.as_ref().unwrap().flags, 0x10);
        assert_eq!(parsed.tcp.as_ref().unwrap().seq, 776);
        // All flows are gone; every TCP tuple is tombstoned, UDP is not.
        assert_eq!(session.flow_count(), 0);
        let now = StdInstant::now();
        assert!(session.tombstones.active(&key, now));
        assert!(
            session
                .tombstones
                .active(&packet::parse(&orphan_syn, true).unwrap().flow, now)
        );
        assert!(!session.tombstones.active(&udp_key, now));
        // Idempotent.
        assert!(session.retire_flows_of().is_empty());
    }
}

#[tokio::test]
async fn emit_retired_pushes_resets_through_the_packet_port() {
    let (mut session, mut events) = link_session_cap(false, 8);
    let syn = tcp_packet(0x02);
    session.handle_tun_packet(&syn, Some(41)).await.unwrap();
    let mut data = tcp_packet(0x10);
    data[28..32].copy_from_slice(&777u32.to_be_bytes());
    session.handle_tun_packet(&data, Some(41)).await.unwrap();

    session.emit_retired_resets();
    for expected_flags in [0x04u8, 0x10] {
        let (epoch, event) = events.recv().await.unwrap();
        assert_eq!(
            epoch,
            link_io::Epoch {
                link: 2,
                generation: 7
            }
        );
        let link_io::Event::Packet(packet) = event else {
            panic!("expected a packet event");
        };
        assert_eq!(packet.id, 41);
        let parsed = packet::parse(&packet.bytes, false).unwrap();
        assert_eq!(parsed.tcp.as_ref().unwrap().flags, expected_flags);
    }
    assert!(events.try_recv().is_err());
    assert_eq!(session.flow_count(), 0);
}

#[tokio::test]
async fn tombstoned_packets_get_closed_rule_reset_and_never_admit() {
    let (mut session, mut events) = link_session_cap(false, 8);
    let mut data = tcp_packet(0x10);
    data[24..28].copy_from_slice(&500u32.to_be_bytes());
    data[28..32].copy_from_slice(&900u32.to_be_bytes());
    data[2..4].copy_from_slice(&44u16.to_be_bytes());
    data.resize(44, 0);
    let key = packet::parse(&data, true).unwrap().flow;
    session.tombstones.insert(key, StdInstant::now());

    session.handle_tun_packet(&data, Some(41)).await.unwrap();
    let (_, event) = events.recv().await.unwrap();
    let link_io::Event::Packet(packet) = event else {
        panic!("expected a packet event");
    };
    let parsed = packet::parse(&packet.bytes, false).unwrap();
    assert_eq!(parsed.flow, key);
    assert_eq!(parsed.tcp.as_ref().unwrap().flags, 0x04);
    // CLOSED rule: the reply's seq is the incoming packet's ack.
    assert_eq!(parsed.tcp.as_ref().unwrap().seq, 900);
    assert!(!session.has_flow(41));
    assert_eq!(session.flow_count(), 0);

    // Rate limit: an immediate repeat is silently dropped, still unadmitted.
    session.handle_tun_packet(&data, Some(41)).await.unwrap();
    assert!(events.try_recv().is_err());
    assert_eq!(session.flow_count(), 0);

    // A client RST into the tombstone: no response, no admission.
    session
        .handle_tun_packet(&tcp_packet(0x04), Some(41))
        .await
        .unwrap();
    assert!(events.try_recv().is_err());
    assert_eq!(session.flow_count(), 0);

    // A re-SYN for the same tuple is still refused while the tombstone lives.
    let syn = tcp_packet(0x02);
    assert_eq!(packet::parse(&syn, true).unwrap().flow, key);
    session.handle_tun_packet(&syn, Some(41)).await.unwrap();
    assert_eq!(session.flow_count(), 0);
    assert!(!session.has_flow(41));
}

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
            session.tcp_open_server(PREFLIGHT_ID, key).await.unwrap();
            let Plane::Tcp(plane) = &session.plane else {
                unreachable!()
            };
            plane.flows[&PREFLIGHT_ID].tcp_token.unwrap()
        } else {
            session.channels_tcp_open(PREFLIGHT_ID, key).await.unwrap();
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
        session.tcp_connected(PREFLIGHT_ID).await.unwrap();
        session
            .deliver_to_tun(Incoming {
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
    session.flow_open(PREFLIGHT_ID, key, Some(5)).await.unwrap();
    // Model the completed FlowEcho/Commit exchange.
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.flows.get_mut(&PREFLIGHT_ID).unwrap().active = true;
    assert!(matches!(commands.try_recv(), Ok(TaskCommand::Record(_))));

    session
        .deliver_to_tun(Incoming {
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
        Ok(TaskCommand::Data(id, bytes)) if id == PREFLIGHT_ID && bytes == reply
    ));
    assert!(packet::icmp_echo_reply_matches(
        &reply,
        0x1234,
        7,
        &[0xa5; 16]
    ));
}
