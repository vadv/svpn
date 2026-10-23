//! Session flow lifecycle: admission, flow IDs, RST/close ordering, commit accounting.

mod common;

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant as StdInstant;

use common::session::{assert_closed, link_session, link_session_cap, tcp_packet, test_key};
use svpn::control::Message;
use svpn::link_io::{self, FIRST_PROBE_ID, PREFLIGHT_ID};
use svpn::packet;
use svpn::selector::{Action, Allowed, Candidate, Selector};
use svpn::session::*;
use svpn::udp::Incoming;
use tokio::sync::mpsc;

// ── admission and flow IDs ──

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

// ── RST and close ordering ──

#[tokio::test]
async fn client_rst_reaches_transport_before_retiring_flow() {
    for (legacy, fallback) in [(false, false), (false, true), (true, false)] {
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
                command
                    .try_send(TaskCommand::Data {
                        flow_id: 0,
                        generation: 1,
                        packet: vec![0],
                    })
                    .unwrap();
            }
            match &mut session.plane {
                Plane::Channels(plane) => {
                    let selector = plane.selector.as_mut().unwrap();
                    let now = StdInstant::now();
                    selector.adopt(Candidate::Mosh, Some(5));
                    selector.poll(now);
                    selector.bind_succeeded(41, 1, now);
                    selector.committed(41, 1);
                    selector.take_queue(41);
                    let flow = plane.flows.get_mut(&41).unwrap();
                    flow.active = true;
                    flow.data_started = true;
                    if fallback {
                        flow.tcp = Some(FlowTcp {
                            cancel: None,
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
                                key: [7; 16],
                                established: true,
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
                    flow.active = true;
                    flow.data_started = true;
                    flow.pending.clear();
                    flow.binding_deadline = None;
                    flow.outgoing = Some(out);
                }
            }
            let rst = tcp_packet(4);
            session.handle_tun_packet(&rst, Some(41)).await.unwrap();
            assert!(session.has_flow(41), "RST closed the flow before delivery");
            assert!(events.try_recv().is_err());
            if full {
                assert_eq!(session.stats.dropped_packets, 0);
                assert_eq!(session.stats.inner_tx_packets, 0);
                if legacy || fallback {
                    assert_eq!(outgoing.try_recv().unwrap(), vec![0]);
                } else {
                    assert!(matches!(
                        commands.try_recv(),
                        Ok(TaskCommand::Data { flow_id: 0, .. })
                    ));
                }
                session.committed(41, 1).await.unwrap();
            }
            if legacy || fallback {
                assert_eq!(outgoing.try_recv().unwrap(), rst);
            } else {
                assert!(
                    matches!(commands.try_recv(), Ok(TaskCommand::Data { flow_id: 41, generation: 1, packet: bytes }) if bytes == rst)
                );
            }
            // EOF/reset can overtake Close on the independent SSH channel.
            match ending {
                "eof" if legacy || fallback => session.tcp_closed(41, 1).await.unwrap(),
                "error" if legacy || fallback => session.tcp_failed(41, 1).await.unwrap(),
                _ => session
                    .dispatch_control(if legacy {
                        Message::Close {
                            generation: 1,
                            id: 41,
                        }
                    } else {
                        Message::FlowClose {
                            generation: 1,
                            flow_id: 41,
                        }
                    })
                    .await
                    .unwrap(),
            }
            assert_closed(events.try_recv().unwrap(), 41, key);
            assert!(!session.has_flow(41));
            // The other ordering: transport completion arrives after Close.
            session.tcp_closed(41, 1).await.unwrap();
            session.tcp_failed(41, 1).await.unwrap();
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
            Plane::Channels(plane) => {
                let flow = plane.flows.get_mut(&41).unwrap();
                flow.active = true;
                flow.data_started = true;
            }
            Plane::Tcp(plane) => {
                let flow = plane.flows.get_mut(&41).unwrap();
                flow.active = true;
                flow.data_started = true;
                flow.binding_deadline = None;
            }
        }
        session
            .expire_flows(tokio::time::Instant::now() + TCP_IDLE + Duration::from_secs(1))
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
                generation: 1,
                id: 41,
                channel: None,
                packet: rst.clone(),
            })
            .await
            .unwrap();
        assert!(session.has_flow(41));
        assert!(events.try_recv().is_err());
        match &mut session.plane {
            Plane::Channels(plane) => {
                let flow = plane.flows.get_mut(&41).unwrap();
                flow.active = true;
                flow.data_started = true;
            }
            Plane::Tcp(plane) => {
                let flow = plane.flows.get_mut(&41).unwrap();
                flow.active = true;
                flow.data_started = true;
                flow.binding_deadline = None;
            }
        }
        for id in [40, 42] {
            session
                .deliver_to_tun(Incoming {
                    generation: 1,
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
                generation: 1,
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
                generation: 1,
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
                generation: 1,
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

// ── commit accounting ──

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
                    selector.bind_succeeded(1, 1, now);
                } else {
                    plane.selector = None;
                }
                let mut flow = Flow::new(key, tokio::time::Instant::now());
                flow.channel = Some(10);
                flow.tcp_connected = tcp;
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
                        cancel: None,
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
                        key: [7; 16],
                        established: true,
                        command,
                        task: tokio::spawn(std::future::pending()),
                        cancel: None,
                        relay: None,
                    },
                );
                for _ in 0..2 {
                    if client {
                        session.committed(1, 1).await.unwrap();
                    } else {
                        session.commit(1, 1).await.unwrap();
                    }
                }
                assert_eq!(session.stats.inner_tx_packets, if accepted { 2 } else { 0 });
                assert_eq!(
                    session.stats.inner_tx_bytes,
                    if accepted { 2 * bytes.len() as u64 } else { 0 }
                );
                assert_eq!(session.stats.dropped_packets, 0);
                if !accepted {
                    let Plane::Channels(plane) = &session.plane else {
                        unreachable!()
                    };
                    if client {
                        assert_eq!(
                            plane.selector.as_ref().unwrap().queued_bytes(),
                            2 * bytes.len()
                        );
                    } else {
                        assert_eq!(
                            plane.flows[&1].pending,
                            VecDeque::from([bytes.clone(), bytes.clone()])
                        );
                    }
                }
                if accepted {
                    for _ in 0..2 {
                        if tcp {
                            assert_eq!(received.as_mut().unwrap().try_recv().unwrap(), bytes);
                        } else {
                            assert!(
                                matches!(commands.as_mut().unwrap().try_recv().unwrap(), TaskCommand::Data { flow_id: 1, generation: 1, packet } if packet == bytes)
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
    for duplicate in [false, true] {
        let (mut session, mut events) = link_session(false);
        let bytes =
            packet::icmp_echo_request(session.client_ip, test_key().destination, 123, 0, b"probe");
        let key = packet::parse(&bytes, true).unwrap().flow;
        let id = PREFLIGHT_ID;
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        plane.selector = None;
        let unrelated = svpn::packet::FlowKey {
            source_port: 4000,
            ..key
        };
        plane
            .flows
            .insert(2, Flow::new(unrelated, tokio::time::Instant::now()));
        plane.by_key.insert(unrelated, 2);
        if duplicate {
            let mut flow = Flow::new(key, tokio::time::Instant::now());
            flow.channel = Some(10);
            plane.flows.insert(id, flow);
            plane.by_key.insert(key, id);
        }
        let (command, mut commands) = mpsc::channel(1);
        assert!(
            command
                .try_send(TaskCommand::Data {
                    flow_id: 2,
                    generation: 1,
                    packet: bytes
                })
                .is_ok()
        );
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
        tokio::time::timeout(
            Duration::from_millis(100),
            session.flow_open(id, 1, key, Some(10), false),
        )
        .await
        .expect("FlowProbe blocked the session loop")
        .unwrap();
        assert!(!session.has_flow(id));
        assert!(session.has_flow(2));
        assert!(events.try_recv().is_err());
        let Plane::Channels(plane) = &session.plane else {
            unreachable!()
        };
        assert!(!plane.by_key.contains_key(&key));
        assert_eq!(plane.by_key.get(&unrelated), Some(&2));
        assert!(plane.channels.contains_key(&10));
        assert!(matches!(
            commands.try_recv(),
            Ok(TaskCommand::Data {
                flow_id: 2,
                generation: 1,
                packet: _
            })
        ));
    }
}

#[tokio::test]
async fn udp_commit_does_not_wait_for_a_full_shared_command_queue() {
    let (mut session, _events) = link_session(false);
    let bytes = common::udp_packet(true);
    let key = packet::parse(&bytes, false).unwrap().flow;
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.selector = None;
    let mut flow = Flow::new(key, tokio::time::Instant::now());
    flow.active = true;
    flow.channel = Some(10);
    plane.flows.insert(1, flow);
    let (command, mut commands) = mpsc::channel(1);
    assert!(
        command
            .try_send(TaskCommand::Data {
                flow_id: 2,
                generation: 1,
                packet: bytes.clone()
            })
            .is_ok()
    );
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
    plane.by_key.insert(key, 1);
    tokio::time::timeout(
        Duration::from_millis(100),
        session.handle_tun_packet(&bytes, Some(1)),
    )
    .await
    .expect("commit blocked the session loop")
    .unwrap();
    assert_eq!(session.stats.dropped_packets, 0);
    assert_eq!(session.stats.inner_tx_packets, 0);
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    assert_eq!(plane.flows[&1].pending, VecDeque::from([bytes.clone()]));
    assert!(!plane.flows[&1].data_started);
    assert!(matches!(
        commands.try_recv(),
        Ok(TaskCommand::Data {
            flow_id: 2,
            generation: 1,
            packet: _
        })
    ));
    session.commit(1, 1).await.unwrap();
    assert!(
        matches!(commands.try_recv(), Ok(TaskCommand::Data { flow_id: 1, generation: 1, packet }) if packet == bytes)
    );
    assert_eq!(session.stats.inner_tx_packets, 1);
    assert!(session.has_flow(1));
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
        .tcp_opened_client(1, 1, 9000, [1; 16], Some([2; 16]))
        .await
        .unwrap();
    assert_eq!(session.stats.inner_tx_packets, 0);
    session.tcp_connected(1, 1).await.unwrap();
    assert_eq!(session.stats.inner_tx_packets, 0);
    session.committed(1, 1).await.unwrap();
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
        .channels_tcp_opened(1, 1, 9000, [1; 16], Some([2; 16]))
        .await
        .unwrap();
    assert_eq!(session.stats.inner_tx_packets, 0);
    session.tcp_connected(1, 1).await.unwrap();
    assert_eq!(session.stats.inner_tx_packets, 0);
    session.committed(1, 1).await.unwrap();
    assert_eq!(session.stats.inner_tx_packets, 3);
    session.handle_tun_packet(&bytes, Some(1)).await.unwrap();
    assert_eq!(session.stats.inner_tx_packets, 4);
    assert_eq!(session.stats.inner_tx_bytes, 4 * bytes.len() as u64);
}

#[tokio::test]
async fn legacy_binding_token_and_connected_do_not_activate_before_commit() {
    for authenticated in [false, true] {
        let (mut session, _events) = link_session(true);
        let Plane::Tcp(plane) = &mut session.plane else {
            unreachable!()
        };
        plane.server_ip = None;
        let bytes = common::udp_packet(false);
        let key = packet::parse(&bytes, true).unwrap().flow;
        session.tcp_open_server(1, 1, key).await.unwrap();
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
            session.tcp_connected(1, 1).await.unwrap();
            let Plane::Tcp(plane) = &session.plane else {
                unreachable!()
            };
            assert!(!plane.flows[&1].active);
            session.commit(1, 1).await.unwrap();
        }
        session.close_flow(1, false).await.unwrap();
        assert_eq!(session.stats.open_failed_flows, u64::from(!authenticated));
    }
}

#[tokio::test]
async fn failed_open_counts_once_but_active_close_is_not_an_open_failure() {
    for tcp in [false, true] {
        for (active, data_started) in [(false, false), (true, false), (false, true), (true, true)] {
            let (mut session, _events) = link_session(tcp);
            let bytes = common::udp_packet(false);
            session.handle_tun_packet(&bytes, Some(1)).await.unwrap();
            match &mut session.plane {
                Plane::Channels(plane) => {
                    let flow = plane.flows.get_mut(&1).unwrap();
                    flow.active = active;
                    flow.data_started = data_started;
                }
                Plane::Tcp(plane) => {
                    let flow = plane.flows.get_mut(&1).unwrap();
                    flow.active = active;
                    flow.data_started = data_started;
                }
            }
            session.close_flow(1, false).await.unwrap();
            session.close_flow(1, false).await.unwrap();
            assert_eq!(
                session.stats.open_failed_flows,
                u64::from(!active && !data_started)
            );
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

// ── return-path validation ──

#[tokio::test]
async fn return_packets_are_validated_before_bounded_delivery() {
    for tcp in [false, true] {
        let (mut session, mut events) = link_session(tcp);
        let outgoing = common::udp_packet(false);
        session.handle_tun_packet(&outgoing, Some(9)).await.unwrap();
        let bytes = common::udp_packet(true);
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: 9,
                channel: None,
                packet: bytes.clone(),
            })
            .await
            .unwrap();
        assert!(events.try_recv().is_err()); // Not active yet.
        match &mut session.plane {
            Plane::Channels(plane) => {
                let flow = plane.flows.get_mut(&9).unwrap();
                flow.active = true;
                flow.generation = 2;
            }
            Plane::Tcp(plane) => {
                let flow = plane.flows.get_mut(&9).unwrap();
                flow.active = true;
                flow.generation = 2;
            }
        }
        for (id, generation, packet) in [
            (10, 2, bytes.clone()),
            (9, 2, vec![0]),
            (9, 2, outgoing),
            (9, 0, bytes.clone()),
            (9, 1, bytes.clone()),
            (9, 3, bytes.clone()),
        ] {
            session
                .deliver_to_tun(Incoming {
                    generation,
                    id,
                    channel: None,
                    packet,
                })
                .await
                .unwrap();
            assert!(events.try_recv().is_err());
        }
        for _ in 0..2 {
            session
                .deliver_to_tun(Incoming {
                    generation: 2,
                    id: 9,
                    channel: None,
                    packet: bytes.clone(),
                })
                .await
                .unwrap();
        }
        assert_eq!(session.stats.inner_rx_packets, 0); // Still queued, not delivered.
        assert_eq!(session.stats.dropped_packets, 8);
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
