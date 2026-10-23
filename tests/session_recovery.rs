//! Recovery boundaries: terminal generations and bounded backpressure wakeups.

mod common;

use std::time::{Duration, Instant as StdInstant};

use common::session::{assert_closed, link_session, link_session_cap, link_session_with, test_key};
use svpn::channel;
use svpn::control::{Control, Message};
use svpn::link_io;
use svpn::packet;
use svpn::selector::{Action, Candidate, Reason};
use svpn::session::{
    ChannelHandle, ChannelsPlane, Flow, FlowTcp, PacketIo, Plane, Recovery, TaskCommand, TaskEvent,
    TcpFlow,
};
use svpn::udp::Incoming;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::{Instant, advance, timeout};

// ── terminal cleanup ──

#[tokio::test]
async fn final_failure_closes_the_current_generation_on_both_peers() {
    let (writer, reader) = tokio::io::duplex(4096);
    let (mut client, mut events) =
        link_session_with(false, Control::new(tokio::io::empty(), writer));
    let (mut server, mut server_events) = link_session(false);
    let key = test_key();
    for (session, is_server) in [(&mut client, false), (&mut server, true)] {
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        if is_server {
            plane.selector = None;
            plane.server_ip = None;
        }
        let mut flow = Flow::new(key, Instant::now());
        flow.generation = 2;
        plane.flows.insert(1, flow);
        plane.by_key.insert(key, 1);
    }
    client
        .execute_actions(vec![
            Action::FailFlow {
                flow_id: 1,
                flow: key,
                reason: Reason::PathTimeout,
            },
            Action::CloseFlow { flow_id: 1 },
        ])
        .await
        .unwrap();
    let mut lines = BufReader::new(reader).lines();
    for expected in [
        Message::FlowReject {
            flow_id: 1,
            generation: 2,
            reason: Reason::PathTimeout,
        },
        Message::FlowClose {
            flow_id: 1,
            generation: 2,
        },
    ] {
        let line = timeout(Duration::from_secs(1), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let message: Message = serde_json::from_str(&line).unwrap();
        assert_eq!(
            serde_json::to_value(&message).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        server.dispatch_control(message).await.unwrap();
    }
    for session in [&client, &server] {
        assert!(!session.has_flow(1));
        assert_eq!(session.stats.closed_flows, 1);
        let Plane::Channels(plane) = &session.plane else {
            unreachable!()
        };
        assert!(!plane.by_key.contains_key(&key));
    }
    assert_closed(events.try_recv().unwrap(), 1, key);
    assert_closed(server_events.try_recv().unwrap(), 1, key);
    assert!(events.try_recv().is_err());
    assert!(server_events.try_recv().is_err());
}

// ── queue wakeups ──

// ── quiet flows prove recovery by probe round-trip ──

fn quiet_rebound_flow(
    plane: &mut ChannelsPlane,
    key: svpn::packet::FlowKey,
    generation: u64,
    channel: u64,
    command: mpsc::Sender<TaskCommand>,
) {
    let mut flow = Flow::new(key, Instant::now());
    flow.active = true;
    flow.generation = generation;
    flow.channel = Some(channel);
    flow.recovery = Some(Recovery {
        started: Instant::now(),
        from: Some(Candidate::Mosh),
        attempts: 1,
    });
    plane.flows.insert(1, flow);
    plane.by_key.insert(key, 1);
    plane.channels.insert(
        channel,
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
}

#[tokio::test(start_paused = true)]
async fn a_quiet_rebound_flow_proves_the_new_binding_by_probe() {
    let (mut session, _events) = link_session(false);
    let (command, mut commands) = mpsc::channel(4);
    let key = test_key();
    {
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        let selector = plane.selector.as_mut().unwrap();
        selector.adopt(Candidate::Mosh, Some(10));
        selector
            .request(1, key, b"first", StdInstant::now())
            .unwrap();
        let _ = selector.bind_succeeded(1, 1, StdInstant::now());
        quiet_rebound_flow(plane, key, 1, 10, command);
    }
    session.committed(1, 1).await.unwrap();
    let challenge = match commands.try_recv() {
        Ok(TaskCommand::Record(channel::Record::FlowProbe {
            flow_id: 1,
            generation: 1,
            challenge,
        })) => challenge,
        other => panic!("committed must arm a probe, got {}", other.is_ok()),
    };
    session
        .dispatch_task_event(TaskEvent::FlowEcho {
            channel: 10,
            flow_id: 1,
            generation: 1,
            echo: challenge,
        })
        .await
        .unwrap();
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    let flow = plane.flows.get(&1).unwrap();
    assert!(flow.recovery.is_none(), "probe round-trip proves delivery");
    assert!(flow.echo_pending.is_none());
}

#[tokio::test(start_paused = true)]
async fn the_peers_probe_is_delivery_evidence_for_the_receiving_side() {
    let (mut session, _events) = link_session(false);
    let (command, _commands) = mpsc::channel(1);
    let key = test_key();
    {
        let Plane::Channels(plane) = &mut session.plane else {
            unreachable!()
        };
        plane.selector = None;
        quiet_rebound_flow(plane, key, 2, 10, command);
    }
    session
        .dispatch_task_event(TaskEvent::ProbeSeen {
            channel: 10,
            flow_id: 1,
            generation: 2,
        })
        .await
        .unwrap();
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    assert!(plane.flows.get(&1).unwrap().recovery.is_none());
    // A stale-generation probe is not evidence: the recovery budget stays.
    let flow = plane.flows.get_mut(&1).unwrap();
    flow.generation = 3;
    flow.recovery = Some(Recovery {
        started: Instant::now(),
        from: Some(Candidate::Mosh),
        attempts: 1,
    });
    session
        .dispatch_task_event(TaskEvent::ProbeSeen {
            channel: 10,
            flow_id: 1,
            generation: 2,
        })
        .await
        .unwrap();
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    assert!(plane.flows.get(&1).unwrap().recovery.is_some());
}

#[tokio::test(start_paused = true)]
async fn a_busy_flow_cannot_postpone_another_flows_flush_deadline() {
    let (mut session, _events) = link_session(false);
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.selector = None;
    let mut outputs = Vec::new();
    let mut packets = Vec::new();
    for id in [1, 2] {
        let (out, receive) = mpsc::channel(1);
        out.try_send(vec![0]).unwrap();
        outputs.push(receive);
        let mut bytes = common::tcp_packet(true);
        bytes[22..24].copy_from_slice(&(12344 + id as u16).to_be_bytes());
        let key = packet::parse(&bytes, false).unwrap().flow;
        packets.push(bytes);
        let mut flow = Flow::new(key, Instant::now());
        flow.active = true;
        flow.tcp = Some(FlowTcp {
            key: [1; 16],
            token: None,
            out: Some(out),
            receiver: None,
            task: None,
            cancel: None,
        });
        plane.flows.insert(id, flow);
        plane.by_key.insert(key, id);
    }
    session
        .handle_tun_packet(&packets[0], Some(1))
        .await
        .unwrap();
    let deadline = session.flush_at.unwrap();
    assert_eq!(deadline, Instant::now() + Duration::from_millis(10));
    assert_eq!(outputs[0].try_recv().unwrap(), vec![0]);
    for _ in 0..4 {
        advance(Duration::from_millis(5)).await;
        session
            .handle_tun_packet(&packets[1], Some(2))
            .await
            .unwrap();
        assert_eq!(session.flush_at, Some(deadline));
    }
    assert!(session.flush_at.unwrap() <= Instant::now());
    assert!(session.has_flow(1));
    assert!(outputs[0].try_recv().is_err());
}

// ── recovery budget covers carried data on the Tcp plane ──

#[tokio::test]
async fn tcp_recovery_with_carried_data_is_bounded_by_the_recovery_budget() {
    // Rebind accepted queued data (data_started) before delivery evidence;
    // only RECOVERY_BUDGET, not the 2h TCP idle timeout, may bound the wait.
    let (mut session, _events) = link_session(true);
    let key = test_key();
    let now = Instant::now();
    let Plane::Tcp(plane) = &mut session.plane else {
        unreachable!()
    };
    let mut recovering = TcpFlow::new(key, now);
    recovering.data_started = true;
    recovering.active = true;
    recovering.recovery = Some(Recovery {
        started: now,
        from: Some(Candidate::Tcp),
        attempts: 1,
    });
    plane.flows.insert(1, recovering);
    let mut settled = TcpFlow::new(key, now);
    settled.data_started = true;
    settled.active = true;
    plane.flows.insert(2, settled);
    plane.by_key.insert(key, 1);
    session
        .expire_flows(now + Duration::from_secs(10))
        .await
        .unwrap();
    assert!(!session.has_flow(1));
    assert!(session.has_flow(2));
    assert_eq!(session.stats.closed_flows, 1);
}

#[tokio::test]
async fn failed_tun_write_does_not_start_data() {
    // A packet that never reached the TUN must not lift the pre-data
    // FLOW_BUDGET bound.
    let (mut session, mut events) = link_session_cap(false, 1);
    let mut inbound = common::tcp_packet(false);
    inbound[33] = 0x10;
    let key = packet::parse(&inbound, true).unwrap().flow;
    let now = Instant::now();
    let (command, _commands) = mpsc::channel(4);
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.server_ip = None;
    plane.selector = None;
    let mut flow = Flow::new(key, now);
    flow.channel = Some(10);
    plane.flows.insert(1, flow);
    plane.by_key.insert(key, 1);
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
    session.commit(1, 1).await.unwrap();
    let PacketIo::Link(io) = &session.io else {
        unreachable!()
    };
    io.events
        .try_send((io.epoch, link_io::Event::Checking))
        .unwrap();
    session
        .deliver_to_tun(Incoming {
            id: 1,
            generation: 1,
            channel: Some(10),
            packet: inbound,
        })
        .await
        .unwrap();
    // Free the queue slot so close_flow's Closed event is not awaited forever.
    assert!(matches!(
        events.try_recv().unwrap().1,
        link_io::Event::Checking
    ));
    session
        .expire_flows(now + Duration::from_secs(31))
        .await
        .unwrap();
    assert!(!session.has_flow(1));
}
