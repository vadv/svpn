//! Flow lifetime and admission: TCP silence, half-close, bounded state, probe reserve.

mod common;

use std::time::Duration;

use common::session::{
    activate, assert_closed, fill, link_session_cap, link_session_with, reply, tcp_packet,
};
use svpn::control::{Control, Message};
use svpn::link_io::{self, FIRST_PROBE_ID};
use svpn::packet::{self, FlowKey};
use svpn::selector::{Candidate, Reason};
use svpn::session::*;
use svpn::udp::Incoming;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::{Instant, advance};

// ── idle and FIN ──

#[tokio::test(start_paused = true)]
async fn tcp_survives_udp_idle_and_keeps_forwarding_in_both_planes() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        let bytes = tcp_packet(2);
        let key = packet::parse(&bytes, true).unwrap().flow;
        session.handle_tun_packet(&bytes, Some(1)).await.unwrap();
        let mut outgoing = activate(&mut session, 1);
        // The far-end answer marks the flow proven; only then may a TCP
        // flow outlive the UDP idle limit.
        let greeting = reply(0x10);
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: 1,
                channel: None,
                packet: greeting.clone(),
            })
            .await
            .unwrap();
        assert!(
            matches!(events.try_recv().unwrap().1, link_io::Event::Packet(p) if p.bytes == greeting)
        );
        advance(FLOW_IDLE + Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(session.has_flow(1));
        assert!(events.try_recv().is_err());

        let ack = tcp_packet(0x10);
        session.handle_tun_packet(&ack, Some(1)).await.unwrap();
        assert_eq!(outgoing.try_recv().unwrap(), ack);
        let reply = reply(0x10);
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: 1,
                channel: None,
                packet: reply.clone(),
            })
            .await
            .unwrap();
        assert!(
            matches!(events.try_recv().unwrap().1, link_io::Event::Packet(p) if p.bytes == reply)
        );
        advance(TCP_IDLE - Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(session.has_flow(1));
        advance(Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert_closed(events.try_recv().unwrap(), 1, key);
        assert!(!session.has_flow(1));
    }
}

#[tokio::test(start_paused = true)]
async fn udp_still_expires_at_its_idle_limit() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        let bytes = common::udp_packet(false);
        let key = packet::parse(&bytes, true).unwrap().flow;
        session.handle_tun_packet(&bytes, Some(1)).await.unwrap();
        let _outgoing = activate(&mut session, 1);
        advance(FLOW_IDLE - Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert!(session.has_flow(1));
        advance(Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert_closed(events.try_recv().unwrap(), 1, key);
        assert!(!session.has_flow(1));
    }
}

#[tokio::test(start_paused = true)]
async fn either_half_close_and_repeated_fin_survive_until_both_directions_finish() {
    for legacy in [false, true] {
        for client_first in [false, true] {
            let (mut session, mut events) = link_session_cap(legacy, 4);
            let syn = tcp_packet(2);
            let key = packet::parse(&syn, true).unwrap().flow;
            session.handle_tun_packet(&syn, Some(1)).await.unwrap();
            let mut outgoing = activate(&mut session, 1);
            // The handshake's far-end answer marks the flow proven.
            let synack = reply(0x10);
            session
                .deliver_to_tun(Incoming {
                    generation: 1,
                    id: 1,
                    channel: None,
                    packet: synack.clone(),
                })
                .await
                .unwrap();
            assert!(matches!(
                events.try_recv().unwrap().1,
                link_io::Event::Packet(p) if p.bytes == synack
            ));
            for (step, from_client) in [client_first, client_first, !client_first]
                .into_iter()
                .enumerate()
            {
                if from_client {
                    let fin = tcp_packet(0x11);
                    session.handle_tun_packet(&fin, Some(1)).await.unwrap();
                    assert_eq!(outgoing.try_recv().unwrap(), fin);
                } else {
                    session
                        .deliver_to_tun(Incoming {
                            generation: 1,
                            id: 1,
                            channel: None,
                            packet: reply(0x11),
                        })
                        .await
                        .unwrap();
                    assert!(matches!(
                        events.try_recv().unwrap().1,
                        link_io::Event::Packet(_)
                    ));
                }
                if step < 2 {
                    advance(FIN_DWELL + Duration::from_secs(1)).await;
                    session.expire_flows(Instant::now()).await.unwrap();
                    assert!(
                        session.has_flow(1),
                        "half-close or repeated FIN retired the flow"
                    );
                    assert!(events.try_recv().is_err());
                }
            }
            // Delivered to the second direction, the FIN arms the dwell
            // even though the final ACKs never arrive: a lost ACK must not
            // pin the flow until TCP_IDLE.
            advance(FIN_DWELL - Duration::from_secs(1)).await;
            session.expire_flows(Instant::now()).await.unwrap();
            assert!(session.has_flow(1));
            advance(Duration::from_secs(1)).await;
            session.expire_flows(Instant::now()).await.unwrap();
            assert_closed(events.try_recv().unwrap(), 1, key);
            assert!(!session.has_flow(1));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn opening_deadline_is_not_extended_by_more_packets() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        let syn = tcp_packet(2);
        let key = packet::parse(&syn, true).unwrap().flow;
        session.handle_tun_packet(&syn, Some(1)).await.unwrap();
        let budget = svpn::selector::FLOW_BUDGET;
        advance(budget - Duration::from_secs(1)).await;
        session.handle_tun_packet(&syn, Some(1)).await.unwrap();
        advance(Duration::from_secs(1)).await;
        session.expire_flows(Instant::now()).await.unwrap();
        assert_closed(events.try_recv().unwrap(), 1, key);
        assert!(!session.has_flow(1));
    }
}

#[tokio::test]
async fn target_reset_leaves_the_close_decision_to_the_client_kernel() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        session
            .handle_tun_packet(&tcp_packet(2), Some(1))
            .await
            .unwrap();
        let mut outgoing = activate(&mut session, 1);
        session
            .deliver_to_tun(Incoming {
                generation: 1,
                id: 1,
                channel: None,
                packet: reply(4),
            })
            .await
            .unwrap();
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Packet(_)
        ));
        assert!(session.has_flow(1));
        assert!(events.try_recv().is_err());
        session
            .handle_tun_packet(&tcp_packet(0x10), Some(1))
            .await
            .unwrap();
        assert_eq!(outgoing.try_recv().unwrap(), tcp_packet(0x10));
    }
}

#[test]
fn fin_dwell_arms_on_both_fins_and_handles_payload_wrap_and_retransmission() {
    for seq in [100, u32::MAX] {
        let now = Instant::now();
        let mut close = TcpClose::default();
        let mut fin = packet::parse(&tcp_packet(0x11), true).unwrap();
        fin.tcp.as_mut().unwrap().seq = seq;
        fin.tcp.as_mut().unwrap().payload_len = 2;
        close.observe(&fin, true, now);
        assert!(!close.finished());
        assert!(close.deadline().is_none());
        close.observe(&fin, false, now);
        assert!(close.finished(), "FINs in both directions arm the dwell");
        assert_eq!(close.deadline(), Some(now + FIN_DWELL));
        close.observe(&fin, true, now);
        assert_eq!(
            close.deadline(),
            Some(now + FIN_DWELL),
            "a repeated FIN cannot re-arm the dwell"
        );
        fin.tcp.as_mut().unwrap().seq = seq.wrapping_add(20);
        close.observe(&fin, true, now);
        assert_eq!(
            close.deadline(),
            Some(now + FIN_DWELL),
            "a late FIN cannot extend a completed close"
        );
    }
}

// ── capacity ──

#[tokio::test]
async fn full_client_refuses_only_new_flows_and_reclaims_closed_slots() {
    for legacy in [false, true] {
        let (mut session, mut events) = link_session_cap(legacy, 4);
        fill(&mut session, true);
        if let Plane::Channels(plane) = &mut session.plane {
            plane
                .selector
                .as_mut()
                .unwrap()
                .request(1, plane.flows[&1].key, b"", std::time::Instant::now())
                .unwrap();
        }
        let mut outgoing = activate(&mut session, 1);
        let mut bytes = tcp_packet(2);
        bytes[20..22].copy_from_slice(&65000u16.to_be_bytes());
        let key = packet::parse(&bytes, true).unwrap().flow;
        let id = FLOW_CAP as u64 + 1;
        session.handle_tun_packet(&bytes, Some(id)).await.unwrap();
        // The refusal is visible: a reset toward the client, then closed.
        assert!(matches!(
            events.try_recv().unwrap().1,
            link_io::Event::Packet(ref p) if packet::parse(&p.bytes, false).is_some_and(|r| r.is_rst)
        ));
        assert_closed(events.try_recv().unwrap(), id, key);
        assert!(!session.has_flow(id));
        assert_eq!(session.flow_count(), FLOW_CAP);
        assert_eq!(session.stats.open_failed_flows, 1);

        let mut existing = tcp_packet(0x10);
        existing[20..22].copy_from_slice(&10001u16.to_be_bytes());
        session.handle_tun_packet(&existing, Some(1)).await.unwrap();
        assert_eq!(outgoing.try_recv().unwrap(), existing);
        assert!(session.has_flow(1));
        assert!(events.try_recv().is_err());
        session.close_flow(1, false).await.unwrap();
        assert_closed(
            events.try_recv().unwrap(),
            1,
            packet::parse(&existing, true).unwrap().flow,
        );
        session
            .handle_tun_packet(&bytes, Some(id + 1))
            .await
            .unwrap();
        assert!(session.has_flow(id + 1));
        assert_eq!(session.flow_count(), FLOW_CAP);
    }
}

#[tokio::test]
async fn control_opens_respect_capacity_and_bounded_probe_reserve() {
    for mode in ["datagram", "candidate", "legacy", "reverse"] {
        let (writer, reader) = tokio::io::duplex(4096);
        let control = Control::new(tokio::io::empty(), writer);
        let (mut session, _events) = link_session_with(mode == "legacy", control);
        fill(&mut session, true);
        let (commands, mut receive) = mpsc::channel(32);
        match &mut session.plane {
            Plane::Channels(plane) => {
                if mode != "reverse" {
                    plane.selector = None;
                }
                plane.tcp_port = Some(9000);
                plane.channels.insert(
                    7,
                    ChannelHandle {
                        candidate: Candidate::Mosh,
                        key: [7; 16],
                        established: true,
                        cancel: None,
                        command: commands,
                        task: tokio::spawn(std::future::pending()),
                        relay: None,
                    },
                );
            }
            Plane::Tcp(plane) => plane.server_ip = None,
        }
        let mut lines = BufReader::new(reader).lines();
        let mut key = packet::parse(&tcp_packet(2), true).unwrap().flow;
        key.source_port = 65000;
        let id = FLOW_CAP as u64 + 1;
        session.dispatch_control(open(mode, id, key)).await.unwrap();
        let rejected: Message =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert!(
            matches!(rejected,
                Message::FlowReject { generation: 1, flow_id, reason: Reason::ResourceExhausted } if flow_id == id
            ) || matches!(rejected, Message::Close { generation: 1, id: closed } if closed == id)
        );
        assert_eq!(session.flow_count(), FLOW_CAP);
        assert!(!session.has_flow(id));
        if mode == "reverse" {
            continue;
        }
        for slot in 0..=PROBE_FLOW_RESERVE {
            let id = FIRST_PROBE_ID + slot as u64;
            key.protocol = 1;
            key.source_port = slot as u16 + 1;
            key.destination_port = 0;
            session.dispatch_control(open(mode, id, key)).await.unwrap();
            if slot == PROBE_FLOW_RESERVE {
                let rejected: Message =
                    serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
                assert!(
                    matches!(rejected,
                        Message::FlowReject { generation: 1, flow_id, reason: Reason::ResourceExhausted } if flow_id == id
                    ) || matches!(rejected, Message::Close { generation: 1, id: closed } if closed == id)
                );
                assert!(!session.has_flow(id));
            } else {
                assert!(session.has_flow(id));
                if mode == "datagram" {
                    assert!(matches!(
                        receive.try_recv().unwrap(),
                        TaskCommand::Record(_)
                    ));
                } else {
                    let opened: Message =
                        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
                    assert!(
                        matches!(opened, Message::Opened { generation: 1, id: opened_id, .. } if opened_id == id)
                    );
                }
            }
        }
        assert_eq!(session.flow_count(), FLOW_CAP);
    }
}

// ── helpers ──

fn open(mode: &str, id: u64, flow: FlowKey) -> Message {
    if mode == "datagram" || mode == "reverse" {
        Message::FlowOpen {
            generation: 1,
            resume: false,
            flow_id: id,
            flow,
            channel: (mode == "datagram").then_some(7),
        }
    } else {
        Message::Open {
            generation: 1,
            id,
            flow,
        }
    }
}
