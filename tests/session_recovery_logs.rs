//! Recovery journals: commit is readiness, only current delivered peer data is success.

mod common;

use std::collections::VecDeque;
use std::time::Instant as StdInstant;

use common::session::link_session;
use svpn::link_io;
use svpn::packet;
use svpn::selector::{Candidate, RECOVERY_BUDGET};
use svpn::session::Recovery;
use svpn::session::{ChannelHandle, Flow, PacketIo, Plane, Session, TcpFlow};
use svpn::udp::Incoming;
use tokio::sync::mpsc;
use tokio::time::Instant;

// ── journal and delivery boundary ──

#[tokio::test]
async fn recovery_success_requires_observed_delivery() {
    // Isolate the process-global logger and inspect the actual production records.
    if std::env::var_os("SVPN_RECOVERY_LOG_CHILD").is_none() {
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery_success_requires_observed_delivery",
                "--nocapture",
            ])
            .env("SVPN_RECOVERY_LOG_CHILD", "1")
            .output()
            .await
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "{stderr}");
        assert_eq!(
            stderr.matches("flow_recovery_restored ").count(),
            4,
            "{stderr}"
        );
        assert_eq!(stderr.matches("stage=peer_packet ").count(), 4, "{stderr}");
        assert_eq!(
            stderr.matches("flow_recovery_abandoned ").count(),
            4,
            "{stderr}"
        );
        return;
    }
    svpn::logging::init(svpn::logging::Level::Info).unwrap();
    for fixed in [false, true] {
        for client in [false, true] {
            for confirmed in [false, true] {
                let (mut session, mut events) = link_session(fixed);
                let mut outbound = common::tcp_packet(!client);
                outbound[33] = 0x10;
                let mut inbound = common::tcp_packet(client);
                inbound[33] = 0x10;
                let key = packet::parse(&inbound, !client).unwrap().flow;
                let now = Instant::now();
                let recovery = Some(Recovery {
                    started: now,
                    from: Some(Candidate::Mosh),
                    attempts: 1,
                });
                let (command, _commands) = mpsc::channel(4);
                let (outgoing, _outgoing) = mpsc::channel(4);
                match &mut session.plane {
                    Plane::Channels(plane) => {
                        if client {
                            let selector = plane.selector.as_mut().unwrap();
                            let at = StdInstant::now();
                            selector.request(1, key, &outbound, at).unwrap();
                            selector.channel_ready(Candidate::Mosh, 1, 10, at);
                            selector.probes_passed(Candidate::Mosh, 10, at);
                            selector.peer_verified(Candidate::Mosh, 10, at);
                            selector.bind_succeeded(1, 1, at);
                        } else {
                            plane.server_ip = None;
                            plane.selector = None;
                        }
                        let mut flow = Flow::new(key, now);
                        flow.channel = Some(10);
                        flow.recovery = recovery;
                        if !client {
                            flow.pending.push_back(outbound);
                        }
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
                    }
                    Plane::Tcp(plane) => {
                        if !client {
                            plane.server_ip = None;
                        }
                        let mut flow = TcpFlow::new(key, now);
                        flow.tcp_connected = true;
                        flow.outgoing = Some(outgoing);
                        flow.pending = VecDeque::from([outbound]);
                        flow.recovery = recovery;
                        plane.flows.insert(1, flow);
                        plane.by_key.insert(key, 1);
                    }
                }
                if client {
                    session.committed(1, 1).await.unwrap();
                } else {
                    session.commit(1, 1).await.unwrap();
                }
                assert!(
                    awaiting_evidence(&session),
                    "commit is not delivery evidence"
                );
                let channel = (!fixed).then_some(10);
                for (generation, channel) in [(0, channel), (1, Some(99))] {
                    session
                        .deliver_to_tun(Incoming {
                            id: 1,
                            generation,
                            channel,
                            packet: inbound.clone(),
                        })
                        .await
                        .unwrap();
                    assert!(awaiting_evidence(&session));
                }
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
                        channel,
                        packet: inbound.clone(),
                    })
                    .await
                    .unwrap();
                assert!(
                    awaiting_evidence(&session),
                    "failed Hub delivery is not success"
                );
                events.try_recv().unwrap();
                if confirmed {
                    for _ in 0..2 {
                        session
                            .deliver_to_tun(Incoming {
                                id: 1,
                                generation: 1,
                                channel,
                                packet: inbound.clone(),
                            })
                            .await
                            .unwrap();
                        assert!(matches!(
                            events.try_recv().unwrap().1,
                            link_io::Event::Packet(_)
                        ));
                        assert!(!awaiting_evidence(&session));
                    }
                }
                // A quiet, ready binding is not failed merely because evidence has not arrived.
                if !fixed {
                    // Channels-plane recovery is bounded by RECOVERY_BUDGET; the
                    // fixed-TCP opening budget (pre-data) covers its retries.
                    session.expire_flows(now + RECOVERY_BUDGET).await.unwrap();
                    assert_eq!(session.has_flow(1), confirmed);
                }
                session.close_flow(1, false).await.unwrap();
            }
        }
    }
    svpn::logging::finish();
}

// ── helpers ──

fn awaiting_evidence(session: &Session) -> bool {
    match &session.plane {
        Plane::Channels(plane) => plane.flows[&1].recovery.is_some(),
        Plane::Tcp(plane) => plane.flows[&1].recovery.is_some(),
    }
}
