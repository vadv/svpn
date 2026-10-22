//! Session preflight rounds: probing, verdicts, backoff and retry, readiness.

mod common;

use std::time::Duration;
use std::time::Instant as StdInstant;

use common::session::{assert_closed, link_session, link_session_cap, test_key};
use svpn::control::{Control, Message, Stats, Strategy};
use svpn::link_io::{self, FIRST_PROBE_ID, PREFLIGHT_ID};
use svpn::packet;
use svpn::selector::{Action, Allowed, Candidate, Reason, Selector};
use svpn::session::*;
use svpn::udp::Incoming;
use tokio::sync::mpsc;

// ── probe rounds ──

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
    let (mut session, _keep, probes) = parallel_round().await;
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
    // The first verified echo opens the grace window; mosh and tcp are still out.
    let round = session.round.as_ref().expect("grace window is open");
    let decide_at = round.decide_at.expect("window deadline set");
    assert_eq!(round.verified.len(), 1);
    session.poll_round(decide_at).await.unwrap();
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
async fn every_candidate_verified_decides_without_the_window() {
    let (mut session, _keep, probes) = parallel_round().await;
    let round = session.round.as_ref().unwrap();
    let tcp_id = round.tcp_id.unwrap();
    let request = round.request.clone();
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.flows.get_mut(&tcp_id).unwrap().active = true;
    session
        .deliver_to_tun(Incoming {
            id: tcp_id,
            channel: None,
            packet: echo_reply_for(&request),
        })
        .await
        .unwrap();
    // The window opened: two UDP candidates have not answered yet.
    assert!(session.round.as_ref().unwrap().decide_at.is_some());
    for (id, channel, _, _, probe_request) in &probes {
        session
            .deliver_to_tun(Incoming {
                id: *id,
                channel: Some(*channel),
                packet: echo_reply_for(probe_request),
            })
            .await
            .unwrap();
    }
    // Everyone answered: the verdict is immediate, not after the window.
    // Equal RTTs: the first verified UDP candidate (mosh) beats TCP's penalty.
    assert!(session.round.is_none());
    assert_eq!(session.readiness, Some(Readiness::Verified(Some(100))));
}

#[tokio::test]
async fn faster_candidate_verified_inside_the_window_wins() {
    let (mut session, _keep, probes) = parallel_round().await;
    // Obfs (channel 101) answers first, but its probe left 300 ms ago.
    session
        .round
        .as_mut()
        .unwrap()
        .pending
        .get_mut(&probes[1].0)
        .unwrap()
        .sent_at = Some(tokio::time::Instant::now() - Duration::from_millis(300));
    for (verified, probe) in [(1, &probes[1]), (2, &probes[0])] {
        session
            .deliver_to_tun(Incoming {
                id: probe.0,
                channel: Some(probe.1),
                packet: echo_reply_for(&probe.4),
            })
            .await
            .unwrap();
        // Tcp is still out, so neither echo decides on its own.
        let round = session.round.as_ref().expect("window still open");
        assert_eq!(round.verified.len(), verified);
    }
    let decide_at = session.round.as_ref().unwrap().decide_at.unwrap();
    session.poll_round(decide_at).await.unwrap();
    assert!(session.round.is_none());
    // Mosh verified later but with a far better RTT bucket.
    assert_eq!(session.readiness, Some(Readiness::Verified(Some(100))));
    let Plane::Channels(plane) = &session.plane else {
        unreachable!()
    };
    assert!(plane.channels.contains_key(&100));
    assert!(!plane.channels.contains_key(&101));
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
    // The fixture bypasses the TCP send path; mark the probe as sent.
    session.round.as_mut().unwrap().tcp_started = Some(tokio::time::Instant::now());
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

// ── failure and retry ──

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

// ── TCP rounds ──

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
    session.round_won(None, None).await.unwrap();
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
    session.round_won(None, None).await.unwrap();
    session
        .channel_failed(Some(attempt), None, Reason::PathTimeout)
        .await
        .unwrap();
    assert!(session.round.is_none());
    assert_eq!(session.readiness, Some(Readiness::Verified(None)));
    assert!(events.try_recv().is_err());
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

// ── stale probe events ──

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
        selector.adopt(Candidate::Mosh, Some(10), None);
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
        session.round_won(None, None).await.unwrap();
        assert_eq!(session.readiness, Some(Readiness::Verified(None)));
        assert_eq!(session.has_flow(1), !transport_failed);
        let Plane::Channels(plane) = &session.plane else {
            unreachable!()
        };
        assert_eq!(plane.channels.contains_key(&10), !transport_failed);
        assert_eq!(plane.by_key.contains_key(&key), !transport_failed);
    }
}

// ── grace-window verdict ──

fn verified(entries: &[(u64, Candidate, u64)]) -> Vec<(u64, Candidate, Option<u64>, Duration)> {
    entries
        .iter()
        .map(|(attempt, candidate, rtt_ms)| {
            (
                *attempt,
                *candidate,
                Some(*attempt + 100),
                Duration::from_millis(*rtt_ms),
            )
        })
        .collect()
}

#[test]
fn pick_verified_prefers_the_lowest_time() {
    let entries = verified(&[
        (1, Candidate::Quic, 130),
        (2, Candidate::Obfs, 90),
        (3, Candidate::Tcp, 200),
    ]);
    assert_eq!(pick_verified(&entries), Some(1));
    // Two UDP candidates are compared exactly, even below the TCP penalty.
    let entries = verified(&[(1, Candidate::Mosh, 40), (2, Candidate::Obfs, 10)]);
    assert_eq!(pick_verified(&entries), Some(1));
    assert!(pick_verified(&[]).is_none());
}

#[test]
fn pick_verified_counts_tcp_fifty_milliseconds_slower() {
    // Quic is 25 ms slower than tcp and still wins.
    let entries = verified(&[(1, Candidate::Tcp, 430), (2, Candidate::Quic, 455)]);
    assert_eq!(pick_verified(&entries), Some(1));
    // 60 ms slower is too much for the head start.
    let entries = verified(&[(1, Candidate::Tcp, 430), (2, Candidate::Quic, 490)]);
    assert_eq!(pick_verified(&entries), Some(0));
}

#[test]
fn pick_verified_head_start_boundary_is_exact() {
    // Exactly 50 ms apart is a tie: the earliest verification wins.
    let entries = verified(&[(1, Candidate::Tcp, 100), (2, Candidate::Quic, 150)]);
    assert_eq!(pick_verified(&entries), Some(0));
    let entries = verified(&[(1, Candidate::Quic, 150), (2, Candidate::Tcp, 100)]);
    assert_eq!(pick_verified(&entries), Some(0));
    // One millisecond either side of the boundary flips the verdict.
    let entries = verified(&[(1, Candidate::Tcp, 100), (2, Candidate::Quic, 151)]);
    assert_eq!(pick_verified(&entries), Some(0));
    let entries = verified(&[(1, Candidate::Tcp, 100), (2, Candidate::Quic, 149)]);
    assert_eq!(pick_verified(&entries), Some(1));
}

#[test]
fn pick_verified_keeps_earliest_verification_on_full_tie() {
    let entries = verified(&[(1, Candidate::Obfs, 80), (2, Candidate::Mosh, 80)]);
    assert_eq!(pick_verified(&entries), Some(0));
}

#[tokio::test]
async fn candidate_that_fails_after_its_echo_cannot_win() {
    let (mut session, _keep, probes) = parallel_round().await;
    // Obfs (channel 101) verifies first, then its path dies inside the window.
    session
        .deliver_to_tun(Incoming {
            id: probes[1].0,
            channel: Some(probes[1].1),
            packet: echo_reply_for(&probes[1].4),
        })
        .await
        .unwrap();
    session
        .round_attempt_failed(probes[1].0, Reason::PathTimeout)
        .await
        .unwrap();
    assert!(session.round.as_ref().unwrap().verified.is_empty());
    // Mosh verifies; it is the only live verified candidate when the window ends.
    session
        .deliver_to_tun(Incoming {
            id: probes[0].0,
            channel: Some(probes[0].1),
            packet: echo_reply_for(&probes[0].4),
        })
        .await
        .unwrap();
    let decide_at = session.round.as_ref().unwrap().decide_at.unwrap();
    session.poll_round(decide_at).await.unwrap();
    assert!(session.round.is_none());
    assert_eq!(session.readiness, Some(Readiness::Verified(Some(100))));
}

#[tokio::test]
async fn round_starts_webrtc_last_so_it_cannot_delay_the_others() {
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
        webrtc: true,
        obfs: true,
        mosh: true,
        ..Allowed::default()
    }));
    session.begin_preflight().await.unwrap();
    let mut strategies = Vec::new();
    for _ in 0..3 {
        match tokio::time::timeout(Duration::from_secs(5), peer.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Message::ChannelPrepare { strategy, .. } => strategies.push(strategy),
            _ => panic!("unexpected round start message"),
        }
    }
    // Cold order is webrtc, obfs, mosh; building the WebRTC peer takes
    // hundreds of milliseconds on a router, so it must not hold up the rest.
    assert_eq!(
        strategies,
        [Strategy::Obfs, Strategy::Mosh, Strategy::WebRtc]
    );
}

// ── verdict window ──

/// The window scales with the measured RTT; a candidate that reached
/// `established` inside it gets 6 more RTTs and can still win.
#[tokio::test(start_paused = true)]
async fn established_candidate_extends_the_window_and_can_win() {
    let (mut session, _keep, probes) = parallel_round().await;
    let t0 = tokio::time::Instant::now();
    // TCP answers first: its probe left 100 ms ago.
    let (tcp_id, request) = {
        let round = session.round.as_mut().unwrap();
        round.tcp_started = Some(t0 - Duration::from_millis(100));
        (round.tcp_id.unwrap(), round.request.clone())
    };
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.flows.get_mut(&tcp_id).unwrap().active = true;
    session
        .deliver_to_tun(Incoming {
            id: tcp_id,
            channel: None,
            packet: echo_reply_for(&request),
        })
        .await
        .unwrap();
    // 8 × 100 ms beats the 400 ms floor.
    let decide_at = session.round.as_ref().unwrap().decide_at.unwrap();
    assert_eq!(decide_at, t0 + Duration::from_millis(800));
    // Mosh reaches `established` right at the end of the window.
    tokio::time::advance(Duration::from_millis(800)).await;
    session
        .round
        .as_mut()
        .unwrap()
        .pending
        .get_mut(&probes[0].0)
        .unwrap()
        .established = true;
    session
        .poll_round(t0 + Duration::from_millis(800))
        .await
        .unwrap();
    // Extended by 6 RTT from now: the window moves from 800 to 1400 ms.
    assert!(session.round.is_some());
    assert_eq!(
        session.round.as_ref().unwrap().decide_at.unwrap(),
        t0 + Duration::from_millis(1400)
    );
    // Mosh's echo arrives inside the extension with a far better RTT and wins.
    session
        .round
        .as_mut()
        .unwrap()
        .pending
        .get_mut(&probes[0].0)
        .unwrap()
        .sent_at = Some(tokio::time::Instant::now() - Duration::from_millis(50));
    session
        .deliver_to_tun(Incoming {
            id: probes[0].0,
            channel: Some(probes[0].1),
            packet: echo_reply_for(&probes[0].4),
        })
        .await
        .unwrap();
    tokio::time::advance(Duration::from_millis(600)).await;
    session
        .poll_round(t0 + Duration::from_millis(1400))
        .await
        .unwrap();
    assert!(session.round.is_none());
    assert_eq!(session.readiness, Some(Readiness::Verified(Some(100))));
}

/// A candidate that never reports `established` extends nothing: the verdict
/// comes exactly at the window end.
#[tokio::test(start_paused = true)]
async fn silent_candidates_do_not_extend_the_window() {
    let (mut session, _keep, _probes) = parallel_round().await;
    let t0 = tokio::time::Instant::now();
    let (tcp_id, request) = {
        let round = session.round.as_mut().unwrap();
        round.tcp_started = Some(t0 - Duration::from_millis(100));
        (round.tcp_id.unwrap(), round.request.clone())
    };
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.flows.get_mut(&tcp_id).unwrap().active = true;
    session
        .deliver_to_tun(Incoming {
            id: tcp_id,
            channel: None,
            packet: echo_reply_for(&request),
        })
        .await
        .unwrap();
    assert_eq!(
        session.round.as_ref().unwrap().decide_at.unwrap(),
        t0 + Duration::from_millis(800)
    );
    tokio::time::advance(Duration::from_millis(800)).await;
    session
        .poll_round(t0 + Duration::from_millis(800))
        .await
        .unwrap();
    assert!(session.round.is_none());
    assert_eq!(session.readiness, Some(Readiness::Verified(None)));
}

/// The extension is capped by the round deadline; past it the verdict runs.
#[tokio::test(start_paused = true)]
async fn window_extension_never_crosses_the_round_deadline() {
    let (mut session, _keep, probes) = parallel_round().await;
    let t0 = tokio::time::Instant::now();
    let (tcp_id, request) = {
        let round = session.round.as_mut().unwrap();
        round.tcp_started = Some(t0 - Duration::from_millis(100));
        (round.tcp_id.unwrap(), round.request.clone())
    };
    let Plane::Channels(plane) = &mut session.plane else {
        unreachable!()
    };
    plane.flows.get_mut(&tcp_id).unwrap().active = true;
    session
        .deliver_to_tun(Incoming {
            id: tcp_id,
            channel: None,
            packet: echo_reply_for(&request),
        })
        .await
        .unwrap();
    session
        .round
        .as_mut()
        .unwrap()
        .pending
        .get_mut(&probes[0].0)
        .unwrap()
        .established = true;
    // The round deadline lands inside the would-be extension (t0+1400).
    session.round.as_mut().unwrap().deadline = t0 + Duration::from_millis(900);
    tokio::time::advance(Duration::from_millis(800)).await;
    session
        .poll_round(t0 + Duration::from_millis(800))
        .await
        .unwrap();
    assert!(session.round.is_some());
    assert_eq!(
        session.round.as_ref().unwrap().decide_at.unwrap(),
        t0 + Duration::from_millis(900)
    );
    // At the deadline the window cannot grow further: decide with what we have.
    tokio::time::advance(Duration::from_millis(100)).await;
    session
        .poll_round(t0 + Duration::from_millis(900))
        .await
        .unwrap();
    assert!(session.round.is_none());
    assert_eq!(session.readiness, Some(Readiness::Verified(None)));
}

/// The `no answer` list says how far each candidate got.
#[tokio::test]
async fn unanswered_reports_the_stage_of_each_candidate() {
    let (mut session, _keep, probes) = parallel_round().await;
    session
        .round
        .as_mut()
        .unwrap()
        .pending
        .get_mut(&probes[0].0)
        .unwrap()
        .established = true;
    let round = session.round.as_ref().unwrap();
    assert_eq!(
        unanswered(round),
        "mosh (probe), obfs (handshake), tcp (probe)"
    );
}

/// A started round with mosh (channel 100) and obfs (channel 101) armed next
/// to tcp, every attempt registered on the plane. Returns the session, the
/// handles that keep its ports open, and the probes sorted by channel.
async fn parallel_round() -> (
    Session,
    (mpsc::Receiver<(link_io::Epoch, link_io::Event)>, Control),
    Vec<(u64, u64, Candidate, u16, Vec<u8>)>,
) {
    let (mut session, events) = link_session(false);
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
    // The fixture bypasses the send paths; mark every probe as already sent.
    let sent = tokio::time::Instant::now();
    for rc in round.pending.values_mut() {
        rc.sent_at = Some(sent);
    }
    round.tcp_started = Some(sent);
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
    (session, (events, peer), probes)
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
