//! Shared selector fixtures: Allowed sets, flow keys, request/succeed drivers.

use std::net::Ipv4Addr;
use std::time::Instant;

use svpn::packet::FlowKey;
use svpn::selector::*;

#[allow(dead_code)] // unused by some of the including test targets
pub fn all() -> Allowed {
    Allowed {
        quic: true,
        webrtc: true,
        obfs: true,
        mosh: true,
        tcp: true,
    }
}

#[allow(dead_code)] // unused by some of the including test targets
pub fn udp_only() -> Allowed {
    Allowed {
        quic: true,
        webrtc: true,
        obfs: true,
        mosh: true,
        tcp: false,
    }
}

#[allow(dead_code)] // unused by some of the including test targets
pub fn key(id: u64) -> FlowKey {
    FlowKey {
        protocol: 17,
        source: Ipv4Addr::LOCALHOST,
        source_port: 1000 + id as u16,
        destination: Ipv4Addr::LOCALHOST,
        destination_port: 2000,
    }
}

#[allow(dead_code)] // unused by some of the including test targets
pub fn request(selector: &mut Selector, id: u64) -> Vec<Action> {
    selector
        .request(id, key(id), b"first", Instant::now())
        .expect("admission")
}

/// Full candidate success: prepare → ready → probes → peer → open →
/// opened → commit → committed.
#[allow(dead_code)] // unused by some of the including test targets
pub fn succeed(selector: &mut Selector, id: u64, candidate: Candidate) {
    let now = Instant::now();
    let attempt = selector
        .request(id, key(id), b"first", now)
        .expect("admission")
        .first()
        .map(|action| match action {
            Action::PrepareChannel { attempt, .. } => *attempt,
            _ => panic!("expected prepare, got {action:?}"),
        })
        .unwrap();
    selector.channel_ready(candidate, attempt, 100, now);
    assert!(selector.probes_passed(candidate, 100, now).is_empty());
    let now = Instant::now();
    let actions = selector.peer_verified(candidate, 100, now);
    assert_eq!(
        actions,
        vec![Action::OpenFlow {
            flow_id: id,
            candidate,
            channel: 100
        }]
    );
    assert_eq!(
        selector.bind_succeeded(id, now),
        vec![Action::Commit {
            flow_id: id,
            candidate,
            attempt: attempt + 1
        }]
    );
    assert!(selector.committed(id).is_empty());
}
