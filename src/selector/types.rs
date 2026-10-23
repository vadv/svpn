//! Wire vocabulary of the auto-selector: candidates, failure reasons, the
//! actions session must perform, and admission rejections.
//! String values are the wire protocol vocabulary.

use std::time::Duration;

use crate::packet::FlowKey;

/// A full candidate attempt, including the cover handshake and probes.
pub const ATTEMPT_BUDGET: Duration = Duration::from_secs(5);
/// Shared budget of selection and commit for a new flow (from admission).
pub const FLOW_BUDGET: Duration = Duration::from_secs(30);
pub const RECOVERY_BUDGET: Duration = Duration::from_secs(10);
/// Hold-down for a failed candidate and a total failure.
pub const HOLD_DOWN: Duration = Duration::from_secs(30);
/// Pre-active queue: packets of a flow waiting for transport readiness.
/// Sized for a UDP burst (browser QUIC) in the first RTT of a flow; the
/// global byte budget below stays the real cap.
pub const PREACTIVE_PACKETS: usize = 64;
/// Pre-active queue: concurrently waiting flows.
pub const PENDING_FLOWS: usize = 64;
/// Pre-active queue: total size of waiting packets.
pub const PREACTIVE_BYTES: usize = 2 * 1024 * 1024;

/// Auto candidates in cold order.
pub const COLD_ORDER: [Candidate; 5] = [
    Candidate::Quic,
    Candidate::WebRtc,
    Candidate::Obfs,
    Candidate::Mosh,
    Candidate::Tcp,
];

/// Strategy candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Candidate {
    Quic,
    WebRtc,
    Obfs,
    Mosh,
    Tcp,
}

impl Candidate {
    pub const fn as_str(self) -> &'static str {
        match self {
            Candidate::Quic => "quic",
            Candidate::WebRtc => "webrtc",
            Candidate::Obfs => "obfs",
            Candidate::Mosh => "mosh",
            Candidate::Tcp => "tcp",
        }
    }
}

impl std::fmt::Display for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Failure reasons (wire `reason` strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    PathTimeout,
    OneWay,
    SizeProbeFailed,
    Unsupported,
    EndpointUnavailable,
    ResourceExhausted,
    ChannelFailed,
}

impl Reason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::PathTimeout => "path_timeout",
            Reason::OneWay => "one_way",
            Reason::SizeProbeFailed => "size_probe_failed",
            Reason::Unsupported => "unsupported",
            Reason::EndpointUnavailable => "endpoint_unavailable",
            Reason::ResourceExhausted => "resource_exhausted",
            Reason::ChannelFailed => "channel_failed",
        }
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Selector command for session to perform I/O (control/sockets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Start preparing a strategy channel: `channel_prepare` + probes.
    PrepareChannel {
        candidate: Candidate,
        attempt: u64,
    },
    /// Abort the preparation (deadline/cancel): release the attempt's resources.
    AbortChannel {
        candidate: Candidate,
        attempt: u64,
    },
    /// Retire only the binding; preserve the logical flow and unsent queue.
    ResetBinding {
        flow_id: u64,
        generation: u64,
        from: Option<Candidate>,
        reason: Reason,
    },
    OpenFlow {
        flow_id: u64,
        generation: u64,
        candidate: Candidate,
        channel: u64,
    },
    TryTcp {
        flow_id: u64,
        generation: u64,
    },
    Commit {
        flow_id: u64,
        candidate: Candidate,
        generation: u64,
    },
    /// Flow not established: the reason goes to control `flow_reject`/the log.
    FailFlow {
        flow_id: u64,
        flow: FlowKey,
        reason: Reason,
    },
    /// Close the flow and its local resources (no fallback).
    CloseFlow {
        flow_id: u64,
    },
    /// Proactive-auto: no candidates left — the session stops.
    Exhausted {
        reasons: Vec<(Candidate, Reason)>,
    },
    /// the backoff ban expired; the candidate is eligible again.
    BanExpired {
        candidate: Candidate,
    },
}

/// Admission rejection of a new flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Waiting-flow limit exceeded (fail closed, no blocking).
    PendingFull,
    /// flow_id is already live or finished — no new one is created.
    Duplicate,
}

/// Candidate configuration: the intersection of both sides' capabilities and the CLI mode.
#[derive(Debug, Clone, Default)]
pub struct Allowed {
    pub quic: bool,
    pub webrtc: bool,
    pub obfs: bool,
    pub mosh: bool,
    pub tcp: bool,
}

impl Allowed {
    /// List in cold order; an empty list — the selector always rejects.
    pub fn list(&self) -> Vec<Candidate> {
        COLD_ORDER
            .iter()
            .copied()
            .filter(|candidate| match candidate {
                Candidate::Quic => self.quic,
                Candidate::WebRtc => self.webrtc,
                Candidate::Obfs => self.obfs,
                Candidate::Mosh => self.mosh,
                Candidate::Tcp => self.tcp,
            })
            .collect()
    }
}
