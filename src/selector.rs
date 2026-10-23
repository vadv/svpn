//! Strategy auto-selector: a pure client state machine.
//!
//! Decides which candidate (`quic → webrtc → obfs → mosh → tcp`) to try for
//! a new flow, when a strategy channel is ready, when to commit, and when
//! to fail honestly. No sockets or timers: time arrives as the `now`
//! parameter, I/O is performed by session per the returned [`Action`]s.
//!
//! Invariants:
//! - one selection process: parallel flows wait for one channel preparation;
//! - `last_good` first, erased only by that candidate's own failure;
//! - binding generations reject events from an abandoned attempt;
//! - a bind failure affects one flow, a channel failure affects all its flows;
//! - packets and repeated failures never extend an admission/recovery deadline;
//! - the pre-active queue is bounded (64 packets/flow, 64 flows, 2 MiB);
//! - proactive-auto: a preparation failure (including the first TCP connect) bans
//!   the candidate for the rest of the session; exhausting them all — one `Exhausted`, stop.
//!
//! Layout: `types` holds the wire vocabulary (candidates, reasons, actions),
//! this file the selection machine.
#![allow(dead_code)]

use std::time::Duration;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Instant,
};

use crate::packet::FlowKey;

mod types;

pub use types::{
    ATTEMPT_BUDGET, Action, Allowed, COLD_ORDER, Candidate, FLOW_BUDGET, HOLD_DOWN, PENDING_FLOWS,
    PREACTIVE_BYTES, PREACTIVE_PACKETS, RECOVERY_BUDGET, Reason, Reject,
};

/// A ready strategy channel (after `channel_ready`).
#[derive(Debug, Clone, Copy)]
pub struct ReadyChannel {
    id: u64,
    /// This side verified the round-trip probes itself (PROBE_A/AB/B + SIZE).
    self_verified: bool,
    /// Peer reported `channel_verified`.
    peer_verified: bool,
}

impl ReadyChannel {
    pub fn new(id: u64, verified: bool) -> Self {
        Self {
            id,
            self_verified: verified,
            peer_verified: verified,
        }
    }

    /// Both sides confirmed the round-trip probes.
    fn verified(&self) -> bool {
        self.self_verified && self.peer_verified
    }
}

/// A channel preparation in progress: one selection process for the whole app.
#[derive(Debug, Clone, Copy)]
pub struct Preparation {
    pub candidate: Candidate,
    attempt: u64,
    deadline: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Stage {
    /// Waiting for a candidate choice and a ready channel.
    Pending,
    Binding {
        candidate: Candidate,
        deadline: Instant,
    },
    Committing {
        candidate: Candidate,
        deadline: Instant,
    },
    /// `committed` received: DATA allowed, last_good updated.
    Active { candidate: Candidate },
}

impl Stage {
    /// The bound candidate once a flow left `Pending`; `Pending` has none yet.
    fn candidate(&self) -> Option<Candidate> {
        match self {
            Stage::Binding { candidate, .. }
            | Stage::Committing { candidate, .. }
            | Stage::Active { candidate } => Some(*candidate),
            Stage::Pending => None,
        }
    }

    fn is_active(&self) -> bool {
        matches!(self, Stage::Active { .. })
    }
}

struct FlowSel {
    flow: FlowKey,
    generation: u64,
    recovering: bool,
    retry_at: Option<Instant>,
    /// Overall flow deadline (admission + FLOW_BUDGET).
    deadline: Instant,
    stage: Stage,
    /// Pre-active queue: full IP packets until the transport is ready.
    queue: VecDeque<Vec<u8>>,
    queue_bytes: usize,
    /// Candidates excluded for this flow (bind failures).
    skip: HashSet<Candidate>,
}

/// First ban duration; doubles per consecutive failure, capped.
const BAN_BACKOFF_START: Duration = Duration::from_secs(600);

/// e2e hook: `SVPN_TEST_BAN_BACKOFF_SECS` shrinks the first ban (and, while
/// set, pins every re-ban to the same value) so ban-expiry recovery fits
/// test budgets. Unset in production; a malformed value keeps the default.
/// Can only shorten bans, never lengthen them.
fn ban_backoff_start() -> Duration {
    ban_backoff_from(std::env::var("SVPN_TEST_BAN_BACKOFF_SECS").ok().as_deref())
}

/// Pure parse behind the e2e hook: tested directly in tests/selector_proactive.rs.
pub fn ban_backoff_from(raw: Option<&str>) -> Duration {
    raw.and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map_or(BAN_BACKOFF_START, |secs| {
            BAN_BACKOFF_START.min(Duration::from_secs(secs))
        })
}
/// Ban backoff never grows past this.
const BAN_BACKOFF_CAP: Duration = Duration::from_secs(2 * 3600);

/// Auto-selection machine. All methods are pure: time as a parameter, I/O
/// through the returned actions. One instance per client session.
pub struct Selector {
    configured: Vec<Candidate>,
    pub allowed: Vec<Candidate>,
    suspended: bool,
    flows: HashMap<u64, FlowSel>,
    pub channels: HashMap<Candidate, ReadyChannel>,
    pub preparation: Option<Preparation>,
    hold_down: HashMap<Candidate, Instant>,
    /// RAM hint for this SSH session; stores no keys/ports.
    pub last_good: Option<Candidate>,
    /// Proactive-auto: a preparation failure bans the candidate for the session.
    proactive: bool,
    /// Expiry of the current ban per candidate: the candidate is
    /// eligible again after this moment.
    ban_until: HashMap<Candidate, Instant>,
    /// Next ban duration per candidate: doubles per failure, reset on success.
    ban_backoff: HashMap<Candidate, Duration>,
    /// Jitter sequence for ban expiry; decorrelates retries without a RNG.
    ban_seq: u64,
    /// Ban chronicle for the final exhaustion table.
    pub banned: Vec<(Candidate, Reason)>,
    /// `Exhausted` already sent — the stop signal is not repeated.
    exhausted: bool,
    /// flow_id is never reused in a session, including closed ones.
    used_ids: HashSet<u64>,
    next_attempt: u64,
    queued_bytes: usize,
}

impl Selector {
    /// Fixed mode: failures are handled by hold-down, the session does not die.
    pub fn new(allowed: Allowed) -> Self {
        Self::build(allowed, false)
    }

    /// Auto mode: bans for those that failed to come up, exhaustion stops the session.
    pub fn new_proactive(allowed: Allowed) -> Self {
        Self::build(allowed, true)
    }

    fn build(allowed: Allowed, proactive: bool) -> Self {
        Self {
            configured: allowed.list(),
            allowed: allowed.list(),
            suspended: false,
            flows: HashMap::new(),
            channels: HashMap::new(),
            preparation: None,
            hold_down: HashMap::new(),
            ban_until: HashMap::new(),
            ban_backoff: HashMap::new(),
            ban_seq: 0,
            last_good: None,
            proactive,
            banned: Vec::new(),
            exhausted: false,
            used_ids: HashSet::new(),
            next_attempt: 1,
            queued_bytes: 0,
        }
    }

    /// Candidates allowed by configuration, in the cold order.
    pub fn allowed(&self) -> Vec<Candidate> {
        self.configured.clone()
    }

    pub fn preparation_candidate(&self) -> Option<Candidate> {
        self.preparation.map(|p| p.candidate)
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Flows holding memory the selector has not admitted yet — pre-active,
    /// recovering, or active with a still-undrained queue. Bounded by
    /// `PENDING_FLOWS`: a deliberate admission cap, so a backed-up flow
    /// consumes a slot a new flow would need.
    pub fn pre_active_count(&self) -> usize {
        self.flows
            .values()
            .filter(|flow| (!flow.stage.is_active() && !flow.recovering) || !flow.queue.is_empty())
            .count()
    }

    pub fn has_pending_work(&self) -> bool {
        self.flows.values().any(|flow| !flow.stage.is_active())
    }

    pub fn binding_active(&self, flow_id: u64, generation: u64) -> bool {
        self.flows
            .get(&flow_id)
            .is_some_and(|flow| flow.generation == generation && flow.stage.is_active())
    }

    pub fn has_queued(&self, flow_id: u64) -> bool {
        self.flows
            .get(&flow_id)
            .is_some_and(|flow| !flow.queue.is_empty())
    }

    pub fn pop_packet(&mut self, flow_id: u64) -> Option<Vec<u8>> {
        let flow = self.flows.get_mut(&flow_id)?;
        if !flow.stage.is_active() {
            return None;
        }
        let packet = flow.queue.pop_front()?;
        flow.queue_bytes -= packet.len();
        self.queued_bytes -= packet.len();
        Some(packet)
    }

    pub fn ready_channel(&self, candidate: Candidate) -> Option<u64> {
        self.channels
            .get(&candidate)
            .filter(|channel| channel.verified())
            .map(|channel| channel.id)
    }

    /// Pause selection while preserving queues and their original deadlines.
    pub fn enter_checking(&mut self, now: Instant) -> Vec<Action> {
        self.suspended = true;
        let mut actions = Vec::new();
        if let Some(preparation) = self.preparation.take() {
            actions.push(Action::AbortChannel {
                candidate: preparation.candidate,
                attempt: preparation.attempt,
            });
        }
        self.channels.retain(|_, channel| channel.verified());
        let unfinished: Vec<_> = self
            .flows
            .iter()
            .filter(|(_, flow)| {
                matches!(flow.stage, Stage::Binding { .. } | Stage::Committing { .. })
            })
            .map(|(&id, flow)| (id, flow.generation, flow.recovering))
            .collect();
        for (id, generation, recovering) in unfinished {
            actions.extend(self.retry(id, generation, recovering, Reason::ChannelFailed, now));
        }
        actions
    }

    pub fn resume(&mut self, now: Instant) -> Vec<Action> {
        self.suspended = false;
        self.advance(now)
    }

    /// Remember the round winner; TCP has no shared channel to adopt.
    /// The winner's probe p90 seeds its statistics window — the
    /// degradation baseline exists from minute zero.
    pub fn adopt(&mut self, candidate: Candidate, channel_id: Option<u64>) {
        if let Some(id) = channel_id {
            self.channels.insert(candidate, ReadyChannel::new(id, true));
        }
        if !self.allowed.contains(&candidate) {
            self.allowed.push(candidate);
        }
        self.exhausted = false;
        self.last_good = Some(candidate);
        self.hold_down.remove(&candidate);
        // A proven candidate starts with a clean ban backoff.
        self.ban_backoff.remove(&candidate);
        self.ban_until.remove(&candidate);
        for flow in self
            .flows
            .values_mut()
            .filter(|flow| matches!(flow.stage, Stage::Pending))
        {
            flow.skip.remove(&candidate);
        }
    }

    fn attempt(&mut self) -> u64 {
        let attempt = self.next_attempt;
        self.next_attempt = attempt.checked_add(1).expect("attempt space exhausted");
        attempt
    }

    /// Iteration order: last_good first, then the cold order.
    fn order(&self) -> Vec<Candidate> {
        let mut order = Vec::with_capacity(self.allowed.len() + 1);
        if let Some(best) = self.last_good
            && self.allowed.contains(&best)
        {
            order.push(best);
        }
        order.extend(
            self.allowed
                .iter()
                .copied()
                .filter(|candidate| Some(*candidate) != self.last_good),
        );
        order
    }

    /// Candidate available now: allowed, not in hold-down (for this flow).
    pub fn available(&self, candidate: Candidate, now: Instant) -> bool {
        !self
            .hold_down
            .get(&candidate)
            .is_some_and(|until| *until > now)
    }

    fn next_for_flow(&self, flow_id: &u64, now: Instant) -> Option<Candidate> {
        let flow = self.flows.get(flow_id)?;
        if !matches!(flow.stage, Stage::Pending) {
            return None;
        }
        self.order()
            .into_iter()
            .filter(|candidate| {
                !flow.skip.contains(candidate) && (!flow.recovering || *candidate != Candidate::Tcp)
            })
            .find(|candidate| self.available(*candidate, now))
    }

    /// Advances selection: picks a candidate for every waiting flow. One
    /// channel preparation (PrepareChannel) at a time; assigning already
    /// verified channels and TryTcp are not serialized — otherwise parallel
    /// SYNs would open one per tick.
    fn advance(&mut self, now: Instant) -> Vec<Action> {
        if self.suspended {
            return Vec::new();
        }
        let mut actions = Vec::new();
        let pending: Vec<u64> = self
            .flows
            .iter()
            .filter(|(_, flow)| matches!(flow.stage, Stage::Pending))
            .map(|(&id, _)| id)
            .collect();
        for flow_id in pending {
            if let Some(flow) = self.flows.get_mut(&flow_id)
                && flow.retry_at.is_some_and(|at| now >= at)
            {
                flow.skip.clear();
                flow.retry_at = None;
            }
            let Some(candidate) = self.next_for_flow(&flow_id, now) else {
                // The shared round may still supply a verified channel before the deadline.
                continue;
            };
            match candidate {
                Candidate::Tcp => {
                    self.set_binding(flow_id, candidate, now);
                    actions.push(Action::TryTcp {
                        flow_id,
                        generation: self.flows[&flow_id].generation,
                    });
                }
                udp => {
                    let channel = self
                        .channels
                        .get(&udp)
                        .map(|channel| (channel.id, channel.verified()));
                    match channel {
                        Some((channel_id, true)) => {
                            self.set_binding(flow_id, udp, now);
                            actions.push(Action::OpenFlow {
                                flow_id,
                                generation: self.flows[&flow_id].generation,
                                candidate: udp,
                                channel: channel_id,
                            });
                        }
                        // A channel exists but is not fully verified: the flow waits
                        // for the verified event — preparation is already running or partially done.
                        Some((_, false)) => {}
                        None => {
                            // Another candidate's preparation may already be running: then
                            // this flow waits its turn — one selection process, no handshake race.
                            if self.preparation.is_none() {
                                let attempt = self.attempt();
                                self.preparation = Some(Preparation {
                                    candidate: udp,
                                    attempt,
                                    deadline: now + ATTEMPT_BUDGET,
                                });
                                actions.push(Action::PrepareChannel {
                                    candidate: udp,
                                    attempt,
                                });
                            }
                        }
                    }
                }
            }
        }
        actions
    }

    fn set_binding(&mut self, flow_id: u64, candidate: Candidate, now: Instant) {
        if let Some(flow) = self.flows.get_mut(&flow_id) {
            flow.stage = Stage::Binding {
                candidate,
                deadline: (now + ATTEMPT_BUDGET).min(flow.deadline),
            };
        }
    }

    /// Admission of a new flow. The first packet goes into the pre-active queue.
    pub fn request(
        &mut self,
        flow_id: u64,
        flow: FlowKey,
        first_packet: &[u8],
        now: Instant,
    ) -> Result<Vec<Action>, Reject> {
        if self.suspended {
            return Err(Reject::PendingFull);
        }
        if !self.used_ids.insert(flow_id) {
            return Err(Reject::Duplicate);
        }
        if self.pre_active_count() >= PENDING_FLOWS
            || self.queued_bytes + first_packet.len() > PREACTIVE_BYTES
        {
            return Err(Reject::PendingFull);
        }
        let queue = VecDeque::from([first_packet.to_vec()]);
        self.queued_bytes += first_packet.len();
        self.flows.insert(
            flow_id,
            FlowSel {
                flow,
                generation: 1,
                recovering: false,
                retry_at: None,
                deadline: now + FLOW_BUDGET,
                stage: Stage::Pending,
                queue,
                queue_bytes: first_packet.len(),
                skip: HashSet::new(),
            },
        );
        Ok(self.advance(now))
    }

    /// Another IP packet of a waiting flow until the transport is ready.
    pub fn enqueue(&mut self, flow_id: u64, packet: &[u8]) -> Result<(), Reject> {
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return Err(Reject::Duplicate);
        };
        if flow.queue.len() >= PREACTIVE_PACKETS
            || self.queued_bytes + packet.len() > PREACTIVE_BYTES
        {
            return Err(Reject::PendingFull);
        }
        flow.queue_bytes += packet.len();
        self.queued_bytes += packet.len();
        flow.queue.push_back(packet.to_vec());
        Ok(())
    }

    /// `channel_ready` from the server for the running preparation.
    pub fn channel_ready(
        &mut self,
        candidate: Candidate,
        attempt: u64,
        channel_id: u64,
        _now: Instant,
    ) -> Vec<Action> {
        if !self.preparation_is(candidate, attempt) {
            return Vec::new(); // stale event
        }
        self.preparation = None;
        self.channels
            .insert(candidate, ReadyChannel::new(channel_id, false));
        // Channel probes (PROBE_A/AB/B, SIZE) are now on the driver; their
        // outcome arrives via probes_passed / attempt_failed.
        Vec::new()
    }

    /// Our own channel probes passed (round-trip on both sides + sizes).
    pub fn probes_passed(
        &mut self,
        candidate: Candidate,
        channel_id: u64,
        now: Instant,
    ) -> Vec<Action> {
        let Some(channel) = self.channels.get_mut(&candidate) else {
            return Vec::new();
        };
        if channel.id != channel_id {
            return Vec::new();
        }
        channel.self_verified = true;
        self.verified(candidate, now)
    }

    /// `channel_verified` from the peer.
    pub fn peer_verified(
        &mut self,
        candidate: Candidate,
        channel_id: u64,
        now: Instant,
    ) -> Vec<Action> {
        let Some(channel) = self.channels.get_mut(&candidate) else {
            return Vec::new();
        };
        if channel.id != channel_id {
            return Vec::new();
        }
        channel.peer_verified = true;
        self.verified(candidate, now)
    }

    /// Channel verified on both sides: waiting flows go to bind.
    fn verified(&mut self, candidate: Candidate, now: Instant) -> Vec<Action> {
        if self.suspended {
            return Vec::new();
        }
        let Some(channel) = self.channels.get(&candidate) else {
            return Vec::new();
        };
        if !channel.verified() {
            return Vec::new();
        }
        let channel_id = channel.id;
        let mut actions = Vec::new();
        let pending: Vec<u64> = self
            .flows
            .iter()
            .filter(|(_, flow)| {
                matches!(flow.stage, Stage::Pending) && !flow.skip.contains(&candidate)
            })
            .map(|(&id, _)| id)
            .collect();
        for flow_id in pending {
            self.set_binding(flow_id, candidate, now);
            actions.push(Action::OpenFlow {
                flow_id,
                generation: self.flows[&flow_id].generation,
                candidate,
                channel: channel_id,
            });
        }
        actions
    }

    /// Channel preparation failure (handshake/probes/size). Hold-down for
    /// the candidate, last_good erased on a match, move to the next one.
    pub fn attempt_failed(
        &mut self,
        candidate: Candidate,
        attempt: u64,
        reason: Reason,
        now: Instant,
    ) -> Vec<Action> {
        if !self.preparation_is(candidate, attempt) {
            return Vec::new(); // stale event: it does not concern the new attempt
        }
        self.preparation = None;
        self.channels.remove(&candidate);
        self.fail_candidate(candidate, reason, now);
        if self.proactive {
            // Did not come up: banned until the backoff expires.
            self.ban(candidate, reason, now);
            if let Some(stop) = self.exhaust_if_empty() {
                return stop;
            }
        }
        self.advance(now)
    }

    /// Invalidate this channel only. Session selects affected flows by their actual channel ID.
    pub fn channel_lost(
        &mut self,
        candidate: Candidate,
        channel_id: u64,
        reason: Reason,
        now: Instant,
    ) -> Vec<Action> {
        let Some(channel) = self
            .channels
            .get(&candidate)
            .filter(|channel| channel.id == channel_id)
        else {
            return Vec::new();
        };
        let unverified = !channel.verified();
        self.channels.remove(&candidate);
        let mut actions = Vec::new();
        if self.proactive && unverified {
            self.ban(candidate, reason, now);
            if let Some(stop) = self.exhaust_if_empty() {
                actions.extend(stop);
                return actions;
            }
        } else {
            self.fail_candidate(candidate, reason, now);
        }
        actions.extend(self.advance(now));
        actions
    }

    fn fail_candidate(&mut self, candidate: Candidate, reason: Reason, now: Instant) {
        self.hold_down.insert(candidate, now + HOLD_DOWN);
        if self.last_good == Some(candidate) {
            self.last_good = None;
        }
        if matches!(reason, Reason::Unsupported | Reason::EndpointUnavailable) {
            // Exclude the candidate for the rest of the session: it will not "cool down" into anything useful.
            self.allowed.retain(|allowed| *allowed != candidate);
        }
    }

    /// Proactive ban: the candidate did not come up. The ban expires after a
    /// backoff (10 min, doubling to 2 h) so a transient filter is retried.
    fn ban(&mut self, candidate: Candidate, reason: Reason, now: Instant) {
        self.allowed.retain(|allowed| *allowed != candidate);
        self.hold_down.remove(&candidate);
        if !self.banned.iter().any(|&(banned, _)| banned == candidate) {
            self.banned.push((candidate, reason));
        }
        if self.last_good == Some(candidate) {
            self.last_good = None;
        }
        let base = self
            .ban_backoff
            .get(&candidate)
            .copied()
            .unwrap_or_else(ban_backoff_start);
        // With the e2e hook active every re-ban stays pinned to it: the
        // doubling would push ban-expiry recovery past any test budget.
        let next = if ban_backoff_start() < BAN_BACKOFF_START {
            ban_backoff_start()
        } else {
            (base * 2).min(BAN_BACKOFF_CAP)
        };
        self.ban_backoff.insert(candidate, next);
        // Deterministic jitter in ±20%: decorrelates fleet retries without a RNG.
        let pct = (self.ban_seq % 41) as i64 - 20;
        self.ban_seq = self.ban_seq.wrapping_add(1);
        let jittered = base.mul_f64(1.0 + pct as f64 / 100.0);
        self.ban_until.insert(candidate, now + jittered);
    }

    /// Re-ban a candidate from outside the selector's own action flow
    /// (challenge failures re-ban with the doubled backoff).
    pub fn ban_candidate(&mut self, candidate: Candidate, reason: Reason, now: Instant) {
        self.ban(candidate, reason, now);
    }

    /// All candidates banned in proactive-auto: one `Exhausted` with the table.
    fn exhaust_if_empty(&mut self) -> Option<Vec<Action>> {
        if !self.proactive || self.exhausted || !self.allowed.is_empty() || !self.flows.is_empty() {
            return None;
        }
        self.exhausted = true;
        Some(vec![Action::Exhausted {
            reasons: self.banned.clone(),
        }])
    }

    pub fn bind_succeeded(&mut self, flow_id: u64, generation: u64, now: Instant) -> Vec<Action> {
        let Some(flow) = self
            .flows
            .get_mut(&flow_id)
            .filter(|flow| flow.generation == generation)
        else {
            return Vec::new();
        };
        let Stage::Binding { candidate, .. } = flow.stage else {
            return Vec::new();
        };
        flow.stage = Stage::Committing {
            candidate,
            deadline: (now + ATTEMPT_BUDGET).min(flow.deadline),
        };
        vec![Action::Commit {
            flow_id,
            candidate,
            generation,
        }]
    }

    /// Session calls this only while user data has not entered a transport.
    pub fn bind_failed(
        &mut self,
        flow_id: u64,
        generation: u64,
        reason: Reason,
        now: Instant,
    ) -> Vec<Action> {
        if self.proactive
            && self.flows.get(&flow_id).is_some_and(|flow| {
                flow.generation == generation
                    && matches!(
                        flow.stage,
                        Stage::Binding {
                            candidate: Candidate::Tcp,
                            ..
                        }
                    )
            })
        {
            self.ban(Candidate::Tcp, reason, now);
        }
        self.retry(flow_id, generation, false, reason, now)
    }

    pub fn recover(
        &mut self,
        flow_id: u64,
        generation: u64,
        reason: Reason,
        now: Instant,
    ) -> Vec<Action> {
        self.retry(flow_id, generation, true, reason, now)
    }

    fn retry(
        &mut self,
        flow_id: u64,
        generation: u64,
        recovering: bool,
        reason: Reason,
        now: Instant,
    ) -> Vec<Action> {
        let Some(flow) = self
            .flows
            .get_mut(&flow_id)
            .filter(|flow| flow.generation == generation)
        else {
            return Vec::new();
        };
        if matches!(flow.stage, Stage::Pending) {
            return Vec::new();
        }
        if recovering && flow.stage.is_active() {
            flow.deadline = now + RECOVERY_BUDGET;
            flow.skip.clear();
        }
        if now >= flow.deadline {
            return self.fail_flow(flow_id, reason);
        }
        let Some(generation) = generation.checked_add(1) else {
            return self.fail_flow(flow_id, Reason::ResourceExhausted);
        };
        let from = flow.stage.candidate();
        if let Some(candidate) = from {
            flow.skip.insert(candidate);
        }
        flow.generation = generation;
        flow.retry_at = Some(now + ATTEMPT_BUDGET);
        flow.recovering |= recovering;
        flow.stage = Stage::Pending;
        let mut actions = vec![Action::ResetBinding {
            flow_id,
            generation,
            from,
            reason,
        }];
        actions.extend(self.advance(now));
        actions
    }

    pub fn committed(&mut self, flow_id: u64, generation: u64) -> Vec<Action> {
        let Some(flow) = self
            .flows
            .get_mut(&flow_id)
            .filter(|flow| flow.generation == generation)
        else {
            return Vec::new();
        };
        if let Stage::Committing { candidate, .. } = flow.stage {
            flow.stage = Stage::Active { candidate };
            flow.recovering = false;
            self.last_good = Some(candidate);
        }
        Vec::new()
    }

    /// Flow closure on completion (idle/FIN) — no notifications to the candidate.
    pub fn finished(&mut self, flow_id: u64) -> Vec<Action> {
        let Some(flow) = self.flows.remove(&flow_id) else {
            return Vec::new();
        };
        self.queued_bytes -= flow.queue_bytes;
        Vec::new()
    }

    /// Pre-active packet queue of an active flow (after committed).
    /// Test inspection and channel handover only; production drains via
    /// `pop_packet` inside the session's flush loop.
    pub fn take_queue(&mut self, flow_id: u64) -> Option<VecDeque<Vec<u8>>> {
        let flow = self.flows.get_mut(&flow_id)?;
        if !flow.stage.is_active() {
            return None;
        }
        self.queued_bytes -= flow.queue_bytes;
        flow.queue_bytes = 0;
        Some(std::mem::take(&mut flow.queue))
    }

    pub fn tcp_binding(&self, flow_id: u64) -> bool {
        self.flows.get(&flow_id).is_some_and(|flow| {
            matches!(
                flow.stage,
                Stage::Binding {
                    candidate: Candidate::Tcp,
                    ..
                }
            )
        })
    }

    /// Timers: preparation, bind-attempt, commit, and overall budget deadlines.
    pub fn poll(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        if let Some(prep) = self.preparation
            && now >= prep.deadline
        {
            // attempt_failed itself extinguishes the preparation and moves to the next candidate.
            actions.extend(self.attempt_failed(
                prep.candidate,
                prep.attempt,
                Reason::PathTimeout,
                now,
            ));
        }
        let expired_binds: Vec<_> = self
            .flows
            .iter()
            .filter(|(_, flow)| {
                matches!(&flow.stage, Stage::Binding { deadline, .. } | Stage::Committing { deadline, .. } if now >= *deadline)
            })
            .map(|(&id, flow)| (id, flow.generation, flow.recovering))
            .collect();
        for (flow_id, generation, recovering) in expired_binds {
            actions.extend(if recovering {
                self.recover(flow_id, generation, Reason::PathTimeout, now)
            } else {
                self.bind_failed(flow_id, generation, Reason::PathTimeout, now)
            });
        }
        let expired_flows: Vec<u64> = self
            .flows
            .iter()
            // Active lives until the session's idle sweep — the budget applies
            // only to pre-active preparation (see the pre_active comment in admission).
            .filter(|(_, flow)| now >= flow.deadline && !flow.stage.is_active())
            .map(|(&id, _)| id)
            .collect();
        for flow_id in expired_flows {
            actions.extend(self.fail_flow(flow_id, Reason::PathTimeout));
        }
        // Hold-down expired — the entry is removed.
        self.hold_down.retain(|_, until| *until > now);
        // Ban expiry: the candidate joins the next challenger round again.
        let expired: Vec<Candidate> = self
            .ban_until
            .iter()
            .filter(|(_, until)| **until <= now)
            .map(|(&candidate, _)| candidate)
            .collect();
        for candidate in expired {
            self.ban_until.remove(&candidate);
            if !self.allowed.contains(&candidate) {
                self.allowed.push(candidate);
                self.allowed
                    .sort_by_key(|c| COLD_ORDER.iter().position(|o| o == c).unwrap_or(usize::MAX));
            }
            actions.push(Action::BanExpired { candidate });
        }
        actions.extend(self.advance(now));
        if let Some(stop) = self.exhaust_if_empty() {
            actions.extend(stop);
        }
        actions
    }

    fn fail_flow(&mut self, flow_id: u64, reason: Reason) -> Vec<Action> {
        let Some(flow) = self.flows.remove(&flow_id) else {
            return Vec::new();
        };
        self.queued_bytes -= flow.queue_bytes;
        // Attempt resources (sockets/tasks) are closed by session on CloseFlow.
        vec![
            Action::FailFlow {
                flow_id,
                flow: flow.flow,
                reason,
            },
            Action::CloseFlow { flow_id },
        ]
    }

    fn preparation_is(&self, candidate: Candidate, attempt: u64) -> bool {
        self.preparation
            .is_some_and(|prep| prep.candidate == candidate && prep.attempt == attempt)
    }
}
