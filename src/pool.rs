//! Server readiness and retry state, independent of sockets and TUN ownership.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::time::Instant;

use crate::link_io::Epoch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Connecting,
    Ready,
    /// Data path confirmed lost while the control channel stays alive:
    /// excluded from new flows, existing owner flows keep being served.
    Checking,
    Failed,
    Backoff(Instant),
}

struct Slot {
    epoch: Epoch,
    state: State,
    /// A liveness round is in flight: the slot may still reach Ready. Rounds
    /// armed at startup, on retry and on data-path loss; retired by the round
    /// verdict, a session death or a won round.
    round: bool,
    delay: Duration,
    weight: u32,
    current: i128,
    attempt: u32,
    last_reason: String,
}

pub struct Pool {
    slots: Vec<Slot>,
    started: bool,
}

impl Pool {
    pub fn new(weights: impl IntoIterator<Item = u32>) -> Self {
        Self {
            slots: weights
                .into_iter()
                .enumerate()
                .map(|(link, weight)| Slot {
                    epoch: Epoch {
                        link,
                        generation: 1,
                    },
                    state: State::Connecting,
                    round: true,
                    delay: Duration::from_secs(1),
                    weight,
                    current: 0,
                    attempt: 0,
                    last_reason: String::new(),
                })
                .collect(),
            started: false,
        }
    }

    pub fn ready_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state == State::Ready)
            .count()
    }

    pub fn checking_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state == State::Checking)
            .count()
    }

    /// Ready or Checking with a live epoch: a link that keeps serving its
    /// existing owner flows.
    pub fn is_serving(&self, epoch: Epoch) -> bool {
        self.slots
            .get(epoch.link)
            .is_some_and(|s| s.epoch == epoch && matches!(s.state, State::Ready | State::Checking))
    }

    pub fn is_checking(&self, epoch: Epoch) -> bool {
        self.slots
            .get(epoch.link)
            .is_some_and(|s| s.epoch == epoch && s.state == State::Checking)
    }

    pub fn is_ready(&self, epoch: Epoch) -> bool {
        self.slots
            .get(epoch.link)
            .is_some_and(|s| s.epoch == epoch && s.state == State::Ready)
    }

    pub fn ready(&mut self, epoch: Epoch, now: Instant) -> bool {
        let Some(slot) = self
            .slots
            .get_mut(epoch.link)
            .filter(|s| s.epoch == epoch && matches!(s.state, State::Connecting | State::Checking))
        else {
            return false;
        };
        slot.state = State::Ready;
        slot.round = false;
        slot.delay = Duration::from_secs(1);
        self.started = true;
        for slot in &mut self.slots {
            if slot.state == State::Failed {
                slot.backoff(now);
            }
        }
        true
    }

    /// Mark an in-flight round; return true only for Ready → Checking.
    pub fn checking(&mut self, epoch: Epoch) -> bool {
        let Some(slot) = self.slots.get_mut(epoch.link).filter(|s| {
            s.epoch == epoch
                && matches!(s.state, State::Connecting | State::Ready | State::Checking)
        }) else {
            return false;
        };
        let changed = slot.state == State::Ready;
        if changed {
            slot.state = State::Checking;
        }
        slot.round = true;
        changed
    }

    /// A checking round finished with no winner (the session itself stays
    /// alive and will retry after backoff). The VPN stops only when no slot
    /// can still produce a Ready: none is Ready, Connecting or mid-round.
    pub fn round_failed(&mut self, epoch: Epoch) -> Result<bool> {
        let Some(slot) = self.slots.get_mut(epoch.link).filter(|s| {
            s.epoch == epoch && s.round && matches!(s.state, State::Connecting | State::Checking)
        }) else {
            return Ok(false);
        };
        slot.round = false;
        self.ensure_hope()?;
        Ok(true)
    }

    pub fn failed(&mut self, epoch: Epoch, now: Instant, reason: &str) -> Result<bool> {
        let Some(slot) = self.slots.get_mut(epoch.link).filter(|s| {
            s.epoch == epoch
                && matches!(s.state, State::Connecting | State::Ready | State::Checking)
        }) else {
            return Ok(false);
        };
        slot.state = State::Failed;
        slot.round = false;
        slot.current = 0;
        slot.attempt += 1;
        slot.last_reason = reason.to_string();
        if self.started {
            slot.backoff(now);
        }
        self.ensure_hope()?;
        Ok(true)
    }

    pub fn retry_at(&self, link: usize) -> Option<Instant> {
        match self.slots[link].state {
            State::Backoff(at) => Some(at),
            _ => None,
        }
    }

    pub fn retry_attempt(&self, link: usize) -> u32 {
        self.slots[link].attempt
    }

    pub fn last_reason(&self, link: usize) -> &str {
        &self.slots[link].last_reason
    }

    pub fn next_retry(&self) -> Option<Instant> {
        (0..self.slots.len())
            .filter_map(|link| self.retry_at(link))
            .min()
    }

    pub fn retry_due(&mut self, now: Instant) -> Result<Vec<Epoch>> {
        let mut retries = Vec::new();
        for slot in &mut self.slots {
            if matches!(slot.state, State::Backoff(at) if at <= now) {
                slot.epoch.generation = slot
                    .epoch
                    .generation
                    .checked_add(1)
                    .context("server generation space exhausted")?;
                slot.state = State::Connecting;
                slot.round = true;
                retries.push(slot.epoch);
            }
        }
        Ok(retries)
    }

    pub fn pick(&mut self) -> Option<Epoch> {
        // u32 weights summed across a usize-indexed vector fit comfortably in i128.
        let mut total = 0i128;
        let mut best = None;
        let mut maximum = i128::MIN;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.state != State::Ready {
                continue;
            }
            let weight = i128::from(slot.weight);
            total += weight;
            slot.current += weight;
            if slot.current > maximum {
                maximum = slot.current;
                best = Some(index);
            }
        }
        let slot = &mut self.slots[best?];
        slot.current -= total;
        Some(slot.epoch)
    }

    /// Any slot that may still reach (or keep) Ready.
    fn hope(&self) -> bool {
        self.slots.iter().any(|s| {
            s.state == State::Ready
                || (s.round && matches!(s.state, State::Connecting | State::Checking))
        })
    }

    fn ensure_hope(&self) -> Result<()> {
        if self.hope() {
            return Ok(());
        }
        if self.started {
            bail!("vpn: no server available, stopping");
        }
        bail!("vpn: no server available");
    }
}

impl Slot {
    fn backoff(&mut self, now: Instant) {
        self.state = State::Backoff(now + self.delay);
        self.delay = (self.delay * 2).min(Duration::from_secs(60));
    }
}
