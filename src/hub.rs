//! One client TUN, isolated server tasks and generation-tagged flow ownership.
//!
//! Layout: `routes` holds the flow ownership table (`Owner`, `Routes`), this
//! file the hub itself — link tasks, the select loop, TUN reads and writes.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    task::Poll,
    time::{Duration, Instant as StdInstant},
};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::Instant,
};
use tun_rs::AsyncDevice;

use crate::{
    control::Stats,
    hooks::Hooks,
    link_io::{Delivery, Epoch, Event, LinkIo, Packet},
    local_proxy::{self, LocalServer},
    packet::{self, FlowKey},
    pool::Pool,
    server_spec::LinkParams,
    session, stats,
};

pub mod jobs;
mod routes;

pub use jobs::{JobContext, JobEvent, JobStats};

pub use routes::{Owner, RoutedFlow, Routes, Target, Traffic};

// Burst absorber for link/hub queues: holds Packet slot structs, payload memory scales
// with resident packets only. 1024 absorbs CPU/Wi-Fi jitter without unbounded growth.
pub const QUEUE: usize = 1024;

/// How often the dashboard snapshot is refreshed, in seconds.
pub const SNAPSHOT_INTERVAL: u32 = 1;

/// Packets one drain round may flush to the TUN: one busy flow must not
/// starve the select loop between rounds.
pub const TUN_BATCH: usize = 32;

/// Deadline one TUN flush batch shares; was a fresh timeout per packet.
const TUN_WRITE_TIMEOUT: Duration = Duration::from_millis(100);

/// One TUN flush batch: per-link delivery counters paired with each packet.
type TunBatch = Vec<(Arc<Delivery>, Packet)>;

pub struct Link {
    pub params: LinkParams,
    pub outgoing: Option<mpsc::Sender<Packet>>,
    pub delivery: Arc<Delivery>,
    pub epoch: Option<Epoch>,
    pub latest: Option<watch::Receiver<Stats>>,
    pub stats: stats::Snapshot,
    pub last_reason: String,
    /// Tunnel pair assigned by the server during the current attempt (#181).
    pub assigned: Arc<std::sync::OnceLock<(Ipv4Addr, Ipv4Addr)>>,
}

/// Sticky exit counters, surfaced in the periodic stats report.
#[derive(Default, Clone, Serialize)]
pub struct StickyStats {
    pub lookup_hit: u64,
    pub lookup_miss: u64,
    pub failover_moves: u64,
    pub asn_hit: u64,
    pub asn_miss: u64,
    /// Explicit sticky blocks: matches, resolver outcomes.
    pub block_hit: u64,
    pub resolve_ok: u64,
    pub resolve_fail: u64,
    pub resolved_ips: u64,
    pub purged_ips: u64,
}

impl StickyStats {
    fn lookup(&mut self, hit: bool) {
        if hit {
            self.lookup_hit += 1;
            self.asn_hit += 1;
        } else {
            self.lookup_miss += 1;
            self.asn_miss += 1;
        }
    }
}

#[derive(Default)]
pub struct LocalStats {
    pub opened: u64,
    pub failed: u64,
    pub closed: u64,
}

pub struct LocalExitState {
    pub outgoing: mpsc::Sender<Packet>,
    pub events: Option<mpsc::Receiver<(Epoch, Event)>>,
    pub latest: watch::Receiver<Stats>,
    pub delivery: Arc<Delivery>,
    pub server: LocalServer,
    pub ready: bool,
}

/// Late-bound run inputs: sticky blocks and the job context.
#[derive(Default)]
pub struct Extras {
    pub sticky_blocks: Vec<crate::sticky::StickyBlock>,
    pub jobs: JobContext,
    /// Read-only dashboard address; None keeps the dashboard off.
    pub web_listen: Option<SocketAddr>,
}

/// First-match decision for one destination.
enum Route {
    Local(usize),
    Sticky(usize),
    Auto,
}

pub struct Hub {
    pub links: Vec<Link>,
    pub pool: Pool,
    /// Sticky exit: ASN grouping under exit-policy sticky-asn;
    /// None = weighted balance.
    pub geo: Option<crate::geo::Geo>,
    /// Country table for countries selectors; None — no country data.
    pub country: Option<crate::geo::Geo>,
    /// Explicit sticky blocks, in config order (first match wins).
    pub stickies: Vec<crate::sticky::RuntimeSticky>,
    /// `via` resolved to link indices at startup.
    pub sticky_via: Vec<crate::sticky::ResolvedVia>,
    /// Resolver deliveries; None when no name selectors exist.
    pub sticky_updates: Option<mpsc::Receiver<crate::sticky::Update>>,
    /// Episodic name resolver; aborted when the hub goes away.
    pub sticky_task: Option<tokio::task::JoinHandle<()>>,
    /// Job completions; None when no jobs are configured.
    pub job_events: Option<mpsc::Receiver<JobEvent>>,
    /// Job scheduler; aborted when the hub goes away.
    pub job_task: Option<tokio::task::JoinHandle<()>>,
    /// Job counters for the stats report.
    pub job_stats: JobStats,
    /// Reload sources for the geo/country tables.
    pub geo_path: Option<std::path::PathBuf>,
    pub country_path: Option<std::path::PathBuf>,
    /// A provider job exists but the table is not on disk yet.
    pub geo_pending: Option<String>,
    pub country_pending: Option<String>,
    /// Local serve and client session, started with the live primary TUN.
    pub local: Option<LocalExitState>,
    pub local_cleanup: Option<LocalServer>,
    /// Stable node ids (configured `server` strings) and weights, for rendezvous.
    pub nodes: Vec<(String, u32)>,
    /// Fallback strategy for traffic matched by no sticky block.
    pub policy: crate::cli::ExitPolicy,
    pub sticky_asn_mode: crate::cli::StickyAsnMode,
    /// Hashed ASN and explicit block owners, retained until restart, without snap-back.
    pub exit_owners: crate::exit_state::StickyOwners,
    /// Sticky exit counters, surfaced in the periodic stats report.
    pub sticky: StickyStats,
    pub local_stats: LocalStats,
    pub tasks: JoinSet<(Epoch, Result<()>)>,
    pub events: mpsc::Sender<(Epoch, Event)>,
    pub incoming: mpsc::Receiver<(Epoch, Event)>,
    pub routes: Routes,
    /// Destination tuples of flows retired with a lost link; answered as a
    /// CLOSED endpoint so client sockets fail fast instead of hanging.
    pub tombstones: session::Tombstones,
    /// Shared tunnel pair (client, server) pinned by the first Ready link
    /// (#181): later links and reconnects must negotiate the same pair.
    pub pair: watch::Sender<Option<(Ipv4Addr, Ipv4Addr)>>,
}

impl Hub {
    /// Return a CLOSED-endpoint reset for unowned TCP traffic.
    /// Check the current owner and retired flows before classifying a new
    /// flow; local-exit countries are considered before VPN ownership.
    pub fn dispatch(&mut self, bytes: &[u8], client_ip: Ipv4Addr) -> Result<Option<[u8; 40]>> {
        let parsed = match packet::parse(bytes, true) {
            Some(parsed) if parsed.flow.valid_for(client_ip) => parsed,
            Some(_) => {
                drop_note(
                    &self.links[0].delivery,
                    &self.links,
                    None,
                    "foreign source in client TUN packet",
                );
                return Ok(None);
            }
            None => {
                drop_note(
                    &self.links[0].delivery,
                    &self.links,
                    None,
                    "unparseable packet from client TUN",
                );
                return Ok(None);
            }
        };
        let now = StdInstant::now();
        if self.tombstones.active(&parsed.flow, now) {
            return Ok(self.tombstones.respond(&parsed.flow, &parsed, now));
        }
        match self.routes.target(&parsed.flow) {
            Some(Target::Direct(id)) => self.forward_local(*id, bytes),
            Some(Target::Remote(owner)) if self.pool.is_serving(owner.epoch) => {
                let link = &self.links[owner.epoch.link];
                let Some(outgoing) = &link.outgoing else {
                    return Ok(None);
                };
                let delivery = link.delivery.clone();
                if self.routes.enqueue(
                    bytes,
                    client_ip,
                    owner.epoch,
                    // Existing flow: the fresh-insert path is unreachable here.
                    None,
                    outgoing,
                    &delivery,
                    &self.links,
                )? {
                    self.routes.record(parsed.flow, bytes.len(), 0);
                }
                Ok(None)
            }
            // A non-serving owner still owns the flow: no reset, no reassign.
            Some(Target::Remote(_)) => Ok(None),
            None if parsed.can_open => self.open_flow(&parsed, bytes, client_ip),
            None => Ok(packet::tcp_reset_for(&parsed)),
        }
    }

    /// Where one destination goes: the first matching sticky block decides;
    /// a miss falls back to the automatic strategy.
    fn route(&mut self, destination: Ipv4Addr) -> Route {
        for (index, block) in self.stickies.iter().enumerate() {
            if block.matches(destination, self.country.as_ref(), self.geo.as_ref()) {
                self.sticky.block_hit += 1;
                return match &self.sticky_via[index] {
                    crate::sticky::ResolvedVia::Local => Route::Local(index),
                    crate::sticky::ResolvedVia::Links(_) => Route::Sticky(index),
                };
            }
        }
        Route::Auto
    }

    /// Sticky-block traffic never falls back; other traffic picks a remote
    /// owner through the automatic strategy.
    fn open_flow(
        &mut self,
        parsed: &packet::Packet,
        bytes: &[u8],
        client_ip: Ipv4Addr,
    ) -> Result<Option<[u8; 40]>> {
        let key = parsed.flow;
        let (rule, picked, group) = match self.route(key.destination) {
            Route::Local(index) => return self.open_local(parsed, bytes, index),
            Route::Sticky(index) => {
                let (epoch, group) = self.pick_sticky(index);
                (Some(index), epoch, group)
            }
            Route::Auto => {
                let (epoch, group) = self.pick(&key);
                (None, epoch, group)
            }
        };
        let Some(epoch) = picked else {
            return Ok(None);
        };
        let link = &self.links[epoch.link];
        let Some(outgoing) = &link.outgoing else {
            return Ok(None);
        };
        let delivery = link.delivery.clone();
        if self.routes.enqueue(
            bytes,
            client_ip,
            epoch,
            group,
            outgoing,
            &delivery,
            &self.links,
        )? {
            if let Some(flow) = self.routes.by_key.get_mut(&key) {
                flow.rule = rule;
            }
            self.routes.record(key, bytes.len(), 0);
        }
        Ok(None)
    }

    /// Owner of one sticky group: rendezvous inside `via`, no snap-back,
    /// RAM-only binding until restart under the canonical selector key.
    fn pick_sticky(&mut self, index: usize) -> (Option<Epoch>, Option<u64>) {
        let canonical = self.stickies[index].block.canonical_key();
        let group = crate::sticky::group_key(&canonical);
        let links: Vec<usize> = match &self.sticky_via[index] {
            crate::sticky::ResolvedVia::Links(links) => links.clone(),
            crate::sticky::ResolvedVia::Local => unreachable!("route() separated local blocks"),
        };
        (self.sticky_epoch(group, Some(&links)), Some(group))
    }

    fn open_local(
        &mut self,
        parsed: &packet::Packet,
        bytes: &[u8],
        rule: usize,
    ) -> Result<Option<[u8; 40]>> {
        let key = parsed.flow;
        let Some(local) = &self.local else {
            self.local_stats.failed += 1;
            return Ok(None);
        };
        if !local.ready {
            self.local_stats.failed += 1;
            return Ok(None);
        }
        let outgoing = local.outgoing.clone();
        let delivery = local.delivery.clone();
        let id = self.routes.allocate()?;
        match outgoing.try_send(Packet {
            id,
            bytes: bytes.to_vec(),
        }) {
            Ok(()) => {
                self.local_stats.opened += 1;
                self.routes
                    .insert(key, Target::Direct(id), Some(rule), None);
                self.routes.record(key, bytes.len(), 0);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                delivery.dropped();
                self.local_stats.failed += 1;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.local_stats.failed += 1;
            }
        }
        Ok(None)
    }

    fn forward_local(&mut self, id: u64, bytes: &[u8]) -> Result<Option<[u8; 40]>> {
        let key = packet::parse(bytes, true).map(|packet| packet.flow);
        let Some(local) = &self.local else {
            return Ok(None);
        };
        let outgoing = local.outgoing.clone();
        let delivery = local.delivery.clone();
        match outgoing.try_send(Packet {
            id,
            bytes: bytes.to_vec(),
        }) {
            Ok(()) => {
                if let Some(key) = key {
                    self.routes.record(key, bytes.len(), 0);
                }
            }
            Err(mpsc::error::TrySendError::Full(_)) => delivery.dropped(),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                if let Some(key) = key {
                    self.close_local(id, key, true);
                }
            }
        }
        Ok(None)
    }

    pub async fn handle_local_event(
        &mut self,
        mut event: (Epoch, Event),
        tun: &mut Option<AsyncDevice>,
    ) -> Result<()> {
        loop {
            match event.1 {
                Event::Ready => {
                    if let Some(local) = &mut self.local {
                        local.ready = true;
                        crate::info!("local-exit: ready");
                    }
                }
                Event::Checking | Event::RoundFailed => {
                    if let Some(local) = &mut self.local {
                        local.ready = false;
                    }
                }
                Event::Packet(packet) => {
                    let Some(delivery) = self.local.as_ref().map(|local| local.delivery.clone())
                    else {
                        return Ok(());
                    };
                    if !self.local_current(&packet) {
                        return Ok(());
                    }
                    let tun = tun
                        .as_ref()
                        .context("local-exit packet without client TUN")?;
                    // Same one-deadline flush as link packets: the packets
                    // already queued behind this one share its timer.
                    let (batch, deferred) = self.local_batch(delivery, packet);
                    self.flush_tun_batch(tun, &batch).await?;
                    match deferred {
                        Some(next) => {
                            event = next;
                            continue;
                        }
                        None => return Ok(()),
                    }
                }
                Event::Closing { .. } => {
                    // The local proxy never reports both-FIN closing (no FIN tracking);
                    // only the remote flow owner marks a RoutedFlow closing.
                }
                Event::Closed { id, key } => {
                    self.close_local(id, key, false);
                }
            }
            return Ok(());
        }
    }

    /// A local-exit packet is current while its flow still targets the proxy
    /// session that sent it.
    fn local_current(&self, packet: &Packet) -> bool {
        packet::parse(&packet.bytes, false).is_some_and(|parsed| {
            matches!(self.routes.target(&parsed.flow), Some(Target::Direct(id)) if *id == packet.id)
        })
    }

    /// Gathers the local-exit packets queued behind `first`: at most
    /// `TUN_BATCH`, only current ones, queue order kept. A queued non-packet
    /// event stops the batch and is returned for handling after the flush,
    /// so event order stays strict.
    pub fn local_batch(
        &mut self,
        delivery: Arc<Delivery>,
        first: Packet,
    ) -> (TunBatch, Option<(Epoch, Event)>) {
        let mut batch = Vec::with_capacity(TUN_BATCH);
        batch.push((delivery, first));
        while batch.len() < TUN_BATCH {
            let next = self
                .local
                .as_mut()
                .and_then(|local| local.events.as_mut()?.try_recv().ok());
            match next {
                Some((_, Event::Packet(packet))) => {
                    if self.local_current(&packet)
                        && let Some(delivery) =
                            self.local.as_ref().map(|local| local.delivery.clone())
                    {
                        batch.push((delivery, packet));
                    }
                }
                Some(next) => return (batch, Some(next)),
                None => return (batch, None),
            }
        }
        (batch, None)
    }

    fn close_local(&mut self, id: u64, key: FlowKey, failed: bool) {
        if self.routes.forget_direct(key, id) {
            self.local_stats.closed += 1;
            if failed {
                self.local_stats.failed += 1;
            }
            if key.protocol == 6 {
                self.tombstones.insert(key, StdInstant::now());
            }
        }
    }

    async fn local_stopped(&mut self, reason: String, tun: &mut Option<AsyncDevice>) -> Result<()> {
        crate::error!("local-exit: {reason}");
        self.local_stats.failed += 1;
        if let Some(local) = &mut self.local {
            local.ready = false;
        }
        // Deliver terminal packets before dropping the local event channel.
        loop {
            let event = self
                .local
                .as_mut()
                .and_then(|local| local.events.as_mut()?.try_recv().ok());
            let Some(event) = event else { break };
            if let Err(error) = self.handle_local_event(event, tun).await {
                crate::warn!("local-exit: terminal event failed — {error:#}");
                break;
            }
        }
        let Some(local) = self.local.take() else {
            return Err(anyhow::anyhow!(reason));
        };
        drop(local.outgoing);
        self.local_cleanup = Some(local.server);
        let mut retired = Vec::new();
        self.routes.by_key.retain(|key, flow| {
            if matches!(flow.target, Target::Direct(_)) {
                retired.push(*key);
                false
            } else {
                true
            }
        });
        for key in retired {
            self.local_stats.closed += 1;
            if key.protocol == 6 {
                self.tombstones.insert(key, StdInstant::now());
            }
        }
        Err(anyhow::anyhow!(reason))
    }

    pub fn stats_report(&mut self, elapsed: Duration) -> String {
        let mut delta = Stats::default();
        let mut total = Stats::default();
        let mut per_link = Vec::with_capacity(self.links.len());
        for (index, link) in self.links.iter_mut().enumerate() {
            if let Some(latest) = &link.latest {
                link.stats.observe(latest.borrow().clone());
            }
            let (change, sum) = link.stats.sample();
            stats::add(&mut delta, &change);
            stats::add(&mut total, &sum);
            let state = link_state(&self.pool, link, index);
            let active = link
                .latest
                .as_ref()
                .and_then(|rx| rx.borrow().active_candidate.clone());
            let label = match active {
                Some(candidate) => format!("[{} ({candidate})] {state}", link.params.server),
                None => format!("[{}] {state}", link.params.server),
            };
            per_link.push(stats::format(&label, &change, &sum, elapsed));
        }
        let mut report = format!(
            "stats: last {:.1} s | servers ready {}/{} | RX download / TX upload (inner IP)",
            elapsed.as_secs_f64(),
            self.pool.ready_count(),
            self.links.len()
        );
        if self.links.len() > 1 {
            report.push('\n');
            report.push_str(&stats::format("all servers", &delta, &total, elapsed));
        }
        if self.geo.is_some() {
            report.push_str(&format!(
                "\nsticky: lookup hit {} / miss {} | failover moves {}",
                self.sticky.lookup_hit, self.sticky.lookup_miss, self.sticky.failover_moves
            ));
        }
        if self.job_task.is_some() || self.job_stats.runs > 0 {
            report.push_str(&format!(
                "\njobs: runs {} / failures {} / timeouts {}",
                self.job_stats.runs, self.job_stats.failures, self.job_stats.timeouts
            ));
        }
        if let Some(label) = &self.geo_pending {
            report.push_str(&format!("\ngeo: missing (job {label})"));
        }
        if let Some(label) = &self.country_pending {
            report.push_str(&format!("\ncountry: missing (job {label})"));
        }
        if self
            .stickies
            .iter()
            .any(|s| matches!(s.block.via, crate::sticky::Via::Local))
        {
            report.push_str(&format!(
                "\nlocal-exit: opened {} / failed {} / closed {}",
                self.local_stats.opened, self.local_stats.failed, self.local_stats.closed
            ));
        }
        if !self.stickies.is_empty() {
            report.push_str(&format!(
                "\nsticky: blocks matched {} | resolve ok {} / fail {} | ips {} (purged {})",
                self.sticky.block_hit,
                self.sticky.resolve_ok,
                self.sticky.resolve_fail,
                self.sticky.resolved_ips,
                self.sticky.purged_ips
            ));
        }
        for line in per_link {
            report.push('\n');
            report.push_str(&line);
        }
        report
    }

    /// One server event, shared by the live select loop and the failure-path
    /// drain: queued resets of a dying link must pass while owners are live.
    pub async fn handle_event(
        &mut self,
        mut epoch: Epoch,
        mut event: Event,
        tun: &mut Option<AsyncDevice>,
        params: &LinkParams,
        started: &mut Option<oneshot::Sender<()>>,
        hooks: &mut Hooks,
    ) -> Result<()> {
        loop {
            match event {
                Event::Ready => {
                    let now = Instant::now();
                    if !self.pool.ready(epoch, now) {
                        return Ok(());
                    }
                    // The first Ready pins the shared tunnel pair (#181); a link
                    // that negotiated another pair is retired — dropping its
                    // channel ends the session, and the retry insists on the pin.
                    let pair = self.links[epoch.link]
                        .assigned
                        .get()
                        .copied()
                        .unwrap_or((params.tun_addr, params.peer_addr));
                    // Bind the borrow to a temporary first: `match *self.pair.borrow()`
                    // keeps the read guard alive into the match arms, and the None
                    // arm's send_replace self-deadlocks on the write lock.
                    let pinned = *self.pair.borrow();
                    let (tun_addr, peer_addr) = match pinned {
                        None => {
                            self.pair.send_replace(Some(pair));
                            pair
                        }
                        Some(pinned) if pinned == pair => pinned,
                        Some(_) => {
                            self.links[epoch.link].outgoing = None;
                            return Ok(());
                        }
                    };
                    if tun.is_none() {
                        *tun = Some(crate::create_tun(
                            tun_addr,
                            peer_addr,
                            params.mtu,
                            params.tun_name.as_deref(),
                            true,
                        )?);
                        let name = tun
                            .as_ref()
                            .context("missing configured client TUN")?
                            .name()?;
                        self.start_local(&name, params).await?;
                        hooks.start(name, tun_addr, peer_addr)?;
                        if !hooks.starting() {
                            self.announce_started(params, started);
                        }
                    }
                    self.serving();
                }
                Event::Checking => {
                    if self.pool.checking(epoch) {
                        crate::info!(
                            "ssh[{}]: data path lost, control alive — checking",
                            self.links[epoch.link].params.server
                        );
                        self.serving();
                    }
                }
                Event::RoundFailed => {
                    if self.pool.round_failed(epoch)? {
                        crate::info!(
                            "ssh[{}]: checking round failed, retry after backoff",
                            self.links[epoch.link].params.server
                        );
                    }
                }
                Event::Packet(packet) => {
                    if hooks.starting() {
                        return Ok(());
                    }
                    let delivery = self.links[epoch.link].delivery.clone();
                    if !self.pool.is_serving(epoch) {
                        drop_note(&delivery, &self.links, Some(epoch.link), "link not serving");
                        return Ok(());
                    }
                    if !self.routes.accepts(epoch, &packet) {
                        drop_note(
                            &delivery,
                            &self.links,
                            Some(epoch.link),
                            "no owner for packet from link",
                        );
                        return Ok(());
                    }
                    let tun = tun.as_ref().context("ready server without client TUN")?;
                    // Flush the packets already queued behind this one under a
                    // single deadline: one timer per batch, not one per packet.
                    let (batch, deferred) = self.tun_batch((delivery, packet));
                    self.flush_tun_batch(tun, &batch).await?;
                    match deferred {
                        Some((next_epoch, next_event)) => {
                            epoch = next_epoch;
                            event = next_event;
                            continue;
                        }
                        None => return Ok(()),
                    }
                }
                Event::Closing { id, key } => self.routes.mark_closing(key, Owner { epoch, id }),
                Event::Closed { id, key } => self.routes.forget(key, Owner { epoch, id }),
            }
            return Ok(());
        }
    }

    /// Gathers the packets queued behind `first` for one TUN flush: at most
    /// `TUN_BATCH`, every one validated exactly like a lone packet, queue
    /// order kept. A queued non-packet event stops the batch and is returned
    /// for handling after the flush, so event order stays strict.
    pub fn tun_batch(
        &mut self,
        first: (Arc<Delivery>, Packet),
    ) -> (TunBatch, Option<(Epoch, Event)>) {
        let mut batch = Vec::with_capacity(TUN_BATCH);
        batch.push(first);
        while batch.len() < TUN_BATCH {
            match self.incoming.try_recv() {
                Ok((epoch, Event::Packet(packet))) => {
                    let delivery = self.links[epoch.link].delivery.clone();
                    if !self.pool.is_serving(epoch) {
                        drop_note(&delivery, &self.links, Some(epoch.link), "link not serving");
                        continue;
                    }
                    if !self.routes.accepts(epoch, &packet) {
                        drop_note(
                            &delivery,
                            &self.links,
                            Some(epoch.link),
                            "no owner for packet from link",
                        );
                        continue;
                    }
                    batch.push((delivery, packet));
                }
                Ok((epoch, event)) => return (batch, Some((epoch, event))),
                Err(_) => return (batch, None),
            }
        }
        (batch, None)
    }

    /// Writes a drained batch to the TUN under one deadline: the TUN is a
    /// packet device, so every packet keeps its own write, but the whole
    /// batch shares a single timer instead of one timeout per packet. Once
    /// the deadline hits, the remaining packets drop exactly like individual
    /// write timeouts.
    async fn flush_tun_batch(&mut self, tun: &AsyncDevice, batch: &TunBatch) -> Result<()> {
        let sleep = tokio::time::sleep_until(Instant::now() + TUN_WRITE_TIMEOUT);
        tokio::pin!(sleep);
        for (delivery, packet) in batch {
            let result = std::future::poll_fn(|cx| match sleep.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(None),
                Poll::Pending => tun.poll_send(cx, &packet.bytes).map(Some),
            })
            .await;
            if finish_write(delivery, packet.bytes.len(), result)?
                && let Some(parsed) = packet::parse(&packet.bytes, false)
            {
                self.routes.record(parsed.flow, 0, packet.bytes.len());
            }
        }
        Ok(())
    }

    fn start(&mut self, epoch: Epoch) {
        let params = self.links[epoch.link].params.clone();
        // Same rendering as the retry line: the host names the pool link.
        let tag = if self.links.len() > 1 {
            format!("[{}]", params.server)
        } else {
            String::new()
        };
        let link = &mut self.links[epoch.link];
        link.epoch = Some(epoch);
        link.stats.reset();
        let assigned = Arc::new(std::sync::OnceLock::new());
        link.assigned = assigned.clone();
        // Insist on the pinned shared pair when one exists (#181).
        let desired = (*self.pair.borrow()).map(|(client, server)| (server, client));
        let (stats, latest) = watch::channel(Stats::default());
        link.latest = Some(latest);
        let (outgoing, packets) = mpsc::channel(QUEUE);
        link.outgoing = Some(outgoing);
        link.delivery = Arc::default();
        let mut io = LinkIo {
            epoch,
            packets,
            events: self.events.clone(),
            stats,
            delivery: link.delivery.clone(),
            peer_ip: params.peer_addr,
            tag,
        };
        self.tasks.spawn(async move {
            let attempt = async {
                let (control, tail, config, server_ip, addrs) =
                    crate::open_link(&params, &io.tag, desired).await?;
                let _ = assigned.set((addrs.client_ip, addrs.server_ip));
                io.peer_ip = addrs.server_ip;
                let result =
                    session::run_link(control, server_ip, addrs.client_ip, params.mtu, config, io)
                        .await;
                drop(addrs); // hold the local pair claim for the whole session
                tail.close().await;
                result
            };
            (epoch, attempt.await)
        });
    }

    pub fn pick(&mut self, key: &FlowKey) -> (Option<Epoch>, Option<u64>) {
        if self.policy != crate::cli::ExitPolicy::StickyAsn {
            return (self.pool.pick(), None);
        }
        let Some(geo) = &self.geo else {
            return (self.pool.pick(), None);
        };
        let Some(asn) = geo.lookup(key.destination) else {
            // Uncovered /32 uses stateless rendezvous without ownership.
            self.sticky.lookup(false);
            return (
                crate::geo::rendezvous(crate::geo::ip_key(key.destination), &self.nodes)
                    .into_iter()
                    .find_map(|link| self.pool.ready_epoch(link)),
                None,
            );
        };
        let group = crate::geo::asn_key(asn);
        let epoch = match self.sticky_asn_mode {
            crate::cli::StickyAsnMode::Balanced => self.balanced_epoch(group),
            crate::cli::StickyAsnMode::Hashed => self.sticky_epoch(group, None),
        };
        (epoch, Some(group))
    }

    /// Derive placement from live flows only, once per new flow (not per packet).
    fn balanced_epoch(&mut self, group: u64) -> Option<Epoch> {
        if let Some(epoch) = self.routes.asn_owner(group) {
            self.sticky.lookup(true);
            return self
                .pool
                .ready_epoch(epoch.link)
                .filter(|&ready| ready == epoch);
        }
        self.sticky.lookup(false);
        let mut counts = vec![0_u128; self.nodes.len()];
        for epoch in self.routes.asn_owners().values() {
            counts[epoch.link] += 1;
        }
        // Rendezvous order breaks equal scores; integer cross-products avoid rounding.
        crate::geo::rendezvous(group, &self.nodes)
            .into_iter()
            .filter_map(|link| self.pool.ready_epoch(link))
            .min_by(|a, b| {
                (counts[a.link] * u128::from(self.nodes[b.link].1))
                    .cmp(&(counts[b.link] * u128::from(self.nodes[a.link].1)))
            })
    }

    /// Select a hashed sticky owner without snap-back. None means all links.
    fn sticky_epoch(&mut self, group: u64, candidates: Option<&[usize]>) -> Option<Epoch> {
        let serves = |link: usize| candidates.is_none_or(|set| set.contains(&link));
        // Do not split a live group, even between failure notification and flow retirement.
        if let Some(epoch) = self.routes.group_owner(group) {
            self.sticky.lookup(true);
            return self
                .pool
                .ready_epoch(epoch.link)
                .filter(|&ready| ready == epoch && serves(epoch.link));
        }
        if let Some(owner) = self
            .exit_owners
            .link_of(group)
            .filter(|&owner| serves(owner))
        {
            if let Some(epoch) = self.pool.ready_epoch(owner) {
                self.sticky.lookup(true);
                return Some(epoch);
            }
            if self.pool.link_checking(owner) {
                self.sticky.lookup(true);
                return None;
            }
        }
        self.sticky.lookup(false);
        let previous = self.exit_owners.link_of(group);
        let order: Vec<usize> = crate::geo::rendezvous(group, &self.nodes)
            .into_iter()
            .filter(|&link| serves(link))
            .collect();
        let next = order
            .iter()
            .find_map(|&link| self.pool.ready_epoch(link).map(|epoch| (link, epoch)));
        let (link, epoch) = next?;
        if previous != Some(link) {
            if previous.is_some() {
                self.sticky.failover_moves += 1;
            }
            self.exit_owners.assign(group, link);
        }
        Some(epoch)
    }

    /// Fold one resolver delivery into the block cache and the counters.
    fn apply_sticky_update(&mut self, update: crate::sticky::Update) {
        if update.ok {
            self.sticky.resolve_ok += 1;
            self.sticky.resolved_ips = update.ips.len() as u64;
            self.sticky.purged_ips += update.purged as u64;
            if let Some(block) = self.stickies.get_mut(update.index) {
                block.resolved = update.ips;
            }
        } else {
            self.sticky.resolve_fail += 1;
            crate::warn!("sticky: name resolution failed — keeping the previous IP set");
        }
    }

    async fn start_local(&mut self, primary_tun: &str, params: &LinkParams) -> Result<()> {
        let wants_local = self
            .stickies
            .iter()
            .any(|s| matches!(s.block.via, crate::sticky::Via::Local));
        if !wants_local || self.local.is_some() {
            return Ok(());
        }
        let epoch = Epoch {
            link: usize::MAX,
            generation: 1,
        };
        // Proxy-режим: без второго TUN и хуков, пакеты идут в userspace-стек
        // и наружу через WAN-сокеты. Адреса не транслируются.
        match local_proxy::start(epoch, primary_tun, params.mtu).await {
            Ok(proxy) => {
                self.local = Some(LocalExitState {
                    outgoing: proxy.outgoing,
                    events: Some(proxy.events),
                    latest: proxy.latest,
                    delivery: proxy.delivery,
                    server: proxy.server,
                    ready: false,
                });
            }
            Err(error) => {
                crate::warn!("local-proxy: {error:#} — local exit disabled");
            }
        }
        Ok(())
    }

    pub async fn shutdown_local(&mut self) -> Result<()> {
        if let Some(server) = self.local_cleanup.take() {
            server.shutdown().await?;
        }
        let Some(local) = self.local.take() else {
            return Ok(());
        };
        drop(local.outgoing);
        local.server.shutdown().await
    }

    async fn relay(
        &mut self,
        mut started: Option<oneshot::Sender<()>>,
        stats_interval: u32,
        tun: &mut Option<AsyncDevice>,
        hooks: &mut Hooks,
        shutdown: &mut watch::Receiver<bool>,
        dashboard: Option<watch::Sender<crate::web::Snapshot>>,
    ) -> Result<()> {
        // Interface addressing is deterministic, independent of connection timing.
        let params = self.links[0].params.clone();
        let mut buffer = vec![0u8; params.mtu as usize];
        let mut last_report = Instant::now();
        let mut reports = report_timer(stats_interval);
        let mut dashboard_timer = dashboard
            .as_ref()
            .and_then(|_| report_timer(SNAPSHOT_INTERVAL));
        loop {
            let retry_at = self.pool.next_retry();
            tokio::select! {
                _ = shutdown.changed() => return Ok(()),
                result = hooks.wait_up() => {
                    result?;
                    self.announce_started(&params, &mut started);
                }
                read = async {
                    match &tun {
                        Some(tun) => tun.recv(&mut buffer).await,
                        None => std::future::pending().await,
                    }
                }, if !hooks.starting() => {
                    let length = read.context("read client TUN")?;
                    ensure!(length != 0, "client TUN closed");
                    let local =
                        (*self.pair.borrow()).map_or(params.tun_addr, |(client, _)| client);
                    if let Some(reset) = self.dispatch(&buffer[..length], local)? {
                        let tun = tun.as_ref().context("TCP reset without client TUN")?;
                        let result =
                            tokio::time::timeout(TUN_WRITE_TIMEOUT, tun.send(&reset)).await;
                        finish_write(&self.links[0].delivery, reset.len(), result.ok())?;
                    }
                }
                event = self.incoming.recv() => {
                    let (epoch, event) = event.context("server event channel stopped")?;
                    self.handle_event(epoch, event, tun, &params, &mut started, hooks).await?;
                }
                update = async {
                    match &mut self.sticky_updates {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                }, if self.sticky_updates.is_some() => {
                    match update {
                        Some(update) => self.apply_sticky_update(update),
                        None => self.sticky_updates = None,
                    }
                }
                job = async {
                    match &mut self.job_events {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                }, if self.job_events.is_some() => {
                    match job {
                        Some(job) => self.handle_job_event(job),
                        None => self.job_events = None,
                    }
                }
                event = async {
                    match &mut self.local {
                        Some(local) => match &mut local.events {
                            Some(events) => events.recv().await,
                            None => std::future::pending().await,
                        },
                        None => std::future::pending().await,
                    }
                }, if self.local.as_ref().is_some_and(|local| local.events.is_some()) => {
                    match event {
                        Some(event) => self.handle_local_event(event, tun).await?,
                        None => self.local_stopped("event channel closed".to_owned(), tun).await?,
                    }
                }
                task = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    let (epoch, result) = task.context("link tasks stopped")?.context("server task panicked")?;
                    let reason = result.err().map_or_else(|| "session ended".to_string(), |e| format!("{e:#}"));
                    let link = &self.links[epoch.link];
                    // name the transport that was live when the link died.
                    let transport = link
                        .latest
                        .as_ref()
                        .and_then(|rx| rx.borrow().active_candidate.clone())
                        .map(|candidate| format!(" ({candidate})"))
                        .unwrap_or_default();
                    if self.links.len() > 1 {
                        crate::error!("vpn[{}]: link failed{transport} — {reason}", link.params.server);
                    } else { crate::error!("vpn: link failed{transport} — {reason}"); }
                    // A Ready of another link may already sit in `incoming`
                    // while this completion was picked first: pool.failed()
                    // counts ready links, so drain everything queued before
                    // the failure before deciding to stop the VPN.
                    self.drain_queued(tun, &params, &mut started, hooks, None)
                        .await?;
                    // The dying session queued its synthesized resets
                    // (and tail packets) before failing. `handle_event`
                    // drops everything a not-ready epoch emits, and after
                    // `remove_epoch` non-RST tail packets of a reused tuple
                    // must not reach a flow now owned by another link — so
                    // forward only RSTs straight to the TUN, drop the rest.
                    self.drain_queued(tun, &params, &mut started, hooks, Some(epoch))
                        .await?;
                    let retired = self.routes.remove_epoch(epoch);
                    let now = StdInstant::now();
                    for key in retired {
                        // Only TCP tuples get a CLOSED-endpoint reply; UDP
                        // and ICMP flows just vanish.
                        if key.protocol == 6 {
                            self.tombstones.insert(key, now);
                        }
                    }
                    self.links[epoch.link].outgoing = None;
                    let link = &mut self.links[epoch.link];
                    if let Some(latest) = link.latest.take() {
                        link.stats.observe(latest.borrow().clone());
                    }
                    link.epoch = None;
                    link.stats.reset();
                    link.last_reason = reason.clone();
                    let now = Instant::now();
                    if self.pool.failed(epoch, now, &reason)? {
                        self.log_retry(epoch.link, now, &reason);
                        self.serving();
                    }
                }
                _ = async {
                    match &mut reports {
                        Some(timer) => { timer.tick().await; }
                        None => std::future::pending().await,
                    }
                } => {
                    let now = Instant::now();
                    let report = self.stats_report(now.duration_since(last_report));
                    crate::info!("{report}");
                    last_report = now;
                }
                _ = async {
                    match &mut dashboard_timer {
                        Some(timer) => { timer.tick().await; }
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(tx) = &dashboard {
                        let _ = tx.send(crate::web::snapshot(self));
                    }
                }
                _ = async {
                    match retry_at {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                } => {
                    for epoch in self.pool.retry_due(Instant::now())? { self.start(epoch); }
                }
            }
        }
    }

    async fn drain_queued(
        &mut self,
        tun: &mut Option<AsyncDevice>,
        params: &LinkParams,
        started: &mut Option<oneshot::Sender<()>>,
        hooks: &mut Hooks,
        rst_of: Option<Epoch>,
    ) -> Result<()> {
        while let Ok((queued_epoch, queued)) = self.incoming.try_recv() {
            if let Some(epoch) = rst_of
                && queued_epoch == epoch
                && let Event::Packet(packet) = &queued
                && self.routes.accepts(epoch, packet)
                && packet::parse(&packet.bytes, false).is_some_and(|p| p.is_rst)
                && let Some(tun) = tun.as_ref()
            {
                let result = tokio::time::timeout(TUN_WRITE_TIMEOUT, tun.send(&packet.bytes)).await;
                if matches!(result, Ok(Ok(n)) if n == packet.bytes.len())
                    && let Some(parsed) = packet::parse(&packet.bytes, false)
                {
                    self.routes.record(parsed.flow, 0, packet.bytes.len());
                }
                continue;
            }
            self.handle_event(queued_epoch, queued, tun, params, started, hooks)
                .await?;
        }
        Ok(())
    }

    fn serving(&self) {
        if self.links.len() > 1 {
            crate::info!(
                "vpn: serving ({}/{} servers ready, {} checking)",
                self.pool.ready_count(),
                self.links.len(),
                self.pool.checking_count()
            );
        }
    }

    fn log_retry(&self, link: usize, now: Instant, reason: &str) {
        if let Some(at) = self.pool.retry_at(link) {
            let attempt = self.pool.retry_attempt(link);
            let reason_label = if reason.is_empty() { "unknown" } else { reason };
            crate::info!(
                "ssh[{}]: retrying in {} s (attempt {}, last: {})",
                self.links[link].params.server,
                at.saturating_duration_since(now).as_secs(),
                attempt,
                reason_label
            );
        }
    }

    fn announce_started(&self, params: &LinkParams, started: &mut Option<oneshot::Sender<()>>) {
        if self.links.len() == 1 {
            crate::info!("vpn: started (client, server {})", params.server);
        } else {
            crate::info!("vpn: started (client, {} servers)", self.links.len());
        }
        if let Some(started) = started.take() {
            let _ = started.send(());
        }
        let now = Instant::now();
        for link in 0..self.links.len() {
            self.log_retry(link, now, &self.links[link].last_reason);
        }
    }
}

/// Geo-driven exit inputs of one client run: the ASN affinity table, the
/// country table, the fallback strategy and the explicit sticky blocks.
#[derive(Default)]
pub struct GeoExits {
    /// ASN database; None — sticky-asn degraded to weighted balance.
    pub geo: Option<crate::geo::Geo>,
    /// Country database; None — no country data.
    pub country: Option<crate::geo::Geo>,
    /// Fallback strategy for traffic matched by no sticky block.
    pub policy: crate::cli::ExitPolicy,
    pub sticky_asn_mode: crate::cli::StickyAsnMode,
    /// The table is missing but a provider job is fetching it (degraded start).
    pub geo_pending: Option<String>,
    pub country_pending: Option<String>,
}

/// Start the episodic name resolver for name selectors.
fn spawn_sticky_resolver(
    stickies: &[crate::sticky::RuntimeSticky],
    shutdown: &mut watch::Receiver<bool>,
) -> (
    Option<mpsc::Receiver<crate::sticky::Update>>,
    Option<tokio::task::JoinHandle<()>>,
) {
    let named: Vec<(usize, Vec<String>, Duration)> = stickies
        .iter()
        .enumerate()
        .filter_map(|(index, block)| match &block.block.selector {
            crate::sticky::Selector::Names(names) => {
                Some((index, names.clone(), block.block.every))
            }
            _ => None,
        })
        .collect();
    if named.is_empty() {
        return (None, None);
    }
    let (tx, rx) = mpsc::channel(16);
    let mut shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        let mut caches: Vec<crate::sticky::ResolveCache> =
            (0..named.len()).map(|_| Default::default()).collect();
        let mut next: Vec<tokio::time::Instant> =
            named.iter().map(|_| tokio::time::Instant::now()).collect();
        // One blocking lookup per slot at a time: a stuck getaddrinfo (glibc
        // bounds its own retries) delays its block instead of piling up
        // blocking threads on every tick.
        let mut in_flight: Vec<Option<tokio::task::JoinHandle<Option<Vec<Ipv4Addr>>>>> =
            (0..named.len()).map(|_| None).collect();
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                () = tokio::time::sleep_until(next.iter().min().copied().unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(60))) => {
                    let now = tokio::time::Instant::now();
                    for slot in 0..named.len() {
                        if next[slot] > now {
                            continue;
                        }
                        if let Some(handle) = &mut in_flight[slot] {
                            if !handle.is_finished() {
                                next[slot] = now + Duration::from_secs(1);
                                continue;
                            }
                            let outcome = handle.await.unwrap_or(None);
                            in_flight[slot] = None;
                            deliver(&tx, &mut caches[slot], named[slot].0, outcome).await;
                            next[slot] = now + named[slot].2;
                            continue;
                        }
                        let names = named[slot].1.clone();
                        in_flight[slot] = Some(tokio::task::spawn_blocking(move || {
                            let mut ips = Vec::new();
                            for name in &names {
                                match resolve_blocking(name) {
                                    Some(found) => ips.extend(found),
                                    None => return None,
                                }
                            }
                            Some(ips)
                        }));
                        // Re-check the join soon: the first refresh must land
                        // right after startup, not one `every` later.
                        next[slot] = now + Duration::from_millis(100);
                    }
                }
            }
        }
    });
    (Some(rx), Some(task))
}

/// Fold one finished lookup into the cache and send the update upstream.
async fn deliver(
    tx: &mpsc::Sender<crate::sticky::Update>,
    cache: &mut crate::sticky::ResolveCache,
    index: usize,
    outcome: Option<Vec<Ipv4Addr>>,
) {
    let (ips, ok) = match outcome {
        Some(mut ips) => {
            ips.sort_unstable();
            ips.dedup();
            (ips, true)
        }
        None => (Vec::new(), false),
    };
    let (set, purged) = if ok {
        cache.refresh(&ips)
    } else {
        (Default::default(), 0)
    };
    let _ = tx
        .send(crate::sticky::Update {
            index,
            ips: set,
            purged,
            ok,
        })
        .await; // a closed channel ends the task via the next send error path
}

/// One name → unique IPv4 addresses via the system resolver, on a blocking
/// thread. An empty answer is `Some(vec![])`: the refresh still counts (that
/// is how disappeared IPs purge). None on error keeps the previous cache.
fn resolve_blocking(name: &str) -> Option<Vec<Ipv4Addr>> {
    use std::net::ToSocketAddrs;
    // Only a real answer counts as a refresh: a resolver error keeps the
    // previous set instead of purging it (glibc reports NODATA and NXDOMAIN
    // alike as errors, so absence ages out only via a successful empty set).
    (name, 0).to_socket_addrs().ok().map(|addrs| {
        addrs
            .map(|addr| addr.ip())
            .filter_map(|ip| match ip {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(_) => None,
            })
            .collect::<Vec<_>>()
    })
}

impl Drop for Hub {
    fn drop(&mut self) {
        if let Some(task) = &self.sticky_task {
            task.abort();
        }
        if let Some(task) = &self.job_task {
            task.abort();
        }
    }
}

pub async fn run(
    servers: Vec<LinkParams>,
    started: Option<oneshot::Sender<()>>,
    stats_interval: u32,
    mut hooks: Hooks,
    mut shutdown: watch::Receiver<bool>,
    exits: GeoExits,
    extras: Extras,
) -> Result<()> {
    let Extras {
        sticky_blocks,
        jobs,
        web_listen,
    } = extras;
    let GeoExits {
        geo,
        country,
        policy: exits_policy,
        sticky_asn_mode,
        geo_pending,
        country_pending,
    } = exits;
    let job_stats = JobStats::new(&jobs.specs, geo.is_some(), country.is_some());
    let (job_events, job_task) = jobs::spawn_scheduler(&jobs, &mut shutdown);
    ensure!(!servers.is_empty(), "no servers configured");
    let stickies: Vec<crate::sticky::RuntimeSticky> = sticky_blocks
        .into_iter()
        .map(crate::sticky::RuntimeSticky::new)
        .collect();
    let label_index: std::collections::HashMap<String, usize> = servers
        .iter()
        .enumerate()
        .filter(|(_, params)| !params.label.is_empty())
        .map(|(index, params)| (params.label.clone(), index))
        .collect();
    let sticky_via: Vec<crate::sticky::ResolvedVia> = stickies
        .iter()
        .map(|block| match &block.block.via {
            crate::sticky::Via::Local => crate::sticky::ResolvedVia::Local,
            crate::sticky::Via::Servers(labels) => crate::sticky::ResolvedVia::Links(
                labels
                    .iter()
                    .map(|label| label_index[label])
                    .collect::<Vec<usize>>(),
            ),
        })
        .collect();
    if hooks.needs_auto_up() || hooks.needs_auto_down() {
        hooks.set_server_addrs(crate::client_routing::server_addrs(&servers).await?);
    }
    let pool = Pool::new(servers.iter().map(|s| s.weight));
    // Stable node identity is host:port (spec): a port change is a new node.
    let nodes: Vec<(String, u32)> = servers
        .iter()
        .map(|s| (format!("{}:{}", s.server, s.ssh_port), s.weight))
        .collect();
    let (events, incoming) = mpsc::channel(QUEUE);
    let (sticky_updates, sticky_task) = spawn_sticky_resolver(&stickies, &mut shutdown);
    let mut hub = Hub {
        geo,
        country,
        policy: exits_policy,
        sticky_asn_mode,
        job_events,
        job_task,
        job_stats,
        geo_path: jobs.geo_db,
        country_path: jobs.country_db,
        geo_pending,
        country_pending,
        stickies,
        sticky_via,
        sticky_updates,
        sticky_task,
        local: None,
        local_cleanup: None,
        nodes,
        exit_owners: crate::exit_state::StickyOwners::default(),
        sticky: StickyStats::default(),
        local_stats: LocalStats::default(),
        links: servers
            .into_iter()
            .map(|params| Link {
                params,
                outgoing: None,
                delivery: Arc::default(),
                epoch: None,
                latest: None,
                stats: stats::Snapshot::default(),
                last_reason: String::new(),
                assigned: Arc::default(),
            })
            .collect(),
        pool,
        pair: watch::channel(None).0,
        tasks: JoinSet::new(),
        events,
        incoming,
        routes: Routes::default(),
        tombstones: session::Tombstones::default(),
    };
    for link in 0..hub.links.len() {
        hub.start(Epoch {
            link,
            generation: 1,
        });
    }
    // This scope owns the TUN until every configured cleanup hook has finished.
    let mut tun = None;
    let dashboard = match web_listen {
        Some(addr) => {
            let listener = crate::web::bind(addr).await?;
            let (tx, rx) = watch::channel(crate::web::snapshot(&hub));
            let geo_path = hub.geo_path.clone();
            let task = tokio::spawn(async move {
                if let Err(error) = crate::web::serve(listener, rx, geo_path).await {
                    crate::error!("dashboard: {error:#}");
                }
            });
            crate::info!("dashboard: http://{addr}");
            Some((tx, task))
        }
        None => None,
    };
    let result = hub
        .relay(
            started,
            stats_interval,
            &mut tun,
            &mut hooks,
            &mut shutdown,
            dashboard.as_ref().map(|(tx, _)| tx.clone()),
        )
        .await;
    if let Some((_, task)) = dashboard {
        task.abort();
    }
    let canceled = hooks.cancel_up().await;
    hub.tasks.shutdown().await;
    let cleanup = match canceled {
        Ok(()) => hooks.finish().await,
        Err(error) => Err(error),
    };
    let local = hub.shutdown_local().await;
    drop(tun);
    match result {
        Err(error) => {
            if let Err(cleanup) = cleanup {
                crate::error!("hook: cleanup failed — {cleanup:#}");
            }
            if let Err(local) = local {
                crate::error!("local-exit: shutdown failed — {local:#}");
            }
            Err(error)
        }
        Ok(()) => cleanup.and(local),
    }
}

pub fn report_timer(seconds: u32) -> Option<tokio::time::Interval> {
    if seconds == 0 {
        return None;
    }
    let period = Duration::from_secs(u64::from(seconds));
    let mut timer = tokio::time::interval_at(Instant::now() + period, period);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    Some(timer)
}

fn drop_note(delivery: &Delivery, links: &[Link], link: Option<usize>, reason: &str) {
    delivery.dropped();
    match link {
        // dispatch() runs before a link is chosen: there is no index to blame.
        Some(index) if links.len() > 1 => crate::error!(
            "vpn[{}]: dropped packet — {reason}",
            links[index].params.server
        ),
        _ => crate::error!("vpn: dropped packet — {reason}"),
    }
}

pub(crate) fn link_state(pool: &Pool, link: &Link, index: usize) -> &'static str {
    if link.epoch.is_some_and(|epoch| pool.is_ready(epoch)) {
        return "ready";
    }
    if link.epoch.is_some_and(|epoch| pool.is_checking(epoch)) {
        return "checking";
    }
    if pool.retry_at(index).is_some() {
        return "backoff";
    }
    if link.epoch.is_some() {
        return "connecting";
    }
    "failed"
}

/// Accounting for one TUN write: a fully written packet counts as received,
/// a missed deadline (`None`) or a failed/short write as dropped. Real write
/// errors abort the run like the write itself would.
pub fn finish_write(
    delivery: &Delivery,
    length: usize,
    result: Option<std::io::Result<usize>>,
) -> Result<bool> {
    let written = matches!(&result, Some(Ok(n)) if *n == length);
    match result {
        Some(Ok(written)) if written == length => delivery.received(length),
        None => {
            delivery.dropped();
            crate::error!("vpn: dropped packet — client TUN write timeout");
        }
        Some(result) => {
            delivery.dropped();
            crate::error!("vpn: dropped packet — failed client TUN write");
            ensure!(
                result.context("write client TUN")? == length,
                "short client TUN write"
            );
        }
    }
    Ok(written)
}
