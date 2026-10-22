//! One client TUN, isolated server tasks and generation-tagged flow ownership.
//!
//! Layout: `routes` holds the flow ownership table (`Owner`, `Routes`), this
//! file the hub itself — link tasks, the select loop, TUN reads and writes.

use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant as StdInstant},
};

use anyhow::{Context, Result, ensure};
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
    packet::{self, FlowKey},
    pool::Pool,
    server_spec::LinkParams,
    session, stats,
};

mod routes;

pub use routes::{Owner, Routes};

// Burst absorber for link/hub queues: holds Packet slot structs, payload memory scales
// with resident packets only. 1024 absorbs CPU/Wi-Fi jitter without unbounded growth.
pub const QUEUE: usize = 1024;

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

pub struct Hub {
    pub links: Vec<Link>,
    pub pool: Pool,
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
    /// Returns a CLOSED-endpoint reset for unowned or tombstoned TCP traffic.
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
        let epoch = match self.routes.by_key.get(&parsed.flow) {
            Some(owner) if self.pool.is_serving(owner.epoch) => Some(owner.epoch),
            Some(_) => None,
            None if parsed.can_open => self.pick(&parsed.flow),
            None => return Ok(packet::tcp_reset_for(&parsed)),
        };
        let Some(epoch) = epoch else { return Ok(None) };
        let link = &self.links[epoch.link];
        if let Some(outgoing) = &link.outgoing {
            self.routes.enqueue(
                bytes,
                client_ip,
                epoch,
                outgoing,
                &link.delivery,
                &self.links,
            )?;
        }
        Ok(None)
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
        epoch: Epoch,
        event: Event,
        tun: &mut Option<AsyncDevice>,
        params: &LinkParams,
        started: &mut Option<oneshot::Sender<()>>,
        hooks: &mut Hooks,
    ) -> Result<()> {
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
                let result =
                    tokio::time::timeout(Duration::from_millis(100), tun.send(&packet.bytes)).await;
                finish_write(&delivery, packet.bytes.len(), result)?;
            }
            Event::Closed { id, key } => self.routes.forget(key, Owner { epoch, id }),
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

    /// The flow key is available here for a future destination-stickiness policy.
    fn pick(&mut self, _key: &FlowKey) -> Option<Epoch> {
        self.pool.pick()
    }

    async fn relay(
        &mut self,
        mut started: Option<oneshot::Sender<()>>,
        stats_interval: u32,
        tun: &mut Option<AsyncDevice>,
        hooks: &mut Hooks,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<()> {
        // Interface addressing is deterministic, independent of connection timing.
        let params = self.links[0].params.clone();
        let mut buffer = vec![0u8; params.mtu as usize];
        let mut last_report = Instant::now();
        let mut reports = report_timer(stats_interval);
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
                            tokio::time::timeout(Duration::from_millis(100), tun.send(&reset)).await;
                        finish_write(&self.links[0].delivery, reset.len(), result)?;
                    }
                }
                event = self.incoming.recv() => {
                    let (epoch, event) = event.context("server event channel stopped")?;
                    self.handle_event(epoch, event, tun, &params, &mut started, hooks).await?;
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
                && packet::parse(&packet.bytes, false).is_some_and(|p| p.is_rst)
                && let Some(tun) = tun.as_ref()
            {
                let _ =
                    tokio::time::timeout(Duration::from_millis(100), tun.send(&packet.bytes)).await;
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

pub async fn run(
    servers: Vec<LinkParams>,
    started: Option<oneshot::Sender<()>>,
    stats_interval: u32,
    mut hooks: Hooks,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    ensure!(!servers.is_empty(), "no servers configured");
    let pool = Pool::new(servers.iter().map(|s| s.weight));
    let (events, incoming) = mpsc::channel(QUEUE);
    let mut hub = Hub {
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
    let result = hub
        .relay(started, stats_interval, &mut tun, &mut hooks, &mut shutdown)
        .await;
    let canceled = hooks.cancel_up().await;
    hub.tasks.shutdown().await;
    let cleanup = match canceled {
        Ok(()) => hooks.finish().await,
        Err(error) => Err(error),
    };
    drop(tun);
    match result {
        Err(error) => {
            if let Err(cleanup) = cleanup {
                crate::error!("hook: cleanup failed — {cleanup:#}");
            }
            Err(error)
        }
        Ok(()) => cleanup,
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

/// Every counted loss names its reason in the log (#124).
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

fn link_state(pool: &Pool, link: &Link, index: usize) -> &'static str {
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

pub fn finish_write(
    delivery: &Delivery,
    length: usize,
    result: Result<std::io::Result<usize>, tokio::time::error::Elapsed>,
) -> Result<()> {
    match result {
        Ok(Ok(written)) if written == length => delivery.received(length),
        Err(_) => {
            delivery.dropped();
            crate::error!("vpn: dropped packet — client TUN write timeout");
        }
        Ok(result) => {
            delivery.dropped();
            crate::error!("vpn: dropped packet — failed client TUN write");
            ensure!(
                result.context("write client TUN")? == length,
                "short client TUN write"
            );
        }
    }
    Ok(())
}
