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
    local_exit::{self, LocalPair, LocalServer},
    packet::{self, FlowKey},
    pool::Pool,
    server_spec::LinkParams,
    session, stats,
};

mod routes;

pub use routes::{Owner, Routes, Target};

// Burst absorber for link/hub queues: holds Packet slot structs, payload memory scales
// with resident packets only. 1024 absorbs CPU/Wi-Fi jitter without unbounded growth.
pub const QUEUE: usize = 1024;

/// Startup grace for restored sticky owners: two connect budgets
/// (selector::ATTEMPT_BUDGET is 5 s each).
pub const STARTUP_GRACE: Duration = Duration::from_secs(10);

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
#[derive(Default)]
pub struct StickyStats {
    pub lookup_hit: u64,
    pub lookup_miss: u64,
    pub failover_moves: u64,
    pub country_hit: u64,
    pub country_miss: u64,
    pub asn_hit: u64,
    pub asn_miss: u64,
}

impl StickyStats {
    fn lookup(&mut self, country: bool, hit: bool) {
        if hit {
            self.lookup_hit += 1;
        } else {
            self.lookup_miss += 1;
        }
        match (country, hit) {
            (true, true) => self.country_hit += 1,
            (true, false) => self.country_miss += 1,
            (false, true) => self.asn_hit += 1,
            (false, false) => self.asn_miss += 1,
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
    pub pair: LocalPair,
    pub primary_client: Ipv4Addr,
    pub outgoing: mpsc::Sender<Packet>,
    pub events: Option<mpsc::Receiver<(Epoch, Event)>>,
    pub latest: watch::Receiver<Stats>,
    pub delivery: Arc<Delivery>,
    pub server: LocalServer,
    pub ready: bool,
}

/// A destination country with assigned servers.
/// Country constrains candidates; ASN supplies affinity within them.
struct CountryRoute {
    /// Packed ISO code — the rendezvous key payload.
    packed: u32,
    /// Links configured for the country, in configuration order.
    candidates: Vec<usize>,
    /// Destination ASN when the ASN database covers it.
    asn: Option<u32>,
}

impl CountryRoute {
    /// Use a scoped `CC:ASN` persistence key when ASN data is available.
    fn exit_key(&self) -> crate::exit_state::ExitKey {
        let code = crate::geo::unpack_country(self.packed);
        match self.asn {
            Some(asn) => crate::exit_state::ExitKey::ScopedAsn(code, asn),
            None => crate::exit_state::ExitKey::Country(code),
        }
    }
}

pub struct Hub {
    pub links: Vec<Link>,
    pub pool: Pool,
    /// Sticky exit: ASN grouping under exit-policy sticky-asn;
    /// None = weighted balance.
    pub geo: Option<crate::geo::Geo>,
    /// Sticky exit: country table for the destination Country constraint;
    /// None = no country routing.
    pub country: Option<crate::geo::Geo>,
    /// Packed home country for LocalExit admission.
    pub home_country: Option<u32>,
    /// Local serve and client session, started with the live primary TUN.
    pub local: Option<LocalExitState>,
    pub local_task: Option<tokio::task::JoinHandle<Result<()>>>,
    /// Stable node ids (configured `server` strings) and weights, for rendezvous.
    pub nodes: Vec<(String, u32)>,
    /// Sticky owners: group key → link index. An alive owner keeps its group
    /// (no snap-back); reassigned only when the owner cannot serve new flows.
    pub exit_owners: std::collections::HashMap<u64, usize>,
    /// Failover persistence; None in balance mode.
    pub exit_state: Option<crate::exit_state::ExitState>,
    /// Sticky exit counters, surfaced in the periodic stats report.
    pub sticky: StickyStats,
    pub local_stats: LocalStats,
    /// Restored owners keep their groups while connecting until this instant.
    pub grace_until: Option<StdInstant>,
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

/// What dispatching one client packet produced for the TUN.
#[derive(Debug, PartialEq)]
pub enum Dispatched {
    Reset([u8; 40]),
}

impl Hub {
    /// Return a CLOSED-endpoint reset for unowned TCP traffic.
    /// Dispatch reverse-NAT, current owner and retired flows before classifying
    /// a new flow; home country is considered before VPN ownership.
    pub async fn dispatch(
        &mut self,
        bytes: &[u8],
        client_ip: Ipv4Addr,
    ) -> Result<Option<Dispatched>> {
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
            return Ok(self
                .tombstones
                .respond(&parsed.flow, &parsed, now)
                .map(Dispatched::Reset));
        }
        match self.routes.by_key.get(&parsed.flow) {
            Some(Target::Direct(id)) => self.forward_local(*id, bytes),
            Some(Target::Remote(owner)) if self.pool.is_serving(owner.epoch) => {
                let link = &self.links[owner.epoch.link];
                let Some(outgoing) = &link.outgoing else {
                    return Ok(None);
                };
                let delivery = link.delivery.clone();
                self.routes.enqueue(
                    bytes,
                    client_ip,
                    owner.epoch,
                    outgoing,
                    &delivery,
                    &self.links,
                )?;
                Ok(None)
            }
            // A non-serving owner still owns the flow: no reset, no reassign.
            Some(Target::Remote(_)) => Ok(None),
            None if parsed.can_open => self.open_flow(&parsed, bytes, client_ip).await,
            None => Ok(packet::tcp_reset_for(&parsed).map(Dispatched::Reset)),
        }
    }

    /// Whether the destination is an exact match of the home country (spec
    /// §3.1): direct applies; a database miss is a non-home destination.
    fn is_home(&self, destination: Ipv4Addr) -> bool {
        self.home_country.is_some_and(|home| {
            self.country
                .as_ref()
                .and_then(|geo| geo.lookup(destination))
                == Some(home)
        })
    }

    /// Classification of a new flow: home traffic uses LocalExit and never
    /// falls back to the VPN; everything else picks the remote owner.
    async fn open_flow(
        &mut self,
        parsed: &packet::Packet,
        bytes: &[u8],
        client_ip: Ipv4Addr,
    ) -> Result<Option<Dispatched>> {
        let key = parsed.flow;
        if self.is_home(key.destination) {
            return self.open_local(parsed, bytes);
        }
        let Some(epoch) = self.pick(&key) else {
            return Ok(None);
        };
        let link = &self.links[epoch.link];
        let Some(outgoing) = &link.outgoing else {
            return Ok(None);
        };
        let delivery = link.delivery.clone();
        self.routes
            .enqueue(bytes, client_ip, epoch, outgoing, &delivery, &self.links)?;
        Ok(None)
    }

    fn open_local(&mut self, parsed: &packet::Packet, bytes: &[u8]) -> Result<Option<Dispatched>> {
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
        let primary = local.primary_client;
        let local_ip = local.pair.client;
        let delivery = local.delivery.clone();
        let id = self.routes.allocate()?;
        let translated = packet::translate_v4(bytes, primary, local_ip)
            .context("local-exit packet translation")?;
        match outgoing.try_send(Packet {
            id,
            bytes: translated,
        }) {
            Ok(()) => {
                self.local_stats.opened += 1;
                self.routes.by_key.insert(key, Target::Direct(id));
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

    fn forward_local(&mut self, id: u64, bytes: &[u8]) -> Result<Option<Dispatched>> {
        let key = packet::parse(bytes, true).map(|packet| packet.flow);
        let Some(local) = &self.local else {
            return Ok(None);
        };
        let outgoing = local.outgoing.clone();
        let primary = local.primary_client;
        let local_ip = local.pair.client;
        let delivery = local.delivery.clone();
        let translated = packet::translate_v4(bytes, primary, local_ip)
            .context("local-exit packet translation")?;
        match outgoing.try_send(Packet {
            id,
            bytes: translated,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => delivery.dropped(),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.local_stats.failed += 1;
                if let Some(key) = key {
                    self.close_local(id, key, true);
                }
            }
        }
        Ok(None)
    }

    pub async fn handle_local_event(
        &mut self,
        (_epoch, event): (Epoch, Event),
        tun: &mut Option<AsyncDevice>,
    ) -> Result<()> {
        match event {
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
                let Some(local) = &self.local else {
                    return Ok(());
                };
                let primary = local.primary_client;
                let local_ip = local.pair.client;
                let delivery = local.delivery.clone();
                let bytes = match packet::translate_v4(&packet.bytes, local_ip, primary) {
                    Some(bytes) => bytes,
                    None => return Ok(()),
                };
                let current = packet::parse(&bytes, false).is_some_and(|parsed| {
                    matches!(self.routes.by_key.get(&parsed.flow), Some(Target::Direct(id)) if *id == packet.id)
                });
                if !current {
                    return Ok(());
                }
                let tun = tun
                    .as_ref()
                    .context("local-exit packet without client TUN")?;
                let result =
                    tokio::time::timeout(Duration::from_millis(100), tun.send(&bytes)).await;
                finish_write(&delivery, bytes.len(), result)?;
            }
            Event::Closed { id, key } => {
                let Some(local) = &self.local else {
                    return Ok(());
                };
                let key = translate_key(key, local.pair.client, local.primary_client);
                self.close_local(id, key, false);
            }
        }
        Ok(())
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

    fn local_stopped(&mut self, reason: String) {
        crate::error!("local-exit: {reason}");
        if let Some(local) = &mut self.local {
            local.ready = false;
            local.events = None;
            local.server.abort();
        }
        let mut retired = Vec::new();
        self.routes.by_key.retain(|key, target| {
            if matches!(target, Target::Direct(_)) {
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
        if self.geo.is_some() || self.country.is_some() {
            report.push_str(&format!(
                "\nsticky: lookup hit {} / miss {} | failover moves {}",
                self.sticky.lookup_hit, self.sticky.lookup_miss, self.sticky.failover_moves
            ));
            report.push_str(&format!(
                "\ncountry: lookup hit {} / miss {} | asn: lookup hit {} / miss {}",
                self.sticky.country_hit,
                self.sticky.country_miss,
                self.sticky.asn_hit,
                self.sticky.asn_miss
            ));
        }
        if self.home_country.is_some() {
            report.push_str(&format!(
                "\nlocal-exit: opened {} / failed {} / closed {}",
                self.local_stats.opened, self.local_stats.failed, self.local_stats.closed
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
                    self.start_local(tun_addr, peer_addr, &params).await?;
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

    pub fn pick(&mut self, key: &FlowKey) -> Option<Epoch> {
        // Retry throttled persistence even when no failover follows.
        if let Some(state) = &mut self.exit_state {
            state.flush_due(StdInstant::now());
        }
        // Country constrains candidates before ASN affinity, even in balance mode.
        if let Some(route) = self.country_route(key.destination) {
            let group = match route.asn {
                Some(asn) => crate::geo::scoped_asn_key(route.packed, asn),
                None => crate::geo::country_key(route.packed),
            };
            return self.sticky_epoch(group, Some(&route.candidates), route.exit_key(), true);
        }
        let Some(geo) = &self.geo else {
            return self.pool.pick();
        };
        let Some(asn) = geo.lookup(key.destination) else {
            // Uncovered /32 uses stateless rendezvous without persisted ownership.
            self.sticky.lookup(false, false);
            return crate::geo::rendezvous(crate::geo::ip_key(key.destination), &self.nodes)
                .into_iter()
                .find_map(|link| self.pool.ready_epoch(link));
        };
        let group = crate::geo::asn_key(asn);
        self.sticky_epoch(group, None, crate::exit_state::ExitKey::Asn(asn), false)
    }

    /// Return assigned destination countries as a candidate constraint.
    /// Unknown or unassigned countries leave normal selection unchanged.
    fn country_route(&self, destination: Ipv4Addr) -> Option<CountryRoute> {
        let packed = self.country.as_ref()?.lookup(destination)?;
        let code = crate::geo::unpack_country(packed);
        let candidates: Vec<usize> = self
            .links
            .iter()
            .enumerate()
            .filter(|(_, link)| link.params.countries.contains(&code))
            .map(|(link, _)| link)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        Some(CountryRoute {
            packed,
            candidates,
            // The ASN affinity applies only under exit-policy sticky-asn:
            // without the ASN database the group is the country itself.
            asn: self.geo.as_ref().and_then(|geo| geo.lookup(destination)),
        })
    }

    /// Select a sticky owner without snap-back.
    /// Checking/restored owners retain their grace period; failover stays
    /// within candidates and persists the deviation. None means all links.
    fn sticky_epoch(
        &mut self,
        group: u64,
        candidates: Option<&[usize]>,
        key: crate::exit_state::ExitKey,
        country: bool,
    ) -> Option<Epoch> {
        let serves = |link: usize| candidates.is_none_or(|set| set.contains(&link));
        if let Some(&owner) = self.exit_owners.get(&group) {
            if let Some(epoch) = self.pool.ready_epoch(owner) {
                self.sticky.lookup(country, true);
                return Some(epoch);
            }
            // Checking owner keeps its group: serve new flows from a reserve
            // without migrating (spec: no migration on Checking).
            if self.pool.link_checking(owner) {
                self.sticky.lookup(country, true);
                return crate::geo::rendezvous(group, &self.nodes)
                    .into_iter()
                    .filter(|&link| link != owner && serves(link))
                    .find_map(|link| self.pool.ready_epoch(link));
            }
            // Startup grace: a restored owner still connecting keeps its
            // groups until the deadline; afterwards it fails over.
            if self.pool.is_connecting(owner)
                && self
                    .grace_until
                    .is_some_and(|until| StdInstant::now() < until)
            {
                return None;
            }
        }
        self.sticky.lookup(country, false);
        let previous = self.exit_owners.get(&group).copied();
        let order: Vec<usize> = crate::geo::rendezvous(group, &self.nodes)
            .into_iter()
            .filter(|&link| serves(link))
            .collect();
        let next = order
            .iter()
            .find_map(|&link| self.pool.ready_epoch(link).map(|epoch| (link, epoch)));
        let (link, epoch) = next?;
        if previous != Some(link) {
            self.exit_owners.insert(group, link);
            // The rendezvous baseline needs no state; failover or an unavailable
            // primary creates a persisted deviation to prevent restart snap-back.
            let deviation = order.first() != Some(&link);
            if previous.is_some() {
                self.sticky.failover_moves += 1;
            }
            if (previous.is_some() || deviation)
                && let Some(state) = &mut self.exit_state
            {
                // Batched: dirty here, flushed by flush_due / clean stop.
                state.assign(key, &self.nodes[link].0);
            }
        }
        Some(epoch)
    }

    async fn start_local(
        &mut self,
        client: Ipv4Addr,
        peer: Ipv4Addr,
        params: &LinkParams,
    ) -> Result<()> {
        if self.home_country.is_none() || self.local.is_some() {
            return Ok(());
        }
        let epoch = Epoch {
            link: usize::MAX,
            generation: 1,
        };
        let local = local_exit::start(
            epoch,
            (peer, client),
            params.mtu,
            params.server_up.clone(),
            params.server_down.clone(),
            None,
        )
        .await?;
        let local_exit::LocalExit {
            control,
            config,
            io,
            pair,
            outgoing,
            events,
            latest,
            delivery,
            server,
        } = local;
        let task = tokio::spawn(session::run_link(
            control,
            pair.server,
            pair.client,
            params.mtu,
            config,
            io,
        ));
        self.local = Some(LocalExitState {
            pair,
            primary_client: client,
            outgoing,
            events: Some(events),
            latest,
            delivery,
            server,
            ready: false,
        });
        self.local_task = Some(task);
        Ok(())
    }

    async fn shutdown_local(&mut self) -> Result<()> {
        if let Some(task) = self.local_task.take() {
            task.abort();
            let _ = task.await;
        }
        let Some(mut local) = self.local.take() else {
            return Ok(());
        };
        drop(local.outgoing);
        match tokio::time::timeout(Duration::from_secs(2), local.server.join()).await {
            Ok(result) => result,
            Err(_) => {
                local.server.abort();
                Err(anyhow::anyhow!("local-exit shutdown timeout"))
            }
        }
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
                    match self.dispatch(&buffer[..length], local).await? {
                        Some(Dispatched::Reset(reset)) => {
                            let tun = tun.as_ref().context("TCP reset without client TUN")?;
                            let result = tokio::time::timeout(
                                Duration::from_millis(100),
                                tun.send(&reset),
                            )
                            .await;
                            finish_write(&self.links[0].delivery, reset.len(), result)?;
                        }
                        None => {}
                    }
                }
                event = self.incoming.recv() => {
                    let (epoch, event) = event.context("server event channel stopped")?;
                    self.handle_event(epoch, event, tun, &params, &mut started, hooks).await?;
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
                        None => self.local_stopped("event channel closed".to_owned()),
                    }
                }
                result = async {
                    match &mut self.local_task {
                        Some(task) => task.await,
                        None => std::future::pending().await,
                    }
                }, if self.local_task.is_some() => {
                    self.local_task = None;
                    let reason = match result {
                        Ok(Ok(())) => "session ended".to_owned(),
                        Ok(Err(error)) => format!("{error:#}"),
                        Err(error) => format!("local client task: {error}"),
                    };
                    self.local_stopped(reason);
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
                && self.routes.accepts(epoch, packet)
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

/// Geo-driven exit inputs of one client run (spec §2-4): the ASN affinity
/// table, the country constraint table and the one shared owner state.
#[derive(Default)]
pub struct GeoExits {
    /// ASN database; None — sticky-asn degraded to weighted balance.
    pub geo: Option<crate::geo::Geo>,
    /// Country database; None — no country routing.
    pub country: Option<crate::geo::Geo>,
    /// Packed home country for LocalExit admission.
    pub home_country: Option<u32>,
    /// Sticky owner persistence; None — nothing sticky is active.
    pub exit_state: Option<crate::exit_state::ExitState>,
}

/// Map a persisted typed owner key to its numeric rendezvous group.
/// Restore only while the owner remains a candidate for its country.
#[doc(hidden)]
pub fn restored_group(
    servers: &[LinkParams],
    key: crate::exit_state::ExitKey,
    link: usize,
) -> Option<u64> {
    let candidate = |code: &str| {
        servers
            .get(link)
            .is_some_and(|params| params.countries.iter().any(|c| c == code))
    };
    match key {
        crate::exit_state::ExitKey::Asn(asn) => Some(crate::geo::asn_key(asn)),
        crate::exit_state::ExitKey::Country(code) if candidate(&code) => {
            Some(crate::geo::country_key(crate::geo::pack_country(&code)?))
        }
        crate::exit_state::ExitKey::ScopedAsn(code, asn) if candidate(&code) => Some(
            crate::geo::scoped_asn_key(crate::geo::pack_country(&code)?, asn),
        ),
        _ => None,
    }
}

pub async fn run(
    servers: Vec<LinkParams>,
    started: Option<oneshot::Sender<()>>,
    stats_interval: u32,
    mut hooks: Hooks,
    mut shutdown: watch::Receiver<bool>,
    exits: GeoExits,
) -> Result<()> {
    let GeoExits {
        geo,
        country,
        home_country,
        exit_state,
    } = exits;
    ensure!(!servers.is_empty(), "no servers configured");
    let pool = Pool::new(servers.iter().map(|s| s.weight));
    // Stable node identity is host:port (spec): a port change is a new node.
    let nodes: Vec<(String, u32)> = servers
        .iter()
        .map(|s| (format!("{}:{}", s.server, s.ssh_port), s.weight))
        .collect();
    let mut exit_state = exit_state;
    let ids: Vec<String> = nodes.iter().map(|(id, _)| id.clone()).collect();
    let exit_owners = match &mut exit_state {
        Some(state) => {
            state.retain_nodes(&ids);
            state
                .owner_indices(&ids)
                .into_iter()
                .filter_map(|(key, link)| {
                    restored_group(&servers, key, link).map(|group| (group, link))
                })
                .collect()
        }
        None => std::collections::HashMap::new(),
    };
    // Startup grace covers exactly the restored owners: two connect budgets.
    let grace_until = (!exit_owners.is_empty()).then(|| StdInstant::now() + STARTUP_GRACE);
    let (events, incoming) = mpsc::channel(QUEUE);
    let mut hub = Hub {
        geo,
        country,
        home_country,
        local: None,
        local_task: None,
        nodes,
        exit_owners,
        exit_state,
        sticky: StickyStats::default(),
        local_stats: LocalStats::default(),
        grace_until,
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
    if let Some(state) = &mut hub.exit_state {
        state.flush();
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

fn translate_key(mut key: FlowKey, from: Ipv4Addr, to: Ipv4Addr) -> FlowKey {
    if key.source == from {
        key.source = to;
    }
    if key.destination == from {
        key.destination = to;
    }
    key
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
