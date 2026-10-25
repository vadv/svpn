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
    direct::icmp::IcmpEngine,
    direct::{DirectConfig, DirectEngine, DirectEvent, Uplink},
    hooks::Hooks,
    link_io::{Delivery, Epoch, Event, LinkIo, Packet},
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
}

/// A destination country with assigned servers: the candidates constraint
/// of spec §3. Country is the constraint, ASN — when covered by the ASN
/// database — the affinity inside it.
struct CountryRoute {
    /// Packed ISO code — the rendezvous key payload.
    packed: u32,
    /// Links configured for the country, in configuration order.
    candidates: Vec<usize>,
    /// Destination ASN when the ASN database covers it.
    asn: Option<u32>,
}

impl CountryRoute {
    /// The typed persistence key (spec §4): a scoped `CC:ASN` key keeps its
    /// country, a bare country key otherwise.
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
    /// Packed home country for direct admission; None — direct disabled.
    pub home_country: Option<u32>,
    /// Captured physical uplink (spec §5.1); None — direct disabled.
    pub uplink: Option<Uplink>,
    /// Direct TCP/UDP engine, started at the first Ready with the live TUN
    /// identity; a TCP/UDP init failure stops startup (spec §2).
    pub direct: Option<DirectEngine>,
    /// Direct ICMP sibling (spec §5.4); its init failure is ICMP-only and
    /// warning-graded — home ICMP never falls back to the VPN.
    pub icmp: Option<IcmpEngine>,
    /// Stable node ids (configured `server` strings) and weights, for rendezvous.
    pub nodes: Vec<(String, u32)>,
    /// Sticky owners: group key → link index. An alive owner keeps its group
    /// (no snap-back); reassigned only when the owner cannot serve new flows.
    pub exit_owners: std::collections::HashMap<u64, usize>,
    /// Failover persistence; None in balance mode.
    pub exit_state: Option<crate::exit_state::ExitState>,
    /// Sticky exit counters, surfaced in the periodic stats report.
    pub sticky: StickyStats,
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

/// What dispatching one client packet produced for the TUN: a synthesized
/// CLOSED reset for an unowned TCP tuple, or a direct-engine packet (a
/// rewritten segment or a rebuilt reply).
#[derive(Debug, PartialEq)]
pub enum Dispatched {
    Reset([u8; 40]),
    Direct(Vec<u8>),
}

impl Hub {
    /// Returns a CLOSED-endpoint reset for unowned or tombstoned TCP traffic.
    ///
    /// Dispatch order (spec §5.5): reverse-NAT of kernel listener packets,
    /// the current owner (remote or direct), retired tuples, and only then
    /// the classification of a new flow — home country before any VPN
    /// owner (spec §3.1).
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
        // Kernel listener packets of the direct NAT (spec §5.2) map back to
        // the original tuple before any admission: a reverse SYN-ACK never
        // reaches unowned flow classification.
        if let Some(engine) = &self.direct
            && let Some(rewritten) = engine.rewrite_reverse(bytes)
        {
            return Ok(Some(Dispatched::Direct(rewritten)));
        }
        let now = StdInstant::now();
        if self.tombstones.active(&parsed.flow, now) {
            return Ok(self
                .tombstones
                .respond(&parsed.flow, &parsed, now)
                .map(Dispatched::Reset));
        }
        match self.routes.by_key.get(&parsed.flow) {
            Some(Target::Direct(id)) => self.forward_direct(*id, parsed.flow, bytes).await,
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

    /// Classification of a new flow: a home-country destination opens a
    /// direct flow and never falls back to the VPN; everything else picks
    /// the remote owner exactly as before.
    async fn open_flow(
        &mut self,
        parsed: &packet::Packet,
        bytes: &[u8],
        client_ip: Ipv4Addr,
    ) -> Result<Option<Dispatched>> {
        let key = parsed.flow;
        if self.is_home(key.destination) {
            return self.open_direct(parsed, bytes).await;
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

    /// Opens a home-country flow on the direct engines. The owner table
    /// gets a `Target::Direct` only when the engine accepted the flow; an
    /// engine that is unavailable or full drops the packet — the home
    /// country must never leak into the VPN (spec §3.1).
    async fn open_direct(
        &mut self,
        parsed: &packet::Packet,
        bytes: &[u8],
    ) -> Result<Option<Dispatched>> {
        let key = parsed.flow;
        let id = self.routes.allocate()?;
        let (accepted, rewritten) = match key.protocol {
            6 => match &mut self.direct {
                Some(engine) => match engine.open_tcp(id, parsed, bytes) {
                    Ok(rewritten) => (true, rewritten),
                    Err(error) => {
                        crate::error!("vpn: dropped packet — direct open: {error:#}");
                        (false, None)
                    }
                },
                None => {
                    crate::error!(
                        "vpn: dropped packet — direct TCP engine unavailable, no VPN fallback"
                    );
                    (false, None)
                }
            },
            17 => match &mut self.direct {
                Some(engine) => match engine.open_udp(id, parsed, bytes).await {
                    Ok(()) => (true, None),
                    Err(error) => {
                        crate::error!("vpn: dropped packet — direct open: {error:#}");
                        (false, None)
                    }
                },
                None => {
                    crate::error!(
                        "vpn: dropped packet — direct UDP engine unavailable, no VPN fallback"
                    );
                    (false, None)
                }
            },
            // ICMP raw sockets need a privilege the startup may not have:
            // ICMP-only degradation, never a VPN fallback (spec §5.4).
            _ => match &mut self.icmp {
                Some(engine) => match engine.open_icmp(id, parsed, bytes).await {
                    Ok(()) => (true, None),
                    Err(error) => {
                        crate::error!("vpn: dropped packet — direct icmp open: {error:#}");
                        (false, None)
                    }
                },
                None => {
                    crate::error!("vpn: dropped packet — direct icmp unavailable, no VPN fallback");
                    (false, None)
                }
            },
        };
        if accepted {
            self.routes.by_key.insert(key, Target::Direct(id));
        }
        Ok(rewritten.map(Dispatched::Direct))
    }

    /// An established direct flow: later packets go to the engine. A
    /// network error closes only this flow — the engine reports the close
    /// itself through the reliable channel (spec §5.3, §5.4).
    async fn forward_direct(
        &mut self,
        id: u64,
        key: FlowKey,
        bytes: &[u8],
    ) -> Result<Option<Dispatched>> {
        let result: Result<Option<Vec<u8>>> = match key.protocol {
            6 => self
                .direct
                .as_mut()
                .context("direct engine missing for an established TCP flow")?
                .forward_tcp(id, bytes),
            17 => self
                .direct
                .as_mut()
                .context("direct engine missing for an established UDP flow")?
                .forward_udp(id, bytes)
                .await
                .map(|()| None),
            _ => self
                .icmp
                .as_mut()
                .context("direct icmp engine missing for an established ICMP flow")?
                .forward_icmp(id, bytes)
                .await
                .map(|()| None),
        };
        match result {
            Ok(rewritten) => Ok(rewritten.map(Dispatched::Direct)),
            Err(error) => {
                crate::error!("vpn: dropped packet — direct flow {key:?}: {error:#}");
                Ok(None)
            }
        }
    }

    /// One event from the direct engines: returned packets are written into
    /// the TUN; a close reconciles the owner table — only the still-current
    /// generation may tombstone the tuple (spec §5.5).
    pub async fn handle_direct_event(
        &mut self,
        event: DirectEvent,
        tun: &mut Option<AsyncDevice>,
    ) -> Result<()> {
        match event {
            DirectEvent::Packet { id, bytes } => {
                // A queued reply from an old generation must not be written
                // into a replacement flow (or after its close).
                let current = packet::parse(&bytes, true).is_some_and(|packet| {
                    matches!(self.routes.by_key.get(&packet.flow), Some(Target::Direct(current)) if *current == id)
                });
                if !current {
                    return Ok(());
                }
                let tun = tun.as_ref().context("direct packet without client TUN")?;
                let result =
                    tokio::time::timeout(Duration::from_millis(100), tun.send(&bytes)).await;
                match result {
                    Ok(Ok(written)) if written == bytes.len() => {}
                    Err(_) => {
                        crate::error!("vpn: dropped packet — client TUN write timeout")
                    }
                    Ok(result) => {
                        crate::error!("vpn: dropped packet — failed client TUN write");
                        ensure!(
                            result.context("write client TUN")? == bytes.len(),
                            "short client TUN write"
                        );
                    }
                }
            }
            DirectEvent::Closed { id, key } => {
                // Only TCP tuples get a CLOSED-endpoint reply; UDP and ICMP
                // flows just vanish (same as a retired remote epoch).
                if self.routes.forget_direct(key, id) && key.protocol == 6 {
                    self.tombstones.insert(key, StdInstant::now());
                }
            }
        }
        Ok(())
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
                    // The direct engines start with the live TUN identity,
                    // immediately after creation and before user hooks change
                    // the routing view (spec §5.1).
                    self.start_direct(&name, tun_addr, peer_addr, params.mtu)
                        .await?;
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
        // An assigned country constrains candidates before any ASN
        // affinity (spec §3): a constrained flow never spills to a
        // non-candidate exit, even under exit-policy=balance.
        if let Some(route) = self.country_route(key.destination) {
            let group = match route.asn {
                Some(asn) => crate::geo::scoped_asn_key(route.packed, asn),
                None => crate::geo::country_key(route.packed),
            };
            return self.sticky_epoch(group, Some(&route.candidates), route.exit_key());
        }
        let Some(geo) = &self.geo else {
            return self.pool.pick();
        };
        let Some(asn) = geo.lookup(key.destination) else {
            // Uncovered /32: deterministic stateless rendezvous, never
            // recorded in exit_owners or persisted (spec: no /32 overrides).
            self.sticky.lookup_miss += 1;
            return crate::geo::rendezvous(crate::geo::ip_key(key.destination), &self.nodes)
                .into_iter()
                .find_map(|link| self.pool.ready_epoch(link));
        };
        let group = crate::geo::asn_key(asn);
        self.sticky_epoch(group, None, crate::exit_state::ExitKey::Asn(asn))
    }

    /// The destination's country when servers are assigned to it (spec
    /// §3): a constraint on candidates. An unassigned country and a
    /// database miss are no constraint — the global sticky-ASN or balance
    /// selection applies unchanged.
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

    /// Sticky owner of `group`: an alive owner keeps the group (no
    /// snap-back), a Checking owner keeps it while a reserve serves new
    /// flows, a restored owner still connecting holds the group through
    /// the startup grace, then the group fails over inside `candidates`
    /// and the deviation is persisted under `key`. `None` candidates —
    /// every configured link.
    fn sticky_epoch(
        &mut self,
        group: u64,
        candidates: Option<&[usize]>,
        key: crate::exit_state::ExitKey,
    ) -> Option<Epoch> {
        let serves = |link: usize| candidates.is_none_or(|set| set.contains(&link));
        if let Some(&owner) = self.exit_owners.get(&group) {
            if let Some(epoch) = self.pool.ready_epoch(owner) {
                self.sticky.lookup_hit += 1;
                return Some(epoch);
            }
            // Checking owner keeps its group: serve new flows from a reserve
            // without migrating (spec: no migration on Checking).
            if self.pool.link_checking(owner) {
                self.sticky.lookup_hit += 1;
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
        self.sticky.lookup_miss += 1;
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
            // Baseline — first node of the (restricted) rendezvous order —
            // reproduces itself and needs no disk. Deviations (a failover
            // transition or a first assignment that skipped an unavailable
            // primary) do not, so they are persisted; a restart must not
            // snap back (spec).
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

    /// Starts the direct engines (spec §5): the TCP/UDP engine binds its
    /// kernel listener on the negotiated client address and ensures the
    /// `peer/32` return route — both startup-fatal (spec §2). The ICMP
    /// sibling degrades to a warning: home ICMP never falls back to the
    /// VPN (spec §5.4).
    async fn start_direct(
        &mut self,
        tun_name: &str,
        client: Ipv4Addr,
        peer: Ipv4Addr,
        mtu: u16,
    ) -> Result<()> {
        let Some(uplink) = self.uplink.clone() else {
            return Ok(());
        };
        let config = DirectConfig {
            client,
            peer,
            tun_index: crate::tun::if_index_of(tun_name)?,
            tun_name: tun_name.to_owned(),
            mtu,
            uplink,
        };
        let mut engine = DirectEngine::new(config.clone()).await?;
        if let Err(error) = engine.ensure_peer_route() {
            if let Err(cleanup) = engine.shutdown().await {
                crate::warn!("direct: cleanup after route setup failure failed — {cleanup:#}");
            }
            return Err(error);
        }
        self.direct = Some(engine);
        match IcmpEngine::new(config).await {
            Ok(engine) => self.icmp = Some(engine),
            Err(error) => {
                crate::warn!("direct icmp unavailable — home ICMP has no VPN fallback — {error:#}")
            }
        }
        Ok(())
    }

    /// Bounded direct teardown (spec §5.5): the engines stop their tasks
    /// within the join budget and remove only the return route they
    /// installed. Runs after the hub tasks and hooks have stopped.
    async fn shutdown_direct(&mut self) -> Result<()> {
        let direct = match self.direct.take() {
            Some(engine) => engine.shutdown().await,
            None => Ok(()),
        };
        let icmp = match self.icmp.take() {
            Some(engine) => engine.shutdown().await,
            None => Ok(()),
        };
        match (direct, icmp) {
            (Err(error), Err(icmp_error)) => {
                crate::warn!("direct icmp: shutdown failed — {icmp_error:#}");
                Err(error)
            }
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
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
                        Some(Dispatched::Direct(bytes)) => {
                            // A direct-engine packet has no per-link delivery
                            // accounting; a loss is logged, never silent.
                            let tun = tun.as_ref().context("direct packet without client TUN")?;
                            let result = tokio::time::timeout(
                                Duration::from_millis(100),
                                tun.send(&bytes),
                            )
                            .await;
                            match result {
                                Ok(Ok(written)) if written == bytes.len() => {}
                                Err(_) => {
                                    crate::error!("vpn: dropped packet — client TUN write timeout")
                                }
                                Ok(result) => {
                                    crate::error!("vpn: dropped packet — failed client TUN write");
                                    ensure!(
                                        result.context("write client TUN")? == bytes.len(),
                                        "short client TUN write"
                                    );
                                }
                            }
                        }
                        None => {}
                    }
                }
                event = self.incoming.recv() => {
                    let (epoch, event) = event.context("server event channel stopped")?;
                    self.handle_event(epoch, event, tun, &params, &mut started, hooks).await?;
                }
                event = async {
                    match self.direct.as_mut() {
                        Some(engine) => engine.recv_event().await,
                        None => std::future::pending::<DirectEvent>().await,
                    }
                }, if self.direct.is_some() => {
                    self.handle_direct_event(event, tun).await?;
                }
                event = async {
                    match self.icmp.as_mut() {
                        Some(engine) => engine.recv_event().await,
                        None => std::future::pending::<DirectEvent>().await,
                    }
                }, if self.icmp.is_some() => {
                    self.handle_direct_event(event, tun).await?;
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

/// Geo-driven exit inputs of one client run (spec §2-4): the ASN affinity
/// table, the country constraint table and the one shared owner state.
#[derive(Default)]
pub struct GeoExits {
    /// ASN database; None — sticky-asn degraded to weighted balance.
    pub geo: Option<crate::geo::Geo>,
    /// Country database; None — no country routing.
    pub country: Option<crate::geo::Geo>,
    /// Packed home country for direct admission; None — direct disabled.
    pub home_country: Option<u32>,
    /// Physical uplink of the IPv4 default route, captured before the hub
    /// runs — before any user hook can change the routing view (spec §5.1);
    /// None — direct disabled.
    pub uplink: Option<Uplink>,
    /// Sticky owner persistence; None — nothing sticky is active.
    pub exit_state: Option<crate::exit_state::ExitState>,
}

/// A restored owner's rendezvous group, or `None` to drop it (spec §4):
/// typed keys map onto disjoint numeric key domains — the persisted
/// strings are never hashed — and a country or scoped owner restores only
/// while its node is still a candidate for the country, so the scoped key
/// keeps its country before the first flow.
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
        uplink,
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
        uplink,
        direct: None,
        icmp: None,
        nodes,
        exit_owners,
        exit_state,
        sticky: StickyStats::default(),
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
    // Direct teardown after the hub tasks and hooks stopped: flow tasks
    // join bounded and the owned return route is removed even on a failed
    // exit (spec §5.5).
    let direct = hub.shutdown_direct().await;
    drop(tun);
    match result {
        Err(error) => {
            if let Err(cleanup) = cleanup {
                crate::error!("hook: cleanup failed — {cleanup:#}");
            }
            if let Err(direct) = direct {
                crate::error!("direct: shutdown failed — {direct:#}");
            }
            Err(error)
        }
        Ok(()) => cleanup.and(direct),
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
