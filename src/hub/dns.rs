//! DNS that follows the exit, inside the hub: UDP/53 datagrams from the
//! client TUN are answered by the exit that would carry the traffic to the
//! name. A VPN exit resolves in `svpn server` over the control channel, the
//! local exit through the WAN resolvers. The exit of a name the hub does not
//! remember is read off a first answer (the probe), and the name is asked
//! again through the exit that answer's first address belongs to.
//!
//! The cache keeps every answer for exactly the TTL it carried and counts
//! that TTL down for the clients it serves. Past the TTL the answer is kept
//! for a while longer and served only when asking the exit fails.

use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use tokio::{task::JoinSet, time::Instant};

use crate::{
    control::{DNS_VERSION, Message, VERSION},
    dns::{self, relay, wire},
    link_io::{Delivery, Epoch, Event, Packet},
    packet::{self, FlowKey},
    sticky::{ResolvedVia, Selector},
};

use super::{Hub, Route};

/// Epoch of local-exit answers: the proxy has no link.
const LOCAL: Epoch = Epoch {
    link: usize::MAX,
    generation: 1,
};
/// The hub's own wait for one leg: `relay::BUDGET` and the queues around it.
const DEADLINE: Duration = Duration::from_millis(2500);
/// After a failed attempt the cache answers this key itself for this long,
/// so that a dead exit costs one timeout and not one per query.
const HOLD: Duration = Duration::from_secs(5);
/// Past its TTL an answer is kept this long, for when asking fails.
const STALE: Duration = Duration::from_secs(3600);
/// No record of an answer served past its TTL promises more than this.
const STALE_TTL: u32 = 30;
/// Queries in flight at once; the next one is answered by the cache.
const MAX_PENDING: usize = 256;
/// Stubs waiting on one flight; past it a datagram is dropped, and the stub
/// asks again.
const MAX_CLIENTS: usize = 32;
/// Cached answers and remembered names; past it the oldest entries go.
const MAX_CACHE: usize = 4096;

/// Where a name resolves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Local,
    Link(Epoch),
}

impl Exit {
    fn epoch(self) -> Epoch {
        match self {
            Self::Local => LOCAL,
            Self::Link(epoch) => epoch,
        }
    }
}

/// Counters of the periodic stats report.
#[derive(Default)]
pub struct DnsStats {
    pub queries: u64,
    pub cache_hits: u64,
    /// Answers served past their TTL because asking failed.
    pub stale: u64,
    /// Names asked a second time: the first answer named another exit.
    pub moved: u64,
    pub failed: u64,
}

/// One stub datagram waiting for its reply.
struct Client {
    /// Source of the query in the client TUN.
    source: Ipv4Addr,
    /// The resolver the stub asked: the reply's source address.
    resolver: Ipv4Addr,
    port: u16,
    query: wire::Query,
}

/// What every stub of one flight shares: the first stub's message, as it
/// goes upstream.
struct Request {
    /// Cache and flight key: the message with id zeroed and qname lowercased.
    key: Vec<u8>,
    wire: Vec<u8>,
    /// Lowercased wire qname.
    name: Vec<u8>,
    qtype: u16,
}

struct Pending {
    request: Request,
    clients: Vec<Client>,
    /// Exit of the leg in flight.
    via: Exit,
    /// The name was asked again; the next answer is final.
    second: bool,
    /// The first answer while the second leg is in flight.
    spare: Option<Vec<u8>>,
    deadline: Instant,
}

impl Pending {
    /// A stub joins the flight and gets its answer — unless too many are
    /// already waiting: then its datagram is dropped and the stub asks again.
    fn join(&mut self, client: Client, drops: &Delivery) {
        if self.clients.len() < MAX_CLIENTS {
            self.clients.push(client);
        } else {
            drops.dropped();
        }
    }
}

struct Cached {
    /// The answer as the exit gave it; `None` for a failure with nothing older.
    answer: Option<Vec<u8>>,
    /// When the answer arrived: its TTLs count down from here.
    at: Instant,
    /// End of the answer's own TTL; after it the answer is only served when
    /// asking fails.
    until: Instant,
    /// A fresh attempt failed: until this instant the cache answers alone.
    failed: Option<Instant>,
}

impl Cached {
    /// A failure with nothing to serve.
    fn tombstone(now: Instant) -> Self {
        Self {
            answer: None,
            at: now,
            until: now,
            failed: Some(now + HOLD),
        }
    }

    /// Whether the entry still has something to give.
    fn live(&self, now: Instant) -> bool {
        match self.answer {
            Some(_) => now <= self.until + STALE,
            None => self.failed.is_some_and(|until| until > now),
        }
    }
}

/// What the cache says about one query.
enum Verdict {
    /// Inside its TTL: the answer, with TTLs counted down.
    Fresh(Vec<u8>),
    /// Asking failed a moment ago: the kept answer with short TTLs, or
    /// nothing at all.
    Held(Option<Vec<u8>>),
    /// The exit has to be asked.
    Ask,
}

#[derive(Default)]
pub struct DnsState {
    /// `dns { mode = "exit" }`.
    pub on: bool,
    pub stats: DnsStats,
    /// Resolvers of the local exit, as sockets.
    local: Vec<SocketAddr>,
    /// Device the local exit's queries leave through; unknown until the
    /// client TUN is up.
    wan: Option<String>,
    /// Links whose server speaks only the plain control version.
    legacy: HashSet<usize>,
    /// No exit can resolve right now: UDP/53 is passed through, as without
    /// the mode.
    idle: bool,
    cache: HashMap<Vec<u8>, Cached>,
    /// qname → the exit its addresses last went to, as long as that answer
    /// is kept.
    names: HashMap<Vec<u8>, (Exit, Instant)>,
    flights: HashMap<Vec<u8>, u64>,
    pending: HashMap<u64, Pending>,
    /// Client TUN writes waiting for the hub loop.
    replies: Vec<(Arc<Delivery>, Packet)>,
    tasks: JoinSet<()>,
    next_id: u64,
}

impl DnsState {
    pub fn new(settings: &dns::Settings) -> Self {
        let files = [relay::RESOLV_CONF, relay::OPENWRT_RESOLV];
        let found = relay::local_nameservers(&settings.local, &files);
        let local = relay::sockets(&found);
        if local.is_empty() {
            crate::warn!(
                "dns: local exit has no resolvers — set dns.local; its names resolve through VPN exits"
            );
        } else {
            let list: Vec<String> = found.iter().map(ToString::to_string).collect();
            crate::info!("dns: local exit resolves through {}", list.join(", "));
        }
        Self {
            on: true,
            local,
            idle: true,
            ..Self::default()
        }
    }
}

impl Hub {
    /// Whether link `index` asks its server for DNS relay.
    pub fn dns_asks(&self, index: usize) -> bool {
        self.dns.on && !self.dns.legacy.contains(&index)
    }

    /// The client TUN exists: the local exit's queries leave through `device`.
    pub fn dns_set_wan(&mut self, device: Option<String>) {
        self.dns.wan = device;
    }

    /// The resolvers the local exit asks, as sockets.
    pub fn dns_set_resolvers(&mut self, resolvers: Vec<SocketAddr>) {
        self.dns.local = resolvers;
    }

    /// A link reached Ready. A server too old for DNS relay is named once
    /// and stops being asked.
    pub fn dns_ready(&mut self, link: usize) {
        if !self.dns.on || self.links[link].resolver.get().is_some() {
            return;
        }
        if self.dns.legacy.insert(link) {
            crate::warn!(
                "dns[{}]: server speaks control v{VERSION}, not v{DNS_VERSION} — this exit cannot resolve until svpn on the server is updated",
                self.links[link].params.server
            );
        }
    }

    /// UDP/53 from the client TUN; `true` once the hub takes the datagram,
    /// `false` leaves it to ordinary routing.
    pub fn dns_packet(&mut self, flow: &FlowKey, bytes: &[u8]) -> bool {
        if !self.dns.on
            || flow.protocol != 17
            || flow.destination_port != dns::PORT
            || !self.dns_serving()
        {
            return false;
        }
        let Some(query) = packet::udp_payload(bytes).and_then(wire::Query::parse) else {
            return false;
        };
        self.dns.stats.queries += 1;
        let client = Client {
            source: flow.source,
            resolver: flow.destination,
            port: flow.source_port,
            query,
        };
        let key = client.query.key().to_vec();
        if let Some(&id) = self.dns.flights.get(&key)
            && let Some(pending) = self.dns.pending.get_mut(&id)
        {
            pending.join(client, &self.links[0].delivery);
            return true;
        }
        match self.dns_cached(&key) {
            Verdict::Ask => {}
            Verdict::Fresh(answer) => {
                self.dns.stats.cache_hits += 1;
                self.dns_reply(client, Some(&answer));
                return true;
            }
            Verdict::Held(answer) => {
                self.dns.stats.stale += u64::from(answer.is_some());
                self.dns_reply(client, answer.as_deref());
                return true;
            }
        }
        let request = Request {
            key: key.clone(),
            wire: client.query.wire().to_vec(),
            name: client.query.name().to_vec(),
            qtype: client.query.qtype,
        };
        // A name the rules or memory already place goes straight to its exit;
        // an unknown one is probed through the default VPN exit.
        let known = self
            .dns_block_exit(&request.name)
            .or_else(|| self.dns_known_exit(&request.name));
        let via = match known {
            Some(via) => Some(via),
            None => self.dns_probe_exit(),
        };
        let Some(id) = via.and_then(|via| self.dns_ask(via, request)) else {
            // Nowhere to ask: the same answer a failed exit gets.
            self.dns.stats.failed += 1;
            let answer = self.dns_failed(&key);
            self.dns.stats.stale += u64::from(answer.is_some());
            self.dns_reply(client, answer.as_deref());
            return true;
        };
        if let Some(pending) = self.dns.pending.get_mut(&id) {
            pending.join(client, &self.links[0].delivery);
        }
        true
    }

    /// The answer to leg `id` of a flight; `None` when the exit had none.
    pub fn dns_answer(&mut self, epoch: Epoch, id: u64, answer: Option<Vec<u8>>) {
        let Some(mut pending) = self.dns.pending.remove(&id) else {
            return;
        };
        if pending.via.epoch() != epoch {
            self.dns.pending.insert(id, pending);
            return;
        }
        if pending.second {
            let exit = answer.is_some().then_some(pending.via);
            let answer = answer.or(pending.spare.take());
            return self.dns_finish(pending, answer, exit);
        }
        let Some(first) = answer else {
            return self.dns_finish(pending, None, None);
        };
        // Where the first address of the name goes now.
        let owner = (pending.request.qtype == 1)
            .then(|| wire::addresses(&first).first().copied())
            .flatten()
            .and_then(|ip| self.dns_exit_for(ip));
        if let Some(owner) = owner.filter(|owner| *owner != pending.via)
            && self.dns_capable(owner)
            && self.dns_send(owner, id, &pending.request.wire)
        {
            self.dns.stats.moved += 1;
            self.dns.flights.insert(pending.request.key.clone(), id);
            pending.via = owner;
            pending.second = true;
            pending.spare = Some(first);
            pending.deadline = Instant::now() + DEADLINE;
            self.dns.pending.insert(id, pending);
            return;
        }
        let exit = (owner == Some(pending.via)).then_some(pending.via);
        self.dns_finish(pending, Some(first), exit);
    }

    /// When the oldest flight runs out of patience, if any is waiting.
    pub fn dns_deadline(&self) -> Option<Instant> {
        self.dns
            .pending
            .values()
            .map(|pending| pending.deadline)
            .min()
    }

    /// Flights whose wait is over end like a failed exit; the first answer
    /// of a second leg is used when there is one.
    pub fn dns_expire(&mut self) {
        let now = Instant::now();
        self.dns_abandon(|pending| pending.deadline <= now);
    }

    /// A link is gone: its flights end the same way, without waiting.
    pub fn dns_link_failed(&mut self, epoch: Epoch) {
        self.dns_abandon(|pending| pending.via.epoch() == epoch);
    }

    fn dns_abandon(&mut self, flight: impl Fn(&Pending) -> bool) {
        let due: Vec<u64> = self
            .dns
            .pending
            .iter()
            .filter(|(_, pending)| flight(pending))
            .map(|(&id, _)| id)
            .collect();
        for id in due {
            if let Some(mut pending) = self.dns.pending.remove(&id) {
                let spare = pending.spare.take();
                self.dns_finish(pending, spare, None);
            }
        }
    }

    /// Client TUN writes queued since the last call.
    pub fn dns_replies(&mut self) -> Vec<(Arc<Delivery>, Packet)> {
        std::mem::take(&mut self.dns.replies)
    }

    /// Whether an exit can resolve. Flips are logged: the mode changes what
    /// happens to every UDP/53 datagram of the client TUN.
    fn dns_serving(&mut self) -> bool {
        let serving = (0..self.links.len()).any(|link| {
            self.pool
                .ready_epoch(link)
                .is_some_and(|_| self.links[link].resolver.get().is_some())
        });
        if serving == self.dns.idle {
            self.dns.idle = !serving;
            if serving {
                crate::info!("dns: on — UDP/53 from the client TUN resolves at the exit");
            } else {
                crate::warn!(
                    "dns: no exit can resolve — UDP/53 passes through until a server speaks control v{DNS_VERSION}"
                );
            }
        }
        serving
    }

    /// Whether the exit can be asked to resolve.
    fn dns_capable(&self, exit: Exit) -> bool {
        match exit {
            Exit::Local => {
                !self.dns.local.is_empty()
                    && self.dns.wan.is_some()
                    && self.local.as_ref().is_some_and(|local| local.ready)
            }
            Exit::Link(epoch) => {
                self.pool.is_ready(epoch) && self.links[epoch.link].resolver.get().is_some()
            }
        }
    }

    /// The exit a new flow to `ip` takes now: the decision `open_flow`
    /// makes, without the flow.
    fn dns_exit_for(&mut self, ip: Ipv4Addr) -> Option<Exit> {
        match self.route_of(ip) {
            Route::Local(_) => self
                .local
                .as_ref()
                .filter(|local| local.ready)
                .map(|_| Exit::Local),
            Route::Sticky(index) => self.pick_sticky(index).0.map(Exit::Link),
            Route::Auto => self
                .pick(&FlowKey {
                    protocol: 17,
                    source: Ipv4Addr::UNSPECIFIED,
                    source_port: 0,
                    destination: ip,
                    destination_port: 0,
                })
                .0
                .map(Exit::Link),
        }
    }

    /// Exit of the first `names` block the name is listed in.
    fn dns_block_exit(&mut self, name: &[u8]) -> Option<Exit> {
        let index = self
            .stickies
            .iter()
            .position(|sticky| match &sticky.block.selector {
                Selector::Names(names) => names.iter().any(|text| wire::is_name(name, text)),
                _ => false,
            })?;
        match &self.sticky_via[index] {
            ResolvedVia::Local => self
                .local
                .as_ref()
                .filter(|local| local.ready)
                .map(|_| Exit::Local),
            ResolvedVia::Links(_) => self.pick_sticky(index).0.map(Exit::Link),
        }
    }

    fn dns_known_exit(&self, name: &[u8]) -> Option<Exit> {
        let &(exit, until) = self.dns.names.get(name)?;
        (until > Instant::now()).then_some(exit)
    }

    /// The VPN exit an unknown name is probed through: the one traffic to
    /// nobody's address takes, else the first ready one that can resolve.
    fn dns_probe_exit(&mut self) -> Option<Exit> {
        match self.dns_exit_for(Ipv4Addr::UNSPECIFIED) {
            Some(exit @ Exit::Link(_)) if self.dns_capable(exit) => Some(exit),
            _ => (0..self.links.len()).find_map(|link| {
                self.pool
                    .ready_epoch(link)
                    .filter(|_| self.links[link].resolver.get().is_some())
                    .map(Exit::Link)
            }),
        }
    }

    /// Start a flight through `via`; `None` when the exit cannot be asked.
    fn dns_ask(&mut self, via: Exit, request: Request) -> Option<u64> {
        if self.dns.pending.len() >= MAX_PENDING {
            return None;
        }
        let id = self.dns.next_id;
        self.dns.next_id = self.dns.next_id.wrapping_add(1);
        if !self.dns_send(via, id, &request.wire) {
            return None;
        }
        self.dns.flights.insert(request.key.clone(), id);
        self.dns.pending.insert(
            id,
            Pending {
                request,
                clients: Vec::new(),
                via,
                second: false,
                spare: None,
                deadline: Instant::now() + DEADLINE,
            },
        );
        Some(id)
    }

    /// Put one query in front of the exit without waiting on any queue.
    fn dns_send(&mut self, via: Exit, id: u64, wire: &[u8]) -> bool {
        match via {
            Exit::Link(epoch) => self.links[epoch.link]
                .resolver
                .get()
                .is_some_and(|resolver| {
                    resolver.try_send(Message::DnsQuery {
                        id,
                        data: dns::encode(wire),
                    })
                }),
            Exit::Local => self.dns_local(id, wire),
        }
    }

    fn dns_local(&mut self, id: u64, wire: &[u8]) -> bool {
        let Some(permit) = relay::acquire() else {
            return false;
        };
        let resolvers = self.dns.local.clone();
        let device = self.dns.wan.clone();
        let events = self.events.clone();
        let wire = wire.to_vec();
        self.dns.tasks.spawn(async move {
            let _permit = permit;
            let answer = relay::exchange(&resolvers, device.as_deref(), &wire, relay::BUDGET).await;
            let _ = events.send((LOCAL, Event::DnsAnswer { id, answer })).await;
        });
        true
    }

    /// End one flight: a good answer is kept for the lifetime it names and
    /// goes to every stub; a failed one leaves the cache to answer.
    fn dns_finish(&mut self, mut pending: Pending, answer: Option<Vec<u8>>, exit: Option<Exit>) {
        self.dns.flights.remove(&pending.request.key);
        // A resolver failure is no answer when the cache kept an older one.
        let servfail = answer
            .as_ref()
            .is_some_and(|answer| wire::rcode(answer) == Some(wire::SERVFAIL));
        let answer = match (servfail, self.dns_kept(&pending.request.key)) {
            (true, true) => None,
            _ => answer,
        };
        // The bytes did come down that exit; a failure came from nowhere.
        let delivery = match pending.via {
            Exit::Link(epoch) => self.links[epoch.link].delivery.clone(),
            Exit::Local => self
                .local
                .as_ref()
                .map(|local| local.delivery.clone())
                .unwrap_or_else(|| self.links[0].delivery.clone()),
        };
        // A negative answer carries its caching lifetime in its SOA's TTL.
        let answer = answer.map(|answer| wire::normalised(&answer).unwrap_or(answer));
        let stale = match &answer {
            Some(answer) => {
                if let Some(lifetime) = wire::lifetime(answer) {
                    let until = Instant::now() + lifetime;
                    self.dns_remember(pending.request.key.clone(), answer, until);
                    // The exit is remembered as long as the answer is kept:
                    // asking it first costs one leg when it is still right.
                    if let Some(exit) = exit {
                        self.dns
                            .names
                            .insert(pending.request.name.clone(), (exit, until + STALE));
                    }
                }
                None
            }
            None => {
                self.dns.stats.failed += 1;
                let stale = self.dns_failed(&pending.request.key);
                self.dns.stats.stale += u64::from(stale.is_some());
                stale
            }
        };
        for client in pending.clients.drain(..) {
            let answer = answer.as_deref().or(stale.as_deref());
            self.dns_push(&client, answer, &delivery);
        }
    }

    /// Keep one answer until `until`; full tables drop what is closest to
    /// its end first.
    fn dns_remember(&mut self, key: Vec<u8>, answer: &[u8], until: Instant) {
        let now = Instant::now();
        make_room(
            &mut self.dns.cache,
            |cached| !cached.live(now),
            |cached| (cached.until, cached.at),
        );
        make_room(
            &mut self.dns.names,
            |(_, until)| *until <= now,
            |(_, until)| (*until, *until),
        );
        self.dns.cache.insert(
            key,
            Cached {
                answer: Some(answer.to_vec()),
                at: now,
                until,
                failed: None,
            },
        );
    }

    /// What the cache says about `key`; dead entries are dropped on the way.
    fn dns_cached(&mut self, key: &[u8]) -> Verdict {
        let now = Instant::now();
        let dead = self
            .dns
            .cache
            .get(key)
            .is_some_and(|cached| !cached.live(now));
        if dead {
            self.dns.cache.remove(key);
        }
        let Some(cached) = self.dns.cache.get(key) else {
            return Verdict::Ask;
        };
        if cached.failed.is_some_and(|until| until > now) {
            return Verdict::Held(
                cached
                    .answer
                    .as_ref()
                    .and_then(|answer| wire::short_lived(answer, STALE_TTL)),
            );
        }
        let aged = cached
            .answer
            .as_ref()
            .filter(|_| cached.until > now)
            .and_then(|answer| wire::aged(answer, now - cached.at));
        match aged {
            Some(answer) => Verdict::Fresh(answer),
            None => Verdict::Ask,
        }
    }

    /// Whether the cache still holds an older answer for `key`.
    fn dns_kept(&self, key: &[u8]) -> bool {
        let now = Instant::now();
        self.dns
            .cache
            .get(key)
            .is_some_and(|cached| cached.answer.is_some() && now <= cached.until + STALE)
    }

    /// A fresh attempt failed. The entry remembers that for `HOLD`, and the
    /// stubs get what it kept from before: the answer past its TTL with
    /// short TTLs, or nothing.
    fn dns_failed(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let now = Instant::now();
        let cached = self
            .dns
            .cache
            .entry(key.to_vec())
            .or_insert_with(|| Cached::tombstone(now));
        cached.failed = Some(now + HOLD);
        if cached.answer.is_some() && now <= cached.until + STALE {
            cached
                .answer
                .as_ref()
                .and_then(|answer| wire::short_lived(answer, STALE_TTL))
        } else {
            cached.answer = None;
            None
        }
    }

    /// A reply that needed no exit: from the cache, or a refusal.
    fn dns_reply(&mut self, client: Client, answer: Option<&[u8]>) {
        let delivery = self.links[0].delivery.clone();
        self.dns_push(&client, answer, &delivery);
    }

    fn dns_push(&mut self, client: &Client, answer: Option<&[u8]>, delivery: &Arc<Delivery>) {
        let limit = client
            .query
            .limit
            .min(self.links[0].params.mtu.saturating_sub(28));
        let reply = match answer {
            None => client.query.error(wire::SERVFAIL, false),
            Some(answer) => client
                .query
                .reply(answer)
                .filter(|reply| reply.len() <= usize::from(limit))
                .unwrap_or_else(|| client.query.truncated()),
        };
        let datagram = packet::udp_datagram(
            SocketAddrV4::new(client.resolver, dns::PORT),
            SocketAddrV4::new(client.source, client.port),
            &reply,
        );
        match datagram {
            Some(bytes) => self
                .dns
                .replies
                .push((delivery.clone(), Packet { id: 0, bytes })),
            None => delivery.dropped(),
        }
    }
}

/// Make room in a full table: dead entries go, then the one closest to its
/// end. `end` orders by (end, arrival), so the longest-lived entry stays.
fn make_room<V>(
    table: &mut HashMap<Vec<u8>, V>,
    dead: impl Fn(&V) -> bool,
    end: impl Fn(&V) -> (Instant, Instant),
) {
    if table.len() < MAX_CACHE {
        return;
    }
    table.retain(|_, value| !dead(value));
    while table.len() >= MAX_CACHE {
        let oldest = table
            .iter()
            .min_by_key(|(_, value)| end(value))
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            table.remove(&oldest);
        } else {
            break;
        }
    }
}
