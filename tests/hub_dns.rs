//! DNS that follows the exit inside the hub: what is intercepted, which exit
//! resolves a name, and what the cache does with answers and failures.

mod common;

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::{Arc, OnceLock},
    time::Duration,
};

use common::dns;
use svpn::{
    control::{Control, Message, Stats},
    dns::wire,
    hooks::Hooks,
    hub::*,
    link_io::{self, Epoch, Event},
    local_proxy::LocalServer,
    packet,
    pool::Pool,
    session, sticky,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader, DuplexStream},
    sync::{mpsc, watch},
    task::JoinSet,
};

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
const RESOLVER: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const A: u16 = 1;
/// A TTL no wait of these tests reaches.
const TTL: u32 = 3600;

// ── fixtures ──

fn epoch(link: usize) -> Epoch {
    Epoch {
        link,
        generation: 1,
    }
}

fn params(link: usize) -> svpn::server_spec::LinkParams {
    let mut params = common::link_params(Ipv4Addr::new(192, 0, 2, 1), u32::from(link == 0));
    params.server = format!("link{link}");
    params
}

/// What one link's server was asked.
struct Asked {
    id: u64,
    wire: Vec<u8>,
}

/// A hub in exit mode: every link is Ready and its server relays DNS onto
/// a wire the test reads. The first link takes every automatic choice.
struct Bench {
    hub: Hub,
    /// Each link's control channel, as its server sees it.
    wires: Vec<BufReader<DuplexStream>>,
    /// Ordinary traffic the hub hands each link.
    flows: Vec<mpsc::Receiver<link_io::Packet>>,
    /// Keep the control writers alive.
    _controls: Vec<Control>,
}

impl Bench {
    fn new(count: usize, stickies: Vec<sticky::StickyBlock>) -> Self {
        let (events, incoming) = mpsc::channel(QUEUE);
        let weights = std::iter::once(1).chain(std::iter::repeat_n(0, count - 1));
        let mut pool = Pool::new(weights);
        let now = tokio::time::Instant::now();
        let (mut wires, mut flows, mut controls, mut senders, mut outgoing) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for link in 0..count {
            let (half, wire) = tokio::io::duplex(256 * 1024);
            controls.push(Control::new(tokio::io::empty(), half));
            senders.push(controls[link].sender());
            wires.push(BufReader::new(wire));
            let (sender, forwarded) = mpsc::channel(16);
            outgoing.push(sender);
            flows.push(forwarded);
            pool.ready(epoch(link), now);
        }
        let mut via = Vec::new();
        let mut blocks = Vec::new();
        for block in stickies {
            via.push(match &block.via {
                sticky::Via::Local => sticky::ResolvedVia::Local,
                sticky::Via::Servers(labels) => sticky::ResolvedVia::Links(
                    labels
                        .iter()
                        .map(|label| label.strip_prefix("link").unwrap().parse().unwrap())
                        .collect(),
                ),
            });
            blocks.push(sticky::RuntimeSticky::new(block));
        }
        let hub = Hub {
            policy: svpn::cli::ExitPolicy::Balance,
            sticky_asn_mode: Default::default(),
            links: (0..count)
                .map(|link| Link {
                    params: params(link),
                    outgoing: Some(outgoing.remove(0)),
                    delivery: Arc::default(),
                    epoch: Some(epoch(link)),
                    latest: None,
                    stats: Default::default(),
                    last_reason: String::new(),
                    assigned: Arc::default(),
                    resolver: Arc::new(OnceLock::from(senders[link].clone())),
                })
                .collect(),
            pool,
            geo: None,
            country: None,
            stickies: blocks,
            sticky_via: via,
            sticky_updates: None,
            sticky_task: None,
            job_events: None,
            job_task: None,
            job_stats: JobStats::default(),
            geo_path: None,
            country_path: None,
            geo_pending: None,
            country_pending: None,
            local: None,
            local_cleanup: None,
            nodes: (0..count)
                .map(|link| (format!("link{link}"), u32::from(link == 0)))
                .collect(),
            exit_owners: Default::default(),
            sticky: StickyStats::default(),
            local_stats: Default::default(),
            tasks: JoinSet::new(),
            events,
            incoming,
            routes: Routes::default(),
            tombstones: session::Tombstones::default(),
            pair: watch::channel(None).0,
            history: None,
            history_prev: None,
            history_ts: None,
            dns: DnsState::new(&Default::default()),
            telegram: None,
        };
        Self {
            hub,
            wires,
            flows,
            _controls: controls,
        }
    }

    /// What `link`'s server was asked.
    async fn asked(&mut self, link: usize) -> Asked {
        let mut line = String::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            self.wires[link].read_line(&mut line),
        )
        .await
        .expect("no query reached the link in time")
        .expect("the control channel closed");
        let Message::DnsQuery { id, data } = serde_json::from_str(&line).unwrap() else {
            panic!("not a dns_query: {line}");
        };
        Asked {
            id,
            wire: svpn::dns::decode(&data).unwrap(),
        }
    }

    /// `link`'s server answers; the client replies that produces.
    async fn answer(&mut self, link: usize, id: u64, answer: Option<Vec<u8>>) -> Vec<Vec<u8>> {
        self.hub
            .events
            .send((epoch(link), Event::DnsAnswer { id, answer }))
            .await
            .unwrap();
        self.settle().await
    }

    /// Run everything queued for the hub; the client replies it wrote.
    async fn settle(&mut self) -> Vec<Vec<u8>> {
        let params = self.hub.links[0].params.clone();
        let (mut tun, mut started, mut hooks) = (None, None, Hooks::default());
        while let Ok((epoch, event)) = self.hub.incoming.try_recv() {
            self.hub
                .handle_event(epoch, event, &mut tun, &params, &mut started, &mut hooks)
                .await
                .unwrap();
        }
        self.hub
            .dns_replies()
            .into_iter()
            .map(|(_, packet)| packet.bytes)
            .collect()
    }

    /// A stub's query enters the client TUN; the replies written on the spot.
    async fn query(&mut self, datagram: &[u8]) -> Vec<Vec<u8>> {
        assert!(self.hub.dispatch(datagram, CLIENT).unwrap().is_none());
        self.settle().await
    }

    /// Ask for `host` through link 0 and let its server answer one address.
    async fn resolve(&mut self, host: &str, address: [u8; 4]) {
        let datagram = datagram(1, host, 40000, None);
        assert!(self.query(&datagram).await.is_empty());
        let asked = self.asked(0).await;
        let answer = dns::addressed(&asked.wire, TTL, &[address]);
        self.answer(0, asked.id, Some(answer)).await;
    }
}

/// A stub's UDP/53 datagram for `host`; `port` and `id` tell stubs apart.
fn datagram(id: u16, host: &str, port: u16, edns: Option<u16>) -> Vec<u8> {
    packet::udp_datagram(
        SocketAddrV4::new(CLIENT, port),
        SocketAddrV4::new(RESOLVER, svpn::dns::PORT),
        &dns::query(id, host, A, edns),
    )
    .unwrap()
}

/// The DNS message inside a client reply.
fn message(datagram: &[u8]) -> &[u8] {
    packet::udp_payload(datagram).unwrap()
}

fn id(datagram: &[u8]) -> u16 {
    u16::from_be_bytes([message(datagram)[0], message(datagram)[1]])
}

/// (Resolver address, stub port) a client reply goes to.
fn to(datagram: &[u8]) -> (Ipv4Addr, u16) {
    let flow = packet::parse(datagram, true).unwrap().flow;
    (flow.source, flow.destination_port)
}

fn rcode(datagram: &[u8]) -> u8 {
    wire::rcode(message(datagram)).unwrap()
}

fn truncated(datagram: &[u8]) -> bool {
    message(datagram)[2] & 0x02 != 0
}

fn sticky_block(label: &str, selector: sticky::Selector, via: sticky::Via) -> sticky::StickyBlock {
    sticky::StickyBlock {
        label: label.to_owned(),
        selector,
        via,
        every: Duration::from_secs(300),
    }
}

fn ips_block(net: &str, via: sticky::Via) -> sticky::StickyBlock {
    sticky_block(
        "ips",
        sticky::Selector::Ips(vec![sticky::IpNet::parse(net).unwrap()]),
        via,
    )
}

// ── interception ──

#[tokio::test]
async fn without_the_mode_udp_53_is_ordinary_traffic() {
    let mut bench = Bench::new(1, Vec::new());
    bench.hub.dns.on = false;
    let datagram = datagram(1, dns::HOST, 40000, None);
    assert!(bench.hub.dispatch(&datagram, CLIENT).unwrap().is_none());
    assert_eq!(bench.flows[0].try_recv().unwrap().bytes, datagram);
    assert!(bench.hub.dns_replies().is_empty());
    assert!(
        !bench
            .hub
            .stats_report(Duration::from_secs(1))
            .contains("\ndns: ")
    );
}

#[tokio::test]
async fn an_exit_with_no_open_control_channel_leaves_udp_53_alone() {
    let mut bench = Bench::new(1, Vec::new());
    // A link publishes its control sender once it is open: until then no
    // exit can resolve, and DNS is ordinary traffic.
    bench.hub.links[0].resolver = Arc::default();
    let datagram = datagram(1, dns::HOST, 40000, None);
    assert!(bench.hub.dispatch(&datagram, CLIENT).unwrap().is_none());
    assert_eq!(bench.flows[0].try_recv().unwrap().bytes, datagram);
    assert!(bench.hub.dns_replies().is_empty());
}

#[tokio::test]
async fn what_is_no_question_to_answer_is_left_to_routing() {
    let mut bench = Bench::new(1, Vec::new());
    // QR set: a response walking through, not a question.
    let mut response = datagram(1, dns::HOST, 40000, None);
    response[30] |= 0x80;
    assert!(bench.hub.dispatch(&response, CLIENT).unwrap().is_none());
    assert_eq!(bench.flows[0].try_recv().unwrap().bytes, response);
    // DNS on another port is somebody's protocol of its own.
    let mut other_port = datagram(2, dns::HOST, 40001, None);
    other_port[22..24].copy_from_slice(&5353u16.to_be_bytes());
    assert!(bench.hub.dispatch(&other_port, CLIENT).unwrap().is_none());
    assert_eq!(bench.flows[0].try_recv().unwrap().bytes, other_port);
    assert!(bench.hub.dns_replies().is_empty());
}

// ── which exit ──

#[tokio::test(start_paused = true)]
async fn a_name_resolves_through_the_default_exit_and_is_kept_for_its_ttl() {
    let mut bench = Bench::new(2, Vec::new());
    let first = datagram(1, dns::HOST, 40000, Some(1232));
    assert!(
        bench.query(&first).await.is_empty(),
        "nothing before the exit answers"
    );
    assert!(
        bench.flows[0].try_recv().is_err(),
        "no ordinary flow was opened"
    );
    let asked = bench.asked(0).await;
    assert_eq!(
        asked.wire,
        dns::query(1, dns::HOST, A, Some(1232)),
        "the stub's message, as written"
    );
    let answer = dns::addressed(&asked.wire, 60, &[[93, 184, 216, 34]]);
    let replies = bench.answer(0, asked.id, Some(answer)).await;
    assert_eq!(replies.len(), 1);
    let reply = &replies[0];
    assert_eq!(to(reply), (RESOLVER, 40000));
    assert_eq!(id(reply), 1);
    assert_eq!(
        wire::addresses(message(reply)),
        [Ipv4Addr::new(93, 184, 216, 34)]
    );
    assert_eq!(wire::ttls(message(reply)), [(A, 60)], "the TTL as received");

    // Inside its TTL the cache answers, with what is left of the TTL.
    tokio::time::advance(Duration::from_secs(30)).await;
    let second = datagram(2, dns::HOST, 40001, Some(1232));
    let replies = bench.query(&second).await;
    assert_eq!(replies.len(), 1);
    assert_eq!((to(&replies[0]), id(&replies[0])), ((RESOLVER, 40001), 2));
    assert_eq!(wire::ttls(message(&replies[0])), [(A, 30)]);

    // The TTL over, the exit is asked again; a fresh answer replaces the kept one.
    tokio::time::advance(Duration::from_secs(30)).await;
    let third = datagram(3, dns::HOST, 40002, Some(1232));
    assert!(bench.query(&third).await.is_empty());
    let asked = bench.asked(0).await;
    assert_eq!(asked.wire, dns::query(3, dns::HOST, A, Some(1232)));
    let answer = dns::addressed(&asked.wire, 60, &[[93, 184, 216, 35]]);
    let replies = bench.answer(0, asked.id, Some(answer)).await;
    assert_eq!(
        wire::addresses(message(&replies[0])),
        [Ipv4Addr::new(93, 184, 216, 35)]
    );
    let stats = &bench.hub.dns.stats;
    assert_eq!(
        (stats.queries, stats.cache_hits, stats.moved, stats.failed),
        (3, 1, 0, 0)
    );
}

#[tokio::test(start_paused = true)]
async fn a_name_that_belongs_to_another_exit_is_asked_again_there() {
    let sticky = ips_block(
        "203.0.113.0/24",
        sticky::Via::Servers(vec!["link1".to_owned()]),
    );
    let mut bench = Bench::new(2, vec![sticky]);
    let query = datagram(1, dns::HOST, 40000, None);
    assert!(bench.query(&query).await.is_empty());
    // The probe goes through the default exit.
    let probe = bench.asked(0).await;
    let spare = dns::addressed(&probe.wire, TTL, &[[203, 0, 113, 7]]);
    assert!(
        bench
            .answer(0, probe.id, Some(spare.clone()))
            .await
            .is_empty(),
        "the first address names another exit"
    );
    // Asked again there, the very same message.
    let again = bench.asked(1).await;
    assert_eq!(again.id, probe.id);
    assert_eq!(again.wire, probe.wire);
    let answer = dns::addressed(&again.wire, TTL, &[[203, 0, 113, 8]]);
    let replies = bench.answer(1, again.id, Some(answer.clone())).await;
    assert_eq!(replies.len(), 1);
    assert_eq!(message(&replies[0]), answer);
    assert_eq!(bench.hub.dns.stats.moved, 1);

    // Next time the name goes straight to its exit: one leg.
    tokio::time::advance(Duration::from_secs(TTL.into())).await;
    let query = datagram(2, dns::HOST, 40001, None);
    assert!(bench.query(&query).await.is_empty());
    let asked = bench.asked(1).await;
    assert_eq!(asked.wire, dns::query(2, dns::HOST, A, None));
    let answer = dns::addressed(&asked.wire, TTL, &[[203, 0, 113, 8]]);
    let replies = bench.answer(1, asked.id, Some(answer)).await;
    assert_eq!(id(&replies[0]), 2);
    assert_eq!(
        bench.hub.dns.stats.moved, 1,
        "no probe through the default exit"
    );
}

#[tokio::test]
async fn a_listed_name_goes_straight_to_its_block_exit() {
    let sticky = sticky_block(
        "pinned",
        sticky::Selector::Names(vec!["pinned.example.com".to_owned()]),
        sticky::Via::Servers(vec!["link1".to_owned()]),
    );
    let mut bench = Bench::new(2, vec![sticky]);
    // The block's resolver put the name's address in its set.
    let address = Ipv4Addr::new(198, 51, 100, 9);
    bench.hub.stickies[0].resolved.insert(address);
    let query = datagram(1, "pinned.example.com", 40000, None);
    assert!(bench.query(&query).await.is_empty());
    let asked = bench.asked(1).await;
    assert_eq!(
        asked.wire,
        dns::query(1, "pinned.example.com", A, None),
        "no probe through the default exit"
    );
    let answer = dns::addressed(&asked.wire, TTL, &[[198, 51, 100, 9]]);
    let replies = bench.answer(1, asked.id, Some(answer)).await;
    assert_eq!(wire::addresses(message(&replies[0])), [address]);
    assert_eq!(
        bench.hub.dns.stats.moved, 0,
        "the address is the block's own"
    );

    // A subdomain is not the listed name.
    let query = datagram(2, "www.pinned.example.com", 40001, None);
    assert!(bench.query(&query).await.is_empty());
    bench.asked(0).await;
}

#[tokio::test]
async fn one_answer_serves_every_stub_that_asked() {
    let mut bench = Bench::new(1, Vec::new());
    let first = datagram(1, dns::HOST, 40000, None);
    // Another stub, another port, and DNS 0x20 case.
    let second = datagram(2, "WwW.Example.COM", 40001, None);
    assert!(bench.query(&first).await.is_empty());
    assert!(bench.query(&second).await.is_empty());
    let asked = bench.asked(0).await;
    assert_eq!(asked.wire, dns::query(1, dns::HOST, A, None));
    let answer = dns::addressed(&asked.wire, TTL, &[[203, 0, 113, 7]]);
    let replies = bench.answer(0, asked.id, Some(answer)).await;
    assert_eq!(replies.len(), 2);
    assert_eq!((to(&replies[0]), id(&replies[0])), ((RESOLVER, 40000), 1));
    assert_eq!((to(&replies[1]), id(&replies[1])), ((RESOLVER, 40001), 2));
    // Each stub sees its own question.
    let asked = dns::name("WwW.Example.COM");
    assert_eq!(
        message(&replies[1])[12..12 + asked.len()],
        asked,
        "the second stub's case"
    );
}

#[tokio::test]
async fn too_many_stubs_on_one_flight_wait_elsewhere() {
    let mut bench = Bench::new(1, Vec::new());
    for id in 0..33u16 {
        let datagram = datagram(id, dns::HOST, 40000 + id, None);
        assert!(bench.query(&datagram).await.is_empty());
    }
    let asked = bench.asked(0).await;
    let replies = bench
        .answer(0, asked.id, Some(dns::answered(&asked.wire)))
        .await;
    // The 33rd datagram was dropped rather than kept: its stub asks again.
    assert_eq!(replies.len(), 32);
    let mut stats = Stats::default();
    bench.hub.links[0].delivery.apply(&mut stats);
    assert_eq!(stats.dropped_packets, 1);
}

// ── cache and failures ──

#[tokio::test(start_paused = true)]
async fn a_failed_exit_is_answered_from_the_cache() {
    let mut bench = Bench::new(1, Vec::new());
    let address = [203, 0, 113, 7];
    let first = datagram(1, dns::HOST, 40000, None);
    assert!(bench.query(&first).await.is_empty());
    let asked = bench.asked(0).await;
    let answer = dns::addressed(&asked.wire, 60, &[address]);
    bench.answer(0, asked.id, Some(answer)).await;

    // The TTL is over and the exit has nothing: the kept answer stands in,
    // promising little.
    tokio::time::advance(Duration::from_secs(61)).await;
    let second = datagram(2, dns::HOST, 40001, None);
    assert!(
        bench.query(&second).await.is_empty(),
        "the exit is asked first"
    );
    let asked = bench.asked(0).await;
    let replies = bench.answer(0, asked.id, None).await;
    assert_eq!(replies.len(), 1);
    assert_eq!(id(&replies[0]), 2);
    assert_eq!(rcode(&replies[0]), 0);
    assert_eq!(
        wire::addresses(message(&replies[0])),
        [Ipv4Addr::from(address)]
    );
    assert_eq!(wire::ttls(message(&replies[0])), [(A, 30)]);

    // For a while the cache answers alone: one timeout per failure, not per query.
    let third = datagram(3, dns::HOST, 40002, None);
    let replies = bench.query(&third).await;
    assert_eq!(replies.len(), 1);
    assert_eq!(id(&replies[0]), 3);
    assert_eq!(wire::ttls(message(&replies[0])), [(A, 30)]);
    let stats = &bench.hub.dns.stats;
    assert_eq!((stats.stale, stats.failed), (2, 1));

    // The hold over, the exit is asked again.
    tokio::time::advance(Duration::from_secs(5)).await;
    let fourth = datagram(4, dns::HOST, 40003, None);
    assert!(bench.query(&fourth).await.is_empty());
    let asked = bench.asked(0).await;
    let answer = dns::addressed(&asked.wire, 60, &[[203, 0, 113, 8]]);
    let replies = bench.answer(0, asked.id, Some(answer)).await;
    assert_eq!(
        wire::addresses(message(&replies[0])),
        [Ipv4Addr::new(203, 0, 113, 8)]
    );
    assert_eq!(
        wire::ttls(message(&replies[0])),
        [(A, 60)],
        "a fresh answer keeps its TTL"
    );
    assert_eq!(bench.hub.dns.stats.failed, 1);
}

#[tokio::test(start_paused = true)]
async fn with_nothing_kept_a_failed_exit_means_servfail_for_a_while() {
    let mut bench = Bench::new(1, Vec::new());
    let first = datagram(1, dns::HOST, 40000, None);
    assert!(bench.query(&first).await.is_empty());
    let asked = bench.asked(0).await;
    let replies = bench.answer(0, asked.id, None).await;
    assert_eq!(replies.len(), 1);
    assert_eq!(
        (to(&replies[0]), rcode(&replies[0])),
        ((RESOLVER, 40000), 2)
    );
    assert!(wire::addresses(message(&replies[0])).is_empty());
    // The failure is remembered, not retried per query.
    let second = datagram(2, dns::HOST, 40001, None);
    let replies = bench.query(&second).await;
    assert_eq!((replies.len(), rcode(&replies[0])), (1, 2));
    assert_eq!(bench.hub.dns.stats.failed, 1);
    // Until the hold is over.
    tokio::time::advance(Duration::from_secs(5)).await;
    let third = datagram(3, dns::HOST, 40002, None);
    assert!(bench.query(&third).await.is_empty());
    bench.asked(0).await;
}

#[tokio::test(start_paused = true)]
async fn a_servfail_from_the_exit_yields_to_the_kept_answer() {
    let mut bench = Bench::new(1, Vec::new());
    bench.resolve(dns::HOST, [203, 0, 113, 7]).await;
    tokio::time::advance(Duration::from_secs(TTL.into())).await;

    let query = datagram(2, dns::HOST, 40001, None);
    assert!(bench.query(&query).await.is_empty());
    let asked = bench.asked(0).await;
    let mut servfail = dns::answer(&asked.wire, &[]);
    servfail[3] = 2;
    let replies = bench.answer(0, asked.id, Some(servfail)).await;
    assert_eq!(replies.len(), 1);
    assert_eq!(rcode(&replies[0]), 0);
    assert_eq!(
        wire::addresses(message(&replies[0])),
        [Ipv4Addr::new(203, 0, 113, 7)]
    );

    // With nothing kept, the resolver's SERVFAIL is the client's.
    let query = datagram(5, "other.example.com", 40002, None);
    assert!(bench.query(&query).await.is_empty());
    let asked = bench.asked(0).await;
    let mut servfail = dns::answer(&asked.wire, &[]);
    servfail[3] = 2;
    let replies = bench.answer(0, asked.id, Some(servfail)).await;
    assert_eq!(rcode(&replies[0]), 2);
}

#[tokio::test(start_paused = true)]
async fn a_negative_answer_is_kept_as_its_soa_says() {
    let mut bench = Bench::new(1, Vec::new());
    let soa = {
        let mut rdata = vec![0; 18];
        rdata.extend_from_slice(&5u32.to_be_bytes());
        dns::record(6, 3600, &rdata)
    };
    let first = datagram(1, "nx.example.com", 40000, None);
    assert!(bench.query(&first).await.is_empty());
    let asked = bench.asked(0).await;
    let mut nxdomain = dns::message(&asked.wire, &[], &[soa], &[]);
    nxdomain[3] = 3;
    let replies = bench.answer(0, asked.id, Some(nxdomain)).await;
    assert_eq!(rcode(&replies[0]), 3);

    // min(TTL, MINIMUM) of the SOA: five seconds of negative caching, counted down.
    tokio::time::advance(Duration::from_secs(4)).await;
    let second = datagram(2, "nx.example.com", 40001, None);
    let replies = bench.query(&second).await;
    assert_eq!(replies.len(), 1);
    assert_eq!((id(&replies[0]), rcode(&replies[0])), (2, 3));
    assert_eq!(wire::ttls(message(&replies[0])), [(6, 1)]);
    tokio::time::advance(Duration::from_secs(1)).await;
    let third = datagram(3, "nx.example.com", 40002, None);
    assert!(bench.query(&third).await.is_empty());
    bench.asked(0).await;
}

#[tokio::test(start_paused = true)]
async fn a_flight_out_of_patience_ends_like_a_failed_exit() {
    let mut bench = Bench::new(1, Vec::new());
    let first = datagram(1, dns::HOST, 40000, None);
    assert!(bench.query(&first).await.is_empty());
    assert_eq!(
        bench.hub.dns_deadline(),
        Some(tokio::time::Instant::now() + Duration::from_millis(2500))
    );
    tokio::time::advance(Duration::from_millis(2499)).await;
    bench.hub.dns_expire();
    assert!(bench.settle().await.is_empty(), "still waiting");
    tokio::time::advance(Duration::from_millis(1)).await;
    bench.hub.dns_expire();
    let replies = bench.settle().await;
    assert_eq!((replies.len(), rcode(&replies[0])), (1, 2));
    assert_eq!(bench.hub.dns_deadline(), None);
}

#[tokio::test]
async fn a_lost_link_ends_its_flights_at_once() {
    let sticky = ips_block(
        "203.0.113.0/24",
        sticky::Via::Servers(vec!["link1".to_owned()]),
    );
    let mut bench = Bench::new(2, vec![sticky]);
    let first = datagram(1, dns::HOST, 40000, None);
    assert!(bench.query(&first).await.is_empty());
    let probe = bench.asked(0).await;
    let spare = dns::addressed(&probe.wire, TTL, &[[203, 0, 113, 7]]);
    assert!(
        bench
            .answer(0, probe.id, Some(spare.clone()))
            .await
            .is_empty()
    );
    bench.asked(1).await;
    // The second leg is in flight when its link dies: the first answer goes out.
    bench.hub.dns_link_failed(epoch(1));
    let replies = bench.settle().await;
    assert_eq!(replies.len(), 1);
    assert_eq!(message(&replies[0]), spare);
    assert_eq!(bench.hub.dns_deadline(), None);

    // A first leg lost with nothing kept: SERVFAIL, without waiting.
    let second = datagram(2, "other.example.com", 40001, None);
    assert!(bench.query(&second).await.is_empty());
    bench.asked(0).await;
    bench.hub.dns_link_failed(epoch(0));
    let replies = bench.settle().await;
    assert_eq!((replies.len(), rcode(&replies[0])), (1, 2));
    assert_eq!(bench.hub.dns_deadline(), None);
}

#[tokio::test]
async fn an_answer_too_long_for_the_stub_is_truncated() {
    let mut bench = Bench::new(1, Vec::new());
    let many: Vec<[u8; 4]> = (0..80).map(|index| [203, 0, 113, index]).collect();
    // With EDNS the stub's own limit holds, capped by the TUN's MTU.
    let first = datagram(1, dns::HOST, 40000, Some(1232));
    assert!(bench.query(&first).await.is_empty());
    let asked = bench.asked(0).await;
    let answer = dns::addressed(&asked.wire, TTL, &many);
    let replies = bench.answer(0, asked.id, Some(answer)).await;
    assert!(truncated(&replies[0]));
    assert_eq!(id(&replies[0]), 1);
    assert!(message(&replies[0]).len() <= 1232);
    // Without EDNS the classic size holds, whatever the MTU allows.
    let second = datagram(2, dns::HOST, 40001, None);
    assert!(bench.query(&second).await.is_empty());
    let asked = bench.asked(0).await;
    let answer = dns::addressed(&asked.wire, TTL, &many);
    let replies = bench.answer(0, asked.id, Some(answer)).await;
    assert!(truncated(&replies[0]));
    assert!(message(&replies[0]).len() <= 512);
}

#[tokio::test]
async fn one_query_too_many_is_refused_on_the_spot() {
    let mut bench = Bench::new(1, Vec::new());
    for index in 0..256u16 {
        let datagram = datagram(index, &format!("n{index}.example.com"), 40000, None);
        assert!(bench.query(&datagram).await.is_empty());
    }
    // 256 flights wait for answers nobody gives; the next query waits for nothing.
    let extra = datagram(1, "extra.example.com", 40001, None);
    let replies = bench.query(&extra).await;
    assert_eq!((replies.len(), rcode(&replies[0])), (1, 2));
    assert_eq!(bench.hub.dns.stats.failed, 1);
}

#[tokio::test]
async fn a_full_cache_drops_what_is_closest_to_its_end() {
    let mut bench = Bench::new(1, Vec::new());
    for index in 0..4096 {
        bench
            .resolve(&format!("n{index}.example.com"), [203, 0, 113, 7])
            .await;
    }
    // Every entry is fresh and needed: the one that was filled first gives way.
    bench.resolve("last.example.com", [203, 0, 113, 8]).await;
    let again = datagram(2, "n0.example.com", 40001, None);
    assert!(bench.query(&again).await.is_empty());
    bench.asked(0).await;
    let kept = datagram(3, "n1.example.com", 40002, None);
    let replies = bench.query(&kept).await;
    assert_eq!(replies.len(), 1);
}

#[tokio::test]
async fn the_local_exit_resolves_through_the_wan() {
    let wan = dns::resolver(|socket, query, from| {
        let answer = dns::addressed(query, TTL, &[[198, 51, 100, 7]]);
        let _ = socket.try_send_to(&answer, from);
    })
    .await;
    let sticky = ips_block("198.51.100.0/24", sticky::Via::Local);
    let mut bench = Bench::new(2, vec![sticky]);
    let (outgoing, _packets) = mpsc::channel(4);
    let (_proxy_events, events) = mpsc::channel(4);
    let (_proxy_stats, latest) = watch::channel(Stats::default());
    bench.hub.local = Some(LocalExitState {
        outgoing,
        events: Some(events),
        latest,
        delivery: Arc::default(),
        server: LocalServer::new(tokio::spawn(async { Ok::<(), anyhow::Error>(()) })),
        ready: true,
    });
    // Without the WAN device a local query would loop back into the TUN:
    // the local exit cannot resolve, and the probe's answer stands.
    let first = datagram(1, "first.example.com", 40000, None);
    assert!(bench.query(&first).await.is_empty());
    let probe = bench.asked(0).await;
    let answer = dns::addressed(&probe.wire, TTL, &[[198, 51, 100, 7]]);
    let replies = bench.answer(0, probe.id, Some(answer.clone())).await;
    assert_eq!(message(&replies[0]), answer);
    assert_eq!(bench.hub.dns.stats.moved, 0);

    // With it, the name is asked again through the WAN resolvers.
    bench.hub.dns_set_wan(Some("lo".to_owned()));
    bench.hub.dns_set_resolvers(vec![wan]);
    let second = datagram(2, "second.example.com", 40001, None);
    assert!(bench.query(&second).await.is_empty());
    let probe = bench.asked(0).await;
    let spare = dns::addressed(&probe.wire, TTL, &[[198, 51, 100, 9]]);
    assert!(
        bench.answer(0, probe.id, Some(spare)).await.is_empty(),
        "the address belongs to the local exit"
    );
    // The WAN resolver's answer comes back as an event of its own.
    let (epoch, event) = tokio::time::timeout(Duration::from_secs(2), bench.hub.incoming.recv())
        .await
        .expect("the WAN resolver answered")
        .unwrap();
    bench.hub.events.send((epoch, event)).await.unwrap();
    let replies = bench.settle().await;
    assert_eq!(replies.len(), 1);
    assert_eq!((id(&replies[0]), rcode(&replies[0])), (2, 0));
    assert_eq!(
        wire::addresses(message(&replies[0])),
        [Ipv4Addr::new(198, 51, 100, 7)],
        "the WAN resolver's address, not the probe's"
    );
    let stats = &bench.hub.dns.stats;
    assert_eq!((stats.moved, stats.failed), (1, 0));
}

#[tokio::test]
async fn the_report_counts_dns() {
    let mut bench = Bench::new(1, Vec::new());
    bench.resolve(dns::HOST, [203, 0, 113, 7]).await;
    let report = bench.hub.stats_report(Duration::from_secs(1));
    assert!(
        report.contains("\ndns: queries 1 | cache 0 | stale 0 | moved 0 | failed 0"),
        "{report}"
    );
}
