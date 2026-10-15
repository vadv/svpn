//! sctp-proto laboratory: a deterministic pair of associations without a
//! network.
//!
//! Its purpose is to verify the pinned fork (rev 3266f97) in isolation from
//! DTLS, str0m, and internal TCP: the abandoned-fragment regression and the
//! share of FORWARD-TSN/SACK control traffic under load. Virtual time moves
//! in `TICK` ticks, delivery is a `ONE_WAY` delay in each direction.
#![cfg(test)]

use std::cell::Cell;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use sctp_proto::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Payload,
    PayloadProtocolIdentifier, ReliabilityType, Transmit,
};

const ONE_WAY: Duration = Duration::from_millis(20);
const TICK: Duration = Duration::from_millis(5);
/// 1062 payload bytes, aligned to 4 bytes, + 16-byte DATA header + 12-byte
/// packet header.
const FRAGMENT_FIRST_LEN: usize = 1092;

type DropFn<'a> = &'a dyn Fn(bool, usize, usize) -> bool;

struct Side {
    endpoint: Endpoint,
    handle: Option<AssociationHandle>,
    association: Option<Association>,
    addr: SocketAddr,
}

struct Lab {
    /// (arrival time, from client, datagram)
    wire: VecDeque<(Instant, bool, Bytes)>,
    client: Side,
    server: Side,
    seq: usize,
    /// (direction, size) → datagram count.
    histogram: [std::collections::BTreeMap<usize, u64>; 2],
    /// Received bytes per 100-ms intervals of virtual time.
    rx_intervals: Vec<u64>,
    start: Instant,
}

impl Lab {
    fn new(max_payload: u32) -> Self {
        let config = Arc::new(EndpointConfig::new().max_payload_size(max_payload).clone());
        Self {
            wire: VecDeque::new(),
            client: Side {
                endpoint: Endpoint::new(Arc::clone(&config), None),
                handle: None,
                association: None,
                addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000)),
            },
            server: Side {
                endpoint: Endpoint::new(config, Some(Arc::new(sctp_proto::ServerConfig::new()))),
                handle: None,
                association: None,
                addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5000)),
            },
            seq: 0,
            histogram: Default::default(),
            rx_intervals: vec![0],
            start: Instant::now(),
        }
    }

    fn step(&mut self, now: Instant, drop_datagram: DropFn) {
        self.deliver(now);
        self.pump(now, true, drop_datagram);
        self.pump(now, false, drop_datagram);
        let received = self.drain_server_reads();
        *self.rx_intervals.last_mut().expect("intervals live") += received;
    }

    fn deliver(&mut self, now: Instant) {
        while self
            .wire
            .front()
            .is_some_and(|(arrive, _, _)| *arrive <= now)
        {
            let (_, from_client, datagram) = self.wire.pop_front().expect("front checked");
            let remote = self.side(from_client).addr;
            let side = self.side_mut(!from_client);
            let Some((handle, event)) =
                side.endpoint
                    .handle(now, remote, Some(side.addr.ip()), None, datagram)
            else {
                continue;
            };
            match event {
                DatagramEvent::NewAssociation(association) => {
                    side.handle = Some(handle);
                    side.association = Some(association);
                }
                DatagramEvent::AssociationEvent(event) => {
                    if let Some(association) = side.association.as_mut() {
                        association.handle_event(event);
                    }
                }
            }
        }
    }

    fn pump(&mut self, now: Instant, side_is_client: bool, drop_datagram: DropFn) {
        // Two phases with collection into temporary vectors: endpoint and
        // association borrows must not overlap the &mut self in enqueue.
        let mut transmits = Vec::new();
        {
            let endpoint = &mut self.side_mut(side_is_client).endpoint;
            while let Some(transmit) = endpoint.poll_transmit() {
                transmits.push(transmit);
            }
        }
        for transmit in transmits {
            self.enqueue(now, side_is_client, transmit, drop_datagram);
        }

        let mut assoc_transmits = Vec::new();
        let mut endpoint_events = Vec::new();
        {
            let Some(association) = self.side_mut(side_is_client).association.as_mut() else {
                return;
            };
            while association.poll_timeout().is_some_and(|t| t <= now) {
                association.handle_timeout(now);
            }
            while let Some(transmit) = association.poll_transmit(now) {
                assoc_transmits.push(transmit);
            }
            while let Some(event) = association.poll_endpoint_event() {
                endpoint_events.push(event);
            }
            // The lab has no use for user events; drain them so they do not pile up.
            while association.poll().is_some() {}
        }
        for transmit in assoc_transmits {
            self.enqueue(now, side_is_client, transmit, drop_datagram);
        }
        for event in endpoint_events {
            let side = self.side_mut(side_is_client);
            let Some(handle) = side.handle else {
                continue;
            };
            if let Some(event) = side.endpoint.handle_event(handle, event)
                && let Some(association) = side.association.as_mut()
            {
                association.handle_event(event);
            }
        }
    }

    fn enqueue(
        &mut self,
        now: Instant,
        from_client: bool,
        transmit: Transmit,
        drop_datagram: DropFn,
    ) {
        let Payload::RawEncode(packets) = transmit.payload else {
            return;
        };
        for packet in packets {
            let len = packet.len();
            *self.histogram[usize::from(from_client)]
                .entry(len)
                .or_default() += 1;
            self.seq += 1;
            if drop_datagram(from_client, len, self.seq) {
                continue;
            }
            self.wire.push_back((now + ONE_WAY, from_client, packet));
        }
    }

    /// Returns the bytes the server application read during this call.
    fn drain_server_reads(&mut self) -> u64 {
        let Some(server) = self.server.association.as_mut() else {
            return 0;
        };
        let mut received = 0u64;
        for stream_id in server.stream_ids() {
            let Ok(mut stream) = server.stream(stream_id) else {
                continue;
            };
            while let Ok(Some(chunks)) = stream.read() {
                received += chunks.len() as u64;
            }
        }
        received
    }

    fn advance(&mut self, now: &mut Instant, until: Instant, drop_datagram: DropFn) {
        while *now < until {
            *now += TICK;
            self.step(*now, drop_datagram);
            let idx = now.duration_since(self.start).as_millis() as usize / 100;
            while self.rx_intervals.len() <= idx {
                self.rx_intervals.push(0);
            }
        }
    }

    fn connect(&mut self, start: Instant) {
        self.start = start;
        let (handle, association) = self
            .client
            .endpoint
            .connect(ClientConfig::new(), self.server.addr)
            .expect("sctp connect");
        self.client.handle = Some(handle);
        self.client.association = Some(association);
        let mut now = start;
        self.advance(&mut now, start + Duration::from_secs(1), &|_, _, _| false);
        assert!(
            self.server.association.is_some()
                && self
                    .client
                    .association
                    .as_ref()
                    .is_some_and(|a| !a.is_handshaking()),
            "sctp handshake did not complete"
        );
    }

    fn client_stream(&mut self) -> sctp_proto::Stream<'_> {
        let association = self
            .client
            .association
            .as_mut()
            .expect("client association");
        if !association.stream_ids().contains(&0) {
            association
                .open_stream(0, PayloadProtocolIdentifier::Unknown)
                .expect("open stream 0");
        }
        association.stream(0).expect("stream 0")
    }

    fn side(&self, client: bool) -> &Side {
        if client { &self.client } else { &self.server }
    }

    fn side_mut(&mut self, client: bool) -> &mut Side {
        if client {
            &mut self.client
        } else {
            &mut self.server
        }
    }
}

/// Load matrix (run manually: `cargo test sctp_matrix -- --ignored
/// --nocapture`): five virtual seconds of flow at 40 ms RTT for three
/// reliability modes and a variant that drops every hundredth packet.
/// Compares delivery and the share of FORWARD-TSN/SACK control datagrams
/// (32 bytes) in client traffic.
#[test]
#[ignore = "diagnostic lab, not part of the CI gate"]
fn sctp_matrix() {
    struct Variant {
        label: &'static str,
        message_len: usize,
        reliability: ReliabilityType,
        drop_each: Option<usize>,
    }
    let variants = [
        Variant {
            label: "1000b/Rexmit0",
            message_len: 1000,
            reliability: ReliabilityType::Rexmit,
            drop_each: None,
        },
        Variant {
            label: "1325b/Rexmit0",
            message_len: 1325,
            reliability: ReliabilityType::Rexmit,
            drop_each: None,
        },
        Variant {
            label: "1325b/Reliable",
            message_len: 1325,
            reliability: ReliabilityType::Reliable,
            drop_each: None,
        },
        Variant {
            label: "1325b/Rexmit0/loss1%",
            message_len: 1325,
            reliability: ReliabilityType::Rexmit,
            drop_each: Some(100),
        },
    ];
    for variant in variants {
        let mut lab = Lab::new(1062);
        let start = Instant::now();
        lab.connect(start);
        let mut now = start + Duration::from_secs(1);
        let drop_each = variant.drop_each;
        let mut sent = 0usize;
        let deadline = now + Duration::from_secs(5);
        while now < deadline {
            {
                let mut stream = lab.client_stream();
                stream
                    .set_reliability_params(true, variant.reliability, 0)
                    .expect("reliability params");
                if stream.buffered_amount().expect("buffered") + variant.message_len < 120_000 {
                    let message = vec![0xCD; variant.message_len];
                    if stream.write(&message).expect("write") == variant.message_len {
                        sent += variant.message_len;
                    }
                }
            }
            let until = now + TICK;
            lab.advance(&mut now, until, &|from_client, _len, seq| {
                drop_each.is_some_and(|each| from_client && seq % each == 0)
            });
        }
        let delivered: u64 = lab.rx_intervals.iter().sum();
        let control = lab.histogram[1]
            .iter()
            .filter(|(len, _)| **len <= 48)
            .map(|(_, c)| c)
            .sum::<u64>();
        let data = lab.histogram[1]
            .values()
            .sum::<u64>()
            .saturating_sub(control);
        let mut top: Vec<(usize, u64)> = lab.histogram[1].iter().map(|(&l, &c)| (l, c)).collect();
        top.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        let top = top
            .iter()
            .take(6)
            .map(|(l, c)| format!("{l}b×{c}"))
            .collect::<Vec<_>>()
            .join(" ");
        let mut stats = lab.client.association.as_ref().expect("client").stats();
        println!(
            "{}: sent={} deliv={} ({:.1} Mbps) ctrl/data={}/{} t3={} fast_re={} top: {}",
            variant.label,
            sent,
            delivered,
            delivered as f64 * 8.0 / 5.0 / 1e6,
            control,
            data,
            stats.get_num_t3timeouts(),
            stats.get_num_fast_retrans(),
            top,
        );
    }
}

/// Regression for the fragmentation defect (PR57): with unordered/Rexmit=0
/// the lost first fragment must not be retransmitted, and the message must
/// leave the send queue after FORWARD-TSN.
#[test]
fn fragmented_zero_rexmit_abandons_first_fragment() {
    let mut lab = Lab::new(1062);
    let start = Instant::now();
    lab.connect(start);
    let mut now = start + Duration::from_secs(1);

    {
        let mut stream = lab.client_stream();
        stream
            .set_reliability_params(true, ReliabilityType::Rexmit, 0)
            .expect("reliability params");
        let message = vec![0xAB; 1325];
        assert_eq!(stream.write(&message).expect("write"), 1325);
    }

    let dropped = Cell::new(false);
    let drop_first = |from_client: bool, len: usize, _seq: usize| {
        if from_client && len == FRAGMENT_FIRST_LEN && !dropped.get() {
            dropped.set(true);
            return true;
        }
        false
    };
    let until = now + Duration::from_secs(4);
    lab.advance(&mut now, until, &drop_first);

    let first_datagrams = *lab.histogram[1].get(&FRAGMENT_FIRST_LEN).unwrap_or(&0);
    assert_eq!(
        first_datagrams, 1,
        "first fragment sent once and not retransmitted"
    );
    let delivered: u64 = lab.rx_intervals.iter().sum();
    assert_eq!(
        delivered, 0,
        "undelivered message was not handed to the application"
    );
    {
        let stream = lab.client_stream();
        assert_eq!(
            stream.buffered_amount().expect("buffered_amount"),
            0,
            "abandoned message released after FORWARD-TSN"
        );
    }
    let mut stats = lab
        .client
        .association
        .as_ref()
        .expect("client association")
        .stats();
    let t3 = stats.get_num_t3timeouts();
    assert!(t3 <= 2, "T3 must not loop on an abandoned message: {t3}");
    assert!(
        !lab.client
            .association
            .as_ref()
            .expect("client association")
            .is_closed(),
        "association alive after abandoning one message"
    );
}
