//! DNS wire codec of the hub: what counts as a stub query, how a reply is
//! matched to the stub that asked, and what an answer reveals.

mod common;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use common::dns;
use svpn::{dns::wire, packet};

const HOST: &str = "www.example.com";
const A: u16 = 1;
const AAAA: u16 = 28;
const CNAME: u16 = 5;
const SOA: u16 = 6;

// ── query ──

#[test]
fn one_question_with_or_without_edns_is_a_query() {
    let plain = dns::query(0x1234, HOST, A, None);
    let parsed = wire::Query::parse(&plain).unwrap();
    assert_eq!((parsed.id, parsed.qtype, parsed.limit), (0x1234, A, 512));
    assert_eq!(parsed.wire(), plain);
    assert_eq!(parsed.name(), dns::name(HOST));
    let mut key = plain.clone();
    key[..2].fill(0);
    assert_eq!(parsed.key(), key);

    let edns = wire::Query::parse(&dns::query(7, HOST, AAAA, Some(1232))).unwrap();
    assert_eq!(edns.limit, 1232);
    // The floor of EDNS is the classic size, whatever the stub advertised.
    let tiny = wire::Query::parse(&dns::query(7, HOST, AAAA, Some(100))).unwrap();
    assert_eq!(tiny.limit, 512);
}

#[test]
fn the_key_forgets_the_id_and_the_case() {
    let first = wire::Query::parse(&dns::query(1, "WwW.Example.COM", A, None)).unwrap();
    let second = wire::Query::parse(&dns::query(0xbeef, HOST, A, None)).unwrap();
    assert_eq!(first.key(), second.key());
    assert_eq!(first.name(), dns::name(HOST));
    assert_ne!(first.wire(), second.wire());
    // What the stub asked upstream is what it wrote, case included.
    let asked = dns::name("WwW.Example.COM");
    assert_eq!(first.wire()[12..12 + asked.len()], asked);
}

#[test]
fn anything_else_is_left_to_routing() {
    let mut response = dns::query(1, HOST, A, None);
    response[2] |= 0x80;
    let mut update = dns::query(1, HOST, A, None);
    update[3] = 0x05 << 3;
    let mut two_questions = dns::query(1, HOST, A, None);
    two_questions[4..6].copy_from_slice(&2u16.to_be_bytes());
    let mut with_answers = dns::query(1, HOST, A, None);
    with_answers[6..8].copy_from_slice(&1u16.to_be_bytes());
    let mut trailing = dns::query(1, HOST, A, None);
    trailing.push(0);
    // The OPT's type byte: the record is no OPT.
    let mut foreign_record = dns::query(1, HOST, A, Some(1232));
    foreign_record[12 + dns::name(HOST).len() + 6] = 1;
    let mut long_opt = dns::query(1, HOST, A, Some(1232));
    let end = long_opt.len();
    long_opt[end - 2..].copy_from_slice(&4u16.to_be_bytes());
    let mut pointer = dns::query(1, HOST, A, None);
    pointer[12..14].copy_from_slice(&[0xc0, 0x0c]);
    let mut long_label = dns::query(1, HOST, A, None);
    long_label[12] = 64;
    // Four labels of 63 octets are past the 255-octet limit of a name.
    let mut long_name = vec![0; 12];
    long_name[4..6].copy_from_slice(&1u16.to_be_bytes());
    for _ in 0..4 {
        long_name.push(63);
        long_name.extend(std::iter::repeat_n(b'a', 63));
    }
    long_name.extend_from_slice(&[0]);
    long_name.extend_from_slice(&A.to_be_bytes());
    long_name.extend_from_slice(&1u16.to_be_bytes());

    let rejected = [
        vec![],
        vec![0; 16],
        response,
        update,
        two_questions,
        with_answers,
        trailing,
        foreign_record,
        long_opt,
        pointer,
        long_label,
        long_name,
    ];
    for message in rejected {
        assert!(wire::Query::parse(&message).is_none(), "{message:?}");
    }
}

// ── reply ──

#[test]
fn the_reply_carries_the_stub_id_and_its_own_case() {
    let first = wire::Query::parse(&dns::query(1, "WwW.Example.COM", A, None)).unwrap();
    let second = wire::Query::parse(&dns::query(0xbeef, HOST, A, None)).unwrap();
    let answer = dns::answer(first.wire(), &[dns::a(300, [93, 184, 216, 34])]);

    // The stub whose message went upstream gets the answer byte for byte.
    assert_eq!(first.reply(&answer).unwrap(), answer);

    let reply = second.reply(&answer).unwrap();
    let name = dns::name(HOST).len();
    assert_eq!(reply[..2], 0xbeefu16.to_be_bytes());
    assert_eq!(reply[2..4], 0x8180u16.to_be_bytes());
    assert_eq!(reply[12..12 + name], dns::name(HOST));
    assert_eq!(reply[12 + name..], answer[12 + name..]);
}

#[test]
fn an_answer_to_another_question_is_no_reply() {
    let query = wire::Query::parse(&dns::query(1, HOST, A, None)).unwrap();
    let other_host = dns::answer(&dns::query(1, "other.example.com", A, None), &[]);
    let mut other_type = dns::answer(query.wire(), &[]);
    let name = 12 + dns::name(HOST).len();
    other_type[name..name + 2].copy_from_slice(&AAAA.to_be_bytes());
    for answer in [other_host, other_type, vec![0; 12]] {
        assert!(query.reply(&answer).is_none());
    }
}

#[test]
fn servfail_and_truncation_are_header_and_question() {
    let plain = dns::query(0x4242, HOST, A, None);
    let query = wire::Query::parse(&plain).unwrap();
    let servfail = query.error(wire::SERVFAIL, false);
    assert_eq!(
        servfail[..12],
        [0x42, 0x42, 0x81, 0x82, 0, 1, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(servfail[12..], plain[12..]);

    // The EDNS record of the query is not repeated; TC asks for a retry.
    let edns = wire::Query::parse(&dns::query(0x4242, HOST, A, Some(1232))).unwrap();
    let truncated = edns.truncated();
    assert_eq!(truncated[2..4], [0x83, 0x80]);
    assert_eq!(truncated.len(), servfail.len());

    let mut no_rd = plain;
    no_rd[2] = 0;
    let flags = wire::Query::parse(&no_rd).unwrap().error(0, false)[2..4].to_vec();
    assert_eq!(flags, [0x80, 0x80]);
}

// ── answers ──

#[test]
fn an_answer_must_answer_the_query() {
    let query = dns::query(9, HOST, A, Some(1232));
    let good = dns::answer(&query, &[dns::a(300, [93, 184, 216, 34])]);
    assert_eq!(
        wire::answers(&good, &query).as_deref(),
        Some(good.as_slice())
    );

    let mut id = good.clone();
    id[0] ^= 1;
    let mut not_a_response = good.clone();
    not_a_response[2] &= 0x7f;
    let mut other_question = good.clone();
    other_question[13] ^= 1;
    let mut cut_record = good.clone();
    cut_record[14] = 0xff;
    let mut trailing = good;
    trailing.push(0);
    for answer in [id, not_a_response, other_question, cut_record, trailing] {
        assert!(wire::answers(&answer, &query).is_none());
    }
}

#[test]
fn a_positive_answer_lives_as_its_shortest_record() {
    let query = dns::query(9, HOST, A, Some(1232));
    let cname = dns::record(CNAME, 120, &dns::name("edge.example.net"));
    let full = dns::message(
        &query,
        &[cname, dns::a(300, [1, 1, 1, 1]), dns::a(60, [2, 2, 2, 2])],
        &[dns::record(SOA, 3600, &[0; 22])],
        &[dns::record(41, 0, &[])],
    );
    // Authority and OPT records do not shorten the answer.
    assert_eq!(wire::lifetime(&full), Some(Duration::from_secs(60)));
    // The TTL is honoured as received, long or short.
    let long = dns::answer(&query, &[dns::a(86400, [1, 1, 1, 1])]);
    assert_eq!(wire::lifetime(&long), Some(Duration::from_secs(86400)));
    let mut damaged = full.clone();
    damaged[6..8].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(wire::lifetime(&damaged), None);
}

#[test]
fn a_negative_answer_lives_as_its_soa_says() {
    let query = dns::query(9, HOST, A, None);
    // SOA rdata ends in MINIMUM: min(TTL, MINIMUM) is the negative lifetime.
    let soa = |minimum: u32| {
        let mut rdata = vec![0; 18];
        rdata.extend_from_slice(&minimum.to_be_bytes());
        dns::record(SOA, 3600, &rdata)
    };
    let mut nxdomain = dns::message(&query, &[], &[soa(900)], &[]);
    nxdomain[3] = 3;
    let nodata = dns::message(&query, &[], &[soa(3600)], &[]);
    assert_eq!(wire::lifetime(&nxdomain), Some(Duration::from_secs(900)));
    assert_eq!(wire::lifetime(&nodata), Some(Duration::from_secs(3600)));

    // Nothing says how long to remember: no SOA, or one outside authority.
    assert_eq!(wire::lifetime(&dns::answer(&query, &[])), None);
    let stray = dns::message(&query, &[], &[], &[soa(900)]);
    assert_eq!(wire::lifetime(&stray), None);
}

#[test]
fn a_negative_answer_carries_its_lifetime_in_the_soa() {
    let query = dns::query(9, HOST, A, None);
    let mut soa = vec![0; 18];
    soa.extend_from_slice(&900u32.to_be_bytes());
    let nxdomain = dns::message(&query, &[], &[dns::record(SOA, 3600, &soa)], &[]);
    let normalised = wire::normalised(&nxdomain).unwrap();
    assert_eq!(wire::ttls(&normalised), [(SOA, 900)], "min(TTL, MINIMUM)");
    assert_eq!(
        normalised[..normalised.len() - 26],
        nxdomain[..nxdomain.len() - 26],
        "nothing else moves"
    );
    // Still the same lifetime, and now the aged copy counts from it.
    assert_eq!(wire::lifetime(&normalised), Some(Duration::from_secs(900)));
    assert_eq!(
        wire::ttls(&wire::aged(&normalised, Duration::from_secs(600)).unwrap()),
        [(SOA, 300)]
    );

    // A positive answer is served and kept as it came.
    let positive = dns::answer(&query, &[dns::a(60, [1; 4])]);
    assert_eq!(wire::normalised(&positive).unwrap(), positive);
    assert_eq!(wire::normalised(&dns::answer(&query, &[])), None);
}

#[test]
fn a_cached_answer_counts_its_ttls_down() {
    let query = dns::query(9, HOST, A, Some(1232));
    let full = dns::message(
        &query,
        &[
            dns::record(CNAME, 120, &dns::name("edge.example.net")),
            dns::a(300, [1, 1, 1, 1]),
        ],
        &[],
        &[dns::record(41, 0, &[])],
    );
    let aged = wire::aged(&full, Duration::from_secs(100)).unwrap();
    assert_eq!(wire::ttls(&aged), [(CNAME, 20), (A, 200), (41, 0)]);
    assert_eq!(wire::lifetime(&aged), Some(Duration::from_secs(20)));
    // The OPT's "TTL" is an extended rcode: never touched.
    assert_eq!(aged[full.len() - 11..], full[full.len() - 11..]);

    // Past a record's TTL it is zero, never negative.
    let old = wire::aged(&full, Duration::from_secs(1000)).unwrap();
    assert_eq!(wire::ttls(&old), [(CNAME, 0), (A, 0), (41, 0)]);
    // Served past its TTL no record promises more than the cap.
    let short = wire::short_lived(&full, 30).unwrap();
    assert_eq!(wire::ttls(&short), [(CNAME, 30), (A, 30), (41, 0)]);
}

#[test]
fn the_rcode_is_read_from_the_header() {
    let query = dns::query(9, HOST, A, None);
    assert_eq!(wire::rcode(&dns::answer(&query, &[])), Some(0));
    let mut refused = dns::answer(&query, &[]);
    refused[3] = 5;
    assert_eq!(wire::rcode(&refused), Some(5));
    assert_eq!(wire::rcode(&[0; 3]), None);
}

#[test]
fn addresses_are_the_a_records_in_order() {
    let query = dns::query(9, HOST, A, None);
    let v6 = dns::record(
        AAAA,
        60,
        &[0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    );
    let message = dns::answer(
        &query,
        &[
            dns::record(CNAME, 60, &dns::name("edge.example.net")),
            dns::a(60, [1, 2, 3, 4]),
            v6,
            dns::a(60, [5, 6, 7, 8]),
        ],
    );
    assert_eq!(
        wire::addresses(&message),
        [Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)]
    );
    assert!(wire::addresses(&dns::answer(&query, &[])).is_empty());
}

#[test]
fn a_name_matches_its_config_text_exactly() {
    assert!(wire::is_name(&dns::name("example.com"), "example.com"));
    assert!(wire::is_name(
        &dns::name("WwW.Example.COM"),
        "www.example.com"
    ));
    assert!(wire::is_name(
        &dns::name("a.b.c.example.com"),
        "a.b.c.example.com"
    ));
    assert!(!wire::is_name(&dns::name(HOST), "example.com"));
    assert!(!wire::is_name(&dns::name("example.com"), HOST));
    assert!(!wire::is_name(&dns::name("example.com"), "example.com."));
    assert!(!wire::is_name(&dns::name("xample.com"), "example.com"));
    assert!(!wire::is_name(
        &dns::name("a.b.c.example.com"),
        "b.c.example.com"
    ));
    assert!(!wire::is_name(&[0], ""));
    assert!(!wire::is_name(&[], ""));
}

// ── packets ──

#[test]
fn udp_datagrams_round_trip_with_valid_checksums() {
    let payload = dns::query(1, HOST, A, Some(1232));
    let resolver = Ipv4Addr::new(1, 1, 1, 1);
    let stub = Ipv4Addr::new(10, 77, 0, 2);
    let datagram = packet::udp_datagram(
        SocketAddrV4::new(resolver, 53),
        SocketAddrV4::new(stub, 40000),
        &payload,
    )
    .unwrap();

    // Read back as it leaves the hub: the flow is resolver → stub.
    let parsed = packet::parse(&datagram, true).unwrap();
    assert_eq!(
        (parsed.flow.source, parsed.flow.source_port),
        (resolver, 53)
    );
    assert_eq!(
        (parsed.flow.destination, parsed.flow.destination_port),
        (stub, 40000)
    );
    assert_eq!(packet::udp_payload(&datagram), Some(payload.as_slice()));

    // A checksum in place sums to zero: the IP header, and the UDP segment
    // behind its pseudoheader.
    let segment = |datagram: &[u8]| {
        let mut sum = Vec::new();
        sum.extend_from_slice(&resolver.octets());
        sum.extend_from_slice(&stub.octets());
        sum.extend_from_slice(&[0, 17]);
        let length = u16::try_from(datagram.len() - 20).unwrap();
        sum.extend_from_slice(&length.to_be_bytes());
        sum.extend_from_slice(&datagram[20..]);
        sum
    };
    assert_eq!(packet::internet_checksum(&datagram[..20]), 0);
    assert_eq!(packet::internet_checksum(&segment(&datagram)), 0);

    // One flipped payload byte breaks the UDP checksum and only it.
    let last = datagram.len() - 1;
    let mut broken = datagram;
    broken[last] ^= 0xff;
    assert_eq!(packet::internet_checksum(&broken[..20]), 0);
    assert_ne!(packet::internet_checksum(&segment(&broken)), 0);
}

#[test]
fn an_oversized_datagram_is_refused() {
    let resolver = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53);
    let stub = SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), 40000);
    assert!(packet::udp_datagram(resolver, stub, &vec![0; 65507]).is_some());
    assert!(packet::udp_datagram(resolver, stub, &vec![0; 65508]).is_none());
}
