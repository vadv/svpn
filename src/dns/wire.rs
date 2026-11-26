//! DNS message codec for the hub: what the stub asked, what goes back to it,
//! and what an answer says about its own lifetime and addresses.

use std::{net::Ipv4Addr, time::Duration};

use crate::packet::{dword, word};

/// SERVFAIL: the hub's answer when no exit resolved the name.
pub const SERVFAIL: u8 = 2;

/// Without EDNS a UDP answer may not exceed this (RFC 1035 §4.2.1).
const CLASSIC_LIMIT: u16 = 512;
const HEADER: usize = 12;
const A: u16 = 1;
const IN: u16 = 1;
const OPT: u16 = 41;
const SOA: u16 = 6;

/// One stub query: a single question, opcode QUERY, at most an EDNS OPT
/// behind it. `key` is the same message with the id zeroed and the qname
/// lowercased, so that two stubs asking the same thing share one upstream
/// exchange and one cache entry whatever their ids and DNS 0x20 case;
/// `question` keeps the client's own case for the reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    pub qtype: u16,
    /// Advertised UDP payload size: the OPT RR's, else [`CLASSIC_LIMIT`].
    pub limit: u16,
    wire: Vec<u8>,
    key: Vec<u8>,
    /// qname in the client's case, then qtype and qclass.
    question: Vec<u8>,
}

impl Query {
    /// `None` for a message the hub does not answer: not a query, not one
    /// question, records other than one OPT behind it. Such packets are
    /// routed like any other traffic.
    pub fn parse(message: &[u8]) -> Option<Self> {
        if message.len() < HEADER + 5 || message[2] & 0x80 != 0 || message[3] >> 3 != 0 {
            return None;
        }
        let (an, ns, ar) = (word(message, 6)?, word(message, 8)?, word(message, 10)?);
        if word(message, 4)? != 1 || an != 0 || ns != 0 || ar > 1 {
            return None;
        }
        let name = name_length(message.get(HEADER..)?)?;
        let end = HEADER + name + 4;
        let question = message.get(HEADER..end)?.to_vec();
        let mut key = message.to_vec();
        key[..2].fill(0);
        for byte in &mut key[HEADER..HEADER + name] {
            if byte.is_ascii_uppercase() {
                *byte += b'a' - b'A';
            }
        }
        let limit = if ar == 1 {
            // Root owner, then type, class (the payload size), ttl, rdlength.
            let opt = message.get(end..end + 11)?;
            if opt[0] != 0 || u16::from_be_bytes([opt[1], opt[2]]) != OPT {
                return None;
            }
            let rdata = usize::from(u16::from_be_bytes([opt[9], opt[10]]));
            if end + 11 + rdata != message.len() {
                return None;
            }
            u16::from_be_bytes([opt[3], opt[4]]).max(CLASSIC_LIMIT)
        } else {
            (message.len() == end).then_some(CLASSIC_LIMIT)?
        };
        Some(Self {
            id: u16::from_be_bytes([message[0], message[1]]),
            qtype: word(message, HEADER + name)?,
            limit,
            wire: message.to_vec(),
            key,
            question,
        })
    }

    /// The message to send upstream, exactly as the stub wrote it.
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Lowercased wire qname, ending in the root label.
    pub fn name(&self) -> &[u8] {
        &self.key[HEADER..HEADER + self.question.len() - 4]
    }

    /// `answer` as this stub's reply: with the stub's id and its own
    /// question case. `None` when the answer is not to this question.
    pub fn reply(&self, answer: &[u8]) -> Option<Vec<u8>> {
        let question = answer.get(HEADER..HEADER + self.question.len())?;
        let name = self.question.len() - 4;
        let same_name = question[..name].eq_ignore_ascii_case(&self.question[..name]);
        if !same_name || question[name..] != self.question[name..] {
            return None;
        }
        let mut reply = answer.to_vec();
        reply[..2].copy_from_slice(&self.id.to_be_bytes());
        reply[HEADER..HEADER + self.question.len()].copy_from_slice(&self.question);
        Some(reply)
    }

    /// Header and question only: the answer exists but is too long to send.
    pub fn truncated(&self) -> Vec<u8> {
        self.error(0, true)
    }

    /// Header and question only: `rcode`, RA, TC when `truncated`.
    pub fn error(&self, rcode: u8, truncated: bool) -> Vec<u8> {
        let mut reply = Vec::with_capacity(HEADER + self.question.len());
        reply.extend_from_slice(&self.id.to_be_bytes());
        // QR, the stub's opcode and RD, TC on request, RA.
        let flags = 0x8000
            | (u16::from(self.wire[3] >> 3) << 11)
            | (u16::from(truncated) << 9)
            | (u16::from(self.wire[2] & 0x01) << 8)
            | 0x0080
            | u16::from(rcode);
        reply.extend_from_slice(&flags.to_be_bytes());
        reply.extend_from_slice(&1u16.to_be_bytes());
        reply.extend_from_slice(&[0; 6]);
        reply.extend_from_slice(&self.question);
        reply
    }
}

/// `answer` as a resolver's response to the wire `query`: same id, QR set,
/// the same question, and records ending exactly at the message end.
pub fn answers(answer: &[u8], query: &[u8]) -> Option<Vec<u8>> {
    if answer.len() < HEADER || answer[2] & 0x80 == 0 || answer.get(..2)? != query.get(..2)? {
        return None;
    }
    let question = query.get(HEADER..HEADER + name_length(query.get(HEADER..)?)? + 4)?;
    if answer.get(HEADER..HEADER + question.len())? != question {
        return None;
    }
    let mut records = Records::new(answer)?;
    while records.next().is_some() {}
    records.finished().then(|| answer.to_vec())
}

/// How long an answer may be served from a cache, exactly as its records
/// say: the smallest TTL of the answer section, or for a negative answer
/// (no records there) `min` of the authority SOA's TTL and its MINIMUM field
/// (RFC 2308 §5). `None` when there is nothing to cache: no such record or a
/// damaged message.
pub fn lifetime(message: &[u8]) -> Option<Duration> {
    let mut records = Records::new(message)?;
    let mut answer = None;
    let mut soa = None;
    while let Some((section, record)) = records.next() {
        let ttl = match (section, record.rtype) {
            (0, _) => record.ttl,
            (1, SOA) => {
                let minimum = record.data.len().checked_sub(4)?;
                record.ttl.min(dword(record.data, minimum)?)
            }
            _ => continue,
        };
        match section {
            0 => answer = Some(answer.map_or(ttl, |min: u32| min.min(ttl))),
            _ => soa = Some(soa.map_or(ttl, |min: u32| min.min(ttl))),
        }
    }
    let ttl = records.finished().then_some(answer.or(soa)).flatten()?;
    Some(Duration::from_secs(u64::from(ttl)))
}

/// The answer as stubs and the cache should have it. A negative answer
/// carries its caching lifetime as the TTL of its authority SOA (RFC 2308
/// §5); a positive one is left alone. `None` for an answer `lifetime`
/// rejects.
pub fn normalised(message: &[u8]) -> Option<Vec<u8>> {
    let lifetime = lifetime(message)?;
    let mut records = Records::new(message)?;
    let mut positive = false;
    let mut soas = Vec::new();
    while let Some((section, record)) = records.next() {
        match (section, record.rtype) {
            (0, _) => positive = true,
            (1, SOA) => soas.push(record.ttl_at),
            _ => {}
        }
    }
    if !records.finished() {
        return None;
    }
    let mut copy = message.to_vec();
    if !positive {
        let seconds = u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX);
        for at in soas {
            copy[at..at + 4].copy_from_slice(&seconds.to_be_bytes());
        }
    }
    Some(copy)
}

/// The message with the TTL of every record but the OPT passed through
/// `map`. The OPT's TTL field is an extended rcode, not a lifetime.
fn rettl(message: &[u8], map: impl Fn(u32) -> u32) -> Option<Vec<u8>> {
    let mut records = Records::new(message)?;
    let mut fields = Vec::new();
    while let Some((_, record)) = records.next() {
        if record.rtype != OPT {
            fields.push((record.ttl_at, record.ttl));
        }
    }
    if !records.finished() {
        return None;
    }
    let mut copy = message.to_vec();
    for (at, ttl) in fields {
        copy[at..at + 4].copy_from_slice(&map(ttl).to_be_bytes());
    }
    Some(copy)
}

/// `message` as served from a cache `elapsed` after it arrived: every TTL
/// shorter by that time, never below zero.
pub fn aged(message: &[u8], elapsed: Duration) -> Option<Vec<u8>> {
    let elapsed = u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX);
    rettl(message, |ttl| ttl.saturating_sub(elapsed))
}

/// `message` served past its TTL: no record promises more than `cap`.
pub fn short_lived(message: &[u8], cap: u32) -> Option<Vec<u8>> {
    rettl(message, |ttl| ttl.min(cap))
}

/// Type and TTL of every record of a message, in order; for tests and
/// diagnostics of the cache.
pub fn ttls(message: &[u8]) -> Vec<(u16, u32)> {
    let mut found = Vec::new();
    let Some(mut records) = Records::new(message) else {
        return found;
    };
    while let Some((_, record)) = records.next() {
        found.push((record.rtype, record.ttl));
    }
    found
}

/// Response code of a message.
pub fn rcode(message: &[u8]) -> Option<u8> {
    Some(message.get(3)? & 0x0f)
}

/// IPv4 addresses of the answer section, in record order.
pub fn addresses(message: &[u8]) -> Vec<Ipv4Addr> {
    let mut found = Vec::new();
    let Some(mut records) = Records::new(message) else {
        return found;
    };
    while let Some((0, record)) = records.next() {
        if let (A, IN, [a, b, c, d]) = (record.rtype, record.class, record.data) {
            found.push(Ipv4Addr::new(*a, *b, *c, *d));
        }
    }
    found
}

/// Whether the wire `name` is exactly the configured `text`: a lowercase
/// host without the trailing dot.
pub fn is_name(name: &[u8], text: &str) -> bool {
    let mut rest = name;
    for label in text.split('.') {
        let Some((length, tail)) = rest.split_first() else {
            return false;
        };
        let wire = tail.get(..usize::from(*length));
        if wire.is_none_or(|wire| !wire.eq_ignore_ascii_case(label.as_bytes())) {
            return false;
        }
        rest = &tail[usize::from(*length)..];
    }
    rest == [0]
}

/// Byte length of an uncompressed name at the start of `bytes`, root label
/// included. `None` on a compression pointer, a label over 63 octets or a
/// name past 255 octets.
fn name_length(bytes: &[u8]) -> Option<usize> {
    let mut offset = 0;
    loop {
        let length = usize::from(*bytes.get(offset)?);
        if length == 0 {
            return (offset < 255).then_some(offset + 1);
        }
        if length > 63 {
            return None;
        }
        offset += length + 1;
    }
}

/// Offset just past the name at `offset`, compression pointers included.
fn skip_name(message: &[u8], offset: usize) -> Option<usize> {
    let mut offset = offset;
    loop {
        let length = *message.get(offset)?;
        if length & 0xc0 == 0xc0 {
            return Some(offset + 2);
        }
        offset += 1;
        if length == 0 {
            return Some(offset);
        }
        offset += usize::from(length);
    }
}

struct Record<'a> {
    rtype: u16,
    class: u16,
    /// Offset of the TTL field inside the message.
    ttl_at: usize,
    ttl: u32,
    data: &'a [u8],
}

/// The records after the single question of a message, answer section first.
struct Records<'a> {
    message: &'a [u8],
    offset: usize,
    /// Records left per section: answer, authority, additional.
    left: [u16; 3],
    section: usize,
}

impl<'a> Records<'a> {
    fn new(message: &'a [u8]) -> Option<Self> {
        let offset = HEADER + name_length(message.get(HEADER..)?)? + 4;
        Some(Self {
            message,
            offset,
            left: [word(message, 6)?, word(message, 8)?, word(message, 10)?],
            section: 0,
        })
    }

    /// The next record with its section.
    fn next(&mut self) -> Option<(usize, Record<'a>)> {
        while self.section < 3 && self.left[self.section] == 0 {
            self.section += 1;
        }
        let section = (self.section < 3).then_some(self.section)?;
        self.left[section] -= 1;
        let start = skip_name(self.message, self.offset)?;
        let length = usize::from(word(self.message, start + 8)?);
        let data = self.message.get(start + 10..start + 10 + length)?;
        self.offset = start + 10 + length;
        Some((
            section,
            Record {
                rtype: word(self.message, start)?,
                class: word(self.message, start + 2)?,
                ttl_at: start + 4,
                ttl: dword(self.message, start + 4)?,
                data,
            },
        ))
    }

    /// Whether every record was read and the last ends at the message end.
    fn finished(&self) -> bool {
        self.section == 3 && self.offset == self.message.len()
    }
}
