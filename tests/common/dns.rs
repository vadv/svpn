//! DNS message fixtures: wire queries and answers in the shape stubs and
//! resolvers produce them, and a loopback resolver to relay to.

use std::net::{Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;

#[allow(dead_code)] // unused by some of the including test targets
pub const A: u16 = 1;
#[allow(dead_code)] // unused by some of the including test targets
pub const HOST: &str = "www.example.com";

/// A resolver on loopback: every datagram it gets goes through `respond`
/// with the socket to answer from and the asker's address.
#[allow(dead_code)] // unused by some of the including test targets
pub async fn resolver(
    respond: impl Fn(&UdpSocket, &[u8], SocketAddr) + Send + 'static,
) -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        while let Ok((length, from)) = socket.recv_from(&mut buffer).await {
            respond(&socket, &buffer[..length], from);
        }
    });
    address
}

/// Wire name of a dotted host, root label included.
#[allow(dead_code)] // unused by some of the including test targets
pub fn name(host: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in host.split('.') {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire
}

/// One question for `host`: RD set, EDNS with `payload` when given.
#[allow(dead_code)] // unused by some of the including test targets
pub fn query(id: u16, host: &str, qtype: u16, payload: Option<u16>) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&[0x01, 0x00]);
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&[0; 6]);
    message.extend_from_slice(&name(host));
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    if let Some(payload) = payload {
        // Root owner, type OPT, class = payload size, empty ttl and rdata.
        message.extend_from_slice(&[0, 0, 41]);
        message.extend_from_slice(&payload.to_be_bytes());
        message.extend_from_slice(&[0; 6]);
        message[10..12].copy_from_slice(&1u16.to_be_bytes());
    }
    message
}

/// Record with its owner compressed to the question name.
#[allow(dead_code)] // unused by some of the including test targets
pub fn record(qtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut record = vec![0xc0, 0x0c];
    record.extend_from_slice(&qtype.to_be_bytes());
    record.extend_from_slice(&1u16.to_be_bytes());
    record.extend_from_slice(&ttl.to_be_bytes());
    record.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    record.extend_from_slice(rdata);
    record
}

#[allow(dead_code)] // unused by some of the including test targets
pub fn a(ttl: u32, octets: [u8; 4]) -> Vec<u8> {
    record(1, ttl, &octets)
}

/// `query` answered with `addresses`, each with `ttl`.
#[allow(dead_code)] // unused by some of the including test targets
pub fn addressed(query: &[u8], ttl: u32, addresses: &[[u8; 4]]) -> Vec<u8> {
    let answers: Vec<Vec<u8>> = addresses.iter().map(|&ip| a(ttl, ip)).collect();
    answer(query, &answers)
}

/// `query` answered with one A record.
#[allow(dead_code)] // unused by some of the including test targets
pub fn answered(query: &[u8]) -> Vec<u8> {
    addressed(query, 60, &[[203, 0, 113, 7]])
}

/// The resolver's answer to `query`: QR, RA, the question echoed back,
/// nothing outside the answer section.
#[allow(dead_code)] // unused by some of the including test targets
pub fn answer(query: &[u8], answers: &[Vec<u8>]) -> Vec<u8> {
    message(query, answers, &[], &[])
}

/// A resolver's response with all three record sections given.
#[allow(dead_code)] // unused by some of the including test targets
pub fn message(
    query: &[u8],
    answers: &[Vec<u8>],
    authority: &[Vec<u8>],
    additional: &[Vec<u8>],
) -> Vec<u8> {
    let question = 12 + query[12..].iter().position(|&byte| byte == 0).unwrap() + 1 + 4;
    let mut response = query[..question].to_vec();
    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    for (offset, records) in [(6, answers), (8, authority), (10, additional)] {
        let count = u16::try_from(records.len()).unwrap();
        response[offset..offset + 2].copy_from_slice(&count.to_be_bytes());
    }
    for record in answers.iter().chain(authority).chain(additional) {
        response.extend_from_slice(record);
    }
    response
}
