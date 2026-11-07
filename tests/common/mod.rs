//! Shared packet fixtures for integration tests.

pub mod hub;
pub mod selector;
pub mod session;

use std::net::Ipv4Addr;

use svpn::{logging, packet::internet_checksum, server_spec::LinkParams};

#[allow(dead_code)] // unused by some of the including test targets
pub fn udp_packet(reverse: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; 28];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&[10, 77, 0, if reverse { 1 } else { 2 }]);
    bytes[16..20].copy_from_slice(&[10, 77, 0, if reverse { 2 } else { 1 }]);
    bytes[20..22].copy_from_slice(&(if reverse { 9000u16 } else { 40000 }).to_be_bytes());
    bytes[22..24].copy_from_slice(&(if reverse { 40000u16 } else { 9000 }).to_be_bytes());
    bytes[24..26].copy_from_slice(&8u16.to_be_bytes());
    bytes
}

#[allow(dead_code)] // unused by some of the including test targets
pub fn tcp_packet(reverse: bool) -> Vec<u8> {
    let mut bytes = udp_packet(reverse);
    bytes.resize(40, 0);
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[9] = 6;
    bytes[32] = 0x50;
    bytes[33] = 0x02;
    bytes
}

#[allow(dead_code)] // unused by some of the including test targets
pub fn echo_reply(request: &[u8]) -> Vec<u8> {
    let mut reply = request.to_vec();
    for i in 0..4 {
        reply.swap(12 + i, 16 + i);
    }
    reply[20] = 0;
    reply[22..24].fill(0);
    let checksum = internet_checksum(&reply[20..]);
    reply[22..24].copy_from_slice(&checksum.to_be_bytes());
    reply
}

/// Link parameters of a fake server link.
#[allow(dead_code)] // unused by some of the including test targets
pub fn link_params(server: Ipv4Addr, weight: u32) -> LinkParams {
    LinkParams {
        label: String::new(),
        server: server.to_string(),
        weight,
        identity: None,
        user: None,
        ssh_port: 22,
        host_key: None,
        remote_bin: "svpn".to_string(),
        peer_tun_name: None,
        log_level: logging::Level::Info,
        udp_port_range: (0, 0),
        mimic: Vec::new(),
        remeasure_interval: None,
        tcp_port: None,
        tun_addr: Ipv4Addr::new(10, 77, 0, 2),
        peer_addr: Ipv4Addr::new(10, 77, 0, 1),
        addr_auto: false,
        mtu: 1280,
        tun_name: None,
        server_up: None,
        server_down: None,
    }
}
