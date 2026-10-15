//! Shared packet fixtures for integration tests.

use svpn::packet::internet_checksum;

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
