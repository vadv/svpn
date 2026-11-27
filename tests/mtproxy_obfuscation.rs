//! The obfuscated stream under the Fake TLS: the frame that names the
//! datacenter and the two directions it opens, and where the datacenters are.

mod common;

use std::io;

use common::mtproxy as client;
use common::mtproxy::KEY;
use ctr::cipher::StreamCipher;
use svpn::mtproxy::{
    self,
    obfuscation::{self, Foreign},
};

fn random(bytes: &mut [u8]) -> io::Result<()> {
    getrandom::fill(bytes).map_err(|_| io::Error::other("OS randomness"))
}

/// Two ciphers are the two ends of one direction when a message passes.
fn exchange(mut sender: obfuscation::Cipher, mut receiver: obfuscation::Cipher) {
    let mut message = b"a message of some length".to_vec();
    sender.apply_keystream(&mut message);
    receiver.apply_keystream(&mut message);
    assert_eq!(message, b"a message of some length");
}

// ── a client's frame ──

#[test]
fn a_clients_frame_names_its_datacenter_and_opens_both_directions() {
    let (wire, client) = client::frame(&KEY, -2);
    let (dc, proxy) = obfuscation::received(wire.try_into().unwrap(), &KEY).unwrap();
    assert_eq!(dc, -2);
    // The streams continue after the frame.
    exchange(client.send, proxy.recv);
    exchange(proxy.send, client.recv);
}

#[test]
fn zero_names_the_default_datacenter() {
    let (wire, _) = client::frame(&KEY, 0);
    let (dc, _) = obfuscation::received(wire.try_into().unwrap(), &KEY).unwrap();
    assert_eq!(dc, obfuscation::DEFAULT_DC);
}

#[test]
fn a_frame_of_another_secret_is_foreign() {
    let (wire, _) = client::frame(&KEY, 2);
    let wire: [u8; client::FRAME] = wire.try_into().unwrap();
    assert!(matches!(
        obfuscation::received(wire, &[0xcd; 16]),
        Err(Foreign)
    ));
    // The right secret lets the same frame in.
    assert!(obfuscation::received(wire, &KEY).is_ok());
}

#[test]
fn a_frame_of_another_transport_is_foreign() {
    // The tag travels encrypted: XOR on the wire changes it under the
    // cipher. The intermediate transport has the tag `eeeeeeee`.
    let (wire, _) = client::frame(&KEY, 2);
    let mut other: [u8; client::FRAME] = wire.try_into().unwrap();
    for byte in &mut other[56..60] {
        *byte ^= 0xdd ^ 0xee;
    }
    assert!(matches!(obfuscation::received(other, &KEY), Err(Foreign)));
}

// ── a datacenter's frame ──

#[test]
fn a_sent_frame_opens_the_datacenters_two_directions() {
    let frame = obfuscation::frame(-2, &mut random).unwrap();
    let (wire, proxy) = obfuscation::sent(&frame);
    let (dc, from_proxy, to_proxy) = client::datacenter(wire);
    assert_eq!(dc, -2);
    exchange(proxy.send, from_proxy);
    exchange(to_proxy, proxy.recv);
}

#[test]
fn a_frame_never_starts_as_something_else() {
    for dc in [2, -2, 5] {
        let frame = obfuscation::frame(dc, &mut random).unwrap();
        assert!(client::good_start(&frame));
        assert_eq!(frame[56..60], [0xdd; 4]);
        assert_eq!(frame[60..62], dc.to_le_bytes());
        // The key and the IV are random, the rest of the frame too.
        assert_ne!(&frame[8..56], &[0; 48]);
    }
}

// ── where the datacenters are ──

#[test]
fn datacenter_addresses_drop_the_sign_and_know_five_datacenters() {
    let two: Vec<_> = mtproxy::addresses(2);
    assert_eq!(two.len(), 2);
    assert!(two.contains(&"149.154.167.51:443".parse().unwrap()));
    assert!(two.contains(&"95.161.76.100:443".parse().unwrap()));
    assert_eq!(mtproxy::addresses(-2), two);
    assert_eq!(mtproxy::addresses(1).len(), 1);
    assert_eq!(mtproxy::addresses(5).len(), 1);
    assert!(mtproxy::addresses(9).is_empty());
    assert!(mtproxy::addresses(i16::MIN).is_empty());
}
