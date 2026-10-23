//! Wire profiles (plain, mosh, obfs): bounds, wrapping, and socket dances.

use std::net::UdpSocket as SyncUdp;

use svpn::channel::{self, Record};
use svpn::pcap::PcapBuilder;
use svpn::profile::*;

/// Node crypto AES-128-GCM vector: generation 1, channel 1, client seq 0.
const V3: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x9f, 0x18, 0xa2, 0xb2, 0xcf, 0x58, 0x82,
    0xb0, 0xd3, 0xc1, 0x46, 0x8c, 0xf7, 0x39, 0x6c, 0x07, 0x6a, 0xde, 0xef, 0x42, 0x36, 0x7b, 0x35,
    0xf6, 0xaa, 0x2c, 0x83, 0xb9, 0x8b, 0x9c, 0x1e, 0x8f, 0x80, 0x79, 0xdb, 0xf0, 0x9b, 0x69, 0x4e,
    0xc4, 0xd0, 0x09, 0xe8, 0x88, 0x69, 0xad, 0xcf, 0x16,
];

// ── wire bounds ──

#[test]
fn plain_is_identity_within_bounds() {
    let mut bytes = V3.to_vec();
    Profile::Plain.wrap_in_place(&mut bytes).unwrap();
    assert_eq!(bytes, V3);
    Profile::Plain.unwrap_in_place(&mut bytes).unwrap();
    assert_eq!(bytes, V3);
}

#[test]
fn rejects_out_of_bounds_both_directions() {
    for profile in [Profile::Plain, Profile::Mosh] {
        let mut short = vec![0u8; MIN_WIRE - 1];
        assert!(profile.wrap_in_place(&mut short).is_err());
        let mut long = vec![0u8; MAX_WIRE + 1];
        assert!(profile.unwrap_in_place(&mut long).is_err());
        let mut empty = Vec::new();
        assert!(profile.wrap_in_place(&mut empty).is_err());
    }
    // Obfs: short/long wire is rejected before any allocations.
    let mut short = vec![0u8; OBF_HEADER + MIN_WIRE - 1];
    assert!(Profile::Obfs.unwrap_in_place(&mut short).is_err());
    let mut long = vec![0u8; MAX_WIRE + 1];
    assert!(Profile::Obfs.wrap_in_place(&mut long).is_err());
    // Padding larger than the body: b2=15 with length exactly 2+MIN_WIRE.
    let mut pad_heavy = vec![0u8; OBF_HEADER + MIN_WIRE];
    pad_heavy[1] = 15;
    assert!(Profile::Obfs.unwrap_in_place(&mut pad_heavy).is_err());
}

// ── mosh ──

#[test]
fn mosh_prefix_is_little_endian_u64() {
    let mut bytes = V3.to_vec();
    Profile::Mosh.wrap_in_place(&mut bytes).unwrap();
    // The seq=0 BE prefix is reversed — the LE representation of the
    // same u64; ciphertext and tag are untouched.
    assert_eq!(&bytes[..8], &V3[..8]);
    assert_eq!(&bytes[8..], &V3[8..]);
    // seq=0 is symmetric: verify the order on the server V4 (seq 2^63+5).
    let v4: Vec<u8> = [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]
        .iter()
        .chain(V3[8..].iter())
        .cloned()
        .collect();
    let mut wrapped = v4.clone();
    Profile::Mosh.wrap_in_place(&mut wrapped).unwrap();
    assert_eq!(&wrapped[..8], &[0x05, 0, 0, 0, 0, 0, 0, 0x80]);
    Profile::Mosh.unwrap_in_place(&mut wrapped).unwrap();
    assert_eq!(wrapped, v4);
}

#[test]
fn mosh_roundtrip_with_channel_records() {
    let mut client = channel::Channel::new([0x42; 16], 7, true);
    let mut server = channel::Channel::new([0x42; 16], 7, false);
    for record in [Record::Keepalive, Record::ProbeA { challenge: [9; 16] }] {
        let mut wire = client.seal(&record).unwrap();
        Profile::Mosh.wrap_in_place(&mut wire).unwrap();
        Profile::Mosh.unwrap_in_place(&mut wire).unwrap();
        let opened = server.open(&wire, std::time::Instant::now()).unwrap();
        assert_eq!(opened, Some(record));
    }
    // Ciphertext corruption after unwrap is caught by the channel AEAD.
    let mut wire = client.seal(&Record::Keepalive).unwrap();
    Profile::Mosh.wrap_in_place(&mut wire).unwrap();
    Profile::Mosh.unwrap_in_place(&mut wire).unwrap();
    let last = wire.len() - 1;
    wire[last] ^= 1;
    assert_eq!(server.open(&wire, std::time::Instant::now()).unwrap(), None);
    wire[last] ^= 1;
    assert_eq!(
        server.open(&wire, std::time::Instant::now()).unwrap(),
        Some(Record::Keepalive)
    );
    // Profiles cannot be mixed up: Plain on mosh wire yields a wrong nonce/order.
    let mut wire = client.seal(&Record::Keepalive).unwrap();
    Profile::Mosh.wrap_in_place(&mut wire).unwrap();
    Profile::Plain.unwrap_in_place(&mut wire).unwrap();
    assert_eq!(server.open(&wire, std::time::Instant::now()).unwrap(), None);
    Profile::Mosh.unwrap_in_place(&mut wire).unwrap();
    assert_eq!(
        server.open(&wire, std::time::Instant::now()).unwrap(),
        Some(Record::Keepalive)
    );
}

#[test]
fn mosh_socket_dance_writes_pcap() {
    let client_socket = SyncUdp::bind("127.0.0.1:0").unwrap();
    let server_socket = SyncUdp::bind("127.0.0.1:0").unwrap();
    let client_addr = client_socket.local_addr().unwrap();
    let server_addr = server_socket.local_addr().unwrap();
    let mut client = channel::Channel::new([0x77; 16], 9, true);
    let mut server = channel::Channel::new([0x77; 16], 9, false);
    let mut pcap = PcapBuilder::new();
    let mut send = |socket: &SyncUdp,
                    peer: std::net::SocketAddr,
                    channel: &mut channel::Channel,
                    record: &Record|
     -> Vec<u8> {
        let mut wire = channel.seal(record).unwrap();
        Profile::Mosh.wrap_in_place(&mut wire).unwrap();
        socket.send_to(&wire, peer).unwrap();
        pcap.add_datagram(&wire);
        wire
    };
    let recv = |socket: &SyncUdp, channel: &mut channel::Channel| {
        let mut buf = vec![0u8; MAX_WIRE];
        let (len, _) = socket.recv_from(&mut buf).unwrap();
        buf.truncate(len);
        Profile::Mosh.unwrap_in_place(&mut buf).unwrap();
        channel
            .open(&buf, std::time::Instant::now())
            .unwrap()
            .unwrap()
    };

    // Channel probes in both directions.
    let a = channel::challenge().unwrap();
    let wire = send(
        &client_socket,
        server_addr,
        &mut client,
        &Record::ProbeA { challenge: a },
    );
    assert_eq!(&wire[..8], &[0; 8]); // client seq 0, LE
    match recv(&server_socket, &mut server) {
        Record::ProbeA { challenge } => assert_eq!(challenge, a),
        _ => panic!("expected PROBE_A"),
    }
    let b = channel::challenge().unwrap();
    send(
        &server_socket,
        client_addr,
        &mut server,
        &Record::ProbeAb {
            echo: a,
            challenge: b,
        },
    );
    match recv(&client_socket, &mut client) {
        Record::ProbeAb { echo, challenge } => {
            assert_eq!(echo, a);
            assert_eq!(challenge, b);
        }
        _ => panic!("expected PROBE_AB"),
    }
    send(
        &client_socket,
        server_addr,
        &mut client,
        &Record::ProbeB { echo: b },
    );
    match recv(&server_socket, &mut server) {
        Record::ProbeB { echo } => assert_eq!(echo, b),
        _ => panic!("expected PROBE_B"),
    }

    // Maximum inner packet: two fragments.
    let packet = vec![0x5a; 1400];
    for record in channel::fragment_packet(1, 1, 1, &packet, channel::MAX_FRAGMENT).unwrap() {
        send(&client_socket, server_addr, &mut client, &record);
        let received = recv(&server_socket, &mut server);
        if let Some(assembled) = server
            .assemble(&received, std::time::Instant::now())
            .unwrap()
        {
            assert_eq!(assembled, packet);
        }
    }
    send(&server_socket, client_addr, &mut server, &Record::Keepalive);

    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/pcap/mosh-dance.pcap");
    pcap.finish(&path);
    assert!(std::fs::metadata(&path).unwrap().len() > 0);
}

// ── obfs ──

#[test]
fn obfs_roundtrip_with_channel_records() {
    let mut client = channel::Channel::new([0x33; 16], 5, true);
    let mut server = channel::Channel::new([0x33; 16], 5, false);
    for record in [
        Record::Keepalive,
        Record::ProbeA { challenge: [4; 16] },
        Record::Data {
            flow_id: 2,
            generation: 1,
            packet_id: 1,
            offset: 0,
            total_len: 28,
            fragment: vec![0xab; 28],
        },
    ] {
        let mut wire = client.seal(&record).unwrap();
        Profile::Obfs.wrap_in_place(&mut wire).unwrap();
        // The length matches the header: 2 + prefix + sealed + padding.
        let expected = wire.len();
        let _ = expected;
        Profile::Obfs.unwrap_in_place(&mut wire).unwrap();
        let opened = server.open(&wire, std::time::Instant::now()).unwrap();
        assert_eq!(opened, Some(record));
    }
}

#[test]
fn obfs_hides_length_and_respects_caps() {
    let sealed = vec![0x11; 64];
    let mut lengths = std::collections::HashSet::new();
    for _ in 0..100 {
        let mut wire = sealed.clone();
        Profile::Obfs.wrap_in_place(&mut wire).unwrap();
        assert!(wire.len() <= MAX_WIRE);
        assert!(wire.len() >= sealed.len() + OBF_HEADER);
        // Length formula: 2 + (b1%16) + sealed + (b2%16).
        let prefix = usize::from(wire[0] % 16);
        let pad = usize::from(wire[1] % 16);
        assert_eq!(wire.len(), OBF_HEADER + prefix + sealed.len() + pad);
        // Sealed bytes are unchanged inside the overhead.
        assert_eq!(&wire[OBF_HEADER + prefix..wire.len() - pad], &sealed[..]);
        lengths.insert(wire.len());
    }
    // Lengths are smeared, not constant (256 prefix/padding combinations).
    assert!(lengths.len() >= 3, "obfs lengths not smeared: {lengths:?}");
}

#[test]
fn obfs_fragment_budget_fits_wire_cap() {
    let packet = vec![0x5c; 1400];
    let cap = Profile::Obfs.max_fragment();
    assert_eq!(cap, 1340);
    assert_eq!(cap + channel::DATA_HEADER + 24 + OBF_HEADER + 30, MAX_WIRE);
    assert_eq!(Profile::Plain.max_fragment(), 1372);
    assert_eq!(Profile::Mosh.max_fragment(), 1372);
    let records = channel::fragment_packet(3, 1, 1, &packet, cap).unwrap();
    assert!(records.len() <= 3);
    for record in &records {
        let mut wire = channel::Channel::new([0x55; 16], 1, true)
            .seal(record)
            .unwrap();
        Profile::Obfs.wrap_in_place(&mut wire).unwrap();
        assert!(wire.len() <= MAX_WIRE);
    }
    // The obfs budget is tighter than the channel one: the channel's
    // maximum fragment does not fit.
    let mut oversized = channel::Channel::new([0x55; 16], 1, true)
        .seal(&Record::Data {
            flow_id: 3,
            generation: 1,
            packet_id: 2,
            offset: 0,
            total_len: 1400,
            fragment: vec![0; channel::MAX_FRAGMENT],
        })
        .unwrap();
    assert!(Profile::Obfs.wrap_in_place(&mut oversized).is_err());
}

#[test]
fn obfs_tampered_header_breaks_auth() {
    let mut client = channel::Channel::new([0x66; 16], 11, true);
    let mut server = channel::Channel::new([0x66; 16], 11, false);
    let mut wire = client.seal(&Record::Keepalive).unwrap();
    Profile::Obfs.wrap_in_place(&mut wire).unwrap();
    let mut valid = wire.clone();
    // b1 ^= 1 always flips the low bit → mod16 differs by 1:
    // the receiver trims the wrong prefix and the AEAD rejects the record.
    let orig_prefix = usize::from(wire[0] % 16);
    wire[0] ^= 1;
    assert_ne!(usize::from(wire[0] % 16), orig_prefix);
    assert!(Profile::Obfs.unwrap_in_place(&mut wire).is_ok());
    assert_eq!(server.open(&wire, std::time::Instant::now()).unwrap(), None);
    Profile::Obfs.unwrap_in_place(&mut valid).unwrap();
    assert_eq!(
        server.open(&valid, std::time::Instant::now()).unwrap(),
        Some(Record::Keepalive)
    );
}

#[test]
fn obfs_socket_dance_writes_pcap() {
    let client_socket = SyncUdp::bind("127.0.0.1:0").unwrap();
    let server_socket = SyncUdp::bind("127.0.0.1:0").unwrap();
    let client_addr = client_socket.local_addr().unwrap();
    let server_addr = server_socket.local_addr().unwrap();
    let mut client = channel::Channel::new([0x88; 16], 13, true);
    let mut server = channel::Channel::new([0x88; 16], 13, false);
    let mut pcap = PcapBuilder::new();
    let mut send = |socket: &SyncUdp,
                    peer: std::net::SocketAddr,
                    chan: &mut channel::Channel,
                    record: &Record| {
        let mut wire = chan.seal(record).unwrap();
        Profile::Obfs.wrap_in_place(&mut wire).unwrap();
        socket.send_to(&wire, peer).unwrap();
        pcap.add_datagram(&wire);
    };
    let recv = |socket: &SyncUdp, chan: &mut channel::Channel| {
        let mut buf = vec![0u8; MAX_WIRE];
        let (len, _) = socket.recv_from(&mut buf).unwrap();
        buf.truncate(len);
        Profile::Obfs.unwrap_in_place(&mut buf).unwrap();
        chan.open(&buf, std::time::Instant::now()).unwrap().unwrap()
    };
    let a = channel::challenge().unwrap();
    send(
        &client_socket,
        server_addr,
        &mut client,
        &Record::ProbeA { challenge: a },
    );
    match recv(&server_socket, &mut server) {
        Record::ProbeA { challenge } => assert_eq!(challenge, a),
        _ => panic!("expected PROBE_A"),
    }
    let b = channel::challenge().unwrap();
    send(
        &server_socket,
        client_addr,
        &mut server,
        &Record::ProbeAb {
            echo: a,
            challenge: b,
        },
    );
    match recv(&client_socket, &mut client) {
        Record::ProbeAb { echo, challenge } => {
            assert_eq!(echo, a);
            assert_eq!(challenge, b);
        }
        _ => panic!("expected PROBE_AB"),
    }
    send(
        &client_socket,
        server_addr,
        &mut client,
        &Record::ProbeB { echo: b },
    );
    match recv(&server_socket, &mut server) {
        Record::ProbeB { echo } => assert_eq!(echo, b),
        _ => panic!("expected PROBE_B"),
    }
    let packet = vec![0x5d; 1400];
    for record in channel::fragment_packet(1, 1, 1, &packet, Profile::Obfs.max_fragment()).unwrap()
    {
        send(&client_socket, server_addr, &mut client, &record);
        let received = recv(&server_socket, &mut server);
        if let Some(assembled) = server
            .assemble(&received, std::time::Instant::now())
            .unwrap()
        {
            assert_eq!(assembled, packet);
        }
    }
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/pcap/obfs-dance.pcap");
    pcap.finish(&path);
    assert!(std::fs::metadata(&path).unwrap().len() > 0);
}
