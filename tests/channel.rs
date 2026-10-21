//! Channel: record codec and golden vectors, authentication, reassembly, socket exchange.

use std::net::UdpSocket as SyncUdp;
use std::time::{Duration, Instant};

use svpn::channel::*;
use svpn::crypto;

fn sample_data() -> Record {
    Record::Data {
        flow_id: 9,
        packet_id: 1,
        offset: 0,
        total_len: 4,
        fragment: b"SVPN".to_vec(),
    }
}

// ── records ──

#[test]
fn golden_vectors_match_wire_md() {
    // V1/V2: record plaintexts.
    assert_eq!(
        hex(&sample_data().encode().unwrap()),
        "0100000000000000090000000000000001000000045356504e"
    );
    assert_eq!(
        hex(&Record::ProbeA {
            challenge: [0x31; 16]
        }
        .encode()
        .unwrap()),
        "02000000000000000031313131313131313131313131313131"
    );
    // V3: seal by the client, seq 0, channel 1.
    let mut client = Channel::new([0x07; 16], 1, true);
    assert_eq!(
        hex(&client.seal(&sample_data()).unwrap()),
        "0000000000000000fd9f18a2b2cf5882b0d3c1468cf7396c076adeef46652d65b960713f2adc0e5e28e6ab1c18a7d1f31d"
    );
    // V5: same plaintext, channel 2 — the AAD is channel-dependent, only the tag differs.
    let mut other = Channel::new([0x07; 16], 2, true);
    assert_eq!(
        hex(&other.seal(&sample_data()).unwrap()),
        "0000000000000000fd9f18a2b2cf5882b0d3c1468cf7396c076adeef46652d65b95f670053124a93d787082a8b988eca7a"
    );
    // V4: server direction, seq 2^63+5.
    let mut server = Channel::new([0x07; 16], 1, false);
    for _ in 0..5 {
        server.seal(&Record::Keepalive).unwrap();
    }
    let sealed = server.seal(&sample_data()).unwrap();
    assert!(sealed.starts_with(&[0x80, 0, 0, 0, 0, 0, 0, 5]));
    // V6: keepalive plaintext and seal at seq 1.
    assert_eq!(
        hex(&Record::Keepalive.encode().unwrap()),
        "070000000000000000"
    );
    let mut client = Channel::new([0x07; 16], 1, true);
    client.seal(&Record::Keepalive).unwrap();
    assert_eq!(
        hex(&client.seal(&Record::Keepalive).unwrap()),
        "00000000000000016a9170eadef47a8f28dd135ac18112733d8e961d1a2b02be2e"
    );
}

#[test]
fn round_trip_all_kinds() {
    let records = vec![
        sample_data(),
        Record::ProbeA { challenge: [1; 16] },
        Record::ProbeAb {
            echo: [2; 16],
            challenge: [3; 16],
        },
        Record::ProbeB { echo: [4; 16] },
        Record::FlowProbe {
            flow_id: 7,
            challenge: [5; 16],
        },
        Record::FlowEcho {
            flow_id: 7,
            echo: [6; 16],
        },
        Record::Keepalive,
        Record::SizeProbe {
            padding: vec![9; 500],
        },
    ];
    for record in &records {
        let plain = record.encode().unwrap();
        assert_eq!(&Record::decode(&plain).unwrap(), record);
    }
}

#[test]
fn decode_rejects_malformed_records() {
    // Unknown kind.
    assert!(Record::decode(&[0x09, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    // DATA with flow_id 0 (reserved) and a channel kind with flow_id ≠ 0.
    assert!(Record::decode(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3]).is_err());
    assert!(Record::decode(&[0x02, 0, 0, 0, 0, 0, 0, 0, 7, 1]).is_err());
    // total_len outside [1,1400] and offset+len > total_len.
    for (total, size) in [(0u16, 0usize), (1401, 1400)] {
        let record = Record::Data {
            flow_id: 1,
            packet_id: 1,
            offset: 0,
            total_len: total,
            fragment: vec![0; size],
        };
        assert!(record.encode().is_err());
    }
    let record = Record::Data {
        flow_id: 1,
        packet_id: 1,
        offset: 1399,
        total_len: 1400,
        fragment: vec![0; 42],
    };
    assert!(record.encode().is_err());
    // Truncated bodies.
    assert!(Record::decode(&[0x01, 0, 0, 0, 0, 0, 0, 0, 1]).is_err());
    assert!(Record::decode(&[0x03, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2]).is_err());
}

// ── authentication ──

#[test]
fn tampered_wire_fails_authentication() {
    let wire = Channel::new([0x07; 16], 1, true)
        .seal(&sample_data())
        .unwrap();
    let mut server = Channel::new([0x07; 16], 1, false);
    let now = Instant::now();
    for index in 0..wire.len() {
        let mut bad = wire.clone();
        bad[index] ^= 1;
        assert!(server.open(&bad, now).is_err(), "byte {index} accepted");
    }
    // A foreign channel cannot read the record.
    assert!(Channel::new([0x07; 16], 2, false).open(&wire, now).is_err());
    server.open(&wire, now).unwrap();
}

// ── reassembly ──

#[test]
fn fragments_of_1400_bytes_assemble() {
    // V7: the 1380 cap yields offsets 0..1380 and 1380..1400.
    let packet = vec![0xAB; 1400];
    let records = fragment_packet(5, 77, &packet, MAX_FRAGMENT).unwrap();
    assert_eq!(records.len(), 2);
    let mut reassembly = Reassembly::default();
    let now = Instant::now();
    assert!(reassembly.insert(&records[0], now).unwrap().is_none());
    match &records[1] {
        Record::Data { offset, .. } => assert_eq!(*offset, 1380),
        _ => panic!("not a DATA record"),
    }
    assert_eq!(reassembly.insert(&records[1], now).unwrap(), Some(packet));
    assert_eq!(reassembly.pending(), 0);
}

#[test]
fn duplicate_fragment_ignored_conflict_drops_packet() {
    let records = fragment_packet(5, 1, &vec![7; 1400], 700).unwrap();
    assert_eq!(records.len(), 2);
    let mut reassembly = Reassembly::default();
    let now = Instant::now();
    assert!(reassembly.insert(&records[0], now).unwrap().is_none());
    assert_eq!(reassembly.pending(), 1);
    // Exact duplicate — idempotent.
    assert!(reassembly.insert(&records[0], now).unwrap().is_none());
    assert_eq!(reassembly.pending(), 1);
    // An offset conflict drops the whole packet, not the neighboring ones.
    let conflict = Record::Data {
        flow_id: 5,
        packet_id: 1,
        offset: 0,
        total_len: 1400,
        fragment: vec![8; 700],
    };
    assert!(reassembly.insert(&conflict, now).unwrap().is_none());
    assert_eq!(reassembly.pending(), 0);
}

#[test]
fn pending_limits_drop_new_packets_not_channel() {
    let mut reassembly = Reassembly::default();
    let now = Instant::now();
    for packet_id in 0..MAX_PENDING_PACKETS as u64 {
        let record = Record::Data {
            flow_id: 1,
            packet_id,
            offset: 0,
            total_len: 100,
            fragment: vec![0; 50],
        };
        reassembly.insert(&record, now).unwrap();
    }
    assert_eq!(reassembly.pending(), MAX_PENDING_PACKETS);
    let extra = Record::Data {
        flow_id: 1,
        packet_id: 999,
        offset: 0,
        total_len: 100,
        fragment: vec![0; 50],
    };
    assert!(reassembly.insert(&extra, now).unwrap().is_none());
    assert_eq!(reassembly.pending(), MAX_PENDING_PACKETS);
    // TTL expired — the table is freed, the new packet is accepted.
    let later = now + PENDING_TTL + Duration::from_nanos(1);
    reassembly.expire(later);
    assert_eq!(reassembly.pending(), 0);
    assert!(reassembly.insert(&extra, later).unwrap().is_none());
    assert_eq!(reassembly.pending(), 1);
}

// ── socket exchange ──

#[tokio::test]
async fn plain_channel_socket_dance() {
    // Full exchange over real sockets: channel probes, flow binding,
    // data with fragmentation, keepalive; keys of a single epoch.
    let client_socket = tokio::net::UdpSocket::from_std({
        let socket = SyncUdp::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
    })
    .unwrap();
    let server_socket = tokio::net::UdpSocket::from_std({
        let socket = SyncUdp::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
    })
    .unwrap();
    let client_addr = client_socket.local_addr().unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    let key: [u8; 16] = crypto::random().unwrap();
    let mut client = Channel::new(key, 42, true);
    let mut server = Channel::new(key, 42, false);

    // PROBE_A → PROBE_AB → PROBE_B.
    let first = challenge().unwrap();
    send_record(
        &client_socket,
        server_addr,
        &mut client,
        &Record::ProbeA { challenge: first },
    )
    .await
    .unwrap();
    let (from, record) = recv_record(&server_socket, &mut server, Instant::now())
        .await
        .unwrap();
    assert_eq!(from, client_addr);
    let Record::ProbeA { challenge: echoed } = record else {
        panic!()
    };
    let second = challenge().unwrap();
    send_record(
        &server_socket,
        client_addr,
        &mut server,
        &Record::ProbeAb {
            echo: echoed,
            challenge: second,
        },
    )
    .await
    .unwrap();
    let (_, record) = recv_record(&client_socket, &mut client, Instant::now())
        .await
        .unwrap();
    let Record::ProbeAb {
        echo,
        challenge: next,
    } = record
    else {
        panic!()
    };
    assert_eq!(echo, first);
    send_record(
        &client_socket,
        server_addr,
        &mut client,
        &Record::ProbeB { echo: next },
    )
    .await
    .unwrap();
    let (_, record) = recv_record(&server_socket, &mut server, Instant::now())
        .await
        .unwrap();
    assert!(matches!(record, Record::ProbeB { echo } if echo == second));

    // Flow binding.
    let flow_challenge = challenge().unwrap();
    send_record(
        &client_socket,
        server_addr,
        &mut client,
        &Record::FlowProbe {
            flow_id: 3,
            challenge: flow_challenge,
        },
    )
    .await
    .unwrap();
    let (_, record) = recv_record(&server_socket, &mut server, Instant::now())
        .await
        .unwrap();
    let Record::FlowProbe {
        flow_id,
        challenge: echoed,
    } = record
    else {
        panic!()
    };
    send_record(
        &server_socket,
        client_addr,
        &mut server,
        &Record::FlowEcho {
            flow_id,
            echo: echoed,
        },
    )
    .await
    .unwrap();
    let (_, record) = recv_record(&client_socket, &mut client, Instant::now())
        .await
        .unwrap();
    assert_eq!(
        record,
        Record::FlowEcho {
            flow_id: 3,
            echo: flow_challenge
        }
    );

    // 1400 bytes of data as two fragments + keepalive.
    let inner = vec![0x5A; 1400];
    for record in fragment_packet(3, 1, &inner, MAX_FRAGMENT).unwrap() {
        send_record(&client_socket, server_addr, &mut client, &record)
            .await
            .unwrap();
    }
    send_record(&client_socket, server_addr, &mut client, &Record::Keepalive)
        .await
        .unwrap();
    let mut assembled = None;
    for _ in 0..3 {
        let (_, record) = recv_record(&server_socket, &mut server, Instant::now())
            .await
            .unwrap();
        if matches!(record, Record::Data { .. }) {
            assembled = server
                .assemble(&record, Instant::now())
                .unwrap()
                .or(assembled);
        } else {
            assert!(matches!(record, Record::Keepalive));
        }
    }
    assert_eq!(assembled, Some(inner));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
