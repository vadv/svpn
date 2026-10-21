//! TCP framing: length frames, binding, banner and SSH camouflage, SSH wire formats.

use anyhow::Result;
use svpn::crypto::Cipher;
use svpn::framing::*;

fn decode_all(camouflage: Camouflage, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut decoder = Decoder::new(camouflage);
    decoder.push(bytes);
    let mut payloads = Vec::new();
    while let Some(payload) = decoder.next(None)? {
        payloads.push(payload);
    }
    Ok(payloads)
}

/// Full client flow under L2: hello, binding, tail, data frames, keepalive.
fn ssh_client_stream() -> (Vec<u8>, Cipher) {
    let mut client = Cipher::new([5; 16], 7, true);
    let sealed = client.seal(b"first").unwrap();
    let mut stream = ssh_client_hello();
    stream.extend(ssh_binding_frame(&[9; TOKEN_BYTES], &sealed).unwrap());
    stream.extend(ssh_client_tail());
    stream.extend(ssh_frame(&mut client, b"hello").unwrap());
    stream.extend(ssh_frame(&mut client, &[]).unwrap()); // keepalive
    (stream, client)
}

// ── length frames ──

#[test]
fn frames_round_trip_in_order() {
    let payloads: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![], vec![4; MAX_PAYLOAD]];
    let mut stream = Vec::new();
    for payload in &payloads {
        stream.extend_from_slice(&frame(payload).unwrap());
    }
    assert_eq!(decode_all(Camouflage::None, &stream).unwrap(), payloads);
}

#[test]
fn oversize_payload_and_len_are_rejected() {
    assert!(frame(&[0; MAX_PAYLOAD + 1]).is_err());
    let mut stream = (MAX_PAYLOAD as u32 + 1).to_be_bytes().to_vec();
    stream.extend_from_slice(&[0; 5]);
    let mut decoder = Decoder::new(Camouflage::None);
    decoder.push(&stream);
    assert_eq!(
        decoder.next(None).unwrap_err().to_string(),
        "TCP frame too large"
    );
}

#[test]
fn truncated_frame_waits_for_bytes() {
    let stream = frame(&[5; 30]).unwrap();
    let mut decoder = Decoder::new(Camouflage::None);
    for chunk in [&stream[..2], &stream[2..3], &stream[3..10], &stream[10..20]] {
        decoder.push(chunk);
        assert!(decoder.next(None).unwrap().is_none());
    }
    decoder.push(&stream[20..]);
    assert_eq!(decoder.next(None).unwrap().unwrap(), vec![5; 30]);
    assert!(decoder.next(None).unwrap().is_none());
}

// ── binding ──

#[test]
fn binding_token_survives_round_trip() {
    let token = [7u8; TOKEN_BYTES];
    let packet = vec![9; 24];
    let stream = frame(&binding_payload(&token, &packet)).unwrap();
    let payloads = decode_all(Camouflage::None, &stream).unwrap();
    let (got_token, got_packet) = split_binding(&payloads[0]).unwrap();
    assert_eq!(got_token, token);
    assert_eq!(got_packet, packet);
    assert!(split_binding(&[0u8; TOKEN_BYTES]).is_err());
}

// ── banner camouflage ──

#[test]
fn banner_then_frames_in_one_chunk() {
    let mut stream = banner().to_vec();
    stream.extend_from_slice(&frame(&[6; 24]).unwrap());
    assert_eq!(
        decode_all(Camouflage::Banner, &stream).unwrap(),
        vec![vec![6; 24]]
    );
}

#[test]
fn banner_incomplete_then_completed() {
    let mut stream = b"SSH-2.0-O".to_vec();
    let mut decoder = Decoder::new(Camouflage::Banner);
    decoder.push(&stream);
    assert!(decoder.next(None).unwrap().is_none());
    stream = b"penSSH_9.9p2\r\n".to_vec();
    stream.extend_from_slice(&frame(&[1]).unwrap());
    decoder.push(&stream);
    assert_eq!(decoder.next(None).unwrap().unwrap(), vec![1]);
}

#[test]
fn malformed_banners_are_rejected() {
    for bad in [
        &b"XX-2.0-OpenSSH_9.9p2\r\n"[..],
        b"SSH-2.0-OpenSSH_9.9p2\n",
        b"SSH-\xff\xfe\r\n",
    ] {
        let mut decoder = Decoder::new(Camouflage::Banner);
        decoder.push(bad);
        assert!(decoder.next(None).is_err(), "accepted {bad:?}");
    }
    let mut decoder = Decoder::new(Camouflage::Banner);
    decoder.push(&[b'x'; 300]);
    assert_eq!(
        decoder.next(None).unwrap_err().to_string(),
        "TCP banner too long"
    );
}

#[test]
fn none_mode_rejects_banner_as_frame() {
    // Camouflage level desync: the leading "SSH-" bytes are read as a length.
    let mut decoder = Decoder::new(Camouflage::None);
    decoder.push(banner());
    assert_eq!(
        decoder.next(None).unwrap_err().to_string(),
        "TCP frame too large"
    );
}

// ── ssh camouflage ──

#[test]
fn ssh_stream_round_trip_server_side() {
    let (stream, _client) = ssh_client_stream();
    let mut server = Cipher::new([5; 16], 7, false);
    let mut decoder = Decoder::new_ssh(true);
    // Incrementality: an incomplete hello yields no payload.
    decoder.push(&stream[..30]);
    assert!(decoder.next(None).unwrap().is_none());
    decoder.push(&stream[30..]);
    let binding = decoder.next(None).unwrap().unwrap();
    let (token, first) = split_binding(&binding).unwrap();
    assert_eq!(token, [9u8; TOKEN_BYTES].as_slice());
    assert_eq!(server.open(first).unwrap(), b"first");
    let sealed = decoder.next(Some(&mut server)).unwrap().unwrap();
    assert_eq!(server.open(&sealed).unwrap(), b"hello");
    let keepalive = decoder.next(Some(&mut server)).unwrap().unwrap();
    assert_eq!(server.open(&keepalive).unwrap(), Vec::<u8>::new());
    assert!(decoder.next(Some(&mut server)).unwrap().is_none());
}

#[test]
fn ssh_stream_round_trip_client_side() {
    let mut server = Cipher::new([5; 16], 7, false);
    let mut client = Cipher::new([5; 16], 7, true);
    let mut stream = ssh_server_hello();
    stream.extend(ssh_server_tail());
    stream.extend(ssh_frame(&mut server, b"reply").unwrap());
    let mut decoder = Decoder::new_ssh(false);
    decoder.push(&stream[..stream.len() / 2]);
    assert!(decoder.next(Some(&mut client)).unwrap().is_none());
    decoder.push(&stream[stream.len() / 2..]);
    let sealed = decoder.next(Some(&mut client)).unwrap().unwrap();
    assert_eq!(client.open(&sealed).unwrap(), b"reply");
    assert!(decoder.next(Some(&mut client)).unwrap().is_none());
}

#[test]
fn eof_rejects_incomplete_handshake_and_opened_frame_header() {
    let mut decoder = Decoder::new_ssh(false);
    assert!(decoder.finish().is_err());
    let mut client = Cipher::new([5; 16], 7, true);
    decoder.push(&ssh_server_hello());
    decoder.push(&ssh_server_tail());
    assert!(decoder.next(Some(&mut client)).unwrap().is_none());
    decoder.finish().unwrap();
    let frame = ssh_frame(&mut Cipher::new([5; 16], 7, false), b"payload").unwrap();
    decoder.push(&frame[..1]);
    assert!(decoder.next(Some(&mut client)).unwrap().is_none());
    assert!(decoder.finish().is_err());
    decoder.push(&frame[1..frame.len() - 1]);
    assert!(decoder.next(Some(&mut client)).unwrap().is_none());
    assert!(decoder.pending_len.is_some());
    assert!(decoder.finish().is_err());
    decoder.push(&frame[frame.len() - 1..]);
    assert!(decoder.next(Some(&mut client)).unwrap().is_some());
    decoder.finish().unwrap();
}

#[test]
fn ssh_data_frame_arrives_byte_by_byte() {
    // Regression: the frame header must not be opened again while the body is
    // still arriving (a repeated open of the same seq = "replayed packet").
    let (mut a, mut b) = (
        Cipher::new([3; 16], 11, true),
        Cipher::new([3; 16], 11, false),
    );
    let mut stream = ssh_client_hello();
    let sealed = a.seal(b"first").unwrap();
    stream.extend(ssh_binding_frame(&[9; TOKEN_BYTES], &sealed).unwrap());
    stream.extend(ssh_client_tail());
    let frame = ssh_frame(&mut a, b"pay").unwrap();
    let mut decoder = Decoder::new_ssh(true);
    decoder.push(&stream);
    assert!(decoder.next(None).unwrap().is_some()); // binding
    let mut got = Vec::new();
    for chunk in frame {
        decoder.push(&[chunk]);
        while let Some(payload) = decoder.next(Some(&mut b)).unwrap() {
            got.push(payload);
        }
    }
    assert_eq!(got.len(), 1);
    assert_eq!(b.open(&got[0]).unwrap(), b"pay");
}

#[test]
fn ssh_garbage_handshake_is_rejected() {
    // Garbage instead of KEXINIT after a valid banner.
    let mut stream = banner().to_vec();
    stream.extend_from_slice(b"definitely-not-a-kexinit-frame");
    let mut decoder = Decoder::new_ssh(true);
    decoder.push(&stream);
    assert_eq!(
        decoder.next(None).unwrap_err().to_string(),
        "malformed SSH handshake"
    );
    // KEXINIT is valid, but the binding frame is msg 31 instead of 30.
    let mut stream = ssh_client_hello();
    let mut payload = vec![31];
    payload.extend(vec![0; 24]);
    stream.extend(bpp(&payload));
    let mut decoder = Decoder::new_ssh(true);
    decoder.push(&stream);
    assert_eq!(
        decoder.next(None).unwrap_err().to_string(),
        "malformed TCP binding frame"
    );
    // Binding passed, but the NEWKEYS tail did not match.
    let sealed = Cipher::new([1; 16], 1, true).seal(b"x").unwrap();
    let mut stream = ssh_client_hello();
    stream.extend(ssh_binding_frame(&[1; TOKEN_BYTES], &sealed).unwrap());
    stream.extend_from_slice(b"NOT-NEWKEYS-TAIL");
    let mut decoder = Decoder::new_ssh(true);
    decoder.push(&stream);
    assert!(decoder.next(None).unwrap().is_some());
    assert_eq!(
        decoder.next(None).unwrap_err().to_string(),
        "malformed SSH handshake"
    );
    // Oversized binding BPP frame.
    let mut stream = ssh_client_hello();
    stream.extend_from_slice(&100_000u32.to_be_bytes());
    stream.extend_from_slice(&[4, 30]);
    stream.extend_from_slice(&[0; 40]);
    let mut decoder = Decoder::new_ssh(true);
    decoder.push(&stream);
    assert_eq!(
        decoder.next(None).unwrap_err().to_string(),
        "TCP frame too large"
    );
}

#[test]
fn malformed_handshake_errors_never_include_wire_bytes() {
    let expected = b"expected-handshake";
    for bad in [b"secret".as_slice(), b"secret-payload-longer-than-hello"] {
        assert_eq!(
            Decoder::take_const(expected, &mut bad.to_vec())
                .unwrap_err()
                .to_string(),
            "malformed SSH handshake"
        );
    }
    let mut partial = expected[..4].to_vec();
    assert!(!Decoder::take_const(expected, &mut partial).unwrap());
    partial.extend_from_slice(&expected[4..]);
    assert!(Decoder::take_const(expected, &mut partial).unwrap());
    assert!(partial.is_empty());
}

#[test]
fn ssh_mode_desync_is_rejected() {
    // L0 length frames instead of the Ssh handshake after hello.
    let mut decoder = Decoder::new_ssh(true);
    decoder.push(&ssh_client_hello());
    decoder.push(&frame(&[0; 40]).unwrap());
    assert_eq!(
        decoder.next(None).unwrap_err().to_string(),
        "malformed TCP binding frame"
    );
    // Ssh flow in the L0 decoder: the banner is read as a huge length.
    let mut decoder = Decoder::new(Camouflage::None);
    decoder.push(&ssh_client_hello());
    assert_eq!(
        decoder.next(None).unwrap_err().to_string(),
        "TCP frame too large"
    );
}

// ── ssh wire formats ──

#[test]
fn kexinit_frames_follow_bpp_and_share_lists() {
    let (client, server) = (kexinit(CLIENT_COOKIE_SEED), kexinit(SERVER_COOKIE_SEED));
    assert_ne!(client[6..22], server[6..22]); // the sides' cookies differ
    for frame in [&client, &server] {
        let packet_length = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        let padding = frame[4] as usize;
        assert_eq!(frame.len(), 4 + packet_length);
        assert_eq!(frame.len() % 8, 0);
        assert!((4..=255).contains(&padding));
        assert_eq!(frame[5], 20); // SSH2_MSG_KEXINIT
        // Tail: first_kex_packet_follows=0 and reserved u32=0.
        let payload_end = frame.len() - padding;
        assert_eq!(&frame[payload_end - 5..payload_end], &[0, 0, 0, 0, 0]);
        // The 10 name-lists parse back-to-back and cover the payload exactly.
        let mut offset = 22;
        for expected in KEX_LISTS {
            let length = u32::from_be_bytes(frame[offset..offset + 4].try_into().unwrap()) as usize;
            assert_eq!(length, expected.len());
            assert_eq!(&frame[offset + 4..offset + 4 + length], expected.as_bytes());
            offset += 4 + length;
        }
        assert_eq!(offset, payload_end - 5);
    }
    // Both sides' lists are checked against KEX_LISTS above — the intersection is non-empty (T02 §2).
}

#[test]
fn ssh_control_frames_follow_bpp() {
    let binding = ssh_binding_frame(&[7; TOKEN_BYTES], &[2; 64]).unwrap();
    let packet_length = u32::from_be_bytes(binding[..4].try_into().unwrap()) as usize;
    let padding = binding[4] as usize;
    assert_eq!(binding.len(), 4 + packet_length);
    assert_eq!(binding.len() % 8, 0);
    assert!(padding >= 4);
    assert_eq!(binding[5], 30); // SSH2_MSG_KEX_ECDH_INIT
    assert_eq!(&binding[6..22], &[7; TOKEN_BYTES]);
    assert_eq!(&binding[22..86], &[2; 64]);
    let reply = kex_reply();
    assert_eq!(reply[5], 31);
    assert!(reply.len() >= 100, "kex-reply implausible size"); // T02 §3
    let keys = newkeys();
    assert_eq!(keys.len(), 16); // minimal BPP frame
    assert_eq!(keys[5], 21); // SSH2_MSG_NEWKEYS
    assert!(ssh_client_tail().len() > keys.len());
    assert_eq!(auth_frames(1, 2, 60).len(), 104); // 60 + 60-16
}
