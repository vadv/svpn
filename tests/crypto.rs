//! Wire cipher: AES-GCM primitive, seal/open behavior, replay window, counter budgets.

use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit};
use svpn::crypto::*;

// ── aead primitive ──

#[test]
fn gcm_matches_nist_empty_vector() {
    // NIST GCM test case 1: zero key and nonce, empty plaintext/AAD;
    // the expected tag was cross-checked against an independent implementation (Node crypto).
    let cipher = Aes128Gcm::new((&[0u8; 16]).into());
    let tag = cipher
        .encrypt_in_place_detached(&[0u8; 12].into(), &[], &mut [])
        .unwrap();
    assert_eq!(
        tag.as_slice(),
        [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
            0x45, 0x5a,
        ]
    );
}

// ── seal and open ──

#[test]
fn round_trip_bounds_and_direction() {
    for length in [0, 1, 15, 16, 17, MAX_PLAINTEXT] {
        let mut client = Cipher::new([7; 16], 42, true);
        let mut server = Cipher::new([7; 16], 42, false);
        let plain = vec![3; length];
        let packet = client.seal(&plain).unwrap();
        assert_eq!(packet.len(), length + 24);
        assert!(client.open(&packet).is_err());
        assert_eq!(server.open(&packet).unwrap(), plain);
        let reply = server.seal(&plain).unwrap();
        assert_eq!(client.open(&reply).unwrap(), plain);
    }
    assert!(
        Cipher::new([7; 16], 42, true)
            .seal(&vec![0; MAX_PLAINTEXT + 1])
            .is_err()
    );
}

#[test]
fn tampering_wrong_key_and_wrong_flow_are_rejected() {
    let packet = Cipher::new([7; 16], 42, true).seal(b"packet").unwrap();
    for index in 0..packet.len() {
        let mut bad = packet.clone();
        bad[index] ^= 1;
        assert!(Cipher::new([7; 16], 42, false).open(&bad).is_err());
    }
    assert!(Cipher::new([8; 16], 42, false).open(&packet).is_err());
    assert!(Cipher::new([7; 16], 43, false).open(&packet).is_err());
}

// ── replay window ──

#[test]
fn replay_window_accepts_reordering_not_duplicates_or_old_packets() {
    let mut client = Cipher::new([7; 16], 42, true);
    let packets: Vec<_> = (0..140).map(|_| client.seal(b"packet").unwrap()).collect();
    let mut server = Cipher::new([7; 16], 42, false);
    assert!(server.open(&packets[1]).is_ok());
    assert!(server.open(&packets[0]).is_ok());
    assert!(server.open(&packets[1]).is_err());
    assert!(server.open(&packets[139]).is_ok());
    assert!(server.open(&packets[2]).is_ok()); // age 137 — inside the 4096 window
    assert!(server.open(&packets[2]).is_err());
    assert!(server.open(&packets[138]).is_ok());
}

#[test]
fn replay_window_boundary_is_4096() {
    // Age 4095 is still allowed, 4096 is not.
    let mut client = Cipher::new_channel([7; 16], 1, true);
    let packets: Vec<_> = (0..=4096)
        .map(|_| client.seal(b"packet").unwrap())
        .collect();
    let mut server = Cipher::new_channel([7; 16], 1, false);
    assert!(server.open(&packets[4096]).is_ok());
    assert!(server.open(&packets[1]).is_ok()); // age 4095
    assert!(server.open(&packets[0]).is_err()); // age 4096
    assert!(server.open(&packets[1]).is_err()); // duplicate
}

#[test]
fn replay_shift_moves_bits_across_words() {
    let mut window = ReplayWindow {
        highest: Some(1),
        ..ReplayWindow::default()
    };
    window.seen[0] = 3; // counters 1 and 0
    window.commit(70);
    // 70-1=69-bit shift: bits 0,1 (counters 1,0) move to bits 5,6 of word 1.
    assert_eq!(window.seen[0] & 0b1, 1); // counter 70
    assert_eq!(window.seen[1] >> 5 & 1, 1); // counter 1
    assert_eq!(window.seen[1] >> 6 & 1, 1); // counter 0
    assert!(window.allows(2)); // not seen yet
    assert!(!window.allows(1));
    // Full wipe on a jump past the window: age exactly WINDOW is already outside the window.
    window.commit(70 + WINDOW);
    assert!(!window.allows(70));
    assert!(!window.allows(70 + WINDOW)); // the fresh counter itself
    assert!(window.allows(70 + WINDOW - 1)); // not seen yet
}

#[test]
fn forged_high_counter_does_not_move_replay_window() {
    let mut client = Cipher::new([7; 16], 42, true);
    let packet = client.seal(b"packet").unwrap();
    let mut forged = packet.clone();
    forged[..8].copy_from_slice(&1000u64.to_be_bytes());
    let mut server = Cipher::new([7; 16], 42, false);
    assert!(server.open(&forged).is_err());
    assert!(server.open(&packet).is_ok());
}

// ── counters and budgets ──

#[test]
fn counters_and_key_budgets_never_wrap() {
    let mut client = Cipher::new([7; 16], 42, true);
    client.next = MAX_PACKETS - 1;
    assert!(client.seal(b"last").is_ok());
    assert!(client.seal(b"no").is_err());
    let mut client = Cipher::new([7; 16], 42, true);
    client.sent_blocks = MAX_BLOCKS;
    assert!(client.seal(b"no").is_err());
    let packet = Cipher::new([7; 16], 42, true).seal(b"packet").unwrap();
    let mut server = Cipher::new([7; 16], 42, false);
    server.received_blocks = MAX_BLOCKS;
    assert!(server.open(&packet).is_err());
}
