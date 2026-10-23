//! Channel establishment probe: full dance, wrong key, silent peer, size cap.

use std::time::Duration;

use svpn::channel::Channel;
use svpn::drivers;
use svpn::drivers::Io;
use svpn::probe::*;
use svpn::profile::Profile;
use tokio::net::UdpSocket;
use tokio::time::Instant;

/// A pair of mosh drivers on loopback + channels sharing one key.
async fn mosh_pair() -> (Io, Channel, Io, Channel) {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let key = svpn::crypto::random().unwrap();
    (
        drivers::datagram(server_socket, Profile::Mosh, None),
        Channel::new(key, 7, false),
        drivers::datagram(client_socket, Profile::Mosh, Some(server_addr)),
        Channel::new(key, 7, true),
    )
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

// ── establishment ──

#[tokio::test]
async fn full_dance_verifies_both_sides() {
    let (mut s_io, mut s_ch, mut c_io, mut c_ch) = mosh_pair().await;
    let mut invalid = c_ch.seal(&svpn::channel::Record::Keepalive).unwrap();
    *invalid.last_mut().unwrap() ^= 1;
    c_io.command
        .send(drivers::Command::Send(invalid))
        .await
        .unwrap();
    let (server, client) = tokio::join!(
        server(&mut s_io, &mut s_ch, 1425, deadline()),
        client(&mut c_io, &mut c_ch, 1425, deadline()),
    );
    server.unwrap();
    client.unwrap();
}

// ── failure modes ──

#[tokio::test]
async fn wrong_key_fails_both_sides() {
    let (mut s_io, _s_ch, mut c_io, mut c_ch) = mosh_pair().await;
    // A "server" with a foreign key: AEAD-open will fail.
    let mut s_ch = Channel::new(svpn::crypto::random().unwrap(), 7, false);
    let (server, client) = tokio::join!(
        server(&mut s_io, &mut s_ch, 1425, deadline()),
        client(&mut c_io, &mut c_ch, 1425, deadline()),
    );
    assert!(server.is_err());
    assert!(client.is_err());
}

#[tokio::test]
async fn silent_server_hits_deadline() {
    let (mut _s_io, _s_ch, mut c_io, mut c_ch) = mosh_pair().await;
    let err = client(
        &mut c_io,
        &mut c_ch,
        1425,
        Instant::now() + Duration::from_millis(300),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("deadline"), "{err:#}");
}

#[tokio::test]
async fn oversize_cap_rejected_by_server() {
    let (mut s_io, mut s_ch, mut c_io, mut c_ch) = mosh_pair().await;
    // The client sends a size probe of 1425, the server agreed on cap 512 → rejection.
    let (server, client) = tokio::join!(
        server(&mut s_io, &mut s_ch, 512, deadline()),
        client(&mut c_io, &mut c_ch, 1425, deadline()),
    );
    assert!(server.unwrap_err().to_string().contains("cap"));
    assert!(client.is_err());
}
