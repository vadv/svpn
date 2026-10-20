//! Loopback port token: exclusive, atomic, released on drop (#181).

use std::net::UdpSocket;

use svpn::portlock::PortLock;

fn free_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn token_is_exclusive_and_reusable_after_drop() {
    let port = free_port();
    let first = PortLock::try_acquire(port).unwrap().expect("free port");
    assert!(
        PortLock::try_acquire(port).unwrap().is_none(),
        "a held port rejects a second bind"
    );
    drop(first);
    assert!(
        PortLock::try_acquire(port).unwrap().is_some(),
        "a dropped token relocks"
    );
}
