//! Cross-process exclusive token backed by a loopback UDP port (#181).
//!
//! Binding a UDP port is atomic in the kernel: exactly one process holds
//! 127.0.0.1:port at a time, and the token is released the moment the
//! process dies, even on SIGKILL. The socket carries no traffic; the port
//! number is only the lock name. A generic primitive: the caller picks the
//! port, the module knows nothing about tunnel addressing.

use std::{io, net::UdpSocket};

/// RAII hold on a port token; dropping releases it.
pub struct PortLock {
    _socket: UdpSocket,
}

impl PortLock {
    /// Take the token for `port`; `Ok(None)` when another process holds it.
    /// `SO_REUSEADDR`/`SO_REUSEPORT` are never set, so duplicates fail on
    /// both Linux and macOS.
    pub fn try_acquire(port: u16) -> io::Result<Option<Self>> {
        match UdpSocket::bind(("127.0.0.1", port)) {
            Ok(socket) => Ok(Some(Self { _socket: socket })),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => Ok(None),
            Err(error) => Err(error),
        }
    }
}
