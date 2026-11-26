//! DNS that follows the exit. The hub answers the client's UDP/53 from its
//! TUN; a VPN exit resolves through the control channel in `svpn server`,
//! the local exit through the WAN resolvers, both with the same relay.
//!
//! Layout: this file carries the settings and the control-channel carriage,
//! `wire` the DNS message codec, `relay` the exchange with resolvers, and
//! `hub::dns` the engine itself.

pub mod relay;
pub mod wire;

use std::net::Ipv4Addr;

use base64::Engine as _;

/// The port the hub answers on behalf of any resolver.
pub const PORT: u16 = 53;

/// The `dns` block of the config.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// Resolvers of the local exit; discovered when empty.
    pub local: Vec<Ipv4Addr>,
}

/// DNS over the control channel: base64 of the wire message. An empty
/// `dns_answer` carries no message at all: no resolver answered.
pub fn encode(message: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(message)
}

/// `None` for an empty text or anything that is not standard base64.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .ok()
        .filter(|message| !message.is_empty())
}
