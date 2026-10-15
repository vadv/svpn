//! Common type of delivered channel/flow IP packets for the session loop.

/// IP packet of flow `id`, reassembled by the transport from channel records.
pub struct Incoming {
    pub id: u64,
    /// Actual receiving UDP channel; None denotes a per-flow TCP socket.
    pub channel: Option<u64>,
    pub packet: Vec<u8>,
}
