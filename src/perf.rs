//! Minimal HTTP server for the `svpn perf` benchmark: listens on the server's
//! TUN-IP and sends/receives segments of a given size. Full HTTP is not needed —
//! only `GET /seg?size=N` and `POST /seg`. The interface is internal (reachable
//! only through the VPN), the port is a constant, used only by us.
//!
//! Layout: `server` is the listener (request parsing, segment send/drain),
//! `client` the benchmark driver (streams, byte/RTT tallying), `report` the
//! interval table and its text/JSON renderings.

mod client;
mod report;
mod server;

pub use client::{MeasureArgs, Outcome, StreamAgg, measure};
pub use report::{IntervalRow, Summary, mbit, print_json, print_text, rows, summary};
pub use server::{Request, head, parse, spawn};

/// Port of the perf listener on the TUN-IP (like iperf3); not reachable from outside.
pub const PORT: u16 = 5201;
