//! Traffic history in SQLite: minute rows from the hub's counters, folded
//! into hours and days, read back for the dashboard.
//!
//! Nothing here is on the path of a packet. The hub snapshots its counters
//! once a minute and hands the rows to a thread that owns the database; an
//! error of the database is logged and shown in the dashboard, never
//! propagated into the VPN.

pub mod names;
pub mod query;
pub mod recover;
pub mod sample;
pub mod store;
pub mod writer;

pub use query::{History, Kind, Query, Range, SeriesHistory};
pub use sample::{
    Bytes, Counters, FALLBACK, LOCAL, LinkCounters, LocalCounters, Row, Series, TOP_NETWORKS,
    minute,
};
pub use writer::{Recorder, Status};
