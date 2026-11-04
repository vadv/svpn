//! Resolve the server addresses passed to the automatic client route hook.

use std::collections::BTreeSet;

use anyhow::Result;

use crate::server_spec::{LinkParams, resolve_ipv4};

/// Embedded automatic client routing, used only when manual hooks are absent.
pub const UP: &str = include_str!("../scripts/client-up");
pub const DOWN: &str = include_str!("../scripts/client-down");

/// Resolve every configured VPS once, before the first full-tunnel route.
pub async fn server_addrs(servers: &[LinkParams]) -> Result<String> {
    let mut addresses = BTreeSet::new();
    for server in servers {
        addresses.insert(resolve_ipv4(&server.server).await?);
    }
    Ok(addresses
        .into_iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(" "))
}
