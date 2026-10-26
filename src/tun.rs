//! TUN device creation and the busy-name diagnostics of the serve side.

use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result, ensure};
use tun_rs::{AsyncDevice, DeviceBuilder};

pub fn validate_tun_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    ensure!(
        !bytes.is_empty() && bytes.len() <= 15,
        "TUN name must be 1..=15 bytes"
    );
    ensure!(
        bytes.iter().all(|b| b.is_ascii_graphic() && *b != b'/'),
        "TUN name must not contain spaces, control characters, or '/'"
    );
    Ok(())
}

pub fn create_tun(
    local: Ipv4Addr,
    peer: Ipv4Addr,
    mtu: u16,
    name: Option<&str>,
    announce: bool,
) -> Result<AsyncDevice> {
    let mut builder = DeviceBuilder::new().ipv4(local, 32u8, Some(peer)).mtu(mtu);
    if let Some(name) = name {
        builder = builder.name(name);
    }
    #[cfg(target_os = "macos")]
    let builder = builder.associate_route(false);
    let tun = builder
        .build_async()
        .context("create/configure TUN (requires network privileges)")?;
    crate::debug!(
        "TUN ready: {} local={local} peer={peer} mtu={mtu}",
        tun.name()?
    );
    if announce {
        crate::info!("tun: {} ready — {}, MTU {}", tun.name()?, local, mtu);
    }
    Ok(tun)
}

/// Owned peer return route for a local-exit TUN. The claimed inner pair
/// makes an existing exact route safe to reclaim after a crash.
pub struct PeerRoute {
    route: route_manager::Route,
}

impl PeerRoute {
    pub fn install(peer: Ipv4Addr, tun_name: &str) -> Result<Self> {
        let index = if_index_of(tun_name)?;
        let route = peer_route(peer, index);
        let mut manager = route_manager::RouteManager::new().context("route manager")?;
        let binding = Self { route };
        if route_present(&mut manager, peer, index)? {
            return Ok(binding);
        }
        match manager.add(&binding.route) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(17) => {
                ensure!(
                    route_present(&mut manager, peer, index)?,
                    "foreign route blocks local-exit peer {peer}/32 via {tun_name}"
                );
                return Ok(binding);
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("add local-exit peer route {peer}/32 via {tun_name}")
                });
            }
        }
        ensure!(
            route_present(&mut manager, peer, index)?,
            "local-exit peer route {peer}/32 via {tun_name} did not install"
        );
        Ok(binding)
    }
}

impl Drop for PeerRoute {
    fn drop(&mut self) {
        let Ok(mut manager) = route_manager::RouteManager::new() else {
            return;
        };
        if let Err(error) = manager.delete(&self.route)
            && !matches!(error.raw_os_error(), Some(2 | 3))
        {
            crate::warn!("local-exit peer route cleanup failed — {error}");
        }
    }
}

fn peer_route(peer: Ipv4Addr, index: u32) -> route_manager::Route {
    #[cfg(target_os = "linux")]
    {
        route_manager::Route::new(IpAddr::V4(peer), 32)
            .with_if_index(index)
            .with_table(254)
    }
    #[cfg(not(target_os = "linux"))]
    {
        route_manager::Route::new(IpAddr::V4(peer), 32).with_if_index(index)
    }
}

fn route_present(
    manager: &mut route_manager::RouteManager,
    peer: Ipv4Addr,
    index: u32,
) -> Result<bool> {
    Ok(manager.list().context("list routes")?.iter().any(|route| {
        route.destination() == IpAddr::V4(peer)
            && route.prefix() == 32
            && route.if_index() == Some(index)
            && {
                #[cfg(target_os = "linux")]
                {
                    route.table() == 254
                }
                #[cfg(not(target_os = "linux"))]
                {
                    true
                }
            }
    }))
}

/// Detect EBUSY from TUNSETIFF while another process holds the name.
pub fn is_busy_tun(error: &anyhow::Error) -> bool {
    error
        .root_cause()
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.raw_os_error() == Some(16))
}

/// Return the TUN interface index used by direct return routes.
pub fn if_index_of(name: &str) -> Result<u32> {
    let index = nix::net::if_::if_nametoindex(name)
        .with_context(|| format!("TUN {name} interface index"))?;
    ensure!(index != 0, "TUN {name} has no interface index");
    Ok(index)
}

/// Pids (besides us) holding /dev/net/tun, for the final EBUSY report.
pub fn stale_tun_holders() -> String {
    let me = std::process::id();
    let holders: Vec<String> = std::fs::read_dir("/proc")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .filter(|pid| *pid != me)
        .filter(|pid| {
            std::fs::read_dir(format!("/proc/{pid}/fd"))
                .map(|fds| {
                    fds.filter_map(Result::ok).any(|fd| {
                        std::fs::read_link(fd.path())
                            .is_ok_and(|target| target == std::path::Path::new("/dev/net/tun"))
                    })
                })
                .unwrap_or(false)
        })
        .map(|pid| pid.to_string())
        .collect();
    match holders.is_empty() {
        true => String::new(),
        false => format!(" (pid {})", holders.join(", pid ")),
    }
}
