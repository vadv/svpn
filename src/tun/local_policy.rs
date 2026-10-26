#[cfg(target_os = "linux")]
mod imp {
    use std::net::Ipv4Addr;

    use crate::tun::PeerRoute;
    use anyhow::Result;

    pub struct LocalPolicy {
        _peer: PeerRoute,
    }

    impl LocalPolicy {
        pub fn install(
            local_client: Ipv4Addr,
            local_tun: &str,
            _primary_client: Ipv4Addr,
            _primary_tun: &str,
        ) -> Result<Self> {
            // Source rules cannot classify unbound sockets before route selection.
            Ok(Self {
                _peer: PeerRoute::install(local_client, local_tun)?,
            })
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::net::{IpAddr, Ipv4Addr};

    use anyhow::{Context, Result, ensure};
    use route_manager::{Route, RouteManager};

    pub struct LocalPolicy {
        route: Route,
    }

    impl LocalPolicy {
        pub fn install(
            _local_client: Ipv4Addr,
            local_tun: &str,
            _primary_client: Ipv4Addr,
            _primary_tun: &str,
        ) -> Result<Self> {
            let index = crate::tun::if_index_of(local_tun)?;
            let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                .with_if_index(index)
                .with_if_scope(true);
            let mut manager = RouteManager::new().context("route manager")?;
            match manager.add(&route) {
                Ok(()) => Ok(Self { route }),
                Err(error) if error.raw_os_error() == Some(17) => {
                    ensure!(
                        route_present(&mut manager, &route)?,
                        "foreign scoped default route blocks local-exit"
                    );
                    Ok(Self { route })
                }
                Err(error) => Err(error).context("add local-exit scoped default route"),
            }
        }
    }

    impl Drop for LocalPolicy {
        fn drop(&mut self) {
            let Ok(mut manager) = RouteManager::new() else {
                return;
            };
            match route_present(&mut manager, &self.route) {
                Ok(true) => {
                    if let Err(error) = manager.delete(&self.route) {
                        crate::warn!("local-exit default route cleanup failed — {error}");
                    }
                }
                Ok(false) => {}
                Err(error) => crate::warn!("local-exit default route check failed — {error:#}"),
            }
        }
    }

    fn route_present(manager: &mut RouteManager, expected: &Route) -> Result<bool> {
        Ok(manager.list().context("list routes")?.iter().any(|route| {
            route.destination() == expected.destination()
                && route.prefix() == expected.prefix()
                && route.if_index() == expected.if_index()
                && route.if_scope()
        }))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use std::net::Ipv4Addr;

    use anyhow::Result;

    pub struct LocalPolicy;

    impl LocalPolicy {
        pub fn install(
            _local_client: Ipv4Addr,
            _local_tun: &str,
            _primary_client: Ipv4Addr,
            _primary_tun: &str,
        ) -> Result<Self> {
            Ok(Self)
        }
    }
}

pub use imp::LocalPolicy;
