//! DNS resolution guarded against addresses that must not be reached by scanners.

use crate::ScopeGuard;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::error::Error;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

/// Resolver wrapper that rejects unsafe DNS answers before reqwest can connect.
///
/// A mixed answer set is rejected in full: returning only its public addresses
/// would still make connection behavior depend on resolver answer ordering.
#[derive(Clone)]
pub struct SafeResolve {
    inner: Arc<dyn Resolve>,
    allow_private: bool,
}

impl std::fmt::Debug for SafeResolve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafeResolve").finish_non_exhaustive()
    }
}

impl SafeResolve {
    /// Wrap an existing resolver using a scope guard's private-address authorization.
    #[must_use]
    pub fn new(inner: Arc<dyn Resolve>, guard: &ScopeGuard) -> Self {
        Self {
            inner,
            allow_private: guard.allows_private(),
        }
    }

    /// Create a resolver using the operating system's DNS configuration.
    #[must_use]
    pub fn system(guard: &ScopeGuard) -> Self {
        Self::new(Arc::new(SystemResolve), guard)
    }

    /// Whether this resolver permits private, loopback, and link-local results.
    #[must_use]
    pub fn allows_private(&self) -> bool {
        self.allow_private
    }

    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        is_allowed_ip(ip, self.allow_private)
    }

    /// Resolve `host` and attach `port`, rejecting any unsafe result.
    ///
    /// # Errors
    /// Returns an error if resolution fails, produces no addresses, or includes
    /// any address that is private, loopback, link-local, multicast, unspecified,
    /// IPv4-mapped IPv6, or IPv6 `fe80::/10`.
    pub async fn lookup_host(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let name = Name::from_str(host)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid DNS hostname"))?;
        let mut addrs = self
            .inner
            .resolve(name)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "DNS resolution failed"))?
            .collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "DNS resolution returned no addresses",
            ));
        }
        if addrs.iter().any(|addr| !self.allows_ip(addr.ip())) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS resolution returned a prohibited address",
            ));
        }
        for addr in &mut addrs {
            addr.set_port(port);
        }
        Ok(addrs)
    }
}

impl Resolve for SafeResolve {
    fn resolve(&self, name: Name) -> Resolving {
        let inner = Arc::clone(&self.inner);
        let allow_private = self.allow_private;
        Box::pin(async move {
            let addrs = inner.resolve(name).await?.collect::<Vec<_>>();
            if addrs.is_empty()
                || addrs
                    .iter()
                    .any(|addr| !is_allowed_ip(addr.ip(), allow_private))
            {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "DNS resolution returned no addresses or a prohibited address",
                )) as Box<dyn Error + Send + Sync>);
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[derive(Debug)]
struct SystemResolve;

impl Resolve for SystemResolve {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();
            let addrs = tokio::net::lookup_host((host, 0)).await?;
            Ok(Box::new(addrs) as Addrs)
        })
    }
}

fn is_allowed_ip(ip: IpAddr, allow_private: bool) -> bool {
    is_safe_ip(ip) || (allow_private && is_lab_private_ip(ip))
}

fn is_lab_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unique_local() || is_ipv6_link_local(ip.octets())
        }
    }
}

fn is_ipv6_link_local(octets: [u8; 16]) -> bool {
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

/// Whether an address is allowed as the result of hostname resolution.
#[must_use]
pub fn is_safe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            !ip.is_loopback()
                && !ip.is_unique_local()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && ip.to_ipv4_mapped().is_none()
                && !is_ipv6_link_local(octets)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_prohibited_address_classes() {
        for ip in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "ff02::1",
            "::",
            "::ffff:127.0.0.1",
            "fe80::1",
            "febf::1",
        ] {
            assert!(!is_safe_ip(ip.parse().expect("test IP")), "{ip}");
        }
    }

    #[test]
    fn production_guard_denies_loopback_but_lab_guard_allows_it() {
        let loopback: IpAddr = "127.0.0.1".parse().expect("test IP");
        let production = ScopeGuard::new(&[]).expect("production guard");
        let lab = ScopeGuard::new_lab(&[]).expect("lab guard");
        assert!(!SafeResolve::system(&production).allows_ip(loopback));
        assert!(SafeResolve::system(&lab).allows_ip(loopback));
        // Lab authorization does not relax non-private classes.
        let multicast: IpAddr = "224.0.0.1".parse().expect("test IP");
        assert!(!SafeResolve::system(&lab).allows_ip(multicast));
    }

    #[test]
    fn permits_documentation_address_used_by_rebinding_test() {
        assert!(is_safe_ip("198.51.100.1".parse().expect("test IP")));
    }
}
