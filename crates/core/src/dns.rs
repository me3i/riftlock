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
///
/// Non-routable answers (loopback, private, link-local) are allowed only for a
/// host the scan scope explicitly names: that is the operator's chosen target.
/// Every other hostname still gets the public-address-only policy, so a remote
/// page cannot redirect resolution at internal infrastructure.
#[derive(Clone)]
pub struct SafeResolve {
    inner: Arc<dyn Resolve>,
    scoped_hosts: Arc<[String]>,
    allow_private_any_host: bool,
}

impl std::fmt::Debug for SafeResolve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafeResolve").finish_non_exhaustive()
    }
}

impl SafeResolve {
    /// Wrap an existing resolver using a scope guard's authorized hosts.
    #[must_use]
    pub fn new(inner: Arc<dyn Resolve>, guard: &ScopeGuard) -> Self {
        Self {
            inner,
            scoped_hosts: guard.hosts().into(),
            allow_private_any_host: guard.allows_private(),
        }
    }

    /// Create a resolver using the operating system's DNS configuration.
    #[must_use]
    pub fn system(guard: &ScopeGuard) -> Self {
        Self::new(Arc::new(SystemResolve), guard)
    }

    /// Whether `ip` is an acceptable answer for `host`.
    ///
    /// Public addresses always pass. A non-routable address passes only when
    /// `host` is explicitly in the scan scope (or this is a lab client).
    #[must_use]
    pub fn allows_address(&self, host: &str, ip: IpAddr) -> bool {
        is_safe_ip(ip)
            || (is_lab_private_ip(ip) && (self.allow_private_any_host || self.is_scoped_host(host)))
    }

    fn is_scoped_host(&self, host: &str) -> bool {
        host_in_scope(&self.scoped_hosts, host)
    }

    /// Resolve `host` and attach `port`, rejecting any unsafe result.
    ///
    /// # Errors
    /// Returns an error if resolution fails, produces no addresses, or includes
    /// any address that is not allowed for `host`: multicast, unspecified,
    /// IPv4-mapped IPv6, or IPv6 `fe80::/10` always fail, while private,
    /// loopback and link-local results fail unless `host` is in scope.
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
        if addrs
            .iter()
            .any(|addr| !self.allows_address(host, addr.ip()))
        {
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
        let host = name.as_str().to_owned();
        let scoped_hosts = Arc::clone(&self.scoped_hosts);
        let allow_private_any_host = self.allow_private_any_host;
        Box::pin(async move {
            let addrs = inner.resolve(name).await?.collect::<Vec<_>>();
            let allowed = |ip: IpAddr| {
                is_safe_ip(ip)
                    || (is_lab_private_ip(ip)
                        && (allow_private_any_host || host_in_scope(&scoped_hosts, &host)))
            };
            if addrs.is_empty() || addrs.iter().any(|addr| !allowed(addr.ip())) {
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

/// Host scope comparison. IPv6 hosts arrive both bracketed (from `Url`) and
/// bare (from `Name` or an IP-literal check), so brackets are stripped first.
fn host_in_scope(scoped_hosts: &[String], host: &str) -> bool {
    let bare = |host: &str| {
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned()
    };
    let host = bare(host);
    scoped_hosts
        .iter()
        .any(|scoped| bare(scoped).eq_ignore_ascii_case(&host))
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
    fn scoped_host_may_resolve_private_but_unlisted_host_may_not() {
        let loopback: IpAddr = "127.0.0.1".parse().expect("test IP");
        let target = ScopeGuard::new(&["http://192.168.21.11/"]).expect("scope");
        let resolver = SafeResolve::system(&target);
        assert!(resolver.allows_address("192.168.21.11", loopback));
        assert!(!resolver.allows_address("internal.example", loopback));
        assert!(!resolver.allows_address("internal.example", "224.0.0.1".parse().expect("test IP")));
    }

    #[test]
    fn scoped_ipv6_literal_matches_bracketed_and_bare_forms() {
        let loopback: IpAddr = "::1".parse().expect("test IP");
        let target = ScopeGuard::new(&["http://[::1]:3000/"]).expect("scope");
        let resolver = SafeResolve::system(&target);
        assert!(resolver.allows_address("[::1]", loopback));
        assert!(resolver.allows_address("::1", loopback));
        assert!(!resolver.allows_address("[::2]", loopback));
    }

    #[test]
    fn lab_client_allows_private_for_test_hosts_only() {
        let loopback: IpAddr = "127.0.0.1".parse().expect("test IP");
        let lab = ScopeGuard::new_lab(&[]).expect("lab guard");
        assert!(SafeResolve::system(&lab).allows_address("127.0.0.1", loopback));
        assert!(!SafeResolve::system(&lab)
            .allows_address("127.0.0.1", "224.0.0.1".parse().expect("test IP")));
    }

    #[test]
    fn permits_documentation_address_used_by_rebinding_test() {
        assert!(is_safe_ip("198.51.100.1".parse().expect("test IP")));
    }
}
