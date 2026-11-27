//! Scope enforcement: every HTTP call goes through the guard.

use reqwest::Method;
use std::net::IpAddr;
use url::Url;

/// Scope enforcement failures.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeError {
    /// Target host is not in the configured scope list.
    #[error("host {host} is out of scope")]
    OutOfScope {
        /// The rejected host.
        host: String,
    },
    /// A loopback/private/link-local address was rejected: scanning it is
    /// either an SSRF vector or a mis-scoped internal target.
    #[error("private/internal host {host} refused (ssrf guard)")]
    PrivateIp {
        /// The rejected host.
        host: String,
    },
    /// Active probing was requested with an empty scope list.
    #[error("active probe rejected: scope list is empty (passive-only mode)")]
    PassiveOnly,
    /// A state-changing request was attempted under a read-only guard.
    #[error("state-changing {method} request refused in read-only mode")]
    ReadOnly {
        /// The refused HTTP method.
        method: String,
    },
    /// The provided string is not a valid URL.
    #[error("invalid scope url: {0}")]
    Invalid(#[from] url::ParseError),
    /// The scope file could not be loaded or parsed.
    #[error("scope file error: {0}")]
    ScopeFile(String),
}

/// How much a guard permits once a URL is in scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScanPolicy {
    /// Every method is allowed (auth/max depths).
    #[default]
    Active,
    /// Non-mutating requests only: GET, HEAD and OPTIONS pass; POST, PUT,
    /// PATCH and DELETE are refused.
    ReadOnly,
}

/// Checks URLs against a scope list. An empty list means passive-only mode.
#[derive(Debug, Clone, Default)]
pub struct ScopeGuard {
    hosts: Vec<String>,
    policy: ScanPolicy,
    allow_private: bool,
}

/// Loopback, private, link-local and equivalent IPv6 ranges are refused:
/// they are SSRF targets, never legitimate scan scope.
fn is_private_host(host: &str) -> bool {
    // url serializes IPv6 hosts with brackets; IpAddr::parse does not.
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unique_local() || v6.is_unspecified(),
        Err(_) => false,
    }
}

impl ScopeGuard {
    /// Build a guard from a list of scope origins. Hosts are extracted and
    /// compared host-to-host. Empty list → passive only.
    ///
    /// # Errors
    /// If any entry is not a valid URL, or is a private/internal address
    /// ([`ScopeError::PrivateIp`]).
    pub fn new(scope: &[&str]) -> Result<Self, ScopeError> {
        let mut hosts = Vec::with_capacity(scope.len());
        for entry in scope {
            let url = Url::parse(entry)?;
            match url.host_str() {
                Some(host) if is_private_host(host) => {
                    return Err(ScopeError::PrivateIp {
                        host: host.to_owned(),
                    })
                }
                Some(host) => hosts.push(host.to_owned()),
                None => {
                    return Err(ScopeError::OutOfScope {
                        host: (*entry).into(),
                    })
                }
            }
        }
        Ok(Self {
            hosts,
            policy: ScanPolicy::Active,
            allow_private: false,
        })
    }

    /// Like [`ScopeGuard::new`], but explicitly authorizes private/internal
    /// targets: for lab scans of hosts the operator owns (tests, and the
    /// CLI's `--allow-private`). Requests to hosts *not* listed here are
    /// still rejected by [`ScopeGuard::check`].
    ///
    /// # Errors
    /// If any entry is not a valid URL.
    pub fn new_lab(scope: &[&str]) -> Result<Self, ScopeError> {
        let mut hosts = Vec::with_capacity(scope.len());
        for entry in scope {
            let url = Url::parse(entry)?;
            match url.host_str() {
                Some(host) => hosts.push(host.to_owned()),
                None => {
                    return Err(ScopeError::OutOfScope {
                        host: (*entry).into(),
                    })
                }
            }
        }
        Ok(Self {
            hosts,
            policy: ScanPolicy::Active,
            allow_private: true,
        })
    }

    /// Whether this guard authorizes connections to private, loopback, and
    /// link-local addresses returned by DNS. Only [`ScopeGuard::new_lab`]
    /// grants this authorization.
    #[must_use]
    pub fn allows_private(&self) -> bool {
        self.allow_private
    }

    /// Restrict this guard to non-mutating requests.
    #[must_use]
    pub fn with_policy(mut self, policy: ScanPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Whether this guard refuses state-changing methods.
    pub fn is_read_only(&self) -> bool {
        self.policy == ScanPolicy::ReadOnly
    }

    /// Whether this guard permits only passive (non-probing) operations.
    pub fn is_passive_only(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Passive check: is `url`'s host in scope?
    ///
    /// # Errors
    /// [`ScopeError::PrivateIp`] when the host is an internal address not
    /// explicitly authorized (see [`ScopeGuard::new_lab`]);
    /// [`ScopeError::OutOfScope`] when the host is not listed.
    pub fn check(&self, url: &Url) -> Result<(), ScopeError> {
        let host = url.host_str().unwrap_or_default();
        if is_private_host(host) && !self.hosts.iter().any(|h| h == host) {
            return Err(ScopeError::PrivateIp {
                host: host.to_owned(),
            });
        }
        if self.hosts.iter().any(|h| h == host) {
            Ok(())
        } else {
            Err(ScopeError::OutOfScope {
                host: host.to_owned(),
            })
        }
    }

    /// Active check: additionally rejects when the guard is passive-only.
    ///
    /// # Errors
    /// [`ScopeError::PassiveOnly`] or [`ScopeError::OutOfScope`].
    pub fn check_active(&self, url: &Url) -> Result<(), ScopeError> {
        if self.is_passive_only() {
            return Err(ScopeError::PassiveOnly);
        }
        self.check(url)
    }

    /// Active check for a specific HTTP method. Under [`ScanPolicy::ReadOnly`]
    /// only GET, HEAD and OPTIONS pass; every write method is refused before
    /// the request is built.
    ///
    /// # Errors
    /// [`ScopeError::ReadOnly`] for a write in read-only mode, else the same
    /// failures as [`ScopeGuard::check_active`].
    pub fn check_request(&self, url: &Url, method: &Method) -> Result<(), ScopeError> {
        if self.is_read_only() && !matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS)
        {
            return Err(ScopeError::ReadOnly {
                method: method.as_str().to_owned(),
            });
        }
        self.check_active(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loopback_scope_origin() {
        assert!(matches!(
            ScopeGuard::new(&["http://127.0.0.1"]),
            Err(ScopeError::PrivateIp { .. })
        ));
    }

    #[test]
    fn rejects_private_scope_origin() {
        assert!(matches!(
            ScopeGuard::new(&["http://10.0.0.1"]),
            Err(ScopeError::PrivateIp { .. })
        ));
    }

    #[test]
    fn rejects_link_local_scope_origin() {
        assert!(matches!(
            ScopeGuard::new(&["http://169.254.169.254"]),
            Err(ScopeError::PrivateIp { .. })
        ));
    }

    #[test]
    fn rejects_ipv6_loopback_scope_origin() {
        assert!(matches!(
            ScopeGuard::new(&["http://[::1]:3000"]),
            Err(ScopeError::PrivateIp { .. })
        ));
    }

    #[test]
    fn lab_guard_authorizes_private_target() {
        let guard = ScopeGuard::new_lab(&["http://127.0.0.1"]).expect("lab scope");
        let url = Url::parse("http://127.0.0.1:8000/api").expect("valid url");
        assert_eq!(guard.check(&url), Ok(()));
    }

    #[test]
    fn check_rejects_private_host_outside_scope() {
        let guard = ScopeGuard::new(&["https://a.supabase.co"]).expect("valid scope");
        let url = Url::parse("http://169.254.169.254/latest/meta-data").expect("valid url");
        assert!(matches!(
            guard.check(&url),
            Err(ScopeError::PrivateIp { .. })
        ));
    }

    #[test]
    fn rejects_out_of_scope_host() {
        let guard = ScopeGuard::new(&["https://a.supabase.co"]).expect("valid scope");
        let url = Url::parse("https://b.supabase.co/rest/v1/users").expect("valid url");
        assert!(matches!(
            guard.check(&url),
            Err(ScopeError::OutOfScope { .. })
        ));
        assert!(guard.check_active(&url).is_err());
    }

    #[test]
    fn accepts_in_scope_host() {
        let guard = ScopeGuard::new(&["https://a.supabase.co"]).expect("valid scope");
        let url = Url::parse("https://a.supabase.co/rest/v1/users").expect("valid url");
        assert_eq!(guard.check(&url), Ok(()));
    }

    #[test]
    fn read_only_policy_allows_safe_methods_and_refuses_writes() {
        let guard = ScopeGuard::new_lab(&["http://127.0.0.1"])
            .expect("lab scope")
            .with_policy(ScanPolicy::ReadOnly);
        let url = Url::parse("http://127.0.0.1:8000/api").expect("valid url");
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert_eq!(guard.check_request(&url, &method), Ok(()), "{method}");
        }
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(
                matches!(
                    guard.check_request(&url, &method),
                    Err(ScopeError::ReadOnly { .. })
                ),
                "{method}"
            );
        }
    }

    #[test]
    fn active_policy_still_allows_writes() {
        let guard = ScopeGuard::new_lab(&["http://127.0.0.1"]).expect("lab scope");
        let url = Url::parse("http://127.0.0.1:8000/api").expect("valid url");
        assert_eq!(guard.check_request(&url, &Method::POST), Ok(()));
        assert_eq!(guard.check_request(&url, &Method::DELETE), Ok(()));
    }

    #[test]
    fn empty_scope_is_passive_only() {
        let guard = ScopeGuard::new(&[]).expect("valid scope");
        assert!(guard.is_passive_only());
        let url = Url::parse("https://a.supabase.co").expect("valid url");
        assert!(matches!(
            guard.check_active(&url),
            Err(ScopeError::PassiveOnly)
        ));
    }
}
