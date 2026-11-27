//! Scope enforcement: every HTTP call goes through the guard.

use reqwest::Method;
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
    /// Set only for the lab/test constructor. Scan guards authorize private
    /// resolution per scoped host instead of globally.
    allow_private_any_host: bool,
}

impl ScopeGuard {
    /// Build a guard from a list of scope origins. Hosts are extracted and
    /// compared host-to-host. Empty list → passive only.
    ///
    /// # Errors
    /// If any entry is not a valid URL.
    pub fn new(scope: &[&str]) -> Result<Self, ScopeError> {
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
            allow_private_any_host: false,
        })
    }

    /// Build a guard for isolated lab tests. Like [`ScopeGuard::new`], every
    /// request must still match a listed host; the difference is that DNS
    /// answers may be private for any host, which the in-process wiremock
    /// tests need. Production scans use [`ScopeGuard::new`], where private
    /// resolution is authorized per scoped host.
    ///
    /// # Errors
    /// If any entry is not a valid URL.
    pub fn new_lab(scope: &[&str]) -> Result<Self, ScopeError> {
        Ok(Self {
            allow_private_any_host: true,
            ..Self::new(scope)?
        })
    }

    /// The hosts this guard authorizes, in scope order.
    #[must_use]
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// Whether DNS may resolve private addresses for any host (lab only).
    #[must_use]
    pub fn allows_private(&self) -> bool {
        self.allow_private_any_host
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

    /// Whether `host` exactly matches one of this guard's authorized hosts.
    #[must_use]
    pub fn contains_host(&self, host: &str) -> bool {
        self.hosts
            .iter()
            .any(|authorized| authorized.eq_ignore_ascii_case(host))
    }

    /// Passive check: is `url`'s host in scope?
    ///
    /// # Errors
    /// [`ScopeError::OutOfScope`] when the host is not listed.
    pub fn check(&self, url: &Url) -> Result<(), ScopeError> {
        let host = url.host_str().unwrap_or_default();
        if self.contains_host(host) {
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
    fn accepts_private_target_origins() {
        for origin in [
            "http://127.0.0.1",
            "http://10.0.0.1",
            "http://169.254.169.254",
            "http://[::1]:3000",
        ] {
            assert!(ScopeGuard::new(&[origin]).is_ok(), "{origin}");
        }
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
            Err(ScopeError::OutOfScope { .. })
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
