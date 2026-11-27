//! Path-normalization scanner: proves an authorization check is skipped by
//! an encoded/normalized path variant (`..%2f`, `;`).
//!
//! Requests are sent over a raw [`tokio::net::TcpStream`] because `reqwest`
//! (via the `url` crate) normalizes paths before they hit the wire — which
//! would destroy the bypass. TLS is not supported over raw sockets, so this
//! scanner probes plain-HTTP targets only; HTTPS targets are not probed.

use riftlock_core::{
    Evidence, Finding, ProofGate, ScanError, Scanner, ScopeGuard, ScopedClient as Client,
    SessionMatrix,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use url::Url;

/// Variants that commonly defeat path-based authorization checks.
const BYPASS_VARIANTS: &[&str] = &["/admin/..%2fusers", "/admin;/users"];

/// Fallback admin path probed when discovery found none.
const DEFAULT_PATHS: &[&str] = &["/admin"];

/// Per-request deadline for the raw socket exchange.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The path-normalization scanner. Admin/protected paths come from AST
/// discovery (`paths`, filled by the CLI); a default candidate is probed
/// when discovery found none.
#[derive(Debug, Default)]
pub struct PathScanner {
    /// Session matrix; the `user_a` cookie is carried on bypass probes.
    pub sessions: SessionMatrix,
    /// Admin/protected paths discovered by AST (absolute, e.g. `/admin`).
    pub paths: Vec<String>,
}

/// Extract the HTTP status code from a raw response head.
fn status_of(response: &[u8]) -> Option<u16> {
    let head = std::str::from_utf8(response.get(..64).unwrap_or(response)).ok()?;
    let status_line = head.split("\r\n").next()?;
    status_line.split(' ').nth(1)?.parse().ok()
}

impl PathScanner {
    /// GET `raw_path` sent verbatim over a raw TCP socket (no URL
    /// normalization), with an optional session cookie. Returns the status
    /// code, or `None` when the target is unreachable or not plain HTTP —
    /// an unreachable transport is a negative, not a finding.
    async fn raw_get(
        url: &Url,
        client: &Client,
        raw_path: &str,
        cookie: Option<&str>,
    ) -> Option<u16> {
        if url.scheme() != "http" {
            return None;
        }
        let host = url.host_str()?;
        let port = url.port().unwrap_or(80);
        let addresses = timeout(REQUEST_TIMEOUT, client.lookup_host(host, port))
            .await
            .ok()?
            .ok()?;
        let mut stream = timeout(REQUEST_TIMEOUT, TcpStream::connect(addresses.as_slice()))
            .await
            .ok()?
            .ok()?;
        let host_header = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_owned(),
        };
        let mut request =
            format!("GET {raw_path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n");
        if let Some(c) = cookie {
            request.push_str(&format!("Cookie: {c}\r\n"));
        }
        request.push_str("\r\n");
        timeout(REQUEST_TIMEOUT, stream.write_all(request.as_bytes()))
            .await
            .ok()?
            .ok()?;
        let mut response = Vec::new();
        timeout(REQUEST_TIMEOUT, stream.read_to_end(&mut response))
            .await
            .ok()?
            .ok()?;
        status_of(&response)
    }
}

impl Scanner for PathScanner {
    fn id(&self) -> &'static str {
        "path"
    }

    fn matches(&self, _url: &Url) -> bool {
        // Protected paths can exist on any host; probing is scope-checked.
        true
    }

    async fn scan(
        &self,
        url: &Url,
        _client: &Client,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        if passive {
            return Ok(Vec::new());
        }
        guard.check_active(url)?;
        let mut findings = Vec::new();
        if url.scheme() != "http" {
            // Raw sockets cannot speak TLS; nothing provable here.
            return Ok(findings);
        }
        let user_a = self.sessions.user_a.as_deref();
        let mut paths: Vec<&str> = self.paths.iter().map(String::as_str).collect();
        paths.extend(DEFAULT_PATHS.iter().copied());
        for path in paths {
            let baseline_probe = url.join(path).map_err(|_| ScanError::InvalidUrl)?;
            if guard.check(&baseline_probe).is_err() {
                continue;
            }
            // Baseline: the protected path must actually be protected (401/403)
            // for a bypass to be provable. A 200 baseline leaves nothing to bypass.
            let baseline = PathScanner::raw_get(url, _client, path, user_a).await;
            if !matches!(baseline, Some(401 | 403)) {
                continue;
            }
            for &variant in BYPASS_VARIANTS {
                let variant_probe = url.join(variant).map_err(|_| ScanError::InvalidUrl)?;
                if guard.check(&variant_probe).is_err() {
                    continue;
                }
                if PathScanner::raw_get(url, _client, variant, user_a).await == Some(200) {
                    findings.push(ProofGate::admit(Evidence::PathNormalizationBypass {
                        path: variant.to_owned(),
                    })?);
                }
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::ScopedClient as Client;

    fn sessions_with(cookie: &str) -> SessionMatrix {
        SessionMatrix {
            user_a: Some(cookie.to_owned()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn scan_proves_normalization_bypass() {
        let server = wiremock::MockServer::start().await;
        // Baseline: the protected path is protected.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/admin"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;
        // Vulnerable server: the encoded variant normalizes through to a
        // readable resource.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/admin/..%2fusers"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = PathScanner {
            sessions: sessions_with("sid=abc"),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::PathNormalizationBypass { path }
                if path == "/admin/..%2fusers"
        ));
    }

    #[tokio::test]
    async fn scan_negative_when_variant_still_blocked() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/admin"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;
        // The server blocks every variant: checked negative.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = PathScanner {
            sessions: sessions_with("sid=abc"),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_when_baseline_is_public() {
        let server = wiremock::MockServer::start().await;
        // Baseline 200: the path is not protected, so no bypass exists.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = PathScanner {
            sessions: sessions_with("sid=abc"),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }
}
