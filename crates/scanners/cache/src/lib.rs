//! Cache-deception scanner: proves an authenticated response is served from
//! the cache to an unauthenticated request on a cacheable path variant.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    text_limited_result, CheckState, Coverage, EndpointOutcome, Evidence, Finding, ProofGate,
    ScanError, Scanner, ScopeGuard, SessionMatrix,
};
use url::Url;

/// Well-known protected paths probed for cache deception.
const PROTECTED_PATHS: &[&str] = &["/api/user", "/profile", "/api/me", "/account", "/settings"];

/// Minimum length of the authenticated body before it is treated as
/// user-specific data (shorter bodies are boilerplate/stubs).
const MIN_AUTH_BODY: usize = 16;

/// The cache-deception scanner. `matches()` is always true: cacheable
/// protected endpoints can appear on any host; probing is scope-checked.
#[derive(Debug, Default)]
pub struct CacheScanner {
    /// Session matrix; the `user_a` cookie provides the authenticated tier.
    pub sessions: SessionMatrix,
    /// One check per authenticated or anonymous probe.
    pub coverage: Coverage,
}

/// Whether the unauthenticated response actually contains the user's data:
/// the authenticated body must be substantial and the unauthenticated body
/// must contain it verbatim. Anything weaker is a heuristic, not proof.
fn contains_user_data(auth_body: &str, unauth_body: &str) -> bool {
    let auth = auth_body.trim();
    !auth.is_empty() && auth.len() >= MIN_AUTH_BODY && unauth_body.contains(auth)
}

impl CacheScanner {
    /// GET `path` on `url`'s origin, optionally with a session cookie.
    /// Returns (status, body).
    async fn get(
        client: &Client,
        url: &Url,
        path: &str,
        cookie: Option<&str>,
    ) -> Result<(u16, Result<String, riftlock_core::body::BodyReadError>), ScanError> {
        let target = url.join(path).map_err(|_| ScanError::InvalidUrl)?;
        let mut req = client.get(target);
        if let Some(c) = cookie {
            req = req.header("Cookie", c);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let body = text_limited_result(resp).await;
        Ok((status, body))
    }
}

impl Scanner for CacheScanner {
    fn id(&self) -> &'static str {
        "cache"
    }

    fn matches(&self, _url: &Url) -> bool {
        true
    }

    async fn scan(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        if passive {
            return Ok(Vec::new());
        }
        guard.check_active(url)?;
        let mut findings = Vec::new();
        let Some(user_a) = self.sessions.user_a.as_deref() else {
            // No authenticated tier: the differential is unprovable, so
            // nothing is sent at all.
            return Ok(findings);
        };
        for path in PROTECTED_PATHS {
            let probe = url.join(path).map_err(|_| ScanError::InvalidUrl)?;
            if guard.check(&probe).is_err() {
                self.coverage
                    .endpoint_at(probe.as_str(), EndpointOutcome::Skipped);
                continue;
            }
            let auth_check = self.coverage.begin_check();
            let (auth_status, auth_body) =
                match CacheScanner::get(client, url, path, Some(user_a)).await {
                    Ok(response) => response,
                    Err(error) => {
                        let timed_out = matches!(
                            &error,
                            ScanError::Http(http_error) if http_error.is_timeout()
                        );
                        self.coverage.endpoint_at(
                            probe.as_str(),
                            if timed_out {
                                EndpointOutcome::TimedOut
                            } else {
                                EndpointOutcome::Failed
                            },
                        );
                        let state = if timed_out {
                            CheckState::TimedOut
                        } else {
                            CheckState::Failed
                        };
                        let _ = auth_check.finish(state);
                        continue;
                    }
                };
            let auth_outcome = riftlock_core::classify(auth_status);
            if auth_status != 200 {
                self.coverage.endpoint_at(probe.as_str(), auth_outcome);
                let _ = auth_check.finish(
                    if matches!(
                        auth_outcome,
                        EndpointOutcome::WafBlocked | EndpointOutcome::AuthRequired
                    ) {
                        CheckState::Inconclusive
                    } else {
                        CheckState::Completed
                    },
                );
                continue;
            }
            let auth_body = match auth_body {
                Ok(body) => body,
                Err(_) => {
                    self.coverage
                        .endpoint_at(probe.as_str(), EndpointOutcome::Failed);
                    let _ = auth_check.finish(CheckState::Inconclusive);
                    continue;
                }
            };
            self.coverage
                .endpoint_at(probe.as_str(), EndpointOutcome::Tested);
            let _ = auth_check.finish(CheckState::Completed);
            // Tier 2: the unauthenticated request on the cacheable variant.
            let css_path = format!("{path}/nonexistent.css");
            let anon_url = url
                .join(&css_path)
                .map_or_else(|_| format!("{url}{css_path}"), |joined| joined.to_string());
            let anon_check = self.coverage.begin_check();
            let (unauth_status, unauth_body) =
                match CacheScanner::get(client, url, &css_path, None).await {
                    Ok(response) => response,
                    Err(error) => {
                        let timed_out = matches!(
                            &error,
                            ScanError::Http(http_error) if http_error.is_timeout()
                        );
                        self.coverage.endpoint_at(
                            &anon_url,
                            if timed_out {
                                EndpointOutcome::TimedOut
                            } else {
                                EndpointOutcome::Failed
                            },
                        );
                        let state = if timed_out {
                            CheckState::TimedOut
                        } else {
                            CheckState::Failed
                        };
                        let _ = anon_check.finish(state);
                        continue;
                    }
                };
            let unauth_outcome = riftlock_core::classify(unauth_status);
            if unauth_status != 200 {
                self.coverage.endpoint_at(&anon_url, unauth_outcome);
                let _ = anon_check.finish(
                    if matches!(
                        unauth_outcome,
                        EndpointOutcome::WafBlocked | EndpointOutcome::AuthRequired
                    ) {
                        CheckState::Inconclusive
                    } else {
                        CheckState::Completed
                    },
                );
                continue;
            }
            let unauth_body = match unauth_body {
                Ok(body) => body,
                Err(_) => {
                    self.coverage
                        .endpoint_at(&anon_url, EndpointOutcome::Failed);
                    let _ = anon_check.finish(CheckState::Inconclusive);
                    continue;
                }
            };
            self.coverage
                .endpoint_at(&anon_url, EndpointOutcome::Tested);
            let _ = anon_check.finish(CheckState::Completed);
            if contains_user_data(&auth_body, &unauth_body) {
                findings.push(ProofGate::admit(Evidence::CacheDeception {
                    endpoint: probe.to_string(),
                })?);
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sessions_with(cookie: &str) -> SessionMatrix {
        SessionMatrix {
            user_a: Some(cookie.to_owned()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn scan_proves_cache_deception() {
        let server = wiremock::MockServer::start().await;
        let secret = "{\"email\":\"user@example.com\",\"role\":\"member\"}";
        // Authenticated tier: cookie required.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/user"))
            .and(wiremock::matchers::header("Cookie", "sid=abc"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(secret))
            .mount(&server)
            .await;
        // The cached variant serves the same body without a cookie.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/user/nonexistent.css"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(secret))
            .mount(&server)
            .await;
        // Everything else: 404.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = CacheScanner {
            sessions: sessions_with("sid=abc"),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::CacheDeception { endpoint }
                if endpoint.ends_with("/api/user")
        ));
    }

    #[tokio::test]
    async fn scan_negative_when_unauth_variant_is_generic() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/user"))
            .and(wiremock::matchers::header("Cookie", "sid=abc"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string("{\"email\":\"user@example.com\",\"role\":\"member\"}"),
            )
            .mount(&server)
            .await;
        // 200 but a generic page: the user's data is not in it — no proof.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/user/nonexistent.css"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string("<html>not found</html>"),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = CacheScanner {
            sessions: sessions_with("sid=abc"),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn corrupt_gzip_authenticated_body_is_failed_and_inconclusive() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/user"))
            .and(wiremock::matchers::header("Cookie", "sid=abc"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(b"not a gzip stream".to_vec()),
            )
            .mount(&server)
            .await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = CacheScanner {
            sessions: sessions_with("sid=abc"),
            ..Default::default()
        };

        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("an unreadable response is inconclusive, not a scan error");
        assert!(findings.is_empty());
        let snap = scanner.coverage.snapshot(0);
        assert_eq!(snap.endpoints_failed, 1);
        assert_eq!(snap.vulnerability_checks_inconclusive, 1);
        assert!(snap.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }

    #[tokio::test]
    async fn scan_skips_without_user_session() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = CacheScanner::default();
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }
}
