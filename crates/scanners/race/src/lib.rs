//! Race-condition scanner: proves a write endpoint accepts concurrent
//! identical requests where the action should be single-shot.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    paths_for_method, Coverage, DiscoveredEndpoint, Evidence, Finding, ProofGate, ScanError,
    Scanner, ScopeGuard, SessionMatrix,
};
use std::time::Duration;
use tokio::task::JoinSet;
use url::Url;

/// Concurrent identical writes fired per endpoint.
const RACE_REQUESTS: usize = 10;

/// Substrings marking single-shot write endpoints worth racing.
const RACE_MARKERS: &[&str] = &["checkout", "redeem", "action", "transfer", "orders"];

/// Fallback endpoints raced when AST discovery found none.
const DEFAULT_PATHS: &[&str] = &[
    "/checkout",
    "/redeem",
    "/api/action",
    "/transfer",
    "/api/orders",
];

/// Per-request deadline for a race shot.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The race-condition scanner. Endpoints come from AST discovery
/// (`endpoints`, filtered to single-shot write markers by the scanner);
/// writes are authenticated with the `user_a` session.
#[derive(Debug, Default)]
pub struct RaceScanner {
    /// Session matrix; the `user_a` cookie authenticates the writes.
    pub sessions: SessionMatrix,
    /// Endpoint paths discovered by AST (absolute, e.g. `/checkout`).
    pub endpoints: Vec<String>,
    /// Methods observed for endpoint paths; empty preserves path-only callers.
    pub endpoint_methods: Vec<DiscoveredEndpoint>,
    /// Shared coverage counters for concurrent request outcomes.
    pub coverage: Coverage,
}

/// Candidate endpoints to race: AST-discovered endpoints carrying a
/// single-shot marker; the default candidates when discovery found none.
fn candidates(discovered: &[String], allow_fallback: bool) -> Vec<String> {
    let mut paths: Vec<String> = discovered
        .iter()
        .filter(|e| RACE_MARKERS.iter().any(|m| e.contains(m)))
        .cloned()
        .collect();
    if paths.is_empty() && allow_fallback {
        paths.extend(DEFAULT_PATHS.iter().map(|&p| p.to_owned()));
    }
    paths
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Whether a status counts as an accepted write.
fn accepted(status: u16) -> bool {
    status == 200 || status == 201
}

impl Scanner for RaceScanner {
    fn id(&self) -> &'static str {
        "race"
    }

    fn matches(&self, _url: &Url) -> bool {
        // Single-shot write endpoints exist on any host.
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
        // The race proof is repeated POST writes; read depth never sends them.
        if guard.is_read_only() {
            return Ok(Vec::new());
        }
        guard.check_active(url)?;
        let mut findings = Vec::new();
        let Some(user_a) = self.sessions.user_a.as_deref() else {
            // Writes must be authenticated to prove a same-user race.
            return Ok(findings);
        };
        let post_endpoints = paths_for_method(&self.endpoints, &self.endpoint_methods, "POST");
        let endpoints = candidates(&post_endpoints, self.endpoint_methods.is_empty());
        for endpoint in endpoints {
            let target = url.join(&endpoint).map_err(|_| ScanError::InvalidUrl)?;
            if guard.check(&target).is_err() {
                continue;
            }
            let mut shots = JoinSet::new();
            let check = self.coverage.begin_check();
            let mut failed = false;
            for _ in 0..RACE_REQUESTS {
                let client = client.clone();
                let target = target.clone();
                let cookie = user_a.to_owned();
                shots.spawn(async move {
                    let resp = client
                        .post(target)
                        .timeout(REQUEST_TIMEOUT)
                        .header("Cookie", cookie)
                        .json(&serde_json::json!({}))
                        .send()
                        .await?;
                    Ok::<u16, ScanError>(resp.status().as_u16())
                });
            }
            let mut successful = 0usize;
            while let Some(result) = shots.join_next().await {
                match result {
                    Ok(Ok(status)) if accepted(status) => successful += 1,
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) if error.is_timeout() => failed = true,
                    Ok(Err(_)) | Err(_) => failed = true,
                }
            }
            if successful > 1 {
                findings.push(ProofGate::admit(Evidence::RaceCondition {
                    endpoint: target.to_string(),
                    successful_requests: successful,
                })?);
            }
            if failed {
                self.coverage
                    .endpoint_at(target.as_str(), riftlock_core::EndpointOutcome::Failed);
                let _ = check.finish(riftlock_core::CheckState::Inconclusive);
            } else {
                self.coverage
                    .endpoint_at(target.as_str(), riftlock_core::EndpointOutcome::Tested);
                let _ = check.finish(riftlock_core::CheckState::Completed);
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_only_scan_sends_nothing() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()])
            .expect("guard")
            .with_policy(riftlock_core::ScanPolicy::ReadOnly);
        let findings = Scanner::scan(
            &RaceScanner::default(),
            &base,
            &Client::new_lab(),
            &guard,
            false,
        )
        .await
        .expect("scan");
        assert!(findings.is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }

    fn sessions_with(cookie: &str) -> SessionMatrix {
        SessionMatrix {
            user_a: Some(cookie.to_owned()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn scan_proves_concurrent_writes_all_accepted() {
        let server = wiremock::MockServer::start().await;
        // Vulnerable server: every identical write succeeds.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/checkout"))
            .and(wiremock::matchers::header("Cookie", "sid=abc"))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_string(r#"{"id":1}"#))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = RaceScanner {
            sessions: sessions_with("sid=abc"),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::RaceCondition { endpoint, successful_requests: n }
                if endpoint.ends_with("/checkout") && *n > 1
        ));
    }

    #[tokio::test]
    async fn method_inventory_requires_discovered_post_route() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/checkout"))
            .respond_with(wiremock::ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = RaceScanner {
            sessions: sessions_with("sid=abc"),
            endpoints: vec!["/checkout".to_owned()],
            endpoint_methods: vec![
                DiscoveredEndpoint {
                    path: "/checkout".to_owned(),
                    method: "GET".to_owned(),
                },
                DiscoveredEndpoint {
                    path: "/checkout".to_owned(),
                    method: "DELETE".to_owned(),
                },
            ],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }

    #[tokio::test]
    async fn scan_negative_when_write_is_single_shot() {
        let server = wiremock::MockServer::start().await;
        // Idempotent server: only the first write succeeds, the rest conflict.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/checkout"))
            .and(wiremock::matchers::header("Cookie", "sid=abc"))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_string(r#"{"id":1}"#))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(409))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = RaceScanner {
            sessions: sessions_with("sid=abc"),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_skips_without_user_session() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = RaceScanner::default();
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[test]
    fn candidates_filter_and_fallback() {
        // Discovered action-like paths are kept, non-action paths dropped.
        let found = candidates(&["/checkout".to_owned(), "/static/app.js".to_owned()], true);
        assert_eq!(found, vec!["/checkout".to_owned()]);
        // Nothing discovered: defaults kick in for path-only callers.
        assert!(!candidates(&[], true).is_empty());
        // An explicit method inventory with no POST route does not trigger defaults.
        assert!(candidates(&[], false).is_empty());
    }
}
