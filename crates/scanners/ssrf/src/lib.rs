//! SSRF scanner: proves a server-side fetch of an injected internal URL
//! (cloud metadata, localhost) via URL parameters discovered by AST.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    paths_for_method, text_limited_result, Coverage, DiscoveredEndpoint, Evidence, Finding,
    ProofGate, ScanError, Scanner, ScopeGuard,
};
use std::time::{Duration, Instant};
use url::Url;

/// Internal URLs whose fetch proves SSRF.
const PAYLOADS: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80",
    "http://[::1]:80",
];

/// Parameter names commonly carrying a server-fetched URL.
const PROBE_PARAMS: &[&str] = &["url", "image", "webhook", "target", "link", "feed"];

/// Hard cap on probe requests per scan — params × payloads × endpoints is
/// combinatorial, and request volume must stay bounded.
const MAX_PROBES: usize = 30;

/// Timing delta required to support a material response difference.
const TIMING_DELTA: Duration = Duration::from_millis(200);
const CONTROL_URL: &str = "http://example.com/";

/// Per-request cap so a stalled probe cannot hang the scan.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// The SSRF scanner. Endpoints come from AST discovery (`endpoints`, filled
/// by the CLI); existing GET probes use GET-discovered paths when available.
#[derive(Debug, Default)]
pub struct SsrfScanner {
    /// Endpoint paths discovered by AST (absolute, e.g. `/fetch`).
    pub endpoints: Vec<String>,
    /// Method-aware inventory; empty preserves path-only callers.
    pub endpoint_methods: Vec<DiscoveredEndpoint>,
    /// Shared coverage counters: an unreadable probe is a failed endpoint,
    /// never a timing-based proof.
    pub coverage: Coverage,
}

/// Compare an internal-URL response with a control response. Material
/// differences need timing support or a server-side fetch error signature.
#[allow(clippy::too_many_arguments)]
fn is_ssrf(
    payload: &str,
    internal_body: &str,
    internal_status: u16,
    internal_elapsed: Duration,
    internal_redirected: bool,
    control_body: &str,
    control_status: u16,
    control_elapsed: Duration,
) -> bool {
    if internal_redirected
        || (300..400).contains(&internal_status)
        || internal_body.contains(payload)
    {
        return false;
    }
    let body_differs = materially_differs(internal_body, control_body);
    let status_differs = internal_status != control_status;
    (body_differs || status_differs)
        && (internal_elapsed.abs_diff(control_elapsed) > TIMING_DELTA
            || has_fetch_error_signature(internal_body))
}

fn materially_differs(left: &str, right: &str) -> bool {
    let normalize = |body: &str| body.split_whitespace().collect::<Vec<_>>().join(" ");
    normalize(left) != normalize(right)
}

fn has_fetch_error_signature(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    [
        "connection refused",
        "failed to connect",
        "could not resolve",
        "name or service not known",
        "no route to host",
        "connection timed out",
    ]
    .iter()
    .any(|signature| body.contains(signature))
}

impl SsrfScanner {
    /// GET `endpoint` with `param` set to `payload`, returning (body, elapsed).
    ///
    /// # Errors
    /// Returns transport or body-read errors; the caller records failed
    /// endpoint coverage and continues with the next endpoint.
    async fn probe(
        client: &Client,
        target: &Url,
        param: &str,
        payload: &str,
    ) -> Result<Option<(String, u16, Duration, bool)>, ScanError> {
        let mut probe_url = target.clone();
        probe_url.query_pairs_mut().append_pair(param, payload);
        let start = Instant::now();
        let resp = match client
            .get(probe_url.clone())
            .timeout(PROBE_TIMEOUT)
            .bypass_adaptive_timeout()
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) if e.is_timeout() => return Ok(None),
            Err(e) => return Err(e),
        };
        let status = resp.status().as_u16();
        let redirected = resp.url() != &probe_url;
        let body = text_limited_result(resp).await?;
        Ok(Some((body, status, start.elapsed(), redirected)))
    }
}

impl Scanner for SsrfScanner {
    fn id(&self) -> &'static str {
        "ssrf"
    }

    fn matches(&self, _url: &Url) -> bool {
        // SSRF lives anywhere a server fetches a client-supplied URL.
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
        if let Err(error) = guard.check_active(url) {
            match &error {
                riftlock_core::ScopeError::PassiveOnly => return Ok(Vec::new()),
                riftlock_core::ScopeError::ReadOnly { .. } => {
                    self.coverage.out_of_scope_endpoint_at(url.as_str());
                    riftlock_core::logln!("[~] SSRF write probes skipped: {error}");
                    return Ok(Vec::new());
                }
                _ => {
                    self.coverage.out_of_scope_endpoint_at(url.as_str());
                    riftlock_core::logln!("[~] SSRF target skipped: {error}");
                    return Ok(Vec::new());
                }
            }
        }
        let mut findings = Vec::new();
        let mut probes = 0usize;
        let endpoints = paths_for_method(&self.endpoints, &self.endpoint_methods, "GET");
        for endpoint in &endpoints {
            let target = url.join(endpoint).map_err(|_| ScanError::InvalidUrl)?;
            if let Err(error) = guard.check(&target) {
                self.coverage.out_of_scope_endpoint_at(target.as_str());
                riftlock_core::logln!("[~] SSRF endpoint skipped: {error}");
                continue;
            }
            // One proof per endpoint; further probes add nothing.
            let mut proved = false;
            'endpoint: for &param in PROBE_PARAMS {
                if proved {
                    break;
                }
                if probes >= MAX_PROBES {
                    return Ok(findings);
                }
                probes += 1;
                let control = match SsrfScanner::probe(client, &target, param, CONTROL_URL).await {
                    Ok(Some(control)) => control,
                    Ok(None) | Err(_) => {
                        riftlock_core::logln!("[-] SSRF skipped: control probe unreachable");
                        self.coverage
                            .endpoint_at(target.as_str(), riftlock_core::EndpointOutcome::Skipped);
                        self.coverage.scope_rejected_check();
                        return Ok(Vec::new());
                    }
                };
                for &payload in PAYLOADS {
                    if probes >= MAX_PROBES {
                        return Ok(findings);
                    }
                    probes += 1;
                    let probed = match SsrfScanner::probe(client, &target, param, payload).await {
                        Ok(probed) => probed,
                        Err(error) if error.transport_category().is_some() => {
                            riftlock_core::logln!(
                                "[!] SSRF probe unreadable ({error}); endpoint marked failed."
                            );
                            self.coverage.unreadable_endpoint_at(target.as_str());
                            break 'endpoint;
                        }
                        Err(error) => return Err(error),
                    };
                    let Some((body, status, elapsed, redirected)) = probed else {
                        self.coverage
                            .endpoint_at(target.as_str(), riftlock_core::EndpointOutcome::TimedOut);
                        let check = self.coverage.begin_check();
                        let _ = check.finish(riftlock_core::CheckState::TimedOut);
                        break 'endpoint;
                    };
                    if is_ssrf(
                        payload, &body, status, elapsed, redirected, &control.0, control.1,
                        control.2,
                    ) {
                        findings.push(ProofGate::admit(Evidence::SsrF {
                            endpoint: target.to_string(),
                            payload: payload.to_owned(),
                        })?);
                        proved = true;
                        break;
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

    #[test]
    fn is_ssrf_on_metadata_marker_different_from_control() {
        assert!(is_ssrf(
            "http://169.254.169.254/latest/meta-data/",
            "ami-id\nami-0abc123",
            200,
            Duration::from_millis(300),
            false,
            "ordinary page",
            200,
            Duration::from_millis(55),
        ));
        assert!(is_ssrf(
            "http://127.0.0.1:80",
            "root:x:0:0:root:/root:/bin/sh",
            200,
            Duration::from_millis(300),
            false,
            "ordinary page",
            200,
            Duration::from_millis(55),
        ));
    }

    #[test]
    fn param_echo_is_never_ssrf_proof() {
        let payload = "http://127.0.0.1:80";
        assert!(!is_ssrf(
            payload,
            "the supplied URL was http://127.0.0.1:80",
            200,
            Duration::from_millis(800),
            false,
            "ordinary page",
            200,
            Duration::from_millis(50),
        ));
    }

    #[test]
    fn is_ssrf_on_material_response_diff_with_timing_delta() {
        assert!(is_ssrf(
            "http://127.0.0.1:80",
            "internal response",
            200,
            Duration::from_millis(400),
            false,
            "ordinary page",
            200,
            Duration::from_millis(100),
        ));
        assert!(is_ssrf(
            "http://127.0.0.1:80",
            "connection refused by upstream",
            502,
            Duration::from_millis(50),
            false,
            "ordinary page",
            200,
            Duration::from_millis(55),
        ));
    }

    #[test]
    fn is_not_ssrf_on_fast_generic_body_or_status_alone() {
        assert!(!is_ssrf(
            "http://127.0.0.1:80",
            "<html>ok</html>",
            200,
            Duration::from_millis(50),
            false,
            "<html>ok</html>",
            200,
            Duration::from_millis(50),
        ));
        assert!(!is_ssrf(
            "http://127.0.0.1:80",
            "generic response",
            200,
            Duration::from_millis(50),
            false,
            "generic response",
            302,
            Duration::from_millis(55),
        ));
        assert!(!is_ssrf(
            "http://127.0.0.1:80",
            "different redirect body",
            302,
            Duration::from_millis(500),
            false,
            "ordinary page",
            200,
            Duration::from_millis(50),
        ));
    }

    #[tokio::test]
    async fn scan_proves_metadata_fetch() {
        let server = wiremock::MockServer::start().await;
        // Vulnerable server: fetches the injected URL and returns its body.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/fetch"))
            .and(wiremock::matchers::query_param(
                "url",
                "http://169.254.169.254/latest/meta-data/",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string("ami-id\nami-0abc123")
                    .set_delay(Duration::from_millis(300)),
            )
            .mount(&server)
            .await;
        // Every other probe: a generic page.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("<html>ok</html>"))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SsrfScanner {
            endpoints: vec!["/fetch".to_owned()],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::SsrF { endpoint, payload }
                if endpoint.ends_with("/fetch")
                    && payload == "http://169.254.169.254/latest/meta-data/"
        ));
    }

    #[tokio::test]
    async fn localhost_200_response_alone_does_not_prove_ssrf() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("same generic page"))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SsrfScanner {
            endpoints: vec!["/".to_owned()],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().any(|request| {
            request
                .url
                .query_pairs()
                .any(|(key, value)| key == "url" && value == "http://127.0.0.1:80")
        }));
    }

    #[tokio::test]
    async fn method_inventory_selects_get_when_path_has_multiple_methods() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/fetch"))
            .and(wiremock::matchers::query_param(
                "url",
                "http://169.254.169.254/latest/meta-data/",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string("ami-id")
                    .set_delay(Duration::from_millis(300)),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/fetch"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ordinary page"))
            .mount(&server)
            .await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SsrfScanner {
            endpoints: vec!["/fetch".to_owned()],
            endpoint_methods: vec![
                DiscoveredEndpoint {
                    path: "/fetch".to_owned(),
                    method: "GET".to_owned(),
                },
                DiscoveredEndpoint {
                    path: "/fetch".to_owned(),
                    method: "POST".to_owned(),
                },
            ],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 2, "one control and one payload request");
        assert!(requests.iter().all(|request| request.method == "GET"));
    }

    #[tokio::test]
    async fn out_of_scope_endpoint_is_skipped_and_remaining_endpoint_runs() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/healthy"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ordinary page"))
            .mount(&server)
            .await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let coverage = Coverage::default();
        let scanner = SsrfScanner {
            endpoints: vec![
                "https://outside.invalid/blocked".to_owned(),
                "/healthy".to_owned(),
            ],
            coverage: coverage.clone(),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("out-of-scope endpoint must not abort remaining probes");
        assert!(findings.is_empty());
        let snapshot = coverage.snapshot(0);
        assert_eq!(snapshot.endpoints_skipped, 1, "{snapshot:?}");
        assert_eq!(
            snapshot.vulnerability_checks_inconclusive, 1,
            "{snapshot:?}"
        );
        assert!(coverage.finalize().reconciles());
        let requests = server.received_requests().await.expect("requests");
        assert!(requests
            .iter()
            .any(|request| request.url.path() == "/healthy"));
        assert!(!requests
            .iter()
            .any(|request| request.url.path() == "/blocked"));
    }

    #[tokio::test]
    async fn scan_skips_timed_out_probe() {
        let server = wiremock::MockServer::start().await;
        // The proving response stalls past PROBE_TIMEOUT: the probe is
        // skipped, and the scan returns its partial findings instead of
        // waiting for the body or failing.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/fetch"))
            .and(wiremock::matchers::query_param(
                "url",
                "http://169.254.169.254/latest/meta-data/",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string("ami-id\nami-0abc123")
                    .set_delay(Duration::from_millis(2100)),
            )
            .mount(&server)
            .await;
        // Every other probe answers immediately with a generic page.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("<html>ok</html>"))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let coverage = Coverage::default();
        let scanner = SsrfScanner {
            endpoints: vec!["/fetch".to_owned()],
            coverage: coverage.clone(),
            ..Default::default()
        };
        let started = Instant::now();
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
    async fn unreachable_control_probe_skips_scanner_without_failing() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test port");
        let address = listener.local_addr().expect("local address");
        drop(listener);

        let base = Url::parse(&format!("http://{address}/fetch")).expect("url");
        let guard = ScopeGuard::new_lab(&[&format!("http://{address}")]).expect("guard");
        let coverage = Coverage::default();
        let scanner = SsrfScanner {
            endpoints: vec!["/fetch".to_owned()],
            coverage: coverage.clone(),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("unreachable control probe should be skipped, not fail the scan");

        assert!(findings.is_empty());
        let snapshot = coverage.snapshot(1);
        assert_eq!(snapshot.endpoints_skipped, 1, "{snapshot:?}");
        assert_eq!(
            snapshot.vulnerability_checks_inconclusive, 1,
            "{snapshot:?}"
        );
        assert_eq!(snapshot.checks_failed, 0, "{snapshot:?}");
        assert!(snapshot.check_accounting_invariant());
        assert!(coverage.finalize().reconciles());
    }

    #[tokio::test]
    async fn scan_negative_when_server_rejects_injection() {
        let server = wiremock::MockServer::start().await;
        // The server answers every probe with a fast generic page: the
        // injected URL was never fetched, checked negative.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("<html>ok</html>"))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SsrfScanner {
            endpoints: vec!["/fetch".to_owned()],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }
}
