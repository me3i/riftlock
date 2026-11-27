//! OpenAPI/Swagger doc scanner: endpoints a spec publishes without
//! `security` are verified live and reported as unauthenticated reads.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    text_limited_result, CheckState, Coverage, EndpointOutcome, Evidence, Finding, ProofGate,
    ScanError, Scanner, ScopeGuard,
};
use riftlock_engine::default_verifier;
use serde_json::Value;
use url::Url;

const DOC_PATHS: [&str; 3] = ["/swagger.json", "/openapi.json", "/v3/api-docs"];
// shortcut: cap 20 paths per doc, a spec can list hundreds; upgrade to full enumeration if needed
const MAX_PATHS: usize = 20;
// shortcut: cap 10 verified reads per host, enough to prove the pattern; upgrade if a report needs every endpoint
const MAX_FINDINGS: usize = 10;
/// Longest body snippet kept as the `row_sample` proof.
const SAMPLE_LEN: usize = 120;
const CLAIM_BODY_LIMIT: usize = 4_096;

fn bounded_prefix(body: &str) -> &str {
    if let Some(prefix) = body.get(..CLAIM_BODY_LIMIT) {
        return prefix;
    }
    let end = body
        .char_indices()
        .take_while(|(index, _)| *index < CLAIM_BODY_LIMIT)
        .last()
        .map_or(0, |(index, ch)| {
            (index + ch.len_utf8()).min(CLAIM_BODY_LIMIT)
        });
    &body[..end]
}

/// OpenAPI documentation misconfiguration scanner.
#[derive(Debug, Default)]
pub struct OpenApiScanner {
    /// Run even when `matches()` rejects the host.
    pub force_run: bool,
    /// One check per spec fetch and one per verified endpoint read.
    pub coverage: Coverage,
}

/// True when parsed JSON carries an `openapi` or `swagger` top-level key.
fn is_openapi_doc(doc: &Value) -> bool {
    doc.get("openapi").is_some() || doc.get("swagger").is_some()
}

/// True when `op` is a GET the spec leaves unauthenticated: no operation
/// `security` and no non-empty global `security` at the doc root.
fn claims_unauth_get(doc: &Value, op: &Value) -> bool {
    let global_open = doc
        .get("security")
        .and_then(Value::as_array)
        .is_none_or(|s| s.is_empty());
    global_open && op.get("security").is_none()
}

/// What a probe established. `Unreadable` is not a miss: the evidence never
/// arrived, so the probe cannot be a checked negative.
enum Probe<T> {
    Found(T),
    Absent,
    Unreadable,
}

/// GET a candidate doc URL; `Absent` when the path is absent (404) or the
/// body is not an OpenAPI spec. Probe misses are a skip, not a scan failure.
async fn probe_doc(
    url: &Url,
    client: &Client,
    guard: &ScopeGuard,
) -> Result<Probe<Value>, ScanError> {
    guard.check(url)?;
    let resp = match client.get(url.clone()).send().await {
        Ok(resp) => resp,
        Err(error) => return Err(error),
    };
    if resp.status().as_u16() != 200 {
        return Ok(Probe::Absent);
    }
    let Ok(body) = text_limited_result(resp).await else {
        return Ok(Probe::Unreadable);
    };
    match serde_json::from_str::<Value>(&body) {
        Ok(doc) if is_openapi_doc(&doc) => Ok(Probe::Found(doc)),
        _ => Ok(Probe::Absent),
    }
}

fn waf_marker(body: &str) -> Option<&'static str> {
    let lower = body.to_ascii_lowercase();
    [
        "cloudflare",
        "captcha",
        "access denied",
        "waf",
        "blocked",
        "challenge",
    ]
    .into_iter()
    .find(|marker| lower.contains(marker))
}

/// Verified endpoint response, with the body bounded before verifier use.
struct VerifiedRead {
    status: u16,
    sample: String,
    claim_body: String,
    valid_json: bool,
    html: bool,
}

/// Verify one claimed-unauthenticated GET; returns a bounded sample when the
/// endpoint answers `200` with a non-trivial body or `206`. `Absent` on any
/// other status or transport miss, `Unreadable` when the body cannot be read.
async fn verify_read(
    endpoint: &Url,
    client: &Client,
    guard: &ScopeGuard,
) -> Result<Probe<VerifiedRead>, ScanError> {
    guard.check(endpoint)?;
    let Ok(resp) = client.get(endpoint.clone()).send().await else {
        return Ok(Probe::Absent);
    };
    let status = resp.status().as_u16();
    if status != 200 && status != 206 {
        return Ok(Probe::Absent);
    }
    let Ok(body) = text_limited_result(resp).await else {
        return Ok(Probe::Unreadable);
    };
    let claim_body = bounded_prefix(&body).to_owned();
    let valid_json = serde_json::from_str::<Value>(&body).is_ok();
    if body.len() <= 2 {
        return Ok(Probe::Absent);
    }
    let sample = if status == 206 {
        "<valid JSON response>".to_owned()
    } else {
        body.chars().take(SAMPLE_LEN).collect()
    };
    let html = claim_body
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("<!doctype html")
        || claim_body
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("<html");
    Ok(Probe::Found(VerifiedRead {
        status,
        sample,
        claim_body,
        valid_json,
        html,
    }))
}

impl Scanner for OpenApiScanner {
    fn id(&self) -> &'static str {
        "openapi"
    }

    fn matches(&self, _url: &Url) -> bool {
        true
    }

    /// Fetch the known doc paths, parse their `paths` map, and verify each
    /// GET the spec leaves unauthenticated.
    ///
    /// # Errors
    /// Scope violations, invalid target URLs and proof-gate rejections.
    async fn scan(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        if passive || (!self.force_run && !self.matches(url)) {
            return Ok(Vec::new());
        }
        let mut findings = Vec::new();
        for doc_path in DOC_PATHS {
            let doc_url = url.join(doc_path).map_err(|_| ScanError::InvalidUrl)?;
            // A scope rejection applies to this candidate only: account for
            // it and keep probing the remaining documents.
            if guard.check(&doc_url).is_err() {
                self.coverage.out_of_scope_endpoint_at(doc_url.as_str());
                continue;
            }
            let doc = self.fetch_doc(&doc_url, client, guard).await?;
            let Some(doc) = doc else {
                continue;
            };
            let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
                continue;
            };
            for (path, methods) in paths.iter().take(MAX_PATHS) {
                let Some(op) = methods.get("get") else {
                    continue;
                };
                if !claims_unauth_get(&doc, op) {
                    continue;
                }
                let endpoint = url.join(path).map_err(|_| ScanError::InvalidUrl)?;
                // A spec may claim an endpoint on another host; the guard
                // rejects it, the endpoint is recorded as skipped, and the
                // rest of the spec is still verified.
                if guard.check(&endpoint).is_err() {
                    self.coverage.out_of_scope_endpoint_at(endpoint.as_str());
                    continue;
                }
                let finding = self.verify_checked(&endpoint, client, guard).await?;
                if let Some(finding) = finding {
                    findings.push(finding);
                } else {
                    continue;
                }
                if findings.len() >= MAX_FINDINGS {
                    return Ok(findings);
                }
            }
        }
        Ok(findings)
    }
}

impl OpenApiScanner {
    /// Fetch one candidate spec as one ledger check.
    async fn fetch_doc(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
    ) -> Result<Option<Value>, ScanError> {
        let check = self.coverage.begin_check();
        let result = probe_doc(url, client, guard).await;
        if matches!(&result, Ok(Probe::Unreadable)) {
            self.coverage
                .endpoint_at(url.as_str(), EndpointOutcome::Failed);
        }
        let _ = check.finish(match &result {
            Ok(Probe::Unreadable) => CheckState::Inconclusive,
            Ok(_) => CheckState::Completed,
            Err(_) => CheckState::Failed,
        });
        result.map(|probe| match probe {
            Probe::Found(doc) => Some(doc),
            Probe::Absent | Probe::Unreadable => None,
        })
    }

    /// Verify and admit one claimed-unauthenticated GET as one ledger check.
    async fn verify_checked(
        &self,
        endpoint: &Url,
        client: &Client,
        guard: &ScopeGuard,
    ) -> Result<Option<Finding>, ScanError> {
        let check = self.coverage.begin_check();
        let response = verify_read(endpoint, client, guard).await;
        let (result, state) = match response {
            Err(error) => (Err(error), CheckState::Failed),
            Ok(Probe::Absent) => (Ok(None), CheckState::Completed),
            Ok(Probe::Unreadable) => {
                // Unread evidence is not a checked negative and never a finding.
                self.coverage
                    .endpoint_at(endpoint.as_str(), EndpointOutcome::Failed);
                (Ok(None), CheckState::Inconclusive)
            }
            Ok(Probe::Found(response)) => {
                let VerifiedRead {
                    status,
                    sample,
                    claim_body,
                    valid_json,
                    html,
                } = response;
                if status == 206 && !valid_json {
                    self.coverage
                        .endpoint_at(endpoint.as_str(), EndpointOutcome::WafBlocked);
                    (Ok(None), CheckState::Inconclusive)
                } else {
                    let marker = waf_marker(&claim_body);
                    let row_sample =
                        marker.map_or(sample, |marker| format!("<WAF marker: {marker}>"));
                    let evidence = Evidence::UnauthenticatedRead {
                        endpoint: endpoint.to_string(),
                        row_sample,
                    };
                    let mut claim = format!("status={status}");
                    if html {
                        claim.push_str(" body=html");
                    }
                    claim.push(' ');
                    claim.push_str(&claim_body);
                    match ProofGate::admit_with_verifier(
                        evidence,
                        default_verifier().as_ref(),
                        &claim,
                    ) {
                        Ok(finding) => (Ok(Some(finding)), CheckState::Completed),
                        Err(riftlock_core::ProofError::Heuristic) => {
                            self.coverage
                                .endpoint_at(endpoint.as_str(), EndpointOutcome::WafBlocked);
                            (Ok(None), CheckState::Inconclusive)
                        }
                        Err(error) => (Err(error.into()), CheckState::Failed),
                    }
                }
            }
        };
        let _ = check.finish(state);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Spec with one GET on `path`, optionally with a global `security` block.
    fn doc(path: &str, global_security: bool) -> String {
        let security = if global_security {
            r#", "security": [{"bearerAuth": []}]"#
        } else {
            ""
        };
        format!(
            r#"{{"openapi": "3.0.0", "info": {{"title": "t", "version": "1"}}
            , "paths": {{"{path}": {{"get": {{"summary": "list"}}}}}}{security}}}"#
        )
    }

    /// Mount the spec at "/openapi.json" (unless `doc` is `None`, i.e. 404)
    /// and an endpoint handler; returns the server, base URL and lab guard.
    async fn start_lab(
        doc: Option<String>,
        endpoint_status: u16,
        endpoint_body: &str,
    ) -> (MockServer, Url, ScopeGuard) {
        let doc_response = doc.map_or_else(
            || ResponseTemplate::new(404),
            |spec| ResponseTemplate::new(200).set_body_string(spec),
        );
        let endpoint_response = (endpoint_status != 0).then(|| {
            ResponseTemplate::new(endpoint_status).set_body_string(endpoint_body.to_owned())
        });
        start_lab_responses(doc_response, endpoint_response).await
    }

    async fn start_lab_responses(
        doc_response: ResponseTemplate,
        endpoint_response: Option<ResponseTemplate>,
    ) -> (MockServer, Url, ScopeGuard) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/openapi.json"))
            .respond_with(doc_response)
            .mount(&server)
            .await;
        if let Some(response) = endpoint_response {
            Mock::given(method("GET"))
                .and(path("/users"))
                .respond_with(response)
                .mount(&server)
                .await;
        }
        let host = Url::parse(&server.uri())
            .expect("url")
            .host_str()
            .unwrap_or_default()
            .to_owned();
        let origin = format!("https://{host}");
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        (
            server,
            base,
            ScopeGuard::new_lab(&[origin.as_str()]).expect("guard"),
        )
    }

    async fn scan(
        base: &Url,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        OpenApiScanner {
            force_run: true,
            coverage: Coverage::default(),
        }
        .scan(base, &Client::new_lab(), guard, passive)
        .await
    }

    #[tokio::test]
    async fn unauth_get_verified_emits_finding() {
        let (server, base, guard) =
            start_lab(Some(doc("/users", false)), 200, r#"[{"id": 1}]"#).await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert_eq!(findings.len(), 1);
        match &findings[0].evidence() {
            Evidence::UnauthenticatedRead { endpoint, .. } => {
                assert!(endpoint.ends_with("/users"));
            }
            other => panic!("expected UnauthenticatedRead, got {other:?}"),
        }
        // The doc probe also tried the other two candidate paths first.
        assert_eq!(
            server.received_requests().await.expect("recorded").len(),
            4 // /openapi.json + 2 probe misses + the verified /users GET
        );
    }

    #[tokio::test]
    async fn endpoint_403_is_no_finding() {
        let (server, base, guard) = start_lab(Some(doc("/users", false)), 403, "denied").await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
        // Doc found, endpoint probed once, but the read was refused.
        assert_eq!(server.received_requests().await.expect("recorded").len(), 4);
    }

    #[tokio::test]
    async fn html_200_waf_interstitial_is_inconclusive() {
        let body = "<!doctype html><html><title>Cloudflare challenge</title></html>";
        let (_server, base, guard) = start_lab(Some(doc("/users", false)), 200, body).await;
        let scanner = OpenApiScanner {
            force_run: true,
            coverage: Coverage::default(),
        };
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan continues after verifier rejection");
        assert!(findings.is_empty());
        let coverage = scanner.coverage.snapshot(0);
        assert_eq!(coverage.vulnerability_checks_inconclusive, 1);
        assert_eq!(coverage.endpoints_waf_blocked, 1);
        assert!(coverage.check_accounting_invariant());
    }

    #[tokio::test]
    async fn valid_json_206_passes_the_verifier() {
        let (_server, base, guard) =
            start_lab(Some(doc("/users", false)), 206, r#"[{"id":1}]"#).await;
        let scanner = OpenApiScanner {
            force_run: true,
            coverage: Coverage::default(),
        };
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence(), riftlock_core::Confidence::High);
    }

    #[tokio::test]
    async fn garbage_206_is_inconclusive() {
        let (_server, base, guard) = start_lab(Some(doc("/users", false)), 206, "not JSON").await;
        let scanner = OpenApiScanner {
            force_run: true,
            coverage: Coverage::default(),
        };
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan continues after insufficient response");
        assert!(findings.is_empty());
        let coverage = scanner.coverage.snapshot(0);
        assert_eq!(coverage.vulnerability_checks_inconclusive, 1);
        assert_eq!(coverage.endpoints_waf_blocked, 1);
        assert!(coverage.check_accounting_invariant());
    }

    #[tokio::test]
    async fn global_security_blocks_endpoint_probes() {
        let (server, base, guard) = start_lab(Some(doc("/users", true)), 200, "secret").await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
        let probed: Vec<_> = server
            .received_requests()
            .await
            .expect("recorded")
            .iter()
            .map(|r| r.url.path().to_owned())
            .collect();
        // Only doc candidates probed; the endpoint was never touched.
        assert!(probed.iter().all(|p| DOC_PATHS.contains(&p.as_str())));
    }

    #[tokio::test]
    async fn no_doc_probes_only_candidates() {
        let (server, base, guard) = start_lab(None, 0, "").await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
        let probed: Vec<_> = server
            .received_requests()
            .await
            .expect("recorded")
            .iter()
            .map(|r| r.url.path().to_owned())
            .collect();
        assert_eq!(probed.len(), DOC_PATHS.len());
    }

    #[tokio::test]
    async fn passive_mode_sends_no_requests() {
        let (server, base, guard) = start_lab(Some(doc("/users", false)), 200, "data").await;
        assert!(scan(&base, &guard, true).await.expect("scan").is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty());
    }

    #[tokio::test]
    async fn every_spec_probe_and_verified_read_is_a_check() {
        let (_server, base, guard) = start_lab(Some(doc("/users", false)), 200, "data").await;
        let scanner = OpenApiScanner {
            force_run: true,
            coverage: Coverage::default(),
        };
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        let snap = scanner.coverage.snapshot(0);
        // Three candidate doc paths plus the one verified endpoint read.
        assert_eq!(snap.vulnerability_checks_attempted, 4);
        assert_eq!(snap.vulnerability_checks_completed, 4);
        assert!(snap.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }

    #[tokio::test]
    async fn corrupt_gzip_endpoint_body_is_failed_and_inconclusive() {
        let doc_response = ResponseTemplate::new(200).set_body_string(doc("/users", false));
        let endpoint_response = ResponseTemplate::new(200)
            .insert_header("content-encoding", "gzip")
            .set_body_bytes(b"not a gzip stream".to_vec());
        let (_server, base, guard) =
            start_lab_responses(doc_response, Some(endpoint_response)).await;
        let scanner = OpenApiScanner {
            force_run: true,
            coverage: Coverage::default(),
        };
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan continues after an unreadable endpoint body");
        assert!(findings.is_empty(), "unread evidence is never a finding");
        let snap = scanner.coverage.snapshot(0);
        assert_eq!(snap.endpoints_failed, 1);
        assert_eq!(snap.endpoints_tested_successfully, 0);
        assert_eq!(snap.vulnerability_checks_attempted, 4);
        assert_eq!(snap.vulnerability_checks_completed, 3);
        assert_eq!(snap.vulnerability_checks_inconclusive, 1);
        assert!(snap.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }

    #[tokio::test]
    async fn corrupt_gzip_doc_body_is_failed_and_inconclusive() {
        let doc_response = ResponseTemplate::new(200)
            .insert_header("content-encoding", "gzip")
            .set_body_bytes(b"not a gzip stream".to_vec());
        let (_server, base, guard) = start_lab_responses(doc_response, None).await;
        let scanner = OpenApiScanner {
            force_run: true,
            coverage: Coverage::default(),
        };
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan continues after an unreadable doc body");
        assert!(findings.is_empty());
        let snap = scanner.coverage.snapshot(0);
        assert_eq!(snap.endpoints_failed, 1);
        assert_eq!(snap.vulnerability_checks_attempted, 3);
        assert_eq!(snap.vulnerability_checks_completed, 2);
        assert_eq!(snap.vulnerability_checks_inconclusive, 1);
        assert!(snap.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }
}
