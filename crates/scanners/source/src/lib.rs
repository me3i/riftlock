//! Source-disclosure scanner: probes for exposed `.git`, `.env`, backups,
//! and source maps.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    text_limited_result, CheckState, Coverage, EndpointOutcome, Evidence, Finding, ProofGate,
    ScanError, Scanner, ScopeGuard, SourceKind,
};
use url::Url;

/// Fixed probe paths checked against the target origin.
pub const PROBE_PATHS: &[(&str, SourceKind)] = &[
    ("/.git/HEAD", SourceKind::Git),
    ("/.env", SourceKind::Env),
    ("/backup.sql", SourceKind::Backup),
];

/// The source-disclosure scanner.
#[derive(Debug, Default)]
pub struct SourceScanner {
    /// One check per probed artifact path.
    pub coverage: Coverage,
}

/// Validate a fetched body as genuinely being a disclosed artifact.
/// A 200 with unrelated content (e.g. an SPA's index.html catch-all) is
/// not a disclosure.
pub fn validate(kind: SourceKind, body: &str) -> bool {
    match kind {
        SourceKind::Git => body.trim_start().starts_with("ref:"),
        SourceKind::Env => body.lines().any(|l| {
            let l = l.trim();
            l.contains('=')
                && !l.starts_with('#')
                && l.split('=').next().is_some_and(|k| {
                    !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                })
        }),
        SourceKind::Backup => body.contains("CREATE TABLE") || body.contains("INSERT INTO"),
        SourceKind::SourceMap => serde_json_ok(body),
        // SourceKind is non_exhaustive; future kinds are not validated yet.
        _ => false,
    }
}

fn serde_json_ok(body: &str) -> bool {
    // Minimal JSON-with-"sources" check without pulling serde_json's Value
    // API into scope twice; the field presence is what makes a source map.
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => v.get("sources").is_some(),
        Err(_) => false,
    }
}

/// Probe one path and, if it returns valid artifact content, build a finding.
///
/// # Errors
/// Transport failures.
pub async fn probe_path(
    client: &Client,
    base: &Url,
    path: &str,
    kind: SourceKind,
) -> Result<Option<Finding>, ScanError> {
    let (finding, _) = probe_observed(client, base, path, kind).await?;
    Ok(finding)
}

async fn probe_observed(
    client: &Client,
    base: &Url,
    path: &str,
    kind: SourceKind,
) -> Result<(Option<Finding>, EndpointOutcome), ScanError> {
    let url = base.join(path).map_err(|_| ScanError::InvalidUrl)?;
    let resp = client.get(url.clone()).send().await?;
    let status = resp.status().as_u16();
    let outcome = riftlock_core::classify(status);
    if status != 200 {
        return Ok((None, outcome));
    }
    let body = riftlock_core::body::text_limited_result(resp).await?;
    if !validate(kind, &body) {
        return Ok((None, outcome));
    }
    let evidence = Evidence::SourceDisclosure {
        url: url.as_str().to_owned(),
        kind,
    };
    let finding = ProofGate::admit(evidence).map_err(ScanError::from)?;
    Ok((Some(finding), outcome))
}

impl SourceScanner {
    /// Probe one artifact path as one ledger check. Transport failures end in
    /// a failed/timed-out check and never become a clean negative.
    async fn probe_checked(
        &self,
        client: &Client,
        base: &Url,
        path: &str,
        kind: SourceKind,
    ) -> Result<(Option<Finding>, EndpointOutcome), ScanError> {
        let check = self.coverage.begin_check();
        // Attribute the probe to its concrete URL so the untested surface can
        // name the artifact that could not be verified.
        let probe_url = base
            .join(path)
            .map_or_else(|_| format!("{base}{path}"), |url| url.to_string());
        match probe_observed(client, base, path, kind).await {
            Ok((found, outcome)) => {
                let state = match outcome {
                    EndpointOutcome::Failed => CheckState::Failed,
                    EndpointOutcome::TimedOut => CheckState::TimedOut,
                    EndpointOutcome::WafBlocked | EndpointOutcome::AuthRequired => {
                        CheckState::Inconclusive
                    }
                    EndpointOutcome::Tested | EndpointOutcome::Skipped => CheckState::Completed,
                    _ => CheckState::Inconclusive,
                };
                let _ = check.finish(state);
                self.coverage.endpoint_at(&probe_url, outcome);
                Ok((found, outcome))
            }
            Err(error) => {
                let timed_out = matches!(
                    &error,
                    ScanError::Http(err) if err.is_timeout()
                ) || matches!(
                    &error,
                    ScanError::Body(riftlock_core::body::BodyReadError::Transport(err)) if err.is_timeout()
                );
                let state = if matches!(
                    &error,
                    ScanError::Body(
                        riftlock_core::body::BodyReadError::Transport(_)
                            | riftlock_core::body::BodyReadError::TooLarge
                    )
                ) {
                    CheckState::Inconclusive
                } else if timed_out {
                    CheckState::TimedOut
                } else {
                    CheckState::Failed
                };
                let outcome = if timed_out {
                    EndpointOutcome::TimedOut
                } else {
                    EndpointOutcome::Failed
                };
                let _ = check.finish(state);
                self.coverage.endpoint_at(&probe_url, outcome);
                Err(error)
            }
        }
    }

    /// Probe all fixed paths plus `<bundle>.map` for every script bundle
    /// referenced by the page.
    async fn probe_all(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
    ) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();
        let probe_client = client.isolated_breaker();
        for (path, kind) in PROBE_PATHS {
            match self.probe_checked(&probe_client, url, path, *kind).await {
                Ok((Some(finding), _)) => findings.push(finding),
                Ok((None, _)) => {}
                Err(error) => {
                    riftlock_core::logln!(
                        "[!] Warning: source artifact probe {path} failed: {error}"
                    );
                }
            }
        }
        // Source maps: derive from script tags on the page.
        let check = self.coverage.begin_check();
        let html = match client.get(url.clone()).send().await {
            Ok(response) => {
                let outcome = riftlock_core::classify(response.status().as_u16());
                if outcome != EndpointOutcome::Tested {
                    self.coverage.endpoint_at(url.as_str(), outcome);
                    let state = match outcome {
                        EndpointOutcome::Failed => CheckState::Failed,
                        EndpointOutcome::TimedOut => CheckState::TimedOut,
                        EndpointOutcome::WafBlocked | EndpointOutcome::AuthRequired => {
                            CheckState::Inconclusive
                        }
                        _ => CheckState::Completed,
                    };
                    let _ = check.finish(state);
                    String::new()
                } else {
                    match text_limited_result(response).await {
                        Ok(body) => {
                            self.coverage
                                .endpoint_at(url.as_str(), EndpointOutcome::Tested);
                            let _ = check.finish(CheckState::Completed);
                            body
                        }
                        Err(_) => {
                            self.coverage
                                .endpoint_at(url.as_str(), EndpointOutcome::Failed);
                            let _ = check.finish(CheckState::Inconclusive);
                            String::new()
                        }
                    }
                }
            }
            Err(error) => {
                let outcome = riftlock_core::scan_error_outcome(&error);
                let state = if error.is_timeout() {
                    CheckState::TimedOut
                } else {
                    CheckState::Failed
                };
                self.coverage.endpoint_at(url.as_str(), outcome);
                let _ = check.finish(state);
                String::new()
            }
        };
        // Two script tags can name the same bundle with different query
        // strings; both derive the same `<path>.map`, so probe and emit it
        // once. Findings are keyed by artifact URL, not by bundle tag.
        let mut probed_maps = std::collections::HashSet::new();
        for bundle in riftlock_fingerprint::bundle_urls(&html, url) {
            let map_path = format!("{}.map", bundle.path());
            let map_url = match url.join(&map_path) {
                Ok(map_url) => map_url,
                Err(error) => {
                    self.coverage
                        .endpoint_at(bundle.as_str(), EndpointOutcome::Failed);
                    riftlock_core::logln!(
                        "[!] Warning: optional source map URL for {} is invalid: {error}",
                        bundle
                    );
                    continue;
                }
            };
            if !probed_maps.insert(map_url.clone()) {
                continue;
            }
            if guard.check(&bundle).is_err() || guard.check(&map_url).is_err() {
                self.coverage
                    .endpoint_at(bundle.as_str(), EndpointOutcome::Skipped);
                continue;
            }
            match self
                .probe_checked(&probe_client, url, &map_path, SourceKind::SourceMap)
                .await
            {
                Ok((Some(finding), _)) => findings.push(finding),
                Ok((None, EndpointOutcome::Skipped)) => {
                    riftlock_core::logln!(
                        "[!] Warning: optional source map {} is unavailable",
                        map_url
                    );
                }
                Ok((None, EndpointOutcome::Failed)) => {
                    riftlock_core::logln!(
                        "[!] Warning: optional source map {} returned an unusable HTTP response",
                        map_url
                    );
                }
                Ok((None, EndpointOutcome::TimedOut)) => {
                    riftlock_core::logln!("[!] Warning: optional source map {} timed out", map_url);
                }
                Ok((None, EndpointOutcome::WafBlocked | EndpointOutcome::AuthRequired)) => {
                    riftlock_core::logln!("[!] Warning: optional source map {} was blocked or requires authentication", map_url);
                }
                Ok((None, _)) => {}
                Err(error) => {
                    riftlock_core::logln!(
                        "[!] Warning: optional source map {} failed: {error}",
                        map_url
                    );
                    continue;
                }
            }
        }
        Ok(findings)
    }
}

impl Scanner for SourceScanner {
    fn id(&self) -> &'static str {
        "source"
    }

    fn matches(&self, _url: &Url) -> bool {
        // Source artifacts can be disclosed on any web origin.
        true
    }

    async fn scan(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        guard.check(url)?;
        // These probes are active requests; passive mode observes nothing.
        if passive {
            return Ok(Vec::new());
        }
        guard.check_active(url)?;
        self.probe_all(url, client, guard).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        assert!(validate(SourceKind::Git, "ref: refs/heads/main\n"));
        assert!(!validate(SourceKind::Git, "<!DOCTYPE html>"));
        assert!(validate(SourceKind::Env, "SUPABASE_URL=https://x\n"));
        assert!(!validate(SourceKind::Env, "# just a comment\n"));
        assert!(validate(SourceKind::Backup, "CREATE TABLE users (\n"));
        assert!(validate(SourceKind::SourceMap, r#"{"sources":["a.ts"]}"#));
        assert!(!validate(SourceKind::SourceMap, "not json"));
    }

    #[tokio::test]
    async fn probes_emit_only_valid_disclosures() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.git/HEAD"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ref: refs/heads/main\n"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/.env"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<!DOCTYPE html>"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/backup.sql"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let client = Client::new_lab();

        let git = probe_path(&client, &base, "/.git/HEAD", SourceKind::Git)
            .await
            .expect("probe");
        assert!(git.is_some());

        let env = probe_path(&client, &base, "/.env", SourceKind::Env)
            .await
            .expect("probe");
        assert!(env.is_none(), "200 but invalid content must not emit");

        let sql = probe_path(&client, &base, "/backup.sql", SourceKind::Backup)
            .await
            .expect("probe");
        assert!(sql.is_none(), "404 must not emit");
    }

    #[tokio::test]
    async fn failed_optional_map_does_not_prevent_later_map_finding() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        for probe in ["/.git/HEAD", "/.env", "/backup.sql"] {
            Mock::given(method("GET"))
                .and(path(probe))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<script src="/slow.js"></script><script src="/good.js"></script>"#,
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/slow.js.map"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"sources":["slow.ts"]}"#)
                    .set_delay(std::time::Duration::from_secs(4)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/good.js.map"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"sources":["good.ts"]}"#))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).expect("base URL");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let client = Client::from_builder(
            reqwest::Client::builder().timeout(std::time::Duration::from_millis(100)),
            &guard,
        )
        .expect("client");
        let scanner = SourceScanner::default();
        let findings = scanner
            .scan(&base, &client, &guard, false)
            .await
            .expect("optional map failures do not fail the scanner");

        assert_eq!(findings.len(), 1, "the later valid source map is retained");
        let snapshot = scanner.coverage.snapshot(0);
        assert_eq!(snapshot.vulnerability_checks_attempted, 6);
        assert_eq!(snapshot.checks_timed_out, 1);
        assert_eq!(snapshot.endpoints_timed_out, 1);
        assert_eq!(snapshot.endpoints_skipped, 3);
        assert_eq!(snapshot.endpoints_tested_successfully, 2);
        assert!(snapshot.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }

    #[tokio::test]
    async fn query_variant_bundles_probe_their_shared_map_once() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        for probe in ["/.git/HEAD", "/.env", "/backup.sql"] {
            Mock::given(method("GET"))
                .and(path(probe))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;
        }
        // Same bundle path, two query strings: both derive /app.js.map.
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<script src="/app.js?v=1"></script><script src="/app.js?v=2"></script>"#,
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/app.js.map"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"sources":["app.ts"]}"#))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).expect("base URL");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SourceScanner::default();
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");

        assert_eq!(findings.len(), 1, "one map URL is one finding");
        let hits = server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .filter(|request| request.url.path() == "/app.js.map")
            .count();
        assert_eq!(hits, 1, "the shared map is probed once");
    }

    #[tokio::test]
    async fn corrupt_gzip_page_read_is_failed_and_inconclusive() {
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        for path in ["/.git/HEAD", "/.env", "/backup.sql"] {
            Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path(path))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;
        }
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(b"not a gzip stream".to_vec()),
            )
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).expect("base URL");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SourceScanner::default();
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("an unreadable discovery page does not fail the scanner");

        assert!(findings.is_empty());
        let snap = scanner.coverage.snapshot(0);
        assert_eq!(snap.endpoints_failed, 1);
        assert_eq!(snap.vulnerability_checks_inconclusive, 1);
        assert!(snap.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }

    #[tokio::test]
    async fn every_artifact_probe_is_accounted_as_a_check() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.git/HEAD"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ref: refs/heads/main\n"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/.env"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/backup.sql"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SourceScanner::default();
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        let snap = scanner.coverage.snapshot(0);
        assert_eq!(snap.vulnerability_checks_attempted, 4);
        assert!(snap.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }
}
