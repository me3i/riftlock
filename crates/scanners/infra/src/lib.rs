//! Infrastructure exposure scanner: unauthenticated info files, container
//! orchestrator APIs and bucket-style hosts — one GET each, and the body
//! signature is the evidence. No payload probing.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    text_limited_result, CheckState, Coverage, EndpointOutcome, Evidence, Finding, PendingCheck,
    ProofGate, ScanError, Scanner, ScopeGuard,
};
use serde_json::Value;
use url::Url;

/// The infrastructure scanner. Fetches well-known info files and container
/// API endpoints on the target host; a matching body signature is the proof.
#[derive(Debug, Default)]
pub struct InfraScanner {
    /// One check per info-file / container-API probe.
    pub coverage: Coverage,
}

/// Docker daemon `/version` signature: `ApiVersion`, or `Version` + `Os`.
fn is_docker_version(v: &Value) -> bool {
    v.get("ApiVersion").is_some() || (v.get("Version").is_some() && v.get("Os").is_some())
}

/// Kubernetes API signature: a `NamespaceList` envelope.
fn is_namespace_list(v: &Value) -> bool {
    v.get("kind").and_then(Value::as_str) == Some("NamespaceList")
}

/// The bucket service `host` belongs to, with the XML list marker its
/// listing response must contain.
fn bucket_of(host: &str) -> Option<(&'static str, &'static str)> {
    if host.ends_with(".s3.amazonaws.com") {
        Some(("aws_s3", "<ListBucketResult>"))
    } else if host.ends_with(".blob.core.windows.net") {
        Some(("azure_blob", "<EnumerationResults>"))
    } else {
        None
    }
}

/// One fetch's result: the body, a checked miss, or a body that never arrived.
enum Fetched {
    Body(String),
    Miss,
    Unreadable,
}

/// GET `target`; `Err` only on transport failure so the caller can drop the
/// rest of its stage.
async fn fetch(url: &Url, client: &Client) -> Result<Fetched, riftlock_core::ScanError> {
    let resp = client.get(url.clone()).send().await?;
    if resp.status().as_u16() != 200 {
        return Ok(Fetched::Miss);
    }
    Ok(match text_limited_result(resp).await {
        Ok(body) => Fetched::Body(body),
        Err(_) => Fetched::Unreadable,
    })
}

impl InfraScanner {
    /// Record one probe's endpoint outcome and terminal check state.
    fn settle(
        &self,
        target: &Url,
        check: PendingCheck<'_>,
        result: &Result<Fetched, riftlock_core::ScanError>,
    ) {
        let (outcome, state) = match result {
            Ok(Fetched::Body(_)) => (EndpointOutcome::Tested, CheckState::Completed),
            Ok(Fetched::Miss) => (EndpointOutcome::Skipped, CheckState::Completed),
            Ok(Fetched::Unreadable) => (EndpointOutcome::Failed, CheckState::Inconclusive),
            Err(error) => (riftlock_core::scan_error_outcome(error), CheckState::Failed),
        };
        self.coverage.endpoint_at(target.as_str(), outcome);
        let _ = check.finish(state);
    }
}

impl Scanner for InfraScanner {
    fn id(&self) -> &'static str {
        "infra"
    }

    fn matches(&self, _url: &Url) -> bool {
        // Info files and container APIs can hang off any HTTP host.
        true
    }

    async fn scan(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        _passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        // Info files and container version reads are passive GET observations,
        // so Normal depth runs them too.
        guard.check_active(url)?;
        let mut findings = Vec::new();
        let origin = url.origin().ascii_serialization();
        let host = url.host_str().unwrap_or_default().to_owned();

        // Info files on the target origin. A transport error ends the stage:
        // a host that refuses one connection will refuse the rest, and the
        // budget must not stall the scan.
        for (path, markers, issue) in [
            ("/robots.txt", &["Disallow:"][..], "robots_discloses_paths"),
            ("/sitemap.xml", &["<url>", "<loc>"][..], "sitemap_routes"),
            (
                "/.well-known/security.txt",
                &["Contact:"][..],
                "security_txt_contacts",
            ),
        ] {
            let Ok(target) = Url::parse(&format!("{origin}{path}")) else {
                continue;
            };
            // A guard rejection applies to this path only: account for it
            // and keep checking the remaining paths.
            if guard.check(&target).is_err() {
                self.coverage.out_of_scope_endpoint_at(target.as_str());
                continue;
            }
            let check = self.coverage.begin_check();
            let fetched = fetch(&target, client).await;
            self.settle(&target, check, &fetched);
            match fetched {
                Ok(Fetched::Body(body)) if markers.iter().any(|m| body.contains(m)) => {
                    findings.push(ProofGate::admit(Evidence::DnsMisconfiguration {
                        domain: host.clone(),
                        issue: issue.to_owned(),
                    })?);
                }
                Ok(_) => {}
                // Transport failure: the whole stage is unreachable.
                Err(_) => break,
            }
        }

        // Exposed container/orchestrator APIs on the same origin; same
        // stage-abort rule as above.
        for (path, provider, sig) in [
            (
                "/version",
                "docker",
                is_docker_version as fn(&Value) -> bool,
            ),
            ("/api/v1/namespaces", "kubernetes", is_namespace_list),
        ] {
            let Ok(target) = Url::parse(&format!("{origin}{path}")) else {
                continue;
            };
            if guard.check(&target).is_err() {
                self.coverage.out_of_scope_endpoint_at(target.as_str());
                continue;
            }
            let check = self.coverage.begin_check();
            let fetched = fetch(&target, client).await;
            self.settle(&target, check, &fetched);
            match fetched {
                Ok(Fetched::Body(body)) => match serde_json::from_str::<Value>(&body) {
                    Ok(v) if sig(&v) => {
                        findings.push(ProofGate::admit(Evidence::CloudExposure {
                            url: target.to_string(),
                            provider: provider.to_owned(),
                        })?);
                    }
                    _ => {}
                },
                // Transport failure: the whole stage is unreachable.
                Err(_) => break,
                Ok(Fetched::Miss | Fetched::Unreadable) => {}
            }
        }

        // Docker daemons on their default port; the guard may reject
        // non-standard ports — skip silently. Every miss here is tolerated.
        // kube-apiserver's 6443 speaks TLS and is probed in https targets'
        // normal pass — a plaintext probe here can never match.
        for port in [2375] {
            let Ok(target) = Url::parse(&format!("http://{host}:{port}/version")) else {
                continue;
            };
            if guard.check(&target).is_err() {
                continue;
            }
            let check = self.coverage.begin_check();
            let fetched = fetch(&target, client).await;
            self.settle(&target, check, &fetched);
            if let Ok(Fetched::Body(body)) = fetched {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    if is_docker_version(&v) {
                        findings.push(ProofGate::admit(Evidence::CloudExposure {
                            url: target.to_string(),
                            provider: "docker".to_owned(),
                        })?);
                    }
                }
            }
        }

        // The target itself is a bucket endpoint. No external bucket-name
        // harvesting: offline E2E cannot reach cloud providers.
        if let Some((provider, marker)) = bucket_of(&host) {
            let check = self.coverage.begin_check();
            let fetched = fetch(url, client).await;
            self.settle(url, check, &fetched);
            if let Ok(Fetched::Body(body)) = fetched {
                if body.contains(marker) {
                    findings.push(ProofGate::admit(Evidence::CloudExposure {
                        url: url.to_string(),
                        provider: provider.to_owned(),
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

    async fn scoped_server() -> (wiremock::MockServer, ScopeGuard, Client) {
        let server = wiremock::MockServer::start().await;
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        (server, guard, Client::new_lab())
    }

    fn findings_of(findings: Vec<Finding>) -> Vec<(String, String)> {
        findings
            .into_iter()
            .filter_map(|f| match f.evidence() {
                Evidence::CloudExposure { url, provider } => Some((url.clone(), provider.clone())),
                Evidence::DnsMisconfiguration { domain, issue } => {
                    Some((domain.clone(), issue.clone()))
                }
                _ => None,
            })
            .collect()
    }

    async fn mount_get(server: &wiremock::MockServer, path: &str, body: &str) {
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(path))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/plain")
                    .set_body_string(body),
            )
            .mount(server)
            .await;
    }

    async fn scan_one(
        server: &wiremock::MockServer,
        guard: &ScopeGuard,
        client: &Client,
    ) -> Vec<(String, String)> {
        let url = url::Url::parse(server.uri().as_str()).expect("url");
        findings_of(
            InfraScanner::default()
                .scan(&url, client, guard, false)
                .await
                .expect("scan"),
        )
    }

    #[tokio::test]
    async fn corrupt_gzip_info_file_is_failed_and_inconclusive() {
        let (server, guard, client) = scoped_server().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/robots.txt"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(b"not a gzip stream".to_vec()),
            )
            .mount(&server)
            .await;
        let url = url::Url::parse(server.uri().as_str()).expect("url");
        let scanner = InfraScanner::default();
        let findings = scanner
            .scan(&url, &client, &guard, false)
            .await
            .expect("scan continues after an unreadable body");
        assert!(findings.is_empty());
        let snap = scanner.coverage.snapshot(0);
        // The failed `/version` connection on port 2375 is independently
        // accounted in addition to the unreadable `/robots.txt` response.
        assert_eq!(snap.endpoints_failed, 2);
        assert_eq!(snap.vulnerability_checks_inconclusive, 1);
        assert!(snap.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }

    #[test]
    fn docker_signature_needs_api_version_or_version_plus_os() {
        let v = |s: &str| serde_json::from_str::<Value>(s).expect("json");
        assert!(is_docker_version(&v(r#"{"ApiVersion":"1.41"}"#)));
        assert!(is_docker_version(&v(r#"{"Version":"24.0","Os":"linux"}"#)));
        assert!(!is_docker_version(&v(r#"{"Version":"24.0"}"#)));
    }

    #[test]
    fn kubernetes_signature_requires_namespace_list_kind() {
        let v = |s: &str| serde_json::from_str::<Value>(s).expect("json");
        assert!(is_namespace_list(&v(r#"{"kind":"NamespaceList"}"#)));
        assert!(!is_namespace_list(&v(r#"{"kind":"PodList"}"#)));
    }

    #[test]
    fn bucket_hosts_map_to_provider_and_xml_marker() {
        assert_eq!(
            bucket_of("acme.s3.amazonaws.com"),
            Some(("aws_s3", "<ListBucketResult>"))
        );
        assert_eq!(
            bucket_of("acct.blob.core.windows.net"),
            Some(("azure_blob", "<EnumerationResults>"))
        );
        assert_eq!(bucket_of("example.com"), None);
    }

    #[tokio::test]
    async fn exposed_docker_version_api_is_reported() {
        let (server, guard, client) = scoped_server().await;
        mount_get(
            &server,
            "/version",
            r#"{"ApiVersion":"1.43","MinAPIVersion":"1.12"}"#,
        )
        .await;
        let findings = scan_one(&server, &guard, &client).await;
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].1, "docker");
        assert!(findings[0].0.ends_with("/version"));
    }

    #[tokio::test]
    async fn exposed_kubernetes_namespace_list_is_reported() {
        let (server, guard, client) = scoped_server().await;
        mount_get(
            &server,
            "/api/v1/namespaces",
            r#"{"kind":"NamespaceList","apiVersion":"v1","items":[]}"#,
        )
        .await;
        let findings = scan_one(&server, &guard, &client).await;
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].1, "kubernetes");
    }

    #[tokio::test]
    async fn robots_txt_with_disallow_is_reported() {
        let (server, guard, client) = scoped_server().await;
        mount_get(&server, "/robots.txt", "User-agent: *\nDisallow: /admin\n").await;
        let findings = scan_one(&server, &guard, &client).await;
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].1, "robots_discloses_paths");
    }

    #[tokio::test]
    async fn robots_txt_misses_yield_no_findings() {
        // 404 first, then a 200 with a body lacking the marker: both are
        // checked negatives.
        let (server, guard, client) = scoped_server().await;
        assert!(scan_one(&server, &guard, &client).await.is_empty());
        server.reset().await;
        mount_get(&server, "/robots.txt", "User-agent: *\nAllow: /\n").await;
        assert!(scan_one(&server, &guard, &client).await.is_empty());
    }

    #[tokio::test]
    async fn security_txt_without_contact_is_not_reported() {
        let (server, guard, client) = scoped_server().await;
        mount_get(
            &server,
            "/.well-known/security.txt",
            "Policy: https://example.com/security\n",
        )
        .await;
        assert!(scan_one(&server, &guard, &client).await.is_empty());
    }
}
