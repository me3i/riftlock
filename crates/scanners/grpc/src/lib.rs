//! gRPC exposure scanner: probes the target for the gRPC server
//! reflection service. A reachable reflection endpoint hands out the full
//! service schema to anyone — the reconnaissance primitive for every
//! other gRPC flaw.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    CheckState, Coverage, Evidence, Finding, ProofGate, ScanError, Scanner, ScopeGuard,
};
use url::Url;

/// The gRPC scanner. POSTs the reflection service path with the gRPC
/// content-type; a `200`/`501` whose response carries a gRPC marker
/// (`application/grpc` content-type or a `grpc-status` header) proves the
/// endpoint exists. A bare status is not enough: SPA catch-all routes
/// answer `200` with HTML for any path.
#[derive(Debug, Default)]
pub struct GrpcScanner {
    /// One check for the reflection probe.
    pub coverage: Coverage,
}

/// The standard reflection service path (v1alpha remains what most
/// servers enable, v1 often alongside).
const REFLECTION_PATH: &str = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";

impl Scanner for GrpcScanner {
    fn id(&self) -> &'static str {
        "grpc"
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
        // The reflection probe is a POST; read depth never sends it.
        if guard.is_read_only() {
            return Ok(Vec::new());
        }
        guard.check_active(url)?;
        let probe = url
            .join(REFLECTION_PATH)
            .map_err(|_| ScanError::InvalidUrl)?;
        if guard.check(&probe).is_err() {
            return Ok(Vec::new());
        }
        // A transport miss does not abort the scan, but it is a Failed check:
        // no answer was verified, so it is not a clean negative.
        let check = self.coverage.begin_check();
        let Ok(resp) = client
            .post(probe.clone())
            .header("content-type", "application/grpc")
            .body(Vec::new())
            .send()
            .await
        else {
            // The probe never produced an answer: record Failed, not a
            // clean negative, then keep the historical no-finding result.
            let _ = check.finish(CheckState::Failed);
            return Ok(Vec::new());
        };
        // A gRPC server answers with the grpc content-type (plus in-header
        // trailers like grpc-status); a plain-HTTP SPA fallback serving
        // HTML on every path does not — that is the FP discriminator.
        let status = resp.status().as_u16();
        let grpc_marker = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.contains("application/grpc"))
            || resp.headers().contains_key("grpc-status");
        if (status == 200 || status == 501) && grpc_marker {
            let finding = ProofGate::admit(Evidence::GrpcExposed {
                endpoint: probe.to_string(),
                service: "reflection".to_owned(),
            })?;
            let _ = check.finish(CheckState::Completed);
            return Ok(vec![finding]);
        }
        let _ = check.finish(CheckState::Completed);
        Ok(Vec::new())
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
        let findings = GrpcScanner::default()
            .scan(&base, &Client::new_lab(), &guard, false)
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
    async fn scan_flags_reflection_endpoint_on_200_and_501() {
        for status in [200, 501] {
            let server = wiremock::MockServer::start().await;
            let base = Url::parse(&server.uri()).expect("url");
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::path(REFLECTION_PATH))
                .respond_with(
                    wiremock::ResponseTemplate::new(status)
                        .insert_header("content-type", "application/grpc"),
                )
                .mount(&server)
                .await;
            let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
            let scanner = GrpcScanner::default();
            let findings = scanner
                .scan(&base, &Client::new_lab(), &guard, false)
                .await
                .expect("scan");
            assert_eq!(findings.len(), 1, "status {status}");
            let Evidence::GrpcExposed { endpoint, service } = findings[0].evidence() else {
                panic!("wrong evidence variant");
            };
            assert!(endpoint.ends_with(REFLECTION_PATH), "{endpoint}");
            assert_eq!(service, "reflection");
            let snap = scanner.coverage.snapshot(0);
            assert_eq!(snap.vulnerability_checks_attempted, 1);
            assert_eq!(snap.vulnerability_checks_completed, 1);
            assert!(snap.check_accounting_invariant());
            assert!(scanner.coverage.finalize().reconciles());
        }
    }

    #[tokio::test]
    async fn scan_negative_on_plain_http_404() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let findings = GrpcScanner::default()
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[tokio::test]
    async fn scan_negative_on_spa_catchall_html_200() {
        // SPA fallback: 200 for every path, served as HTML — no gRPC
        // marker, no reflection, no finding.
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body>app</body></html>"),
            )
            .mount(&server)
            .await;
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let findings = GrpcScanner::default()
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[tokio::test]
    async fn passive_scan_sends_nothing() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let findings = GrpcScanner::default()
            .scan(&base, &Client::new_lab(), &guard, true)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }
}
