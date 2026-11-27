//! Clerk scanner: publishable-key detection and static disclosure checks
//! for client-side `unsafeMetadata` handling.

use regex::Regex;
use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    Coverage, EndpointOutcome, Evidence, Finding, ProofGate, ScanError, Scanner, ScopeGuard,
    SourceKind,
};
use riftlock_fingerprint::bundle_urls;
use url::Url;

/// Maximum bundles fetched per scan.
const MAX_BUNDLES: usize = 5;

/// The Clerk scanner. `matches()` is always true: Clerk usage is detected
/// from bundle contents, not the target host.
#[derive(Debug, Default)]
pub struct ClerkScanner {
    /// Shared ledger; bundle body-read failures land here.
    pub coverage: Coverage,
}

/// A Clerk publishable key observed in a bundle (`pk_test_…`/`pk_live_…`).
pub fn find_publishable_keys(source: &str) -> Vec<String> {
    let re = Regex::new(r"pk_(?:test|live)_[A-Za-z0-9_-]{8,}").expect("valid regex");
    re.find_iter(source)
        .map(|m| m.as_str().to_owned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Whether a bundle handles Clerk `unsafeMetadata` with privilege fields
/// that must never be trusted client-side.
fn discloses_unsafe_metadata(source: &str) -> bool {
    source.contains("unsafeMetadata")
        && (source.contains("isAdmin") || source.contains("role") || source.contains("plan"))
}

impl ClerkScanner {
    /// Fetch the page's bundles (capped, scope-checked). Returns the pairs
    /// (bundle URL, source text).
    async fn fetch_sources(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
    ) -> Result<Vec<(Url, String)>, ScanError> {
        guard.check(url)?;
        let html = match client.get(url.clone()).send().await {
            Ok(r) => match riftlock_core::body::text_limited_result(r).await {
                Ok(html) => html,
                Err(error) => {
                    riftlock_core::logger::line(&format!("warning: {error}; body skipped"));
                    self.coverage
                        .endpoint_at(url.as_str(), EndpointOutcome::Failed);
                    String::new()
                }
            },
            // The root is one optional probe URL. An unreachable page is a
            // checked negative for Clerk detection, not an engine failure:
            // record the endpoint and scan nothing.
            Err(error) => {
                let outcome = if error.is_timeout() {
                    EndpointOutcome::TimedOut
                } else {
                    EndpointOutcome::Failed
                };
                self.coverage.endpoint_at(url.as_str(), outcome);
                return Ok(Vec::new());
            }
        };
        let mut sources = vec![(url.clone(), html.clone())];
        for bundle in bundle_urls(&html, url).into_iter().take(MAX_BUNDLES) {
            if guard.check(&bundle).is_err() {
                self.coverage.out_of_scope_endpoint_at(bundle.as_str());
                continue;
            }
            if let Ok(resp) = client.get(bundle.clone()).send().await {
                let text = match riftlock_core::body::text_limited_result(resp).await {
                    Ok(text) => text,
                    Err(error) => {
                        riftlock_core::logger::line(&format!("warning: {error}; body skipped"));
                        self.coverage
                            .endpoint_at(bundle.as_str(), EndpointOutcome::Failed);
                        String::new()
                    }
                };
                sources.push((bundle, text));
            }
        }
        Ok(sources)
    }
}

impl Scanner for ClerkScanner {
    fn id(&self) -> &'static str {
        "clerk"
    }

    fn matches(&self, _url: &Url) -> bool {
        // Clerk apps live on any host; detection happens per bundle.
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
        let sources = self.fetch_sources(url, client, guard).await?;
        let uses_clerk = sources
            .iter()
            .any(|(_, src)| !find_publishable_keys(src).is_empty());
        if !uses_clerk {
            return Ok(Vec::new());
        }
        let mut findings = Vec::new();
        for (bundle_url, src) in sources {
            if discloses_unsafe_metadata(&src) {
                findings.push(ProofGate::admit(Evidence::SourceDisclosure {
                    url: bundle_url.to_string(),
                    kind: SourceKind::ClerkUnsafeMetadata,
                })?);
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_publishable_keys_deduped() {
        let src = r#"var a = "pk_test_ABCDEFGH1"; var b = 'pk_live_xyzw98765'; var c = "pk_test_ABCDEFGH1";"#;
        let keys = find_publishable_keys(src);
        // Deduplicated via BTreeSet: sorted order.
        assert_eq!(
            keys,
            vec![
                "pk_live_xyzw98765".to_owned(),
                "pk_test_ABCDEFGH1".to_owned()
            ]
        );
    }

    #[test]
    fn metadata_detection() {
        assert!(discloses_unsafe_metadata(
            "clerk.users.update({ unsafeMetadata: { isAdmin: true } })"
        ));
        assert!(discloses_unsafe_metadata("unsafeMetadata: { plan }"));
        assert!(!discloses_unsafe_metadata(
            "unsafeMetadata: { theme: 'dark' }"
        ));
        assert!(!discloses_unsafe_metadata("isAdmin: true"));
    }

    #[tokio::test]
    async fn scan_emits_on_clerk_bundle() {
        let server = wiremock::MockServer::start().await;
        let html = r#"<html><script src="/app.js"></script></html>"#;
        let bundle = r#"const k = "pk_test_ABCDEFGH1"; clerk.users.updateCurrentUser({ unsafeMetadata: { isAdmin: u.role === 'admin' } });"#;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/app.js"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(bundle))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let findings = Scanner::scan(
            &ClerkScanner::default(),
            &base,
            &Client::new_lab(),
            &guard,
            false,
        )
        .await
        .expect("scan");
        assert_eq!(findings.len(), 1);
        let Evidence::SourceDisclosure { url, kind } = findings[0].evidence() else {
            panic!("expected SourceDisclosure");
        };
        assert_eq!(kind, &SourceKind::ClerkUnsafeMetadata);
        assert!(url.ends_with("/app.js"));
    }

    #[tokio::test]
    async fn scan_negative_without_clerk_or_metadata() {
        let server = wiremock::MockServer::start().await;
        // No Clerk key at all.
        let html = r#"<html><script src="/app.js"></script></html>"#;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/app.js"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string("unsafeMetadata: { isAdmin: true }"),
            )
            .mount(&server)
            .await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let findings = Scanner::scan(
            &ClerkScanner::default(),
            &base,
            &Client::new_lab(),
            &guard,
            false,
        )
        .await
        .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn unreachable_root_is_a_clean_negative_not_an_engine_failure() {
        // A closed loopback port: the root probe fails at the transport layer.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let url = Url::parse(&format!("http://{addr}/")).expect("url");
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let scanner = ClerkScanner::default();
        let findings = Scanner::scan(&scanner, &url, &Client::new_lab(), &guard, false)
            .await
            .expect("an unreachable optional probe is not an engine failure");
        assert!(findings.is_empty());
        assert_eq!(scanner.coverage.snapshot(0).endpoints_failed, 1);
    }

    #[tokio::test]
    async fn oversized_bundle_body_is_recorded_as_failed_endpoint() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(r#"<script src="/app.js"></script>"#),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/app.js"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![
                b'a';
                riftlock_core::body::MAX_BODY_BYTES
                    + 1
            ]))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = ClerkScanner::default();
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        assert_eq!(scanner.coverage.snapshot(0).endpoints_failed, 1);
    }
}
