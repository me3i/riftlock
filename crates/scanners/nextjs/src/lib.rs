//! Next.js scanner: Server Action ID extraction from bundles and unauthed
//! action probes.

use regex::Regex;
use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    Coverage, DiscoveryContext, DynamicScanner, EndpointOutcome, Evidence, Finding, ProofGate,
    ScanError, Scanner, ScopeGuard, SessionMatrix,
};
use riftlock_fingerprint::bundle_urls;
use std::pin::Pin;
use url::Url;

/// Maximum bundles fetched per scan.
const MAX_BUNDLES: usize = 5;

/// Maximum action IDs probed per scan — bundles carry many unrelated 40-hex
/// digests, so probing is capped to keep request volume bounded.
const MAX_ACTIONS: usize = 25;

/// The Next.js scanner. Runs against any host (Server Actions can appear in
/// any Next.js app); probing is scope-checked per request.
#[derive(Debug, Clone, Default)]
pub struct NextJsScanner {
    /// Action IDs pre-extracted by the CLI's bundle discovery.
    pub action_ids: Vec<String>,
    /// Session matrix for the authenticated tier of the action differential.
    pub sessions: SessionMatrix,
    /// Shared ledger; bundle body-read failures land here.
    pub coverage: Coverage,
}

/// Extract Server Action IDs from JS source: `$ACTION_ID_<hex>` markers and
/// standalone 40+ hex digests. Deduplicated, order preserved.
pub fn extract_action_ids(source: &str) -> Vec<String> {
    let marker = Regex::new(r"\$ACTION_ID_([a-f0-9]+)").expect("valid regex");
    let digest = Regex::new(r"[a-f0-9]{40,}").expect("valid regex");
    let mut ids: Vec<String> = marker
        .captures_iter(source)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_owned()))
        .collect();
    // `regex` has no lookaround, so standalone digests are filtered by
    // checking that the run is not embedded in a longer alphanumeric token.
    ids.extend(
        digest
            .find_iter(source)
            .filter(|m| {
                let (start, end) = (m.start(), m.end());
                let before = source[..start].chars().next_back();
                let after = source[end..].chars().next();
                let edge =
                    |c: Option<char>| !c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
                edge(before) && edge(after)
            })
            .map(|m| m.as_str().to_owned()),
    );
    ids.into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

impl NextJsScanner {
    /// Fetch the page's bundles (capped at [`MAX_BUNDLES`], scope-checked)
    /// and extract Server Action IDs from the HTML plus each bundle. Also
    /// returns the measured guest status of the root page (the baseline GET).
    async fn discover_actions(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
    ) -> Result<(Vec<String>, u16), ScanError> {
        guard.check(url)?;
        let resp = match client.get(url.clone()).send().await {
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        let guest_status = resp.status().as_u16();
        let html = match riftlock_core::body::text_limited_result(resp).await {
            Ok(html) => html,
            Err(error) => {
                riftlock_core::logger::line(&format!("warning: {error}; body skipped"));
                self.coverage
                    .endpoint_at(url.as_str(), EndpointOutcome::Failed);
                String::new()
            }
        };
        let mut sources = vec![html.clone()];
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
                sources.push(text);
            }
        }
        let mut ids = self.action_ids.clone();
        ids.extend(sources.iter().flat_map(|src| extract_action_ids(src)));
        let ids: Vec<String> = ids
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .take(MAX_ACTIONS)
            .collect();
        Ok((ids, guest_status))
    }

    /// POST one Server Action invocation. Returns the measured status and
    /// whether the action actually executed: a 200 that did not redirect to
    /// a login page (reqwest follows redirects, so a login bounce shows up
    /// as a changed final URL).
    async fn probe_action(
        client: &Client,
        url: &Url,
        action_id: &str,
        cookie: Option<&str>,
    ) -> Result<(u16, bool), ScanError> {
        let mut req = client
            .post(url.clone())
            .header("Next-Action", action_id)
            .header("Content-Type", "text/plain;charset=UTF-8")
            .body("[]");
        if let Some(c) = cookie {
            req = req.header("Cookie", c);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let executed = status == 200 && resp.url() == url;
        Ok((status, executed))
    }
}

impl Scanner for NextJsScanner {
    fn id(&self) -> &'static str {
        "nextjs"
    }

    fn matches(&self, _url: &Url) -> bool {
        // Server Actions exist in any Next.js app regardless of host.
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
        // Server Action invocations are POSTs; read depth never sends them.
        if guard.is_read_only() {
            return Ok(Vec::new());
        }
        guard.check_active(url)?;
        let mut findings = Vec::new();
        let (action_ids, guest_status) = self.discover_actions(url, client, guard).await?;
        for action_id in action_ids {
            // Unauthenticated action probe: measured, never assumed.
            let (unauth_status, unauth_executed) =
                NextJsScanner::probe_action(client, url, &action_id, None).await?;
            if !unauth_executed {
                continue;
            }
            // Authenticated tier, measured only when a session is available;
            // otherwise fall back to the measured guest baseline of the app.
            let auth_status = match self.sessions.user_a.as_deref() {
                Some(cookie) => Some(
                    NextJsScanner::probe_action(client, url, &action_id, Some(cookie))
                        .await?
                        .0,
                ),
                None => None,
            };
            findings.push(ProofGate::admit(Evidence::Differential {
                without_key: unauth_status,
                with_key: auth_status.unwrap_or(guest_status),
                inverted: false,
                cross_tenant: false,
                note: Some("nextjs_action_bypass".to_owned()),
            })?);
        }
        Ok(findings)
    }
}

impl DynamicScanner for NextJsScanner {
    fn scan_dynamic(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        ctx: &DiscoveryContext,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<Finding>, ScanError>> + Send + '_>>
    {
        // Clone inputs so the boxed future is self-contained: the trait's
        // elided return ties the future to &self only.
        let url = url.clone();
        let client = client.clone();
        let guard = guard.clone();
        let ctx = ctx.clone();
        Box::pin(async move {
            // Server Action invocations are POSTs; read depth never sends them.
            if guard.is_read_only() {
                return Ok(Vec::new());
            }
            guard.check_active(&url)?;
            let mut findings = Vec::new();
            let Some(user_a) = ctx.sessions.user_a.as_deref() else {
                return Ok(findings);
            };
            for endpoint in &ctx.endpoints {
                let probe = match url.join(endpoint) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                if guard.check(&probe).is_err() {
                    self.coverage.out_of_scope_endpoint_at(probe.as_str());
                    continue;
                }
                for action_id in &self.action_ids {
                    let guest = client
                        .post(probe.clone())
                        .header("Next-Action", action_id)
                        .header("Content-Type", "text/plain;charset=UTF-8")
                        .body("[]")
                        .send()
                        .await?;
                    if guest.status().as_u16() != 401 {
                        continue;
                    }
                    let keyed = client
                        .post(probe.clone())
                        .header("Next-Action", action_id)
                        .header("Content-Type", "text/plain;charset=UTF-8")
                        .header("Authorization", format!("Bearer {user_a}"))
                        .body("[]")
                        .send()
                        .await?;
                    if keyed.status().as_u16() == 200 {
                        findings.push(ProofGate::admit(Evidence::Differential {
                            without_key: 401,
                            with_key: 200,
                            inverted: false,
                            cross_tenant: false,
                            note: Some("nextjs_action".to_owned()),
                        })?);
                        break;
                    }
                }
            }
            Ok(findings)
        })
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
            &NextJsScanner::default(),
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
    fn extracts_marker_and_digest_ids() {
        let src = r#"
            var a = "$ACTION_ID_abc123def456abc123def456abc123def456ab";
            var digest = "0123456789abcdef0123456789abcdef01234567";
            var notHex = "z0123456789abcdef0123456789abcdef01234567";
            var short = "abc123";
        "#;
        let ids = extract_action_ids(src);
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"abc123def456abc123def456abc123def456ab".to_owned()));
        assert!(ids.contains(&"0123456789abcdef0123456789abcdef01234567".to_owned()));
    }

    #[tokio::test]
    async fn scan_proves_unauthed_action() {
        let server = wiremock::MockServer::start().await;
        let action_id = "abc123def456abc123def456abc123def456ab";
        let html = r#"<html><script src="/_next/bundle.js"></script></html>"#.to_string();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_next/bundle.js"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(format!("$ACTION_ID_{action_id}")),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::header("Next-Action", action_id))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = NextJsScanner::default();
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        // without_key = measured unauth action status; with_key falls back to
        // the measured guest baseline (root GET = 200) with no session.
        assert!(matches!(
            findings[0].evidence(),
            Evidence::Differential {
                without_key: 200,
                with_key: 200,
                note: Some(_),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn scan_negative_when_unauth_blocked_but_auth_works() {
        let server = wiremock::MockServer::start().await;
        let action_id = "abc123def456abc123def456abc123def456ab";
        let html = r#"<html><script src="/_next/bundle.js"></script></html>"#.to_string();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_next/bundle.js"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(format!("$ACTION_ID_{action_id}")),
            )
            .mount(&server)
            .await;
        // Action requires the session cookie: unauth POST is blocked (403),
        // cookie-carrying POST succeeds. Not an unauth bypass — no finding.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::header("Cookie", "sid=abc"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = NextJsScanner {
            sessions: SessionMatrix {
                user_a: Some("sid=abc".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_when_action_denied() {
        let server = wiremock::MockServer::start().await;
        let action_id = "abc123def456abc123def456abc123def456ab";
        let html = r#"<html><script src="/_next/bundle.js"></script></html>"#.to_string();
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(html))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_next/bundle.js"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(format!("$ACTION_ID_{action_id}")),
            )
            .mount(&server)
            .await;
        // POST always 401: blocked, checked negative.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = NextJsScanner::default();
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn oversized_bundle_body_is_recorded_as_failed_endpoint() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(r#"<script src="/_next/bundle.js"></script>"#),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_next/bundle.js"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![
                b'a';
                riftlock_core::body::MAX_BODY_BYTES
                    + 1
            ]))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = NextJsScanner::default();
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        assert_eq!(scanner.coverage.snapshot(0).endpoints_failed, 1);
    }
}
