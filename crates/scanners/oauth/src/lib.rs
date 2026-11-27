//! OAuth scanner: proves open-redirect and missing-`state` flaws on
//! authorization endpoints. Given a `/.well-known/openid-configuration`
//! URL it resolves the provider's `authorization_endpoint` first.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    CheckState, Coverage, Evidence, Finding, ProofGate, ScanError, Scanner, ScopeGuard,
};
use url::Url;

/// The OAuth scanner. Two probes against the authorization endpoint, both
/// without redirects followed: an injected foreign `redirect_uri` (open
/// redirect) and a flow that proceeds with no `state` parameter at all.
#[derive(Debug, Default)]
pub struct OAuthScanner {
    /// Discovered paths and URLs to consider alongside the start URL.
    pub endpoints: Vec<String>,
    /// One check per authorization probe (open redirect, missing state).
    pub coverage: Coverage,
}

/// Whether `path` looks OAuth-related enough to consider as a candidate.
fn is_oauth_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.contains("oauth")
        || path.contains("authorize")
        || path.contains("callback")
        || path.contains("/.well-known/openid-configuration")
}

/// Whether the candidate can serve as an authorization endpoint or metadata
/// document for the probes this scanner currently proves.
fn is_probeable_oauth_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.contains("authorize") || path.contains("/.well-known/openid-configuration")
}

/// Start URL and discovered route candidates, resolved and deduplicated.
fn oauth_candidates(start: &Url, discovered: &[String]) -> Vec<Url> {
    let mut seen = std::collections::HashSet::new();
    std::iter::once(start.as_str())
        .chain(discovered.iter().map(String::as_str))
        .filter_map(|candidate| start.join(candidate).ok())
        .filter(|candidate| is_oauth_path(candidate.path()))
        .filter(|candidate| seen.insert(candidate.as_str().to_owned()))
        .collect()
}

/// Test 1 proof: a redirect whose `Location` is the injected foreign
/// `redirect_uri` verbatim — the server forwarded us to the attacker's site.
fn open_redirect_hit(status: u16, location: Option<&str>) -> bool {
    matches!(status, 301 | 302) && location.is_some_and(|l| l.starts_with("https://evil.com"))
}

/// Test 2 proof: the flow proceeds (login page or redirect) even though the
/// probe carried no `state`, and a redirect does not hand `state` back.
/// Only HTML responses count: a JSON/plain error page is a rejection, not a
/// login screen — the Phase-16 false positive.
fn missing_state_hit(status: u16, location: Option<&str>, content_type: Option<&str>) -> bool {
    if !content_type.is_some_and(|c| c.contains("text/html")) {
        return false;
    }
    if status == 200 {
        return true;
    }
    matches!(status, 301 | 302 | 303 | 307 | 308) && location.is_some_and(|l| !l.contains("state="))
}

/// The authorization endpoint to probe: the URL itself for
/// `/oauth/authorize`, otherwise `authorization_endpoint` resolved from the
/// discovery document. `None` when discovery yields nothing (checked
/// negative).
async fn resolve_authorize(url: &Url, client: &Client) -> Result<Option<Url>, ScanError> {
    if url.path().to_ascii_lowercase().contains("authorize") {
        return Ok(Some(url.clone()));
    }
    let doc: serde_json::Value = client.get(url.clone()).send().await?.json().await?;
    Ok(doc
        .get("authorization_endpoint")
        .and_then(|v| v.as_str())
        .and_then(|s| Url::parse(s).ok()))
}

/// Test 1: send the poisoned authorization request and judge the redirect.
async fn probe_open_redirect(
    client: &Client,
    authorize: &Url,
    coverage: &Coverage,
) -> Result<Option<Finding>, ScanError> {
    let check = coverage.begin_check();
    let probe =
        format!("{authorize}?client_id=test&redirect_uri=https://evil.com&response_type=code");
    let resp = match client.get(probe).send().await {
        Ok(resp) => resp,
        Err(error) => {
            let _ = check.finish(if error.is_timeout() {
                CheckState::TimedOut
            } else {
                CheckState::Failed
            });
            return Err(error);
        }
    };
    let status = resp.status().as_u16();
    let location = resp.headers().get("location").and_then(|v| v.to_str().ok());
    let finding = if open_redirect_hit(status, location) {
        Some(ProofGate::admit(Evidence::OAuthMisconfig {
            endpoint: authorize.to_string(),
            flaw: "open_redirect".to_owned(),
        })?)
    } else {
        None
    };
    let _ = check.finish(CheckState::Completed);
    Ok(finding)
}

/// Test 2: send a valid-shaped request with no `state` and judge whether
/// the flow proceeds anyway.
async fn probe_missing_state(
    client: &Client,
    authorize: &Url,
    coverage: &Coverage,
) -> Result<Option<Finding>, ScanError> {
    let check = coverage.begin_check();
    let probe = format!("{authorize}?client_id=test&response_type=code");
    let resp = match client.get(probe).send().await {
        Ok(resp) => resp,
        Err(error) => {
            let _ = check.finish(if error.is_timeout() {
                CheckState::TimedOut
            } else {
                CheckState::Failed
            });
            return Err(error);
        }
    };
    let status = resp.status().as_u16();
    let location = resp.headers().get("location").and_then(|v| v.to_str().ok());
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok());
    let finding = if missing_state_hit(status, location, content_type) {
        Some(ProofGate::admit(Evidence::OAuthMisconfig {
            endpoint: authorize.to_string(),
            flaw: "missing_state".to_owned(),
        })?)
    } else {
        None
    };
    let _ = check.finish(CheckState::Completed);
    Ok(finding)
}

impl Scanner for OAuthScanner {
    fn id(&self) -> &'static str {
        "oauth"
    }

    fn matches(&self, url: &Url) -> bool {
        is_oauth_path(url.path())
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
        guard.check(url)?;
        let candidates = oauth_candidates(url, &self.endpoints);
        let mut authorizes = std::collections::HashSet::new();
        let mut findings = Vec::new();
        for candidate in candidates {
            if !is_probeable_oauth_path(candidate.path()) || guard.check(&candidate).is_err() {
                continue;
            }
            let Some(authorize) = resolve_authorize(&candidate, client).await? else {
                continue;
            };
            // An authorization endpoint outside the scan scope is skipped,
            // not fatal — the target itself was in scope, this host is not.
            if guard.check(&authorize).is_err() || !authorizes.insert(authorize.as_str().to_owned())
            {
                continue;
            }
            if let Some(f) = probe_open_redirect(client, &authorize, &self.coverage).await? {
                findings.push(f);
            }
            if let Some(f) = probe_missing_state(client, &authorize, &self.coverage).await? {
                findings.push(f);
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn oauth_paths_match() {
        assert!(is_oauth_path("/oauth/authorize"));
        assert!(is_oauth_path("/.well-known/openid-configuration"));
        assert!(is_oauth_path("/auth/callback"));
        assert!(!is_oauth_path("/rest/v1/users"));
    }

    #[test]
    fn open_redirect_needs_redirect_status_and_evil_location() {
        assert!(open_redirect_hit(302, Some("https://evil.com/cb")));
        assert!(open_redirect_hit(301, Some("https://evil.com")));
        assert!(!open_redirect_hit(302, Some("https://target.com/cb")));
        assert!(!open_redirect_hit(200, Some("https://evil.com")));
        assert!(!open_redirect_hit(302, None));
    }

    #[test]
    fn missing_state_needs_proceeding_flow_without_state() {
        assert!(missing_state_hit(
            200,
            None,
            Some("text/html; charset=utf-8")
        ));
        assert!(missing_state_hit(
            302,
            Some("https://t/cb?code=abc"),
            Some("text/html")
        ));
        assert!(!missing_state_hit(
            302,
            Some("https://t/cb?state=xyz"),
            Some("text/html")
        ));
        assert!(!missing_state_hit(400, None, Some("text/html")));
        // The Phase-16 false positive: JSON/plain/absent content type is a
        // rejection, not a login page.
        assert!(!missing_state_hit(200, None, Some("application/json")));
        assert!(!missing_state_hit(200, None, Some("text/plain")));
        assert!(!missing_state_hit(200, None, None));
        assert!(!missing_state_hit(302, Some("https://t/cb?code=abc"), None));
    }

    /// A mock OAuth server: the evil-`redirect_uri` request gets a redirect
    /// to the attacker (when `redirects_to_evil`), everything else gets
    /// `other_status` with `content_type` and an optional `Location`.
    async fn spawn_oauth(
        redirects_to_evil: bool,
        other_status: u16,
        content_type: &'static str,
        other_location: Option<String>,
    ) -> Url {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param("redirect_uri", "https://evil.com"))
            .respond_with(
                ResponseTemplate::new(if redirects_to_evil { 302 } else { 400 })
                    .insert_header("location", "https://evil.com/cb"),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        let mut fallback =
            ResponseTemplate::new(other_status).insert_header("content-type", content_type);
        if let Some(loc) = other_location {
            fallback = fallback.insert_header("location", loc);
        }
        Mock::given(method("GET"))
            .respond_with(fallback)
            .with_priority(10)
            .mount(&server)
            .await;
        Url::parse(&format!("{}/oauth/authorize", server.uri())).expect("url")
    }

    async fn scan_with(url: &Url, passive: bool) -> Result<Vec<Finding>, ScanError> {
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let client = Client::new_lab();
        Scanner::scan(&OAuthScanner::default(), url, &client, &guard, passive).await
    }

    #[tokio::test]
    async fn scan_proves_open_redirect() {
        let url = spawn_oauth(true, 400, "text/html", None).await;
        let findings = scan_with(&url, false).await.expect("scan");
        assert!(matches!(
            findings.as_slice(),
            [f] if matches!(f.evidence(),
                Evidence::OAuthMisconfig { flaw, .. } if flaw == "open_redirect")
        ));
    }

    #[tokio::test]
    async fn scan_proves_missing_state_on_login_page() {
        let url = spawn_oauth(false, 200, "text/html", None).await;
        let findings = scan_with(&url, false).await.expect("scan");
        assert!(matches!(
            findings.as_slice(),
            [f] if matches!(f.evidence(),
                Evidence::OAuthMisconfig { flaw, .. } if flaw == "missing_state")
        ));
    }

    #[tokio::test]
    async fn scan_negative_on_json_error_page() {
        // The Phase-16 false positive: a 200 JSON body is not a login page.
        let url = spawn_oauth(false, 200, "application/json", None).await;
        let findings = scan_with(&url, false).await.expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_when_state_is_enforced() {
        // Correct server: 400 on the poisoned request, redirect carrying
        // `state` back on the clean one.
        let url = spawn_oauth(
            false,
            302,
            "text/html",
            Some("https://t/cb?state=xyz&code=abc".to_owned()),
        )
        .await;
        let findings = scan_with(&url, false).await.expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_in_passive_mode() {
        let url = spawn_oauth(true, 200, "text/html", None).await;
        let findings = scan_with(&url, true).await.expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn both_authorization_probes_are_accounted_as_checks() {
        let url = spawn_oauth(false, 200, "application/json", None).await;
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let scanner = OAuthScanner::default();
        let findings = scanner
            .scan(&url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        let snap = scanner.coverage.snapshot(0);
        assert_eq!(snap.vulnerability_checks_attempted, 2);
        assert_eq!(snap.vulnerability_checks_completed, 2);
        assert!(snap.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }

    #[tokio::test]
    async fn scan_skips_an_out_of_scope_discovered_authorize_route() {
        let start_server = MockServer::start().await;
        let start = Url::parse(&start_server.uri()).expect("start URL");
        // ScopeGuard intentionally scopes by hostname, not port; use a
        // different hostname to assert an actual out-of-scope candidate.
        let out_of_scope = "http://other.example/oauth/authorize".to_owned();
        let guard = ScopeGuard::new_lab(&[start.as_str()]).expect("guard");
        let scanner = OAuthScanner {
            endpoints: vec![out_of_scope],
            ..OAuthScanner::default()
        };

        let findings = scanner
            .scan(&start, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        // Candidate scope is checked before any request, so only the start
        // host's initial discovery requests (if any) could be observed.
        assert!(start_server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }

    #[tokio::test]
    async fn scan_resolves_authorize_endpoint_from_discovery() {
        let server = MockServer::start().await;
        let well_known = format!("{}/.well-known/openid-configuration", server.uri());
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "authorization_endpoint": format!("{}/oauth/authorize", server.uri()) }),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("redirect_uri", "https://evil.com"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "https://evil.com/cb"),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&well_known).expect("url");
        let findings = scan_with(&url, false).await.expect("scan");
        assert!(matches!(
            findings.as_slice(),
            [f] if matches!(f.evidence(),
                Evidence::OAuthMisconfig { endpoint, flaw }
                    if flaw == "open_redirect" && *endpoint == format!("{}/oauth/authorize", server.uri()))
        ));
    }
}
