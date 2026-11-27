//! Auth-surface probes: open signup and weak credentials.
//!
//! These are active probes and must only run behind the depth gate and
//! ScopeGuard. Credentials are fixed throwaway test values; no real account
//! is targeted.

use crate::ScanError;
use riftlock_core::{Coverage, EndpointOutcome, ScopedClient as Client};
use url::Url;

/// Extract `access_token` from a Supabase auth response body.
fn extract_token(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("access_token")
        .and_then(|t| t.as_str())
        .map(str::to_owned)
}

/// A random-enough throwaway local part without a uuid dependency.
fn random_local() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() ^ (d.as_secs() as u32))
        .unwrap_or(0);
    format!("riftlock-test-{nanos:08x}")
}

/// Probe open signup: `POST /auth/v1/signup`. Returns `(status, token)` —
/// `Some(token)` only when signup succeeded and a JWT came back.
///
/// # Errors
/// Transport failures or invalid base URL.
pub async fn probe_signup(
    client: &Client,
    base: &Url,
    coverage: &Coverage,
) -> Result<(u16, Option<String>), ScanError> {
    let url = base
        .join("auth/v1/signup")
        .map_err(|_| ScanError::InvalidUrl)?;
    let url_key = url.as_str().to_owned();
    let resp = client
        .post(url)
        .json(&serde_json::json!({
            "email": format!("{}@example.com", random_local()),
            "password": "password123",
        }))
        .send()
        .await?;
    let status = resp.status().as_u16();
    let body = match riftlock_core::body::text_limited_result(resp).await {
        Ok(body) => body,
        Err(error) => {
            riftlock_core::logger::line(&format!("warning: {error}; body skipped"));
            coverage.endpoint_at(&url_key, EndpointOutcome::Failed);
            String::new()
        }
    };
    Ok((status, extract_token(&body)))
}

/// Probe weak credentials on `POST /auth/v1/token?grant_type=password`.
/// Returns the token from the first credential pair that authenticates.
///
/// # Errors
/// Transport failures or invalid base URL.
pub async fn probe_weak_login(
    client: &Client,
    base: &Url,
    coverage: &Coverage,
) -> Result<Option<String>, ScanError> {
    const CREDENTIALS: &[(&str, &str)] = &[
        ("admin@example.com", "password"),
        ("test@test.com", "test"),
        ("user@example.com", "password123"),
    ];
    let url = base
        .join("auth/v1/token?grant_type=password")
        .map_err(|_| ScanError::InvalidUrl)?;
    for (email, password) in CREDENTIALS {
        let resp = client
            .post(url.clone())
            .json(&serde_json::json!({"email": email, "password": password}))
            .send()
            .await?;
        if resp.status().as_u16() != 200 {
            continue;
        }
        let body = match riftlock_core::body::text_limited_result(resp).await {
            Ok(body) => body,
            Err(error) => {
                riftlock_core::logger::line(&format!("warning: {error}; body skipped"));
                coverage.endpoint_at(url.as_str(), EndpointOutcome::Failed);
                String::new()
            }
        };
        if let Some(token) = extract_token(&body) {
            return Ok(Some(token));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_extraction() {
        let body = r#"{"access_token":"eyJx","token_type":"bearer"}"#;
        assert_eq!(extract_token(body), Some("eyJx".to_owned()));
        assert_eq!(extract_token(r#"{"error":"invalid"}"#), None);
    }

    #[test]
    fn random_local_shape() {
        assert!(random_local().starts_with("riftlock-test-"));
    }

    #[tokio::test]
    async fn signup_and_weak_login_probes() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Signup returns 200 with a JWT for the throwaway address only.
        Mock::given(method("POST"))
            .and(path("/auth/v1/signup"))
            .and(body_partial_json(
                serde_json::json!({"password": "password123"}),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"access_token":"eyJsig"}"#),
            )
            .mount(&server)
            .await;
        // Only `test@test.com`/`test` authenticates.
        for (email, password, token) in [
            ("admin@example.com", "password", None),
            ("test@test.com", "test", Some("eyJweak")),
        ] {
            let body = match token {
                Some(t) => format!(r#"{{"access_token":"{t}"}}"#),
                None => r#"{"error":"invalid_credentials"}"#.to_owned(),
            };
            Mock::given(method("POST"))
                .and(path("/auth/v1/token"))
                .and(body_partial_json(
                    serde_json::json!({"email": email, "password": password}),
                ))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .expect(1)
                .mount(&server)
                .await;
        }

        let base = Url::parse(server.uri().as_str()).expect("url");
        let client = Client::new_lab();

        let coverage = Coverage::default();
        let (status, token) = probe_signup(&client, &base, &coverage)
            .await
            .expect("signup");
        assert_eq!(status, 200);
        assert_eq!(token, Some("eyJsig".to_owned()));

        let token = probe_weak_login(&client, &base, &coverage)
            .await
            .expect("weak login");
        assert_eq!(token, Some("eyJweak".to_owned()));
    }

    #[tokio::test]
    async fn oversized_signup_body_is_recorded_as_failed_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/signup"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![
                b'a';
                riftlock_core::body::MAX_BODY_BYTES
                    + 1
            ]))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let coverage = Coverage::default();
        let (status, token) = probe_signup(&Client::new_lab(), &base, &coverage)
            .await
            .expect("signup");
        assert_eq!(status, 200);
        assert_eq!(token, None);
        assert_eq!(coverage.snapshot(0).endpoints_failed, 1);
    }
}
