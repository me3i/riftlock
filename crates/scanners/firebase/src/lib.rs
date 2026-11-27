//! Firebase scanner: RTDB and Firestore unauthenticated-read probes.
//!
//! Root denial is not child denial: rules evaluate at the requested path.
//! A 403 on `/.json` says nothing about `/<key>.json`, so both are probed.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{Evidence, Finding, ProofGate, ScanError, Scanner, ScopeGuard};
use url::Url;

/// Firebase RTDB / Firestore misconfiguration scanner.
#[derive(Debug, Default)]
pub struct FirebaseScanner {
    /// Run even when `matches()` rejects the host — set when the operator
    /// explicitly passed `--provider firebase` (lab targets).
    pub force_run: bool,
}

/// `GET <base>/.json?shallow=true`; on 200 take the first key and read one
/// child row. Emits [`Evidence::UnauthenticatedRead`] when the child returns
/// 200 with data.
///
/// # Errors
/// Transport failures or invalid URL joins.
pub async fn probe_rtdb(
    client: &Client,
    base: &Url,
    guard: &ScopeGuard,
) -> Result<Vec<Finding>, ScanError> {
    let root = base
        .join(".json?shallow=true")
        .map_err(|_| ScanError::InvalidUrl)?;
    guard.check(&root)?;
    let resp = client.get(root).send().await?;
    if resp.status().as_u16() != 200 {
        return Ok(Vec::new());
    }
    let body: serde_json::Value = resp.json().await?;
    let Some(first_key) = body.as_object().and_then(|o| o.keys().next().cloned()) else {
        return Ok(Vec::new());
    };
    let child = base
        .join(&format!("{first_key}.json?limitToFirst=1"))
        .map_err(|_| ScanError::InvalidUrl)?;
    guard.check(&child)?;
    let resp = client.get(child.clone()).send().await?;
    if resp.status().as_u16() != 200 {
        return Ok(Vec::new());
    }
    let child_body: serde_json::Value = resp.json().await?;
    if child_body.is_null() {
        return Ok(Vec::new());
    }
    let endpoint = child
        .as_str()
        .split('?')
        .next()
        .unwrap_or_default()
        .to_owned();
    Ok(vec![ProofGate::admit(Evidence::UnauthenticatedRead {
        endpoint,
        row_sample: redact_row(&child_body),
    })?])
}

/// `GET <base>/v1/projects/default/databases/(default)/documents/users?pageSize=1`;
/// 200 with non-empty `documents` is an unauthenticated read.
///
/// # Errors
/// Transport failures or invalid URL joins.
pub async fn probe_firestore(
    client: &Client,
    base: &Url,
    guard: &ScopeGuard,
) -> Result<Vec<Finding>, ScanError> {
    let url = base
        .join("v1/projects/default/databases/(default)/documents/users?pageSize=1")
        .map_err(|_| ScanError::InvalidUrl)?;
    guard.check(&url)?;
    let resp = client.get(url.clone()).send().await?;
    if resp.status().as_u16() != 200 {
        return Ok(Vec::new());
    }
    let body: serde_json::Value = resp.json().await?;
    let non_empty = body
        .get("documents")
        .and_then(|d| d.as_array())
        .is_some_and(|a| !a.is_empty());
    if !non_empty {
        return Ok(Vec::new());
    }
    let endpoint = url.as_str().to_owned();
    let first = body["documents"][0].clone();
    Ok(vec![ProofGate::admit(Evidence::UnauthenticatedRead {
        endpoint,
        row_sample: redact_row(&first),
    })?])
}

impl Scanner for FirebaseScanner {
    fn id(&self) -> &'static str {
        "firebase"
    }

    fn matches(&self, url: &Url) -> bool {
        url.host_str()
            .is_some_and(|h| h.contains("firebaseio.com") || h.contains("firestore.googleapis.com"))
    }

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
        if url
            .host_str()
            .is_some_and(|h| h.contains("firestore.googleapis.com"))
        {
            probe_firestore(client, url, guard).await
        } else {
            probe_rtdb(client, url, guard).await
        }
    }
}

/// Best-effort one-row redaction: strip values, keep types and keys.
fn redact_row(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let inner = map
                .keys()
                .next()
                .map(|k| format!("{k}: <redacted>"))
                .unwrap_or_else(|| "<empty>".to_owned());
            format!("{{{inner}}}")
        }
        serde_json::Value::String(s) => format!("<string:{}>", s.len()),
        serde_json::Value::Number(_) => "<int>".to_owned(),
        _ => "<redacted>".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn guard_with(host: &str) -> ScopeGuard {
        let origin = format!("https://{host}");
        ScopeGuard::new_lab(&[origin.as_str()]).expect("guard")
    }

    #[tokio::test]
    async fn rtdb_open_root_and_child_emits_read() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"users":{}}"#))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/users.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"id1":{"name":"a"}}"#))
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        let guard = guard_with(
            Url::parse(&server.uri())
                .expect("url")
                .host_str()
                .unwrap_or_default(),
        );
        let findings = probe_rtdb(&Client::new_lab(), &base, &guard)
            .await
            .expect("probe");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::UnauthenticatedRead { endpoint, row_sample }
                if endpoint.ends_with("/users.json") && row_sample == "{id1: <redacted>}"
        ));
    }

    #[tokio::test]
    async fn rtdb_malformed_json_is_an_error_not_a_panic() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        let guard = guard_with(
            Url::parse(&server.uri())
                .expect("url")
                .host_str()
                .unwrap_or_default(),
        );
        assert!(probe_rtdb(&Client::new_lab(), &base, &guard).await.is_err());
    }

    #[tokio::test]
    async fn rtdb_denied_child_is_no_finding() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"users":{}}"#))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/users.json"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        let guard = guard_with(
            Url::parse(&server.uri())
                .expect("url")
                .host_str()
                .unwrap_or_default(),
        );
        let findings = probe_rtdb(&Client::new_lab(), &base, &guard)
            .await
            .expect("probe");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn firestore_empty_documents_is_no_finding() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/v1/projects/default/databases/(default)/documents/users",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"documents": []})),
            )
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        let guard = guard_with(
            Url::parse(&server.uri())
                .expect("url")
                .host_str()
                .unwrap_or_default(),
        );
        let findings = probe_firestore(&Client::new_lab(), &base, &guard)
            .await
            .expect("probe");
        assert!(findings.is_empty());
    }

    #[test]
    fn matches_firebase_hosts() {
        let s = FirebaseScanner { force_run: false };
        assert!(s.matches(&Url::parse("https://x.firebaseio.com/.json").expect("url")));
        assert!(s.matches(&Url::parse("https://firestore.googleapis.com/v1/x").expect("url")));
        assert!(!s.matches(&Url::parse("https://example.com/.json").expect("url")));
    }

    #[tokio::test]
    async fn force_run_probes_a_non_firebase_host() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        let guard = guard_with(
            Url::parse(&server.uri())
                .expect("url")
                .host_str()
                .unwrap_or_default(),
        );
        // Without force_run the host gate skips probing entirely.
        let gated = FirebaseScanner { force_run: false }
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(gated.is_empty());
        assert!(
            server
                .received_requests()
                .await
                .expect("recorded")
                .is_empty(),
            "gated scanner sent requests"
        );
        // With force_run the probe runs against the lab host.
        FirebaseScanner { force_run: true }
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(
            !server
                .received_requests()
                .await
                .expect("recorded")
                .is_empty(),
            "forced scanner never probed"
        );
    }

    #[test]
    fn redact_row_keeps_types_only() {
        assert_eq!(redact_row(&serde_json::json!("secretvalue")), "<string:11>");
        assert_eq!(redact_row(&serde_json::json!(42)), "<int>");
        assert_eq!(redact_row(&serde_json::json!({"k":"v"})), "{k: <redacted>}");
    }
}
