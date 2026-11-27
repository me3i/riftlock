//! Appwrite scanner: unauthenticated collection-document reads against
//! `cloud.appwrite.io` (and self-hosted Appwrite endpoints matched by host).

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    CheckState, Coverage, Evidence, Finding, ProofGate, ScanError, Scanner, ScopeGuard,
};
use url::Url;

/// Appwrite misconfiguration scanner.
#[derive(Debug, Default)]
pub struct AppwriteScanner {
    /// Run even when `matches()` rejects the host — set when the operator
    /// explicitly passed `--provider appwrite` (lab targets).
    pub force_run: bool,
    /// One check for the collection-list + document-read probe.
    pub coverage: Coverage,
}

/// `GET <base>/v1/databases/default/collections`; on 200 take the first
/// collection `$id` and read one document page. Emits
/// [`Evidence::UnauthenticatedRead`] when `total > 0`.
///
/// # Errors
/// Transport failures or invalid URL joins.
pub async fn probe_collections(
    client: &Client,
    base: &Url,
    guard: &ScopeGuard,
) -> Result<Vec<Finding>, ScanError> {
    let list_url = base
        .join("v1/databases/default/collections")
        .map_err(|_| ScanError::InvalidUrl)?;
    guard.check(&list_url)?;
    let resp = client.get(list_url).send().await?;
    if resp.status().as_u16() != 200 {
        return Ok(Vec::new());
    }
    let body: serde_json::Value = resp.json().await?;
    let Some(id) = body["collections"][0]["$id"].as_str().map(str::to_owned) else {
        return Ok(Vec::new());
    };
    let docs_url = base
        .join(&format!(
            "v1/databases/default/collections/{id}/documents?limit=1"
        ))
        .map_err(|_| ScanError::InvalidUrl)?;
    guard.check(&docs_url)?;
    let resp = client.get(docs_url.clone()).send().await?;
    if resp.status().as_u16() != 200 {
        return Ok(Vec::new());
    }
    let body: serde_json::Value = resp.json().await?;
    let total = body["total"].as_u64().unwrap_or(0);
    if total == 0 {
        return Ok(Vec::new());
    }
    let endpoint = docs_url.as_str().to_owned();
    let first = body["documents"][0].clone();
    Ok(vec![ProofGate::admit(Evidence::UnauthenticatedRead {
        endpoint,
        row_sample: redact_doc(&first),
    })?])
}

/// Best-effort one-document redaction: keys plus value types only.
fn redact_doc(v: &serde_json::Value) -> String {
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

impl Scanner for AppwriteScanner {
    fn id(&self) -> &'static str {
        "appwrite"
    }

    fn matches(&self, url: &Url) -> bool {
        url.host_str()
            .is_some_and(|h| h.contains("cloud.appwrite.io"))
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
        let check = self.coverage.begin_check();
        let result = probe_collections(client, url, guard).await;
        let _ = check.finish(if result.is_ok() {
            CheckState::Completed
        } else {
            CheckState::Failed
        });
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mock_host(server: &MockServer) -> ScopeGuard {
        let origin = format!(
            "https://{}",
            Url::parse(&server.uri())
                .expect("url")
                .host_str()
                .unwrap_or_default()
        );
        ScopeGuard::new_lab(&[origin.as_str()]).expect("guard")
    }

    #[tokio::test]
    async fn open_collection_emits_read() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/databases/default/collections"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"collections": [{"$id": "users"}]})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/databases/default/collections/users/documents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"total": 1, "documents": [{"$id": "doc1", "email": "x"}]}),
            ))
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        let guard = mock_host(&server).await;
        let findings = probe_collections(&Client::new_lab(), &base, &guard)
            .await
            .expect("probe");
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn zero_total_is_no_finding() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/databases/default/collections"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"collections": [{"$id": "users"}]})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/databases/default/collections/users/documents"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"total": 0, "documents": []})),
            )
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        let guard = mock_host(&server).await;
        let findings = probe_collections(&Client::new_lab(), &base, &guard)
            .await
            .expect("probe");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn denied_listing_is_no_finding() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/databases/default/collections"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        let guard = mock_host(&server).await;
        let findings = probe_collections(&Client::new_lab(), &base, &guard)
            .await
            .expect("probe");
        assert!(findings.is_empty());
    }

    #[test]
    fn matches_appwrite_hosts() {
        let s = AppwriteScanner {
            force_run: false,
            coverage: Coverage::default(),
        };
        assert!(s.matches(&Url::parse("https://cloud.appwrite.io/v1").expect("url")));
        assert!(!s.matches(&Url::parse("https://example.com/v1").expect("url")));
    }

    #[tokio::test]
    async fn one_probe_run_is_one_accounted_check() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/databases/default/collections"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"collections": []})),
            )
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        let guard = mock_host(&server).await;
        let scanner = AppwriteScanner {
            force_run: true,
            coverage: Coverage::default(),
        };
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        let snap = scanner.coverage.snapshot(0);
        assert_eq!(snap.vulnerability_checks_attempted, 1);
        assert_eq!(snap.vulnerability_checks_completed, 1);
        assert!(snap.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }

    #[test]
    fn redact_doc_keeps_types_only() {
        assert_eq!(redact_doc(&serde_json::json!({"a": 1})), "{a: <redacted>}");
        assert_eq!(redact_doc(&serde_json::json!("s")), "<string:1>");
    }
}
