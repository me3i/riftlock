//! Server-sent-events scanner: proves a stream endpoint serves event data
//! without an `Authorization` header — the stream bypasses API auth.

use futures_util::StreamExt;
use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    paths_for_method, DiscoveredEndpoint, Evidence, Finding, ProofGate, ScanError, Scanner,
    ScopeGuard, SessionMatrix,
};
use std::time::Duration;
use url::Url;

/// The SSE scanner. GETs each stream endpoint with `Accept:
/// text/event-stream` and deliberately no `Authorization` header; a `data:`
/// event arriving within the deadline is the proof.
#[derive(Debug)]
pub struct SseScanner {
    /// Session tokens, supplied by the CLI for the session-differential
    /// contract; the unauthenticated stream itself is the proof.
    pub sessions: SessionMatrix,
    /// Stream endpoint paths discovered by AST (absolute, e.g. `/sse`).
    pub endpoints: Vec<String>,
    /// Method-aware inventory; only GET-discovered paths can be read as streams.
    pub endpoint_methods: Vec<DiscoveredEndpoint>,
    /// Overall read deadline for one stream. Tests shorten it.
    pub read_timeout: Duration,
}

impl Default for SseScanner {
    fn default() -> Self {
        Self {
            sessions: SessionMatrix::default(),
            endpoints: Vec::new(),
            endpoint_methods: Vec::new(),
            read_timeout: Duration::from_secs(3),
        }
    }
}

/// Whether a path targets a streaming endpoint worth probing.
fn is_stream_path(path: &str) -> bool {
    path.contains("/sse")
        || path.contains("/events")
        || path.contains("/stream")
        || path.contains("/api/chat")
}

/// Whether `text` carries a real SSE data event: a `data:` line whose
/// payload is a JSON object (`data: {...}`). Heartbeat text like
/// `data: keepalive` is not event data.
fn has_sse_data(text: &str) -> bool {
    text.lines().any(|line| {
        line.strip_prefix("data:")
            .map(str::trim_start)
            .is_some_and(|payload| payload.starts_with('{') && payload.ends_with('}'))
    })
}

/// Read `url` as an event stream without authentication, up to `timeout`.
/// Returns whatever arrived before the deadline.
///
/// # Errors
/// Request or stream transport failures.
async fn read_stream(client: &Client, url: &Url, timeout: Duration) -> Result<String, ScanError> {
    // No `.bearer_auth()`/`.header("authorization", ...)`: the probe is the
    // unauthenticated request itself.
    let resp = client
        .get(url.clone())
        .header("accept", "text/event-stream")
        .send()
        .await?;
    let mut text = String::new();
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut stream = resp.bytes_stream();
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            chunk = stream.next() => match chunk {
                Some(Ok(bytes)) => text.push_str(&String::from_utf8_lossy(&bytes)),
                Some(Err(e)) => return Err(ScanError::Http(e)),
                None => break,
            }
        }
    }
    Ok(text)
}

impl Scanner for SseScanner {
    fn id(&self) -> &'static str {
        "sse"
    }

    fn matches(&self, _url: &Url) -> bool {
        // Stream endpoints live anywhere; discovery supplies the paths.
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
        // The target itself, plus every discovered stream-looking path.
        let mut candidates = Vec::new();
        let endpoints = paths_for_method(&self.endpoints, &self.endpoint_methods, "GET");
        if is_stream_path(url.path())
            && (self.endpoint_methods.is_empty()
                || endpoints.iter().any(|endpoint| url.path() == endpoint))
        {
            candidates.push(url.clone());
        }
        for endpoint in &endpoints {
            if !is_stream_path(endpoint) {
                continue;
            }
            if let Ok(probe) = url.join(endpoint) {
                if guard.check(&probe).is_ok() && !candidates.contains(&probe) {
                    candidates.push(probe);
                }
            }
        }
        let mut findings = Vec::new();
        for probe in candidates {
            let text = read_stream(client, &probe, self.read_timeout).await?;
            if has_sse_data(&text) {
                findings.push(ProofGate::admit(Evidence::SseDesync {
                    endpoint: probe.to_string(),
                })?);
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn stream_paths_match() {
        assert!(is_stream_path("/api/sse"));
        assert!(is_stream_path("/events"));
        assert!(is_stream_path("/v1/stream"));
        assert!(is_stream_path("/api/chat"));
        assert!(!is_stream_path("/rest/v1/users"));
    }

    #[test]
    fn sse_data_requires_a_json_payload() {
        assert!(has_sse_data("data: {\"delta\":\"hi\"}\n\n"));
        assert!(has_sse_data("event: token\ndata: {\"t\":1}\n\n"));
        assert!(!has_sse_data("data: keepalive\n\n"));
        assert!(!has_sse_data("event: ping\n\n"));
        assert!(!has_sse_data(""));
    }

    /// A stream endpoint: `status` + `body` for the unauthenticated GET.
    async fn spawn_stream(status: u16, content_type: &'static str, body: &'static str) -> Url {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sse"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("content-type", content_type)
                    .set_body_string(body),
            )
            .mount(&server)
            .await;
        Url::parse(&format!("{}/sse", server.uri())).expect("url")
    }

    async fn scan_with(url: &Url, passive: bool) -> Result<Vec<Finding>, ScanError> {
        let scanner = SseScanner {
            read_timeout: Duration::from_millis(300),
            ..SseScanner::default()
        };
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        Scanner::scan(&scanner, url, &Client::new_lab(), &guard, passive).await
    }

    #[tokio::test]
    async fn scan_proves_unauthenticated_event_data() {
        let url = spawn_stream(200, "text/event-stream", "data: {\"delta\":\"hi\"}\n\n").await;
        let findings = scan_with(&url, false).await.expect("scan");
        assert!(matches!(
            findings.as_slice(),
            [f] if matches!(f.evidence(),
                Evidence::SseDesync { endpoint } if endpoint == url.as_str())
        ));
    }

    #[tokio::test]
    async fn method_inventory_selects_get_for_a_path_with_multiple_methods() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sse"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string("data: {\"delta\":\"x\"}\n\n"),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&format!("{}/rest/v1/users", server.uri())).expect("url");
        let scanner = SseScanner {
            endpoints: vec!["/sse".to_owned()],
            endpoint_methods: vec![
                DiscoveredEndpoint {
                    path: "/sse".to_owned(),
                    method: "GET".to_owned(),
                },
                DiscoveredEndpoint {
                    path: "/sse".to_owned(),
                    method: "POST".to_owned(),
                },
            ],
            read_timeout: Duration::from_millis(300),
            ..Default::default()
        };
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let findings = Scanner::scan(&scanner, &url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].url.path(), "/sse");
    }

    #[tokio::test]
    async fn scan_negative_when_auth_is_enforced() {
        let url = spawn_stream(401, "application/json", "{}").await;
        let findings = scan_with(&url, false).await.expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_on_heartbeat_only_stream() {
        // Open stream but no real event data: checked negative.
        let url = spawn_stream(200, "text/event-stream", ": ping\nevent: ping\n\n").await;
        let findings = scan_with(&url, false).await.expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_in_passive_mode() {
        let url = spawn_stream(200, "text/event-stream", "data: {}\n\n").await;
        let findings = scan_with(&url, true).await.expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_probes_discovered_stream_endpoints() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("accept", "text/event-stream"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string("data: {\"delta\":\"x\"}\n\n"),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&format!("{}/rest/v1/users", server.uri())).expect("url");
        let scanner = SseScanner {
            sessions: SessionMatrix::default(),
            endpoints: vec!["/sse".to_owned(), "/not-a-stream".to_owned()],
            read_timeout: Duration::from_millis(300),
            ..Default::default()
        };
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let findings = Scanner::scan(&scanner, &url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(matches!(
            findings.as_slice(),
            [f] if matches!(f.evidence(),
                Evidence::SseDesync { endpoint } if *endpoint == format!("{}/sse", server.uri()))
        ));
    }
}
