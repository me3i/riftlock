//! WebSocket auth-desync scanner for Phoenix/Supabase Realtime channels:
//! proves a channel still accepts subscriptions and serves data after the
//! authenticating token is dropped from the session.

use futures_util::{SinkExt, StreamExt};
use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    Coverage, Evidence, Finding, ProofGate, ScanError, Scanner, ScopeGuard, SessionMatrix,
};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Response;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use url::Url;

/// The WebSocket desync scanner. Joins a realtime channel with
/// `ctx.sessions.user_a`'s token (Phoenix `phx_join`), then simulates auth
/// revocation by reconnecting without the token and attempting the same
/// subscription. Only an unauthenticated join that the server accepts (or
/// that produces broadcast data) proves the desync.
#[derive(Debug)]
pub struct WebSocketScanner {
    /// Session tokens; `user_a` authenticates the baseline join.
    pub sessions: SessionMatrix,
    /// Discovered paths and URLs to consider alongside the start URL.
    pub endpoints: Vec<String>,
    /// Deadline for the connect and each join reply. Tests shorten it.
    pub timeout: Duration,
    /// Shared coverage counters for WebSocket probe outcomes.
    pub coverage: Coverage,
}

impl Default for WebSocketScanner {
    fn default() -> Self {
        Self {
            sessions: SessionMatrix::default(),
            endpoints: Vec::new(),
            timeout: Duration::from_secs(5),
            coverage: Coverage::default(),
        }
    }
}

/// How a realtime server answered a channel join.
#[derive(Debug, PartialEq, Eq)]
enum JoinOutcome {
    /// `phx_reply` with `status: ok` — the join was accepted.
    Acked,
    /// Other data arrived on the topic — we are subscribed regardless.
    Broadcast,
    /// `phx_reply` with an error status.
    Rejected,
    /// Nothing usable before the deadline, or the connection dropped.
    NoReply,
}

/// Whether `url`'s path targets a realtime websocket endpoint.
fn is_realtime_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.contains("/realtime/v1/websocket") || path.contains("/ws") || path.contains("websocket")
}

/// Whether a discovered URL explicitly suggests a WebSocket endpoint.
fn is_websocket_candidate(url: &Url) -> bool {
    matches!(url.scheme(), "ws" | "wss")
        || is_realtime_path(url.path())
        || url.path().to_ascii_lowercase().contains("socket")
}

/// Resolve and deduplicate WebSocket candidates from the start URL and
/// discovered endpoint inventory.
fn websocket_candidates(start: &Url, discovered: &[String]) -> Vec<Url> {
    let mut seen = std::collections::HashSet::new();
    std::iter::once(start.as_str())
        .chain(discovered.iter().map(String::as_str))
        .filter_map(|candidate| start.join(candidate).ok())
        .filter(is_websocket_candidate)
        .filter(|candidate| seen.insert(candidate.as_str().to_owned()))
        .collect()
}

/// The ws/wss form of an http(s) target, same host, port and path.
///
/// # Errors
/// [`ScanError::InvalidUrl`] when the scheme is not http(s) or parts are missing.
fn ws_url(url: &Url) -> Result<Url, ScanError> {
    if matches!(url.scheme(), "ws" | "wss") {
        return Ok(url.clone());
    }
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => return Err(ScanError::InvalidUrl),
    };
    let host = url.host_str().ok_or(ScanError::InvalidUrl)?;
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    Url::parse(&format!("{scheme}://{host}{port}{}", url.path())).map_err(|_| ScanError::InvalidUrl)
}

/// A Phoenix `phx_join` frame for the `realtime` topic, with the
/// authenticating token when present and an empty payload otherwise.
fn join_frame(token: Option<&str>, reference: &str) -> String {
    let payload = match token {
        Some(t) => serde_json::json!({ "access_token": t }),
        None => serde_json::json!({}),
    };
    serde_json::json!({
        "topic": "realtime",
        "event": "phx_join",
        "payload": payload,
        "ref": reference,
    })
    .to_string()
}

/// Classify a text frame: a join reply (ok/error) or broadcast data.
/// `None` for anything that is not JSON (keep waiting).
fn classify(text: &str) -> Option<JoinOutcome> {
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    match value.get("event").and_then(|e| e.as_str()) {
        Some("phx_reply") => {
            let ok = value.pointer("/payload/status").and_then(|s| s.as_str()) == Some("ok");
            Some(if ok {
                JoinOutcome::Acked
            } else {
                JoinOutcome::Rejected
            })
        }
        _ => Some(JoinOutcome::Broadcast),
    }
}

/// Read frames until a join reply (or broadcast) arrives or `timeout`
/// expires.
async fn wait_reply<S>(ws: &mut WebSocketStream<S>, timeout: Duration) -> JoinOutcome
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return JoinOutcome::NoReply,
            Ok(None) | Ok(Some(Err(_))) => return JoinOutcome::NoReply,
            Ok(Some(Ok(Message::Text(text)))) => match classify(&text) {
                Some(outcome) => return outcome,
                None => continue,
            },
            Ok(Some(Ok(_))) => continue, // ping/pong/binary
        }
    }
}

/// Transport failures surface as the raw-socket variant of [`ScanError`].
fn io_err(e: tokio_tungstenite::tungstenite::Error) -> ScanError {
    ScanError::Io(std::io::Error::other(e))
}

/// The connect/handshake/send deadline: a server that never completes the
/// upgrade (or a filtered port's SYN retransmissions) must cost the probe
/// one deadline — tungstenite futures have no internal timeout.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

async fn connect_safe<R>(
    target: &Url,
    client: &Client,
    request: R,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), ScanError>
where
    R: IntoClientRequest + Unpin,
{
    let host = target.host_str().ok_or_else(|| {
        io_err(tokio_tungstenite::tungstenite::Error::Url(
            tokio_tungstenite::tungstenite::error::UrlError::NoHostName,
        ))
    })?;
    let port = target.port_or_known_default().ok_or_else(|| {
        io_err(tokio_tungstenite::tungstenite::Error::Url(
            tokio_tungstenite::tungstenite::error::UrlError::UnsupportedUrlScheme,
        ))
    })?;
    let connected = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let addresses = client
            .lookup_host(host, port)
            .await
            .map_err(ScanError::Io)?;
        let stream = TcpStream::connect(addresses.as_slice())
            .await
            .map_err(ScanError::Io)?;
        tokio_tungstenite::client_async_tls_with_config(request, stream, None, None)
            .await
            .map_err(io_err)
    })
    .await;
    match connected {
        Ok(result) => result,
        Err(_) => Err(io_err(tokio_tungstenite::tungstenite::Error::Io(
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "websocket connect exceeded its deadline",
            ),
        ))),
    }
}

/// Run `fut` under [`HANDSHAKE_TIMEOUT`], surfacing a stall as a transport
/// error instead of an unbounded wait.
async fn bounded<T>(
    fut: impl std::future::Future<Output = Result<T, tokio_tungstenite::tungstenite::Error>>,
) -> Result<T, ScanError> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await {
        Ok(r) => r.map_err(io_err),
        Err(_) => Err(io_err(tokio_tungstenite::tungstenite::Error::Io(
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "websocket operation exceeded its deadline",
            ),
        ))),
    }
}

impl Scanner for WebSocketScanner {
    fn id(&self) -> &'static str {
        "websocket"
    }

    fn matches(&self, url: &Url) -> bool {
        is_realtime_path(url.path())
    }

    async fn scan(
        &self,
        url: &Url,
        _client: &Client,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        if passive {
            return Ok(Vec::new());
        }
        guard.check_active(url)?;
        guard.check(url)?;
        let mut all_findings = Vec::new();
        for candidate in websocket_candidates(url, &self.endpoints) {
            // Without a user_a token there is no authenticated baseline to
            // revoke, though the independent CSWSH probe still runs.
            if guard.check(&candidate).is_err() {
                continue;
            }
            let url = &candidate;
            let target = ws_url(url)?;
            let mut findings = Vec::new();
            let check = self.coverage.begin_check();
            let mut endpoint_failed = false;
            let mut endpoint_tested = false;

            // Baseline: join with the valid token. If even that is rejected the
            // channel enforces auth correctly and no desync can be proven.
            // An unreachable WebSocket endpoint is a checked negative, not a
            // transport abort — the scan must not kill the whole CLI run.
            'desync: {
                let Some(token) = self.sessions.user_a.as_deref() else {
                    break 'desync;
                };
                let (mut ws, _) = match connect_safe(&target, _client, target.as_str()).await {
                    Ok(conn) => conn,
                    Err(_) => {
                        endpoint_failed = true;
                        break 'desync;
                    }
                };
                endpoint_tested = true;
                if bounded(ws.send(Message::Text(join_frame(Some(token), "1"))))
                    .await
                    .is_err()
                {
                    endpoint_failed = true;
                    break 'desync;
                }
                let baseline = wait_reply(&mut ws, self.timeout).await;
                if baseline != JoinOutcome::Acked {
                    endpoint_failed = baseline == JoinOutcome::NoReply;
                    break 'desync;
                }
                drop(ws);

                // Revocation: reconnect without the token and try the same join.
                let (mut ws, _) = match connect_safe(&target, _client, target.as_str()).await {
                    Ok(conn) => conn,
                    Err(_) => {
                        endpoint_failed = true;
                        break 'desync;
                    }
                };
                if bounded(ws.send(Message::Text(join_frame(None, "2"))))
                    .await
                    .is_err()
                {
                    endpoint_failed = true;
                    break 'desync;
                }
                let outcome = wait_reply(&mut ws, self.timeout).await;
                if matches!(outcome, JoinOutcome::Acked | JoinOutcome::Broadcast) {
                    findings.push(ProofGate::admit(Evidence::WebSocketDesync {
                        endpoint: url.to_string(),
                    })?);
                }
                if outcome == JoinOutcome::NoReply {
                    endpoint_failed = true;
                }
            }

            // CSWSH: the same upgrade with a spoofed foreign Origin. A server
            // that completes the handshake does not validate origin; the
            // finding only lands when it also speaks (zero-false-positive bar).
            // The base request comes from IntoClientRequest so the mandatory
            // upgrade headers are present; only Origin is replaced.
            // A malformed target fails this candidate only; earlier candidates'
            // findings stay in `all_findings`.
            if let Ok(mut request) = target.as_str().into_client_request() {
                request.headers_mut().insert(
                    "Origin",
                    tokio_tungstenite::tungstenite::http::HeaderValue::from_static(
                        "https://evil.com",
                    ),
                );
                match connect_safe(&target, _client, request).await {
                    Ok((mut ws, _)) => {
                        endpoint_tested = true;
                        if bounded(ws.send(Message::Text(join_frame(
                            self.sessions.user_a.as_deref(),
                            "cswsh",
                        ))))
                        .await
                        .is_err()
                        {
                            endpoint_failed = true;
                        } else {
                            match wait_reply(&mut ws, self.timeout).await {
                                JoinOutcome::NoReply => endpoint_failed = true,
                                JoinOutcome::Acked | JoinOutcome::Broadcast => {
                                    findings.push(ProofGate::admit(Evidence::WebSocketCswh {
                                        endpoint: url.to_string(),
                                    })?);
                                }
                                JoinOutcome::Rejected => {}
                            }
                        }
                    }
                    Err(_) => endpoint_failed = true,
                }
            } else {
                endpoint_failed = true;
            }
            if endpoint_failed {
                self.coverage
                    .endpoint_at(url.as_str(), riftlock_core::EndpointOutcome::Failed);
                let _ = check.finish(riftlock_core::CheckState::Inconclusive);
            } else if endpoint_tested {
                self.coverage
                    .endpoint_at(url.as_str(), riftlock_core::EndpointOutcome::Tested);
                let _ = check.finish(riftlock_core::CheckState::Completed);
            } else {
                self.coverage
                    .endpoint_at(url.as_str(), riftlock_core::EndpointOutcome::Skipped);
                let _ = check.finish(riftlock_core::CheckState::Completed);
            }
            all_findings.extend(findings);
        }
        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realtime_paths_match() {
        assert!(is_realtime_path("/realtime/v1/websocket"));
        assert!(is_realtime_path("/socket/ws"));
        assert!(!is_realtime_path("/rest/v1/users"));
        assert!(!is_realtime_path("/"));
    }

    #[test]
    fn ws_url_swaps_scheme_and_keeps_host_port_path() {
        let https = Url::parse("https://x.example:8080/realtime/v1/websocket").expect("url");
        assert_eq!(
            ws_url(&https).expect("ws").as_str(),
            "wss://x.example:8080/realtime/v1/websocket"
        );
        let ftp = Url::parse("ftp://x.example/ws").expect("url");
        assert!(matches!(ws_url(&ftp), Err(ScanError::InvalidUrl)));
    }

    #[test]
    fn join_frame_carries_token_when_present_and_empty_payload_otherwise() {
        let authed = join_frame(Some("tok"), "1");
        assert!(authed.contains("\"access_token\":\"tok\""));
        assert!(authed.contains("\"event\":\"phx_join\""));
        let plain = join_frame(None, "2");
        assert!(!plain.contains("access_token"));
    }

    #[test]
    fn classify_reads_phoenix_replies_and_broadcasts() {
        assert_eq!(
            classify(r#"{"topic":"realtime","event":"phx_reply","payload":{"status":"ok"}}"#),
            Some(JoinOutcome::Acked)
        );
        assert_eq!(
            classify(r#"{"topic":"realtime","event":"phx_reply","payload":{"status":"error"}}"#),
            Some(JoinOutcome::Rejected)
        );
        assert_eq!(
            classify(r#"{"topic":"realtime","event":"broadcast","payload":{},"ref":null}"#),
            Some(JoinOutcome::Broadcast)
        );
        assert_eq!(classify("not json"), None);
    }

    /// A local realtime server that handles `connections` sequential joins:
    /// the token-bearing ones always succeed; unauthenticated joins are
    /// accepted only when `unauth_ok`, else rejected with `status: error`.
    /// Every handshake is accepted regardless of Origin (CSWSH-positive).
    async fn spawn_server(unauth_ok: bool) -> Url {
        spawn_server_n(unauth_ok, 2).await
    }

    async fn spawn_server_n(unauth_ok: bool, connections: usize) -> Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            for _ in 0..connections {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let frame = loop {
                    match ws.next().await {
                        Some(Ok(Message::Text(t))) => break t,
                        Some(Ok(_)) => continue,
                        _ => return,
                    }
                };
                let join: serde_json::Value = serde_json::from_str(&frame).expect("json");
                let authed = join.pointer("/payload/access_token").is_some();
                let status = if authed || unauth_ok { "ok" } else { "error" };
                let reply = serde_json::json!({
                    "topic": join["topic"],
                    "event": "phx_reply",
                    "payload": { "status": status },
                    "ref": join["ref"],
                });
                if ws.send(Message::Text(reply.to_string())).await.is_err() {
                    return;
                }
                // Hold the socket open until the client hangs up.
                while let Some(Ok(_)) = ws.next().await {}
            }
        });
        Url::parse(&format!("http://{addr}/realtime/v1/websocket")).expect("url")
    }

    async fn scan_with(
        url: &Url,
        sessions: SessionMatrix,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        let scanner = WebSocketScanner {
            sessions,
            timeout: Duration::from_millis(300),
            ..Default::default()
        };
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        Scanner::scan(&scanner, url, &Client::new_lab(), &guard, passive).await
    }

    /// Scan a root start URL, feeding `endpoints` as the discovered
    /// inventory rather than relying on the start path matching.
    async fn scan_from_root(
        start: &Url,
        endpoints: Vec<String>,
        sessions: SessionMatrix,
    ) -> (Vec<Finding>, Coverage) {
        let coverage = Coverage::default();
        let scanner = WebSocketScanner {
            sessions,
            endpoints,
            timeout: Duration::from_millis(300),
            coverage: coverage.clone(),
        };
        let guard = ScopeGuard::new_lab(&[start.as_str()]).expect("guard");
        let findings = Scanner::scan(&scanner, start, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        (findings, coverage)
    }

    #[tokio::test]
    async fn scan_proves_desync_when_unauth_join_is_accepted() {
        // 3 connections: baseline, revocation, CSWSH probe.
        let url = spawn_server_n(true, 3).await;
        let sessions = SessionMatrix {
            user_a: Some("token-a".into()),
            ..SessionMatrix::default()
        };
        let findings = scan_with(&url, sessions, false).await.expect("scan");
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(matches!(
            findings[0].evidence(),
            Evidence::WebSocketDesync { endpoint } if endpoint == url.as_str()
        ));
        assert!(matches!(
            findings[1].evidence(),
            Evidence::WebSocketCswh { endpoint } if endpoint == url.as_str()
        ));
    }

    #[tokio::test]
    async fn scan_proves_cswsh_without_desync() {
        // Joins are origin-agnostic here: the evil-Origin handshake is
        // accepted AND answered even though unauthenticated joins fail.
        let url = spawn_server_n(false, 3).await;
        let sessions = SessionMatrix {
            user_a: Some("token-a".into()),
            ..SessionMatrix::default()
        };
        let findings = scan_with(&url, sessions, false).await.expect("scan");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(matches!(
            findings[0].evidence(),
            Evidence::WebSocketCswh { endpoint } if endpoint == url.as_str()
        ));
    }

    #[tokio::test]
    async fn scan_negative_when_spoofed_handshake_is_never_answered() {
        // A 101 that is accepted but never speaks is below the proof bar.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                if let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await {
                    // Consume but never reply.
                    while let Some(Ok(_)) = ws.next().await {}
                }
            }
        });
        let url = Url::parse(&format!("http://{addr}/realtime/v1/websocket")).expect("url");
        let coverage = Coverage::default();
        let scanner = WebSocketScanner {
            timeout: Duration::from_millis(100),
            coverage: coverage.clone(),
            ..Default::default()
        };
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let findings = Scanner::scan(&scanner, &url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty(), "{findings:?}");
        let snapshot = coverage.snapshot(1);
        assert_eq!(snapshot.endpoints_failed, 1);
        assert_eq!(snapshot.vulnerability_checks_attempted, 1);
        assert_eq!(snapshot.vulnerability_checks_completed, 0);
        assert_eq!(snapshot.vulnerability_checks_inconclusive, 1);
        assert!(snapshot.check_accounting_invariant());
        assert!(coverage.finalize().reconciles());
    }

    #[tokio::test]
    async fn scan_negative_when_unauth_join_is_rejected() {
        // Only 2 connections: the CSWSH probe finds the server closed.
        let url = spawn_server_n(false, 2).await;
        let sessions = SessionMatrix {
            user_a: Some("token-a".into()),
            ..SessionMatrix::default()
        };
        let findings = scan_with(&url, sessions, false).await.expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_cswh_is_independent_of_sessions() {
        // No user_a: the desync is unprovable, but the CSWSH probe needs
        // no session at all — it runs and proves the open origin.
        let url = spawn_server(true).await;
        let findings = scan_with(&url, SessionMatrix::default(), false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(matches!(
            findings[0].evidence(),
            Evidence::WebSocketCswh { .. }
        ));
    }

    #[tokio::test]
    async fn scan_negative_in_passive_mode() {
        let url = spawn_server(true).await;
        let sessions = SessionMatrix {
            user_a: Some("token-a".into()),
            ..SessionMatrix::default()
        };
        let findings = scan_with(&url, sessions, true).await.expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_when_endpoint_unreachable() {
        // Bind, capture the port, then drop the listener: guaranteed refusal.
        let addr = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            listener.local_addr().expect("addr")
        };
        let url = Url::parse(&format!("http://{addr}/realtime/v1/websocket")).expect("url");
        let sessions = SessionMatrix {
            user_a: Some("token-a".into()),
            ..SessionMatrix::default()
        };
        let findings = scan_with(&url, sessions, false).await.expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_probes_a_discovered_realtime_route_from_root() {
        // The explicit provider must probe discovered routes even when the
        // start URL is `/` — the root path itself never matches.
        let url = spawn_server_n(true, 3).await;
        let root = Url::parse(&format!("{}/", url.origin().ascii_serialization())).expect("root");
        let sessions = SessionMatrix {
            user_a: Some("token-a".into()),
            ..SessionMatrix::default()
        };
        let (findings, coverage) =
            scan_from_root(&root, vec!["/realtime/v1/websocket".to_owned()], sessions).await;
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(matches!(
            findings[0].evidence(),
            Evidence::WebSocketDesync { endpoint } if endpoint == url.as_str()
        ));
        assert!(matches!(
            findings[1].evidence(),
            Evidence::WebSocketCswh { endpoint } if endpoint == url.as_str()
        ));
        let snapshot = coverage.snapshot(1);
        assert_eq!(snapshot.endpoints_tested_successfully, 1);
        assert_eq!(snapshot.vulnerability_checks_attempted, 1);
        assert!(snapshot.check_accounting_invariant());
    }

    #[tokio::test]
    async fn scan_negative_skips_an_out_of_scope_discovered_route() {
        let url = spawn_server(true).await;
        let root = Url::parse(&format!("{}/", url.origin().ascii_serialization())).expect("root");
        let (findings, coverage) = scan_from_root(
            &root,
            vec!["http://other.example/realtime/v1/websocket".to_owned()],
            SessionMatrix {
                user_a: Some("token-a".into()),
                ..SessionMatrix::default()
            },
        )
        .await;
        assert!(findings.is_empty(), "{findings:?}");
        // Never connected: no check was begun for the out-of-scope host.
        assert_eq!(coverage.snapshot(0).vulnerability_checks_attempted, 0);
    }

    #[tokio::test]
    async fn scan_negative_on_non_realtime_path() {
        let url = spawn_server(true).await;
        let url = Url::parse(&format!(
            "{}/rest/v1/users",
            url.origin().ascii_serialization()
        ))
        .expect("url");
        let sessions = SessionMatrix {
            user_a: Some("token-a".into()),
            ..SessionMatrix::default()
        };
        let findings = scan_with(&url, sessions, false).await.expect("scan");
        assert!(findings.is_empty());
    }
}
