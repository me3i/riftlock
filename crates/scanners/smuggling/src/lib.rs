//! HTTP request-smuggling scanner: sends a raw HTTP/1.1 request with
//! conflicting framing headers (`Content-Length` + `Transfer-Encoding`) and
//! judges the server's handling by its raw response.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{Coverage, Evidence, Finding, ProofGate, ScanError, Scanner, ScopeGuard};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

/// How the target server handled the malformed framing request.
#[derive(Debug, PartialEq, Eq)]
enum ProbeOutcome {
    /// No bytes within the deadline: the front-end is waiting on the other
    /// framing interpretation (the classic CL.TE desync hang).
    Hang,
    /// The connection closed without a response.
    Closed,
    /// Raw response bytes (status line + headers + body).
    Response(Vec<u8>),
    /// Name resolution, connect, or write failed before a response arrived.
    Failed,
}

/// The smuggling scanner. Two probes against the target itself, one per
/// desync direction, both `POST`s carrying conflicting framings:
///
/// - CL.TE: `Content-Length: 6` + a chunked body that ends after the
///   zero-length chunk — a server trusting Content-Length hangs waiting for
///   the 6th byte.
/// - TE.CL: the chunked body announces its terminating zero chunk but omits
///   the CRLF that closes it, while `Content-Length: 7` completes the body —
///   a server trusting Transfer-Encoding hangs waiting for the terminator.
///
/// How the server resolves the disagreement is the proof.
///
/// Raw-socket TLS is not implemented, so `https` targets cannot be assessed
/// by this scanner and are recorded as failed/inconclusive.
#[derive(Debug)]
pub struct SmugglingScanner {
    /// Response deadline for the probe. The default (2s) is the hang
    /// threshold; tests shorten it so the hang branch stays fast.
    pub read_timeout: Duration,
    /// Shared coverage counters for raw-protocol probe outcomes.
    pub coverage: Coverage,
}

impl Default for SmugglingScanner {
    fn default() -> Self {
        Self {
            read_timeout: Duration::from_secs(2),
            coverage: Coverage::default(),
        }
    }
}

/// The malformed CL.TE request: `Content-Length: 6` claims 6 body bytes, the
/// chunked body ends after a 0-length chunk (5 bytes) — the framings
/// disagree on where the request ends.
fn smuggle_request(authority: &str, path: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: 6\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         0\r\n\r\n"
    )
    .into_bytes()
}

/// The TE.CL probe: the chunked framing is incomplete (`0` chunk without its
/// terminating CRLF) while `Content-Length: 7` exactly matches the 7 body
/// bytes — the inverse disagreement of [`smuggle_request`].
fn te_cl_request(authority: &str, path: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: 7\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         1\r\nA\r\n0"
    )
    .into_bytes()
}

/// Deadline for the TCP connect and the request write: a filtered port or a
/// black-holed connection must cost the probe one deadline, never the OS's
/// unbounded SYN retransmission window.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Send the malformed request and classify the handling.
///
/// # Errors
/// Write or read failures. A refused connection is a checked negative
/// (`Closed`), not a transport abort — an unreachable target must not kill
/// the whole scan.
async fn probe(
    host: &str,
    port: u16,
    client: &Client,
    request: &[u8],
    read_timeout: Duration,
) -> Result<ProbeOutcome, ScanError> {
    let addresses =
        match tokio::time::timeout(CONNECT_TIMEOUT, client.lookup_host(host, port)).await {
            Ok(Ok(addrs)) => addrs,
            _ => return Ok(ProbeOutcome::Failed),
        };
    let mut stream =
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addresses.as_slice())).await
        {
            Ok(Ok(s)) => s,
            _ => return Ok(ProbeOutcome::Failed),
        };
    match tokio::time::timeout(CONNECT_TIMEOUT, stream.write_all(request)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => return Ok(ProbeOutcome::Failed),
    }
    const MAX_RESPONSE_BYTES: usize = 8192;
    let deadline = tokio::time::Instant::now() + read_timeout;
    let mut chunk = [0u8; 2048];
    let mut response = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Err(_) if response.is_empty() => return Ok(ProbeOutcome::Hang),
            Err(_) => return Ok(ProbeOutcome::Response(response)),
            Ok(Err(_)) => return Ok(ProbeOutcome::Failed),
            Ok(Ok(0)) if response.is_empty() => return Ok(ProbeOutcome::Closed),
            Ok(Ok(0)) => return Ok(ProbeOutcome::Response(response)),
            Ok(Ok(n)) => {
                response.extend_from_slice(&chunk[..n]);
                if response.len() >= MAX_RESPONSE_BYTES {
                    return Ok(ProbeOutcome::Response(response));
                }
            }
        }
    }
}

/// Whether a raw response proves the server mishandled the conflicting
/// framing: a 400/501 that *references* one of the conflicting headers (the
/// server saw both framings and told us so). A generic 400, a 200, or any
/// other status is a checked negative — not evidence.
fn is_smuggling_response(resp: &[u8]) -> bool {
    let text = String::from_utf8_lossy(resp);
    let Some(status) = text.split_whitespace().nth(1) else {
        return false;
    };
    (status == "400" || status == "501")
        && (text.contains("Content-Length") || text.contains("Transfer-Encoding"))
}

impl Scanner for SmugglingScanner {
    fn id(&self) -> &'static str {
        "smuggling"
    }

    fn matches(&self, _url: &Url) -> bool {
        // Any HTTP server can be framed wrongly.
        true
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
        // Raw sockets cannot speak TLS; don't treat the silent TLS handshake
        // as evidence or a clean negative.
        let check = self.coverage.begin_check();
        if url.scheme() != "http" {
            self.coverage
                .endpoint_at(url.as_str(), riftlock_core::EndpointOutcome::Failed);
            let _ = check.finish(riftlock_core::CheckState::Inconclusive);
            return Ok(Vec::new());
        }
        let host = url.host_str().ok_or(ScanError::InvalidUrl)?;
        let port = url.port_or_known_default().ok_or(ScanError::InvalidUrl)?;
        let path = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        };
        let authority = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_owned(),
        };
        // One probe per desync direction; the evidence fields do not carry
        // the variant, so the first proof wins and we stop there.
        for request in [
            smuggle_request(&authority, &path),
            te_cl_request(&authority, &path),
        ] {
            let outcome = match probe(host, port, _client, &request, self.read_timeout).await {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.coverage
                        .endpoint_at(url.as_str(), riftlock_core::EndpointOutcome::Failed);
                    let _ = check.finish(riftlock_core::CheckState::Inconclusive);
                    return Err(error);
                }
            };
            if outcome == ProbeOutcome::Failed {
                self.coverage
                    .endpoint_at(url.as_str(), riftlock_core::EndpointOutcome::Failed);
                let _ = check.finish(riftlock_core::CheckState::Inconclusive);
                return Ok(Vec::new());
            }
            let smuggled = match &outcome {
                ProbeOutcome::Hang => true,
                ProbeOutcome::Response(resp) => is_smuggling_response(resp),
                ProbeOutcome::Closed | ProbeOutcome::Failed => false,
            };
            if smuggled {
                self.coverage
                    .endpoint_at(url.as_str(), riftlock_core::EndpointOutcome::Tested);
                let _ = check.finish(riftlock_core::CheckState::Completed);
                return Ok(vec![ProofGate::admit(Evidence::HttpSmuggling {
                    endpoint: url.to_string(),
                    method: "POST".to_owned(),
                })?]);
            }
        }
        self.coverage
            .endpoint_at(url.as_str(), riftlock_core::EndpointOutcome::Tested);
        let _ = check.finish(riftlock_core::CheckState::Completed);
        Ok(Vec::new())
    }
}

// The Scanner trait hands us a reqwest client; the raw-TCP probe does not
// use it, but tests build one to satisfy the signature.

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw TCP test server: reads the request, then either stays silent
    /// (hang), closes, or answers with `response`.
    async fn spawn_server(response: Option<&'static [u8]>) -> Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await;
                match response {
                    Some(bytes) => {
                        let _ = socket.write_all(bytes).await;
                    }
                    None => tokio::time::sleep(Duration::from_secs(30)).await,
                }
            }
        });
        Url::parse(&format!("http://{addr}")).expect("url")
    }

    #[test]
    fn request_carries_both_framings_and_a_zero_chunk() {
        let req = String::from_utf8(smuggle_request("h:80", "/")).expect("utf8");
        assert!(req.contains("Content-Length: 6"));
        assert!(req.contains("Transfer-Encoding: chunked"));
        assert!(req.ends_with("0\r\n\r\n"));
    }

    #[test]
    fn te_cl_request_differs_from_cl_te_and_is_incomplete_under_chunked() {
        let req = String::from_utf8(te_cl_request("h:80", "/")).expect("utf8");
        assert!(req.contains("Content-Length: 7"));
        assert!(req.contains("Transfer-Encoding: chunked"));
        // The terminating zero chunk has no closing CRLF, so a server that
        // trusts Transfer-Encoding keeps waiting.
        assert!(req.ends_with("1\r\nA\r\n0"));
        assert_ne!(smuggle_request("h:80", "/"), te_cl_request("h:80", "/"));
    }

    #[test]
    fn response_proof_only_when_status_references_the_conflict() {
        let proving =
            b"HTTP/1.1 400 Bad Request\r\n\r\nboth Content-Length and Transfer-Encoding given"
                .as_slice();
        assert!(is_smuggling_response(proving));
        // Generic 400 without a header reference: checked negative.
        assert!(!is_smuggling_response(
            b"HTTP/1.1 400 Bad Request\r\n\r\nbad request"
        ));
        // Any other status: checked negative.
        assert!(!is_smuggling_response(b"HTTP/1.1 200 OK\r\n\r\nok"));
        assert!(!is_smuggling_response(b"garbage"));
    }

    #[tokio::test]
    async fn scan_proves_hang_on_conflicting_framing() {
        // Vulnerable front-end: waits on the Content-Length framing that
        // never completes — the probe times out.
        let url = spawn_server(None).await;
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let scanner = SmugglingScanner {
            read_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::HttpSmuggling { endpoint, method }
                if endpoint == url.as_str() && method == "POST"
        ));
    }

    #[tokio::test]
    async fn scan_proves_400_referencing_conflict() {
        let url = spawn_server(Some(
            b"HTTP/1.1 400 Bad Request\r\n\r\nTransfer-Encoding and Content-Length conflict",
        ))
        .await;
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let scanner = SmugglingScanner {
            read_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn scan_proves_te_cl_when_chunked_terminator_is_missing() {
        // A TE-trusting server: hangs when the chunked body lacks its
        // terminating CRLF (the TE.CL probe), answers 200 otherwise — so
        // only the second probe in the scan can prove the desync.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            // Both probes connect in sequence; keep accepting for both.
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                if buf[..n].ends_with(b"0") {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                } else {
                    let _ = socket.write_all(b"HTTP/1.1 200 OK\r\n\r\nok").await;
                }
            }
        });
        let url = Url::parse(&format!("http://{addr}")).expect("url");
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let scanner = SmugglingScanner {
            read_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::HttpSmuggling { .. }
        ));
    }

    #[tokio::test]
    async fn scan_negative_on_clean_rejection() {
        // Correctly implemented server: answers a generic 400 fast.
        let url = spawn_server(Some(b"HTTP/1.1 400 Bad Request\r\n\r\nbad")).await;
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let scanner = SmugglingScanner {
            read_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_when_server_closes() {
        let url = spawn_server(Some(b"")).await;
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let scanner = SmugglingScanner {
            read_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_negative_when_target_unreachable() {
        // Bind, capture the port, then drop the listener: guaranteed refusal.
        let addr = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            listener.local_addr().expect("addr")
        };
        let url = Url::parse(&format!("http://{addr}")).expect("url");
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let coverage = Coverage::default();
        let scanner = SmugglingScanner {
            read_timeout: Duration::from_millis(100),
            coverage: coverage.clone(),
        };
        let findings = Scanner::scan(&scanner, &url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        let snapshot = coverage.snapshot(1);
        assert_eq!(snapshot.endpoints_failed, 1);
        assert_eq!(snapshot.vulnerability_checks_attempted, 1);
        assert_eq!(snapshot.vulnerability_checks_inconclusive, 1);
    }

    #[tokio::test]
    async fn https_target_is_unassessed_not_a_clean_negative() {
        let url = Url::parse("https://localhost/").expect("url");
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let coverage = Coverage::default();
        let scanner = SmugglingScanner {
            coverage: coverage.clone(),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        let snapshot = coverage.snapshot(1);
        assert_eq!(snapshot.endpoints_failed, 1);
        assert_eq!(snapshot.vulnerability_checks_attempted, 1);
        assert_eq!(snapshot.vulnerability_checks_inconclusive, 1);
        assert_eq!(snapshot.endpoints_tested_successfully, 0);
    }

    #[tokio::test]
    async fn scan_negative_in_passive_mode() {
        let url = spawn_server(Some(b"HTTP/1.1 200 OK\r\n\r\nok")).await;
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let findings = Scanner::scan(
            &SmugglingScanner::default(),
            &url,
            &Client::new_lab(),
            &guard,
            true,
        )
        .await
        .expect("scan");
        assert!(findings.is_empty());
    }
}
