//! TLS/header/CORS/cookie misconfiguration scanner: one GET with a foreign
//! `Origin` and the response headers are the evidence — no payload probing.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    Coverage, EndpointOutcome, Evidence, Finding, ProofGate, ScanError, Scanner, ScopeGuard,
};
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

/// At most five endpoint checks wait on network I/O simultaneously.
const ENDPOINT_CONCURRENCY: usize = 5;
/// Probe the root plus a bounded sample; large crawler inventories are not
/// additional evidence for host-wide header policy and can exhaust run budgets.
/// The scanned root counts as one, so at most nine discovered paths are probed.
const MAX_PROBED_ENDPOINTS: usize = 10;
/// Every fetch, including the CORS bypass probes, gets its own budget so one
/// slow route cannot hold the engine hostage.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Whether `acao` names the foreign origin we sent (or a spelling of it), so
/// the allow-list deserves the extra bypass probes. Wildcards and unrelated
/// allow-listed origins are fully classified by the first request.
fn reflects_foreign_origin(acao: Option<&str>) -> bool {
    acao.map(str::trim)
        .map(str::to_ascii_lowercase)
        .is_some_and(|value| {
            value == "https://evil.com" || value == "evil.com" || value.ends_with(".evil.com")
        })
}

/// The misconfiguration scanner. Probes the scanned URL and a bounded sample
/// of discovered endpoints with a GET carrying `Origin: https://evil.com`, and
/// reads each response's security headers, CORS policy and cookie flags. The caller
/// supplies the shared HTTP client, so its redirect policy applies; the CLI
/// disables redirects to preserve ScopeGuard.
#[derive(Debug, Default)]
pub struct MisconfigScanner {
    /// Discovered endpoints to probe in addition to the scanned URL.
    pub endpoints: Vec<String>,
    /// Shared run ledger. Failed and timed-out probes are recorded here so the
    /// untested surface names them instead of dropping them silently.
    pub coverage: Coverage,
}

/// Why one endpoint produced no findings. Timeouts are separated from other
/// failures because the coverage report classifies them differently.
#[derive(Debug)]
enum ProbeFailure {
    TimedOut,
    Failed(ScanError),
}

impl From<ScanError> for ProbeFailure {
    fn from(error: ScanError) -> Self {
        if error.is_timeout() {
            Self::TimedOut
        } else {
            Self::Failed(error)
        }
    }
}

/// One header-misconfiguration issue found in a response.
struct Issue {
    issue: &'static str,
    severity: &'static str,
}

/// CORS issue for one probe, named by how the allow-list check was bypassed.
fn cors_issues(origin: &str, probe: &str, acao: Option<&str>, acac: bool) -> Vec<Issue> {
    let severity = if acac { "High" } else { "Medium" };
    let Some(acao) = acao.map(str::trim).filter(|value| !value.is_empty()) else {
        return Vec::new();
    };
    let acao_lower = acao.to_ascii_lowercase();
    // The wildcard probe runs once; repeating it per bypass adds no evidence.
    if acao_lower == "*" {
        return if probe == "reflect" {
            vec![Issue {
                issue: if acac {
                    "cors_wildcard_credentials"
                } else {
                    "cors_wildcard"
                },
                severity: "Low",
            }]
        } else {
            Vec::new()
        };
    }
    // Compare hosts so `evil.com` and `https://EVIL.COM` both count as our
    // origin. A `.` suffix match is the server's own allow-list extension.
    let host_of = |value: &str| {
        value
            .strip_prefix("https://")
            .or_else(|| value.strip_prefix("http://"))
            .unwrap_or(value)
            .trim_end_matches('/')
            .to_owned()
    };
    let origin_lower = origin.to_ascii_lowercase();
    let origin_host = host_of(&origin_lower);
    let acao_host = host_of(&acao_lower);
    let names_origin = acao_lower == origin_lower
        || acao_host == origin_host
        || acao_host
            .strip_prefix(&format!("{origin_host}."))
            .is_some()
        // Hosts we injected regardless of which probe they were sent with.
        || acao_host.ends_with("evil.com");
    if !names_origin {
        return Vec::new();
    }
    let issue = if probe == "null" && acao_lower == "null" {
        "cors_null_origin"
    } else if acao_host != origin_host && acao_host.starts_with(&format!("{origin_host}.")) {
        "cors_suffix_match"
    } else {
        match probe {
            "null" => "cors_null_origin",
            "suffix" => "cors_suffix_match",
            "prefix" => "cors_prefix_match",
            "downgrade" => "cors_protocol_downgrade",
            _ if acac => "cors_reflect_credentials",
            _ => "cors_reflect",
        }
    };
    vec![Issue { issue, severity }]
}

/// Classify the response headers of `resp` into misconfiguration issues.
// `origin` and `probe` identify the CORS request that produced `acao`.
// Each flag is one boolean header fact; a struct would just rename them.
#[allow(clippy::too_many_arguments)]
fn classify(
    scheme: &str,
    origin: &str,
    probe: &str,
    acao: Option<&str>,
    acac: bool,
    hsts: bool,
    csp: bool,
    xfo: bool,
    xcto: bool,
    referrer: bool,
    permissions: bool,
    cookies: &[&str],
) -> Vec<Issue> {
    let mut out = Vec::new();
    // HSTS only exists on TLS responses; flagging it on http is noise.
    if scheme == "https" && !hsts {
        out.push(Issue {
            issue: "missing_hsts",
            severity: "Low",
        });
    }
    if !csp {
        out.push(Issue {
            issue: "missing_csp",
            severity: "Medium",
        });
    }
    if !xfo {
        out.push(Issue {
            issue: "missing_xfo",
            severity: "Low",
        });
    }
    if !xcto {
        out.push(Issue {
            issue: "missing_x_content_type_options",
            severity: "Low",
        });
    }
    if !referrer {
        out.push(Issue {
            issue: "missing_referrer_policy",
            severity: "Low",
        });
    }
    if !permissions {
        out.push(Issue {
            issue: "missing_permissions_policy",
            severity: "Low",
        });
    }
    // A wildcard origin blocks credentialed requests in every browser, so
    // ACAC:true is misleading config, not exposed credentials (Low). Only the
    // reflective variants can leak credentials (High).
    out.extend(cors_issues(origin, probe, acao, acac));
    for cookie in cookies {
        let lower = cookie.to_ascii_lowercase();
        let lacks_secure = !lower
            .split(';')
            .any(|a| a.trim().eq_ignore_ascii_case("secure"));
        let lacks_httponly = !lower
            .split(';')
            .any(|a| a.trim().eq_ignore_ascii_case("httponly"));
        if lacks_secure || lacks_httponly {
            out.push(Issue {
                issue: "cookie_insecure",
                severity: "Medium",
            });
        }
    }
    out
}

impl Scanner for MisconfigScanner {
    fn id(&self) -> &'static str {
        "misconfig"
    }

    fn matches(&self, _url: &Url) -> bool {
        // Header/CORS/cookie checks apply to every HTTP host.
        true
    }

    async fn scan(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        _passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        // Header, CORS and cookie checks are passive GET observations, so
        // Normal depth runs them too. A timed-out root is negative space, not a
        // reason to abandon the rest of the sample; other failures still abort.
        let mut findings = match probe_target(url, client, guard).await {
            Ok(found) => found,
            Err(ProbeFailure::TimedOut) => {
                self.coverage
                    .endpoint_at(url.as_str(), EndpointOutcome::TimedOut);
                Vec::new()
            }
            Err(ProbeFailure::Failed(error)) => {
                self.coverage
                    .endpoint_at(url.as_str(), EndpointOutcome::Failed);
                return Err(error);
            }
        };
        let mut seen = HashSet::new();
        let mut reported: HashSet<String> = findings
            .iter()
            .filter_map(|finding| match finding.evidence() {
                Evidence::SecurityMisconfiguration { url, issue, .. } => {
                    let domain = Url::parse(url).ok()?.host_str()?.to_ascii_lowercase();
                    Some(format!("{issue}:{domain}"))
                }
                _ => None,
            })
            .collect();
        seen.insert(url.to_string());
        let mut targets = Vec::new();
        for endpoint in &self.endpoints {
            let Ok(target) = url.join(endpoint) else {
                continue;
            };
            if !seen.insert(target.to_string()) {
                continue;
            }
            // A discovered endpoint outside the run's scope is not this
            // engine's to probe; another engine owns its disposition.
            if guard.check_active(&target).is_err() {
                continue;
            }
            targets.push(target);
            // The scanned root already accounts for one of the total probes.
            if targets.len() == MAX_PROBED_ENDPOINTS - 1 {
                break;
            }
        }

        // Header policy is primarily host-wide, while CORS can vary by route.
        // Probe at most a small, stable sample of unique in-scope paths. The
        // shared client carries the run's transport configuration; bounded
        // concurrency limits latency within that sample. A dead endpoint must
        // never discard findings from the healthy ones.
        let mut pending = targets.into_iter();
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            while tasks.len() < ENDPOINT_CONCURRENCY {
                let Some(target) = pending.next() else {
                    break;
                };
                let client = client.clone();
                let guard = guard.clone();
                tasks.spawn(async move {
                    let result = probe_target(&target, &client, &guard).await;
                    (target, result)
                });
            }
            let Some(joined) = tasks.join_next().await else {
                break;
            };
            let Ok((target, result)) = joined else {
                continue;
            };
            let found = match result {
                Ok(found) => found,
                Err(ProbeFailure::TimedOut) => {
                    self.coverage
                        .endpoint_at(target.as_str(), EndpointOutcome::TimedOut);
                    continue;
                }
                Err(ProbeFailure::Failed(_)) => {
                    self.coverage
                        .endpoint_at(target.as_str(), EndpointOutcome::Failed);
                    continue;
                }
            };
            for finding in found {
                if let Evidence::SecurityMisconfiguration { issue, url, .. } = finding.evidence() {
                    let domain = Url::parse(url)
                        .ok()
                        .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase));
                    if domain.is_some_and(|domain| reported.insert(format!("{issue}:{domain}"))) {
                        findings.push(finding);
                    }
                } else {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}

async fn probe_target(
    url: &Url,
    client: &Client,
    guard: &ScopeGuard,
) -> Result<Vec<Finding>, ProbeFailure> {
    guard
        .check_active(url)
        .map_err(|error| ProbeFailure::Failed(ScanError::from(error)))?;
    let resp = match tokio::time::timeout(
        PROBE_TIMEOUT,
        client
            .get(url.clone())
            .header("origin", "https://evil.com")
            .send(),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => return Err(ProbeFailure::TimedOut),
    };
    let headers = resp.headers();
    let acao = headers
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    let acac = headers
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let cookies: Vec<&str> = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    // Presence with a non-empty value; absent or empty counts as missing.
    let present = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| !v.trim().is_empty())
    };
    let mut issues = classify(
        url.scheme(),
        "https://evil.com",
        "reflect",
        acao,
        acac,
        headers.contains_key("strict-transport-security"),
        headers.contains_key("content-security-policy"),
        headers.contains_key("x-frame-options"),
        present("x-content-type-options"),
        present("referrer-policy"),
        present("permissions-policy"),
        &cookies,
    );
    // Each bypass pattern is its own allow-list mistake, so probe it with the
    // origin that pattern would wrongly accept. Only a route that echoes a
    // foreign origin on the first request can have a bypassable allow-list;
    // spending four more requests on every route made a 300-endpoint run a
    // 1,500-request scan instead of a 300-request one.
    if reflects_foreign_origin(acao) {
        let host = url.host_str().unwrap_or_default();
        let probes = [
            ("null", "null".to_string()),
            ("suffix", format!("https://evil.com.{host}")),
            ("prefix", format!("https://{host}.evil.com")),
            ("downgrade", format!("http://{host}")),
        ];
        for (probe, origin) in probes {
            // An http origin is not a downgrade from an http target.
            if probe == "downgrade" && url.scheme() != "https" {
                continue;
            }
            // A bypass probe that stalls or fails adds no evidence; keep the
            // baseline issues rather than failing the whole endpoint.
            let resp = match tokio::time::timeout(
                PROBE_TIMEOUT,
                client.get(url.clone()).header("origin", &origin).send(),
            )
            .await
            {
                Ok(Ok(resp)) => resp,
                Ok(Err(_)) | Err(_) => break,
            };
            let headers = resp.headers();
            let acao = headers
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok())
                .map(str::trim);
            let acac = headers
                .get("access-control-allow-credentials")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("true"));
            issues.extend(cors_issues(&origin, probe, acao, acac));
        }
    }
    issues
        .into_iter()
        .map(|i| {
            ProofGate::admit(Evidence::SecurityMisconfiguration {
                url: url.to_string(),
                issue: i.issue.to_string(),
                severity: i.severity.to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ProbeFailure::Failed(ScanError::from(error)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_headers_yield_no_issues() {
        let issues = classify(
            "https",
            "https://evil.com",
            "reflect",
            None,
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            &["sid=abc; Secure; HttpOnly; SameSite=Lax"],
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn missing_headers_and_insecure_cookie_are_flagged() {
        let issues = classify(
            "https",
            "https://evil.com",
            "reflect",
            None,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            &["sid=abc; Path=/"],
        );
        let kinds: Vec<_> = issues.iter().map(|i| i.issue).collect();
        assert_eq!(
            kinds,
            [
                "missing_hsts",
                "missing_csp",
                "missing_xfo",
                "missing_x_content_type_options",
                "missing_referrer_policy",
                "missing_permissions_policy",
                "cookie_insecure"
            ]
        );
    }

    #[test]
    fn reflecting_cors_with_credentials_is_high() {
        let issues = classify(
            "https",
            "https://evil.com",
            "reflect",
            Some("https://evil.com"),
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            &[],
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].issue, "cors_reflect_credentials");
        assert_eq!(issues[0].severity, "High");
    }

    #[test]
    fn wildcard_cors_with_credentials_is_not_credentialed_exposure() {
        // Browsers refuse credentialed wildcard requests, so the ACAC flag
        // adds no impact over a plain wildcard: named, but not High.
        let issues = classify(
            "https",
            "https://evil.com",
            "reflect",
            Some("*"),
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            &[],
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].issue, "cors_wildcard_credentials");
        assert_eq!(issues[0].severity, "Low");
    }

    #[test]
    fn cors_without_credentials_is_downgraded() {
        // Wildcard without credentials is a Low hygiene note; the reflective
        // origin without credentials is a Medium (foreign origin echoed).
        let wildcard = classify(
            "https",
            "https://evil.com",
            "reflect",
            Some("*"),
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            &[],
        );
        assert_eq!(wildcard[0].issue, "cors_wildcard");
        assert_eq!(wildcard[0].severity, "Low");
        let reflect = classify(
            "https",
            "https://evil.com",
            "reflect",
            Some("https://evil.com"),
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            &[],
        );
        assert_eq!(reflect[0].issue, "cors_reflect");
        assert_eq!(reflect[0].severity, "Medium");
    }

    #[test]
    fn uncontrolled_origin_is_not_a_finding() {
        // A third-party origin value is the server's own allowlist, not ours.
        assert!(classify(
            "https",
            "https://evil.com",
            "reflect",
            Some("https://app.example.com"),
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            &[]
        )
        .is_empty());
    }

    #[test]
    fn hsts_is_not_flagged_on_plain_http() {
        assert!(!classify(
            "http",
            "https://evil.com",
            "reflect",
            None,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            &[]
        )
        .iter()
        .any(|i| i.issue == "missing_hsts"));
    }

    #[test]
    fn cors_reflection_and_suffix_bypasses_are_flagged() {
        for (origin, acao, probe, expected) in [
            (
                "https://evil.com",
                "https://evil.com",
                "reflect",
                "cors_reflect_credentials",
            ),
            ("null", "null", "null", "cors_null_origin"),
            (
                "https://evil.com",
                "https://evil.com.target.com",
                "suffix",
                "cors_suffix_match",
            ),
        ] {
            let issues = cors_issues(origin, probe, Some(acao), true);
            assert_eq!(issues.len(), 1, "{origin} -> {acao}");
            assert_eq!(issues[0].issue, expected);
            assert_eq!(issues[0].severity, "High");
        }
    }

    #[test]
    fn cors_allowlist_bypasses_are_flagged() {
        for (probe, origin, expected) in [
            ("null", "null", "cors_null_origin"),
            (
                "suffix",
                "https://evil.com.public-firing-range.appspot.com",
                "cors_suffix_match",
            ),
            (
                "prefix",
                "https://public-firing-range.appspot.com.evil.com",
                "cors_prefix_match",
            ),
            (
                "downgrade",
                "http://public-firing-range.appspot.com",
                "cors_protocol_downgrade",
            ),
        ] {
            let issues = classify(
                "https",
                origin,
                probe,
                Some(origin),
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                &[],
            );
            let kinds: Vec<_> = issues.iter().map(|i| i.issue).collect();
            assert_eq!(kinds, [expected], "{probe}");
            assert_eq!(issues[0].severity, "High", "{probe}");
        }
    }

    #[tokio::test]
    async fn cors_request_sends_origin_and_parses_reflected_response() {
        use wiremock::matchers::{header, method};
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("GET"))
            .and(header("origin", "https://evil.com"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("access-control-allow-origin", "https://evil.com")
                    .insert_header("access-control-allow-credentials", "true"),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("mock URL");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("lab scope");
        let findings = MisconfigScanner::default()
            .scan(&url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.iter().any(|finding| matches!(
            finding.evidence(),
            Evidence::SecurityMisconfiguration { issue, severity, .. }
                if issue == "cors_reflect_credentials" && severity == "High"
        )));
    }

    #[tokio::test]
    async fn wildcard_cors_is_flagged() {
        use wiremock::matchers::{header, method};
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("GET"))
            .and(header("origin", "https://evil.com"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("access-control-allow-origin", "*"),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("mock URL");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("lab scope");
        let findings = MisconfigScanner::default()
            .scan(&url, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.iter().any(|finding| matches!(
            finding.evidence(),
            Evidence::SecurityMisconfiguration { issue, .. } if issue == "cors_wildcard"
        )));
    }

    #[tokio::test]
    async fn large_inventory_is_capped_to_a_ten_endpoint_sample() {
        use std::time::{Duration, Instant};
        use wiremock::matchers::{method, path_regex};

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("GET"))
            .and(path_regex(r"^/e/[0-9]+$"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let url = Url::parse(server.uri().as_str()).expect("mock URL");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("lab scope");
        let scanner = MisconfigScanner {
            endpoints: (0..300).map(|index| format!("/e/{index}")).collect(),
            coverage: Coverage::default(),
        };

        let started = Instant::now();
        let findings = tokio::time::timeout(
            Duration::from_secs(45),
            scanner.scan(&url, &Client::new_lab(), &guard, false),
        )
        .await
        .expect("the capped sample must not hit the engine timeout")
        .expect("scan");
        let elapsed = started.elapsed();

        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        let probes = server
            .received_requests()
            .await
            .expect("recorded requests")
            .iter()
            .filter(|request| request.url.path().starts_with("/e/"))
            .count();
        assert_eq!(
            probes, 9,
            "the root plus sample stays within the 10-endpoint limit"
        );
        assert!(findings.iter().any(|finding| matches!(
            finding.evidence(),
            Evidence::SecurityMisconfiguration { .. }
        )));
    }

    #[tokio::test]
    async fn slow_endpoint_is_recorded_as_timed_out_and_others_still_probed() {
        use std::time::{Duration, Instant};
        use wiremock::matchers::{method, path};

        let server = wiremock::MockServer::start().await;
        // Register the slow route first so it wins the equal-priority match.
        wiremock::Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
            .mount(&server)
            .await;
        wiremock::Mock::given(method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let url = Url::parse(server.uri().as_str()).expect("mock URL");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("lab scope");
        let scanner = MisconfigScanner {
            endpoints: vec!["/slow".to_owned(), "/fast".to_owned()],
            coverage: Coverage::default(),
        };

        let started = Instant::now();
        let findings = tokio::time::timeout(
            Duration::from_secs(10),
            scanner.scan(&url, &Client::new_lab(), &guard, false),
        )
        .await
        .expect("per-fetch budget must end the slow probe")
        .expect("scan");
        let elapsed = started.elapsed();

        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        let requests = server.received_requests().await.expect("recorded requests");
        assert!(
            requests.iter().any(|request| request.url.path() == "/fast"),
            "healthy endpoints are still probed"
        );
        assert!(
            !findings.is_empty(),
            "root and /fast findings survive the slow endpoint"
        );
        let slow = format!("{}/slow", server.uri());
        assert!(
            scanner.coverage.endpoint_records().iter().any(|record| {
                record.url == slow && record.outcome == EndpointOutcome::TimedOut
            }),
            "timeout must be recorded for {slow}"
        );
    }

    #[tokio::test]
    async fn hardening_headers_fire_when_missing_and_stay_quiet_when_present() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let base = url::Url::parse(server.uri().as_str()).expect("url");
        let guard = riftlock_core::ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let issues = |findings: Vec<riftlock_core::Finding>| -> Vec<String> {
            findings
                .into_iter()
                .filter_map(|f| match f.evidence() {
                    Evidence::SecurityMisconfiguration { issue, .. } => Some(issue.clone()),
                    _ => None,
                })
                .collect()
        };
        let missing = issues(
            MisconfigScanner::default()
                .scan(&base, &Client::new_lab(), &guard, false)
                .await
                .expect("scan"),
        );
        for expected in [
            "missing_x_content_type_options",
            "missing_referrer_policy",
            "missing_permissions_policy",
        ] {
            assert!(missing.contains(&expected.to_owned()), "{missing:?}");
        }
        // Same priority tie resolves to the first-registered mock, so drop
        // the bare one before serving the hardened response.
        server.reset().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("x-content-type-options", "nosniff")
                    .insert_header("referrer-policy", "no-referrer")
                    .insert_header("permissions-policy", "geolocation=()"),
            )
            .mount(&server)
            .await;
        let present = issues(
            MisconfigScanner::default()
                .scan(&base, &Client::new_lab(), &guard, false)
                .await
                .expect("scan"),
        );
        for absent in [
            "missing_x_content_type_options",
            "missing_referrer_policy",
            "missing_permissions_policy",
        ] {
            assert!(!present.contains(&absent.to_owned()), "{present:?}");
        }
    }
}
