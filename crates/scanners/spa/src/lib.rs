//! Static-only single-page-application scanner.
//!
//! The scanner fetches the start page, extracts every `<script src>` bundle,
//! and runs the source-to-sink taint analysis in [`crate::ast`] over the
//! fetched JavaScript. No browser is launched.
//!
//! Transport policy belongs to [`ScopedClient`]: timeouts, transient-status
//! retries and the per-scan circuit breaker all live there. This scanner
//! issues exactly one send per bundle. A bundle that still fails is recorded
//! as an unreadable endpoint and the remaining bundles are still analyzed.

mod ast;

use riftlock_core::{
    CheckState, Coverage, EndpointOutcome, Evidence, Finding, LabGuard, ProofGate, ScanError,
    Scanner, ScopeGuard, ScopedClient,
};
use scraper::{Html, Selector};
use std::collections::HashSet;
use url::Url;

/// Cap on fetched bundles; upgrade to pagination if real bundles exceed this.
const MAX_BUNDLES: usize = 10;

/// Static-only single-page-application scanner.
#[derive(Debug, Default)]
pub struct SpaScanner {
    /// Run even when `matches()` rejects the URL (explicit `--provider spa`).
    pub force_run: bool,
    /// Lab authorization used by lab-only proof variants. The static analysis
    /// only observes bundles and never needs it.
    pub lab_guard: Option<LabGuard>,
    /// Crawler-discovered endpoints, retained for API compatibility. They are
    /// inventory, not evidence: only proven source-to-sink flows are reported.
    pub endpoints: Vec<String>,
    /// Shared coverage ledger (the CLI swaps in the engine's fork).
    pub coverage: Coverage,
}

/// Proven source-to-sink flows harvested from one page.
#[derive(Default)]
struct Harvest {
    taints: Vec<DomTaint>,
    seen_taints: HashSet<(String, u32, String)>,
}

/// One DOM-XSS flow, keyed to the script that contains the sink.
struct DomTaint {
    sink_url: String,
    sink_line: u32,
    source: String,
    sink: String,
}

impl Harvest {
    /// Analyze one JavaScript source and fold its proven flows into the harvest.
    /// `sink_url` is the inline page or the external bundle that holds the sink.
    fn ingest(&mut self, sink_url: &Url, source: &str) {
        for flow in ast::source_to_sink(source) {
            let sink_url = sink_url.to_string();
            let key = (sink_url.clone(), flow.line, flow.source.clone());
            if self.seen_taints.insert(key) {
                self.taints.push(DomTaint {
                    sink_url,
                    sink_line: flow.line,
                    source: flow.source,
                    sink: flow.sink,
                });
            }
        }
    }
}

impl SpaScanner {
    /// Fetch the start page and every in-scope bundle, analyzing the JS found
    /// in both. Bundle transport failures are coverage records, not scan
    /// failures: one dead bundle must not block the healthy ones.
    async fn static_harvest(
        &self,
        url: &Url,
        client: &ScopedClient,
        guard: &ScopeGuard,
    ) -> Result<Harvest, ScanError> {
        let response = client.get(url.clone()).send().await?;
        let html = riftlock_core::body::text_limited_result(response).await?;
        let (bundles, inline) = extract_scripts(url, &html);

        let mut harvest = Harvest::default();
        for script in &inline {
            harvest.ingest(url, script);
        }

        let mut seen_bundles = HashSet::new();
        for bundle in bundles.into_iter().take(MAX_BUNDLES) {
            if !seen_bundles.insert(bundle.clone()) {
                continue;
            }
            if guard.check(&bundle).is_err() {
                self.coverage.out_of_scope_endpoint_at(bundle.as_str());
                continue;
            }
            let Ok(source) = fetch_bundle(client, &bundle).await else {
                // The transport already retried what it considers retryable.
                // Record the dead bundle and keep going.
                self.coverage.unreadable_endpoint_at(bundle.as_str());
                continue;
            };
            let check = self.coverage.begin_check();
            self.coverage
                .endpoint_at(bundle.as_str(), EndpointOutcome::Tested);
            harvest.ingest(&bundle, &source);
            let _ = check.finish(CheckState::Completed);
        }
        Ok(harvest)
    }
}

/// One send per bundle. Retries and timeouts are owned by the client.
async fn fetch_bundle(client: &ScopedClient, bundle: &Url) -> Result<String, ScanError> {
    let response = client.get(bundle.clone()).send().await?;
    if !response.status().is_success() {
        return Err(ScanError::HttpStatus(response.status().as_u16()));
    }
    Ok(riftlock_core::body::text_limited_result(response).await?)
}

/// Extract external bundle URLs and inline script bodies from the start page.
///
/// `scraper` borrows the document, so everything is collected before the
/// caller awaits the first bundle fetch.
fn extract_scripts(page: &Url, html: &str) -> (Vec<Url>, Vec<String>) {
    let document = Html::parse_document(html);
    let mut bundles = Vec::new();
    if let Ok(selector) = Selector::parse("script[src]") {
        for element in document.select(&selector) {
            let Some(src) = element.value().attr("src") else {
                continue;
            };
            if src.trim().is_empty() {
                continue;
            }
            let Ok(bundle) = page.join(src) else {
                continue;
            };
            if matches!(bundle.scheme(), "http" | "https") {
                bundles.push(bundle);
            }
        }
    }
    let inline = match Selector::parse("script:not([src])") {
        Ok(selector) => document
            .select(&selector)
            .map(|element| element.text().collect::<String>())
            .filter(|script| !script.trim().is_empty())
            .collect(),
        Err(_) => Vec::new(),
    };
    (bundles, inline)
}

fn is_spa_page_path(url: &Url) -> bool {
    let path = url.path();
    path.contains("/dom/") || path.contains("/urldom/") || path.contains("/address/")
}

impl Scanner for SpaScanner {
    fn id(&self) -> &'static str {
        "spa"
    }

    fn matches(&self, url: &Url) -> bool {
        matches!(url.scheme(), "http" | "https")
    }

    async fn scan(
        &self,
        url: &Url,
        client: &ScopedClient,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        if passive || (!self.force_run && !self.matches(url)) || !is_spa_page_path(url) {
            return Ok(Vec::new());
        }
        guard.check(url)?;

        let harvest = self.static_harvest(url, client, guard).await?;
        // Endpoint inventory is not evidence. Only a source that explicitly
        // flows into an executable sink is admitted, and each sink location is
        // reported once.
        let mut findings = Vec::with_capacity(harvest.taints.len());
        for taint in harvest.taints {
            findings.push(ProofGate::admit(Evidence::DomXssTaint {
                url: taint.sink_url,
                source: format!("{} (line {})", taint.source, taint.sink_line),
                sink: taint.sink,
            })?);
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TAINT: &str = r#"document.getElementById("out").innerHTML = location.search;"#;

    fn lab_guard() -> ScopeGuard {
        ScopeGuard::new_lab(&["http://127.0.0.1"]).expect("lab scope")
    }

    fn scanner() -> SpaScanner {
        SpaScanner {
            force_run: true,
            lab_guard: None,
            endpoints: Vec::new(),
            coverage: Coverage::default(),
        }
    }

    fn client(guard: &ScopeGuard, timeout: Duration) -> ScopedClient {
        ScopedClient::from_builder(reqwest::Client::builder().timeout(timeout), guard)
            .expect("lab client")
    }

    fn page_url(server: &MockServer) -> Url {
        Url::parse(&format!("{}/dom/index.html", server.uri())).expect("server url")
    }

    fn root_page_url(server: &MockServer) -> Url {
        Url::parse(&server.uri()).expect("server url")
    }

    async fn mount_page(server: &MockServer, body: &str) {
        mount_page_at(server, "/dom/index.html", body).await;
    }

    async fn mount_page_at(server: &MockServer, route: &str, body: &str) {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(server)
            .await;
    }

    async fn hits(server: &MockServer, target: &str) -> usize {
        server
            .received_requests()
            .await
            .expect("recorded requests")
            .iter()
            .filter(|request| request.url.path() == target)
            .count()
    }

    #[tokio::test]
    async fn root_path_is_skipped_without_request_findings_or_coverage() {
        let server = MockServer::start().await;
        mount_page_at(
            &server,
            "/",
            r#"<script>document.body.innerHTML = location.hash;</script>"#,
        )
        .await;

        let guard = lab_guard();
        let client = client(&guard, Duration::from_secs(5));
        let scanner = scanner();
        let findings = scanner
            .scan(&root_page_url(&server), &client, &guard, false)
            .await
            .expect("ineligible page paths are skipped");

        assert!(findings.is_empty(), "root path must not be analyzed");
        assert_eq!(
            server.received_requests().await.expect("requests").len(),
            0,
            "root path must be skipped before making HTTP requests"
        );
        assert!(
            scanner.coverage.endpoint_records().is_empty(),
            "skipping an ineligible path must not record coverage"
        );
    }

    #[tokio::test]
    async fn bundle_still_failing_after_retry_does_not_block_healthy_bundle() {
        let server = MockServer::start().await;
        mount_page(
            &server,
            r#"<html><body>
                 <script src="/broken.js"></script>
                 <script src="/healthy.js"></script>
               </body></html>"#,
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/broken.js"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/healthy.js"))
            .respond_with(ResponseTemplate::new(200).set_body_string(TAINT))
            .mount(&server)
            .await;

        let guard = lab_guard();
        let client = client(&guard, Duration::from_secs(5));
        let scanner = scanner();
        let findings = scanner
            .scan(&page_url(&server), &client, &guard, false)
            .await
            .expect("a failed bundle does not fail the scan");

        // One request per bundle. A 500 is not retried by the transport, so
        // this also proves the scanner adds no retry of its own.
        assert_eq!(hits(&server, "/broken.js").await, 1);
        assert_eq!(hits(&server, "/healthy.js").await, 1);
        assert_eq!(
            hits(&server, "/broken.js").await + hits(&server, "/healthy.js").await,
            2,
            "exactly one request per bundle"
        );

        // The healthy bundle was analyzed despite its neighbor failing.
        assert!(findings.iter().any(|finding| matches!(
            finding.evidence(),
            Evidence::DomXssTaint { sink, .. } if sink == "innerHTML"
        )));
        let broken = format!("{}/broken.js", server.uri());
        assert!(scanner
            .coverage
            .endpoint_records()
            .iter()
            .any(|record| { record.url == broken && record.outcome == EndpointOutcome::Failed }));
    }

    #[tokio::test]
    async fn timed_out_bundle_is_not_retried_and_does_not_block_scan() {
        let server = MockServer::start().await;
        mount_page(&server, r#"<script src="/slow.js"></script>"#).await;
        // The first request times out under the 1 s adaptive floor seeded by
        // the fast page fetch. It counts once toward the shared host breaker,
        // and the scanner continues without retrying this bundle.
        Mock::given(method("GET"))
            .and(path("/slow.js"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(2_500))
                    .set_body_string(TAINT),
            )
            .mount(&server)
            .await;

        let guard = lab_guard();
        let client = client(&guard, Duration::from_secs(5));
        let scanner = scanner();
        let findings = scanner
            .scan(&page_url(&server), &client, &guard, false)
            .await
            .expect("a timed-out bundle does not fail the scan");

        assert_eq!(
            hits(&server, "/slow.js").await,
            1,
            "a timeout contributes one failure without retry"
        );
        assert!(findings.is_empty(), "the timed-out bundle never loaded");
        let slow = format!("{}/slow.js", server.uri());
        assert!(scanner
            .coverage
            .endpoint_records()
            .iter()
            .any(|record| { record.url == slow && record.outcome == EndpointOutcome::Failed }));
    }

    #[tokio::test]
    async fn static_string_into_inner_html_does_not_fire() {
        let server = MockServer::start().await;
        mount_page(&server, r#"<script src="/app.js"></script>"#).await;
        Mock::given(method("GET"))
            .and(path("/app.js"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    r#"document.getElementById("out").innerHTML = "static string";"#,
                ),
            )
            .mount(&server)
            .await;

        let guard = lab_guard();
        let client = client(&guard, Duration::from_secs(5));
        let findings = scanner()
            .scan(&page_url(&server), &client, &guard, false)
            .await
            .expect("scan");

        assert!(
            findings.is_empty(),
            "a literal assigned to innerHTML is not a taint flow"
        );
    }

    #[tokio::test]
    async fn location_hash_into_inner_html_fires_exactly_once() {
        let server = MockServer::start().await;
        mount_page(&server, r#"<script src="/app.js"></script>"#).await;
        Mock::given(method("GET"))
            .and(path("/app.js"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    r#"document.getElementById("out").innerHTML = location.hash;"#,
                ),
            )
            .mount(&server)
            .await;

        let guard = lab_guard();
        let client = client(&guard, Duration::from_secs(5));
        let findings = scanner()
            .scan(&page_url(&server), &client, &guard, false)
            .await
            .expect("scan");

        assert_eq!(findings.len(), 1, "{findings:?}");
        let Evidence::DomXssTaint { url, source, sink } = findings[0].evidence() else {
            panic!("expected a DOM-XSS taint finding");
        };
        assert_eq!(url, &format!("{}/app.js", server.uri()));
        assert!(source.contains("location.hash"));
        assert!(source.contains("line 1"));
        assert_eq!(sink, "innerHTML");
    }

    #[tokio::test]
    async fn duplicate_inline_flows_are_reported_once() {
        let server = MockServer::start().await;
        let script = r#"<script>document.body.innerHTML = location.hash;</script>"#;
        mount_page(&server, &format!("{script}{script}")).await;

        let guard = lab_guard();
        let client = client(&guard, Duration::from_secs(5));
        let findings = scanner()
            .scan(&page_url(&server), &client, &guard, false)
            .await
            .expect("scan");

        assert_eq!(
            findings.len(),
            1,
            "same sink URL, line and source is one finding"
        );
    }

    #[tokio::test]
    async fn out_of_scope_bundle_skipped() {
        let page_server = MockServer::start().await;
        let other = MockServer::start().await;
        // Same loopback IP, different host spelling: the guard allows
        // 127.0.0.1 only, so localhost is outside the scan boundary.
        let outside = other.uri().replace("127.0.0.1", "localhost");
        let outside_bundle = format!("{outside}/outside.js");
        mount_page(
            &page_server,
            &format!(r#"<script src="{outside_bundle}"></script>"#),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/outside.js"))
            .respond_with(ResponseTemplate::new(200).set_body_string(TAINT))
            .mount(&other)
            .await;

        let guard = lab_guard();
        let client = client(&guard, Duration::from_secs(5));
        let scanner = scanner();
        let findings = scanner
            .scan(&page_url(&page_server), &client, &guard, false)
            .await
            .expect("an out-of-scope bundle does not fail the scan");

        assert!(findings.is_empty());
        assert_eq!(
            other.received_requests().await.expect("requests").len(),
            0,
            "the out-of-scope host is never contacted"
        );
        assert_eq!(
            page_server
                .received_requests()
                .await
                .expect("requests")
                .len(),
            1,
            "only the start page is fetched"
        );
        assert!(scanner.coverage.endpoint_records().iter().any(|record| {
            record.url == outside_bundle && record.outcome == EndpointOutcome::Skipped
        }));
    }
}
