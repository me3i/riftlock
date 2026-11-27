//! Client-side scanner: regex analysis of served JavaScript bundles for
//! DOM XSS sinks, unvalidated `postMessage` handlers, and auth material
//! in web storage. Regex classification, not execution — the browser
//! context is never reproduced here.

use regex::Regex;
use riftlock_core::ScopedClient as Client;
use riftlock_core::{Evidence, Finding, ProofError, ProofGate, ScanError, Scanner, ScopeGuard};
use std::sync::LazyLock;
use url::Url;

/// The client-side scanner. Fetches the JS bundles discovery surfaced and
/// regex-classifies each for the three flaw families.
#[derive(Debug, Default)]
pub struct ClientSideScanner {
    /// Script or HTML page URLs, absolute or relative to the target.
    pub endpoints: Vec<String>,
}

/// DOM XSS sinks: a direct `innerHTML` assignment or React's escape hatch.
static DOM_XSS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"innerHTML\s*=|dangerouslySetInnerHTML").expect("static regex"));
/// A `message` event listener: the entry point of postMessage flaws.
static POSTMESSAGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"addEventListener\(\s*["']message["']"#).expect("static regex"));
/// Web-storage writes keyed with auth-looking names.
static STORAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:localStorage|sessionStorage)\.setItem\(\s*["'][^"']*(?:token|jwt|auth)[^"']*["']"#,
    )
    .expect("static regex")
});

/// How far past a `message` listener the handler body is expected to sit
/// (minified bundles are dense; 400 chars covers a typical handler).
const HANDLER_WINDOW: usize = 400;

/// Flood guard: a minified bundle can sink `innerHTML` dozens of times —
/// one proven sink is a finding, thirty is noise.
const MAX_DOM_XSS_PER_BUNDLE: usize = 3;

/// Snippet width kept in evidence (a trimmed source line).
const SNIPPET_MAX: usize = 120;

/// Static DOM sinks are skipped; large inline HTML is capped too.
const MAX_DOM_XSS_BUNDLE_BYTES: usize = 500 * 1024;

fn skip_dom_xss(url: &Url, source: &str) -> bool {
    let path = url.path();
    [".js", ".mjs", ".css"]
        .iter()
        .any(|extension| path.to_ascii_lowercase().ends_with(extension))
        || source.len() > MAX_DOM_XSS_BUNDLE_BYTES
}

/// The source line containing byte `offset`, trimmed to [`SNIPPET_MAX`].
fn snippet_of(source: &str, offset: usize) -> String {
    let start = source[..offset].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = source[offset..]
        .find('\n')
        .map(|i| offset + i)
        .unwrap_or(source.len());
    let line = source[start..end].trim();
    line.chars().take(SNIPPET_MAX).collect()
}

/// Snippets of `innerHTML =` / `dangerouslySetInnerHTML` sinks, capped at
/// [`MAX_DOM_XSS_PER_BUNDLE`].
fn dom_xss_snippets(url: &Url, source: &str) -> Vec<String> {
    if skip_dom_xss(url, source) {
        return Vec::new();
    }
    DOM_XSS
        .find_iter(source)
        .map(|m| snippet_of(source, m.start()))
        .take(MAX_DOM_XSS_PER_BUNDLE)
        .collect()
}

/// The snippet of the first `message` listener that consumes `event.data`
/// without an `event.origin` check in its body. Origin-checked handlers
/// (and handlers that never touch `.data`) are negatives.
fn unchecked_postmessage_snippet(source: &str) -> Option<String> {
    let m = POSTMESSAGE.find(source)?;
    let window = &source[m.start()..(m.start() + HANDLER_WINDOW).min(source.len())];
    if window.contains(".data") && !window.contains(".origin") {
        Some(snippet_of(source, m.start()))
    } else {
        None
    }
}

/// Snippets of web-storage writes keyed with `token`/`jwt`/`auth` — tokens
/// in `localStorage`/`sessionStorage` are readable by any XSS on the page.
fn insecure_storage_snippets(source: &str) -> Vec<String> {
    STORAGE
        .find_iter(source)
        .map(|m| snippet_of(source, m.start()))
        .collect()
}

fn is_script(url: &Url) -> bool {
    url.path().ends_with(".js") || url.path().ends_with(".mjs")
}

impl Scanner for ClientSideScanner {
    fn id(&self) -> &'static str {
        "clientside"
    }

    fn matches(&self, _url: &Url) -> bool {
        // SPA bundles live anywhere; discovery supplies the bundle list.
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
        let mut candidates = Vec::new();
        for endpoint in
            std::iter::once(url.as_str()).chain(self.endpoints.iter().map(String::as_str))
        {
            let Ok(mut probe) = url.join(endpoint) else {
                continue;
            };
            probe.set_fragment(None);
            let path = probe.path();
            if !is_script(&probe)
                && (path.ends_with(".json")
                    || path.split('/').any(|part| matches!(part, "api" | "rest")))
            {
                continue;
            }
            if guard.check(&probe).is_ok() && !candidates.contains(&probe) {
                candidates.push(probe);
            }
        }
        let mut candidates = candidates.into_iter();
        let mut fetches = tokio::task::JoinSet::new();
        let mut findings = Vec::new();
        loop {
            while fetches.len() < 8 {
                let Some(bundle) = candidates.next() else {
                    break;
                };
                let client = client.clone();
                fetches.spawn(async move {
                    let resp = match client
                        .get(bundle.clone())
                        .timeout(std::time::Duration::from_secs(5))
                        .send()
                        .await
                    {
                        Ok(resp) => resp,
                        Err(_) => return None,
                    };
                    let content_type = resp
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.split(';').next())
                        .unwrap_or("")
                        .trim();
                    let html = content_type.eq_ignore_ascii_case("text/html");
                    let json = content_type.eq_ignore_ascii_case("application/json")
                        || content_type.to_ascii_lowercase().ends_with("+json");
                    if !resp.status().is_success() || json || (!is_script(&bundle) && !html) {
                        return None;
                    }
                    // Failed or oversized bundle reads are not valid empty source.
                    let Ok(source) = riftlock_core::body::text_limited_result(resp).await else {
                        return None;
                    };
                    Some((bundle, source))
                });
            }
            let Some(result) = fetches.join_next().await else {
                break;
            };
            let Some((bundle, source)) =
                result.map_err(|e| ScanError::Io(std::io::Error::other(e)))?
            else {
                continue;
            };
            for (flaw_type, snippet) in dom_xss_snippets(&bundle, &source)
                .into_iter()
                .map(|s| ("dom_xss", s))
                .chain(
                    unchecked_postmessage_snippet(&source)
                        .into_iter()
                        .map(|s| ("postmessage", s)),
                )
                .chain(
                    insecure_storage_snippets(&source)
                        .into_iter()
                        .map(|s| ("insecure_storage", s)),
                )
            {
                match ProofGate::admit(Evidence::ClientSideFlaw {
                    endpoint: bundle.to_string(),
                    flaw_type: flaw_type.to_owned(),
                    snippet,
                }) {
                    Ok(finding) => findings.push(finding),
                    Err(ProofError::Heuristic) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dom_xss_snippets_are_capped_for_inline_html() {
        let src = "a.innerHTML=x;\nb.innerHTML=y;\nc.innerHTML=z;\nd.innerHTML=w;\n";
        let url = Url::parse("https://example.test/page").expect("url");
        let s = dom_xss_snippets(&url, src);
        assert_eq!(s.len(), MAX_DOM_XSS_PER_BUNDLE, "{s:?}");
    }

    #[test]
    fn static_asset_dom_xss_signals_are_dropped() {
        for path in ["/angular.js", "/app.mjs", "/theme.css"] {
            let url = Url::parse(&format!("https://example.test{path}")).expect("url");
            assert!(dom_xss_snippets(&url, "element.innerHTML = input;").is_empty());
        }
    }

    #[test]
    fn vendor_signatures_do_not_hide_dom_xss_sinks_in_inline_html() {
        let src = "jQuery.fn.init.innerHTML=a;\nb.innerHTML=b;\nc.innerHTML=c;\nd.innerHTML=d;\n";
        let url = Url::parse("https://example.test/page").expect("url");
        let s = dom_xss_snippets(&url, src);
        assert_eq!(s.len(), MAX_DOM_XSS_PER_BUNDLE, "{s:?}");
        assert!(s[0].contains("jQuery"), "{s:?}");
    }

    #[test]
    fn sink_extraction_keeps_minified_and_vendor_inline_html() {
        let url = Url::parse("https://example.test/page").expect("url");
        let minified = "app.min.js:1 el.innerHTML=x;";
        assert_eq!(dom_xss_snippets(&url, minified), vec![minified.to_owned()]);
        let vendor = "vendor/core el.innerHTML=y;";
        assert_eq!(dom_xss_snippets(&url, vendor), vec![vendor.to_owned()]);
        let big = format!("{}\nel.innerHTML=x;", "a".repeat(MAX_DOM_XSS_BUNDLE_BYTES));
        assert!(dom_xss_snippets(&url, &big).is_empty());
    }

    #[test]
    fn static_asset_suffix_and_size_skip_dom_xss() {
        for path in [
            "/angular.js",
            "/app.mjs",
            "/theme.css",
            "/nested/scripts.JS?v=1",
        ] {
            let url = Url::parse(&format!("https://example.test{path}")).expect("url");
            assert!(skip_dom_xss(&url, "el.innerHTML=x;"));
        }
        let html = Url::parse("https://example.test/page").expect("url");
        assert!(!skip_dom_xss(&html, "el.innerHTML=x;"));
        assert!(!skip_dom_xss(&html, &"a".repeat(MAX_DOM_XSS_BUNDLE_BYTES)));
        assert!(skip_dom_xss(
            &html,
            &"a".repeat(MAX_DOM_XSS_BUNDLE_BYTES + 1)
        ));
    }

    #[test]
    fn postmessage_requires_data_without_origin() {
        let bad = r#"window.addEventListener("message", (event) => { handle(event.data); });"#;
        assert!(unchecked_postmessage_snippet(bad).is_some());
        let checked = r#"addEventListener("message", (e) => { if (e.origin === "https://ok") handle(e.data); });"#;
        assert_eq!(unchecked_postmessage_snippet(checked), None);
        let no_data = r#"addEventListener("message", () => { refresh(); });"#;
        assert_eq!(unchecked_postmessage_snippet(no_data), None);
    }

    #[test]
    fn storage_requires_auth_looking_key() {
        let src = r#"localStorage.setItem("authToken", t); sessionStorage.setItem("jwt", j); localStorage.setItem("theme", "dark");"#;
        let s = insecure_storage_snippets(src);
        assert_eq!(s.len(), 2, "{s:?}");
        assert!(s[0].contains("authToken"));
    }

    #[test]
    fn snippet_stays_on_one_line_and_is_trimmed() {
        let src = "x = 1;\n  el.innerHTML = payload; // sink\ny = 2;";
        assert_eq!(
            snippet_of(src, src.find("innerHTML").expect("offset")),
            "el.innerHTML = payload; // sink"
        );
    }

    #[tokio::test]
    async fn static_signals_are_suppressed_without_failing_the_scan() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        let bundle = "el.innerHTML = userInput;\ndiv.innerHTML = a;\nspan.innerHTML = b;\np.innerHTML = c;\n\
                      window.addEventListener(\"message\", (event) => { handle(event.data); });\n\
                      localStorage.setItem(\"authToken\", token);";
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/app.js"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/javascript")
                    .set_body_string(bundle),
            )
            .mount(&server)
            .await;
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let scanner = ClientSideScanner {
            endpoints: vec!["/app.js".to_owned()],
        };
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(
            findings.is_empty(),
            "static regex signals must not be reported as findings: {findings:?}"
        );
    }

    #[tokio::test]
    async fn only_scripts_and_successful_html_are_analyzed() {
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };
        let server = MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        for (route, status, content_type, body) in [
            ("/", 200, "text/html", ""),
            ("/app.mjs", 200, "text/javascript", "el.innerHTML = input;"),
            (
                "/page",
                200,
                "Text/HTML; charset=utf-8",
                "<script>el.innerHTML = input;</script>",
            ),
            ("/data", 200, "application/json", "el.innerHTML = input;"),
            (
                "/data.js",
                200,
                "application/problem+json",
                "el.innerHTML = input;",
            ),
            ("/empty", 200, "text/html", ""),
            ("/denied", 403, "text/html", "el.innerHTML = input;"),
            ("/missing", 404, "text/html", "el.innerHTML = input;"),
        ] {
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(
                    ResponseTemplate::new(status).set_body_raw(body.as_bytes(), content_type),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        let mut foreign = base.join("/foreign.js").expect("url");
        foreign.set_host(Some("localhost")).expect("host");
        let scanner = ClientSideScanner {
            endpoints: [
                "/app.mjs?v=1#first",
                "/app.mjs?v=1#second",
                "/page",
                "/data",
                "/data.js",
                "/empty",
                "/denied",
                "/missing",
                "/data.json",
                "/api/v1/data",
                "/rest/data",
            ]
            .into_iter()
            .map(String::from)
            .chain([foreign.to_string()])
            .collect(),
        };
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(
            findings.is_empty(),
            "static client-side patterns must not be reported: {findings:?}"
        );
        assert_eq!(server.received_requests().await.expect("requests").len(), 8);
    }

    #[tokio::test]
    async fn page_header_checks_are_concurrent() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string("el.innerHTML = input;")
                    .set_delay(std::time::Duration::from_millis(200)),
            )
            .expect(8)
            .mount(&server)
            .await;
        let scanner = ClientSideScanner {
            // Eight same-origin requests fit the scanner's concurrency cap;
            // the limiter permits a five-request burst then refills at 5/s.
            endpoints: (1..8).map(|n| format!("/page{n}")).collect(),
        };
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let findings = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            scanner.scan(&base, &Client::new_lab(), &guard, false),
        )
        .await
        .expect("header checks must not run sequentially")
        .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn passive_mode_sends_no_requests() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        assert!(ClientSideScanner::default()
            .scan(&base, &Client::new_lab(), &guard, true)
            .await
            .expect("scan")
            .is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }

    #[tokio::test]
    async fn oversized_bundle_is_skipped_not_buffered() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        // 10 MB: over the 5 MiB cap. The scanner must abort reading the
        // stream, skip the bundle and return clean findings — no OOM, no
        // panic.
        let big = "a".repeat(10 * 1024 * 1024);
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/app.js"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/javascript")
                    .set_body_string(big),
            )
            .mount(&server)
            .await;
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let scanner = ClientSideScanner {
            endpoints: vec!["/app.js".to_owned()],
        };
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan must not crash on an oversized bundle");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[tokio::test]
    async fn scan_is_clean_on_a_hardened_bundle() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        let bundle = r#"addEventListener("message", (e) => { if (e.origin !== ok) return; handle(e.data); }); textContent = safe;"#;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/app.js"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/javascript")
                    .set_body_string(bundle),
            )
            .mount(&server)
            .await;
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let scanner = ClientSideScanner {
            endpoints: vec!["/app.js".to_owned()],
        };
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty(), "{findings:?}");
    }
}
