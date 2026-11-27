//! Passive fingerprinting of Supabase key material and server/framework
//! tech markers in HTML and JS bundles.
//!
//! Fetches the target page plus up to 50 JS bundles, regexes for the four
//! Supabase key types, decodes JWT payloads (no signature verification),
//! and returns masked values + SHA-256 hashes. The full value is held only
//! in memory in a redacted `SecretValue` for interactive opt-in reveal; it
//! is never serialized or logged.

use base64::Engine;
use regex::Regex;
use riftlock_core::ScopedClient as Client;
use riftlock_core::{canonical_url, KeyType, ScopeError, ScopeGuard, SecretValue};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use url::Url;

/// Response content cached for reuse within one scan.
#[derive(Debug, Clone)]
pub struct CachedResource {
    /// Successfully fetched response body.
    pub body: String,
    /// Response headers used by technology fingerprinting.
    pub headers: Vec<(String, String)>,
}

/// In-memory response cache shared by discovery and passive fingerprinting.
#[derive(Debug, Clone, Default)]
pub struct FetchCache(Arc<Mutex<HashMap<Url, Arc<CachedResource>>>>);

impl FetchCache {
    /// Return a cached resource for `url`, ignoring any URL fragment.
    #[must_use]
    pub fn get(&self, url: &Url) -> Option<Arc<CachedResource>> {
        let mut key = url.clone();
        key.set_fragment(None);
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .cloned()
    }

    /// Store a successfully fetched response for reuse during this scan.
    pub fn insert(
        &self,
        url: Url,
        body: String,
        headers: Vec<(String, String)>,
    ) -> Arc<CachedResource> {
        let mut key = url;
        key.set_fragment(None);
        let resource = Arc::new(CachedResource { body, headers });
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, Arc::clone(&resource));
        resource
    }
}

/// One identified key occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// Classified key type.
    pub key_type: KeyType,
    /// Masked value (prefix kept, rest starred). Never the full secret.
    pub masked: String,
    /// SHA-256 hex digest of the full value.
    pub hash: String,
    /// Full value, in memory only (redacted in `Debug`, never serialized).
    pub full: SecretValue,
    /// Where it was observed.
    pub location: String,
}

/// Fingerprint failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FingerprintError {
    /// Transport-level HTTP failure.
    #[error("http failure")]
    Http(#[from] reqwest::Error),
    /// Scope enforcement rejected a request.
    #[error("scope violation")]
    Scope(#[from] ScopeError),
    /// Scan transport failure, including a tripped circuit breaker.
    #[error("scan failure: {0}")]
    Scan(#[from] riftlock_core::ScanError),
    /// Target is not a valid URL.
    #[error("invalid url")]
    InvalidUrl,
}

static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}").expect("static regex")
});
static PUBLISHABLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sb_publishable_[A-Za-z0-9_-]{8,}").expect("static regex"));
static SECRET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sb_secret_[A-Za-z0-9_-]{8,}").expect("static regex"));
static SCRIPT_SRC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<script[^>]+src=["']([^"']+)["']"#).expect("static regex"));
static SERVER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(nginx|Apache|IIS|LiteSpeed)(?:/([\d]+(?:\.[\d]+)*))?").expect("static regex")
});
static X_POWERED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(PHP|Express|ASP\.NET|Next\.js)(?:/([\d]+(?:\.[\d]+)*))?").expect("static regex")
});
static META_GEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']"#)
        .expect("static regex")
});
static META_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(WordPress|Next\.js|Drupal)(?:\s+v?([\d]+(?:\.[\d]+)*))?").expect("static regex")
});
static NG_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"ng-version=["']([\d]+(?:\.[\d]+)*)["']"#).expect("static regex")
});

/// Mask a secret: keep the first 10 ASCII chars, star the rest.
fn mask(value: &str) -> String {
    let kept: String = value.chars().take(10).collect();
    let hidden = value.chars().count().saturating_sub(kept.chars().count());
    format!("{kept}{}", "*".repeat(hidden.clamp(1, 16)))
}

/// SHA-256 hex digest of the full value.
fn hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Decode a JWT payload segment (base64url, unpadded) into JSON.
fn jwt_payload(token: &str) -> Option<Value> {
    let segment = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Classify a JWT-like token by its payload `role` claim. Returns `None`
/// for tokens that are not one of the two legacy Supabase roles.
fn classify_jwt(token: &str) -> Option<KeyType> {
    let role = jwt_payload(token)?.get("role")?.as_str()?.to_owned();
    match role.as_str() {
        "anon" => Some(KeyType::SupabaseAnonLegacy),
        "service_role" => Some(KeyType::SupabaseServiceRoleLegacy),
        _ => None,
    }
}

/// Scan raw text for the four Supabase key types. Pure; testable offline.
pub fn scan_text(text: &str, location: &str) -> Vec<Fingerprint> {
    let mut out = Vec::new();
    for m in PUBLISHABLE_RE.find_iter(text) {
        out.push(make(KeyType::SupabasePublishable, m.as_str(), location));
    }
    for m in SECRET_RE.find_iter(text) {
        out.push(make(KeyType::SupabaseSecret, m.as_str(), location));
    }
    for m in JWT_RE.find_iter(text) {
        if let Some(kt) = classify_jwt(m.as_str()) {
            out.push(make(kt, m.as_str(), location));
        }
    }
    out
}

fn make(key_type: KeyType, value: &str, location: &str) -> Fingerprint {
    Fingerprint {
        key_type,
        masked: mask(value),
        hash: hash(value),
        full: SecretValue(value.to_owned()),
        location: location.to_owned(),
    }
}

/// One identified server/framework technology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechMatch {
    /// Technology name (e.g. "nginx", "Next.js").
    pub technology: String,
    /// Version string when the marker carried one.
    pub version: Option<String>,
    /// 0-100 confidence in the identification.
    pub confidence: u8,
}

fn tech(technology: &str, version: Option<String>, confidence: u8) -> TechMatch {
    TechMatch {
        technology: technology.to_owned(),
        version,
        confidence,
    }
}

/// Keep the first entry per technology unless `m` is more confident.
fn keep_best(out: &mut Vec<TechMatch>, m: TechMatch) {
    match out.iter_mut().find(|t| t.technology == m.technology) {
        Some(t) if t.confidence < m.confidence => *t = m,
        None => out.push(m),
        _ => {}
    }
}

/// Scan response header pairs and a body for server/framework markers.
/// Pure; testable offline. Dedupes by technology (highest confidence wins),
/// capped at 10 matches.
pub fn scan_tech(header_pairs: &[(String, String)], body: &str) -> Vec<TechMatch> {
    let mut out = Vec::new();
    for (name, value) in header_pairs {
        let lower = name.to_ascii_lowercase();
        if lower == "server" {
            if let Some(c) = SERVER_RE.captures(value) {
                keep_best(
                    &mut out,
                    tech(&c[1], c.get(2).map(|v| v.as_str().to_owned()), 95),
                );
            }
            if value.to_ascii_lowercase().contains("awselb") {
                keep_best(&mut out, tech("AWS", None, 90));
            }
        } else if lower == "x-powered-by" {
            if let Some(c) = X_POWERED_RE.captures(value) {
                keep_best(
                    &mut out,
                    tech(&c[1], c.get(2).map(|v| v.as_str().to_owned()), 95),
                );
            }
        } else if lower == "cf-ray"
            || lower == "cf-cache-status"
            || (lower == "set-cookie" && value.contains("__cf_bm="))
        {
            keep_best(&mut out, tech("Cloudflare", None, 95));
        } else if lower.starts_with("x-amz-") {
            keep_best(&mut out, tech("AWS", None, 90));
        }
    }
    if let Some(c) = META_GEN_RE.captures(body) {
        if let Some(m) = META_VERSION_RE.captures(&c[1]) {
            keep_best(
                &mut out,
                tech(&m[1], m.get(2).map(|v| v.as_str().to_owned()), 90),
            );
        }
    }
    if body.contains("__NEXT_DATA__") {
        keep_best(&mut out, tech("Next.js", None, 90));
    }
    if let Some(c) = NG_VERSION_RE.captures(body) {
        keep_best(&mut out, tech("Angular", Some(c[1].to_owned()), 90));
    }
    if body.contains("wp-content") {
        keep_best(&mut out, tech("WordPress", None, 85));
    }
    if body.contains("data-reactroot") || body.contains("/react/") {
        keep_best(&mut out, tech("React", None, 80));
    }
    if body.contains("__VUE__") || body.contains("data-v-") {
        keep_best(&mut out, tech("Vue", None, 80));
    }
    if body.contains("Drupal.settings") || body.contains("/drupal.js") {
        keep_best(&mut out, tech("Drupal", None, 85));
    }
    out.truncate(10);
    out
}

fn header_pairs(resp: &reqwest::Response) -> Vec<(String, String)> {
    resp.headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Extract up to 50 unique script bundle URLs from HTML, resolved against `base`.
pub fn bundle_urls(html: &str, base: &Url) -> Vec<Url> {
    let mut seen = std::collections::HashSet::new();
    SCRIPT_SRC_RE
        .captures_iter(html)
        .filter_map(|c| canonical_url(base, &c[1]).ok())
        .map(|mut url| {
            url.set_fragment(None);
            url
        })
        .filter(|url| seen.insert(url.clone()))
        .take(50)
        .collect()
}

/// Passive fingerprint of `url`: fetch page + up to 50 JS bundles, scan each.
/// Every request passes the scope guard. Passive only — no probing.
///
/// # Errors
/// Scope violations and transport failures.
pub async fn fingerprint_url(
    client: &Client,
    url: &Url,
    guard: &ScopeGuard,
    coverage: &riftlock_core::Coverage,
    cache: &FetchCache,
) -> Result<Vec<Fingerprint>, FingerprintError> {
    guard.check(url)?;
    let mut out = Vec::new();
    let html = if let Some(resource) = cache.get(url) {
        resource.body.clone()
    } else {
        let response = client.get(url.clone()).send().await?;
        let headers = header_pairs(&response);
        match riftlock_core::body::text_limited_result(response).await {
            Ok(body) => cache.insert(url.clone(), body, headers).body.clone(),
            Err(error) => {
                riftlock_core::logger::line(&format!("warning: {error}; body skipped"));
                coverage.endpoint_at(url.as_str(), riftlock_core::EndpointOutcome::Failed);
                String::new()
            }
        }
    };
    out.extend(scan_text(&html, url.as_str()));
    for bundle in bundle_urls(&html, url) {
        if guard.check(&bundle).is_err() {
            coverage.out_of_scope_endpoint_at(bundle.as_str());
            continue;
        }
        let text = if let Some(resource) = cache.get(&bundle) {
            resource.body.clone()
        } else if let Ok(resp) = client
            .get(bundle.clone())
            .send()
            .await
            .and_then(|r| Ok(r.error_for_status()?))
        {
            let headers = header_pairs(&resp);
            match riftlock_core::body::text_limited_result(resp).await {
                Ok(text) => cache.insert(bundle.clone(), text, headers).body.clone(),
                Err(error) => {
                    riftlock_core::logger::line(&format!("warning: {error}; body skipped"));
                    coverage.endpoint_at(bundle.as_str(), riftlock_core::EndpointOutcome::Failed);
                    String::new()
                }
            }
        } else {
            continue;
        };
        out.extend(scan_text(&text, bundle.as_str()));
    }
    Ok(out)
}

/// Passive tech fingerprint of `url`: fetch page + up to 50 JS bundles, match
/// headers and bodies against known tech markers. Every request passes the
/// scope guard. Passive only — no probing.
///
/// # Errors
/// Scope violations and transport failures.
pub async fn tech_url(
    client: &Client,
    url: &Url,
    guard: &ScopeGuard,
    coverage: &riftlock_core::Coverage,
    cache: &FetchCache,
) -> Result<Vec<TechMatch>, FingerprintError> {
    guard.check(url)?;
    let (headers, body) = if let Some(resource) = cache.get(url) {
        (resource.headers.clone(), resource.body.clone())
    } else {
        let resp = client.get(url.clone()).send().await?;
        let headers = header_pairs(&resp);
        match riftlock_core::body::text_limited_result(resp).await {
            Ok(body) => {
                cache.insert(url.clone(), body.clone(), headers.clone());
                (headers, body)
            }
            Err(error) => {
                riftlock_core::logger::line(&format!("warning: {error}; body skipped"));
                coverage.endpoint_at(url.as_str(), riftlock_core::EndpointOutcome::Failed);
                (headers, String::new())
            }
        }
    };
    let mut out = scan_tech(&headers, &body);
    for bundle in bundle_urls(&body, url) {
        guard.check(&bundle)?;
        let (headers, body) = if let Some(resource) = cache.get(&bundle) {
            (resource.headers.clone(), resource.body.clone())
        } else if let Ok(resp) = client
            .get(bundle.clone())
            .send()
            .await
            .and_then(|r| Ok(r.error_for_status()?))
        {
            let headers = header_pairs(&resp);
            match riftlock_core::body::text_limited_result(resp).await {
                Ok(body) => {
                    cache.insert(bundle.clone(), body.clone(), headers.clone());
                    (headers, body)
                }
                Err(error) => {
                    riftlock_core::logger::line(&format!("warning: {error}; body skipped"));
                    coverage.endpoint_at(bundle.as_str(), riftlock_core::EndpointOutcome::Failed);
                    (headers, String::new())
                }
            }
        } else {
            continue;
        };
        for m in scan_tech(&headers, &body) {
            keep_best(&mut out, m);
        }
    }
    out.truncate(10);
    for matched in &out {
        riftlock_core::logger::line(&format!(
            "[Discovery] Fingerprint matched: {} ({}%)",
            matched.technology, matched.confidence
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANON: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.xK9fQ0dG8hZz3wL1mN5vB7jR2cT4yU6iA8oE0sPqWmY";
    const SERVICE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.Zy3wQ1mN5vB7jR2cT4yU6iA8oE0sPqWmYxK9fQ0dG8h";

    #[test]
    fn anon_legacy_jwt() {
        let found = scan_text(ANON, "page");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key_type, KeyType::SupabaseAnonLegacy);
        assert!(!found[0].masked.contains(ANON));
    }

    #[test]
    fn service_role_jwt() {
        let found = scan_text(SERVICE, "page");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key_type, KeyType::SupabaseServiceRoleLegacy);
    }

    #[test]
    fn publishable_key() {
        let found = scan_text("sb_publishable_AbC123xY_zW9", "js/bundle.js");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key_type, KeyType::SupabasePublishable);
        assert_eq!(found[0].location, "js/bundle.js");
    }

    #[test]
    fn secret_key() {
        let found = scan_text("sb_secret_AbC123xY_zW9Qq", "html");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key_type, KeyType::SupabaseSecret);
        assert!(found[0].hash.len() == 64);
    }

    #[test]
    fn unrelated_jwt_ignored() {
        // role: "authenticated" is not one of the four key types.
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYXV0aGVudGljYXRlZCJ9.xK9fQ0dG8hZz3wL1mN5vB7jR2cT4yU6iA8oE0sPqWmY";
        assert!(scan_text(token, "page").is_empty());
    }

    #[test]
    fn server_header_version() {
        let found = scan_tech(&[("Server".into(), "nginx/1.24.0".into())], "");
        assert_eq!(found, vec![tech("nginx", Some("1.24.0".into()), 95)]);
    }

    #[test]
    fn x_powered_by_nextjs() {
        let found = scan_tech(&[("X-Powered-By".into(), "Next.js".into())], "");
        assert_eq!(found, vec![tech("Next.js", None, 95)]);
    }

    #[test]
    fn meta_generator_wordpress_version() {
        let body = r#"<meta name="generator" content="WordPress 6.4.2" />"#;
        let found = scan_tech(&[], body);
        assert_eq!(found, vec![tech("WordPress", Some("6.4.2".into()), 90)]);
    }

    #[test]
    fn next_data_marker() {
        let found = scan_tech(&[], r"<script id=__NEXT_DATA__>{}</script>");
        assert_eq!(found, vec![tech("Next.js", None, 90)]);
    }

    #[test]
    fn angular_ng_version() {
        let found = scan_tech(&[], r#"<app-root ng-version="17.3.0"></app-root>"#);
        assert_eq!(found, vec![tech("Angular", Some("17.3.0".into()), 90)]);
    }

    #[test]
    fn cloudflare_header() {
        let found = scan_tech(&[("cf-ray".into(), "8abc123".into())], "");
        assert_eq!(found, vec![tech("Cloudflare", None, 95)]);
    }

    #[test]
    fn aws_from_header_names() {
        let found = scan_tech(&[("x-amz-request-id".into(), "abc".into())], "");
        assert_eq!(found, vec![tech("AWS", None, 90)]);
    }

    #[test]
    fn dedup_keeps_highest_confidence() {
        // Meta generator (90) beats the wp-content body marker (85) and
        // supplies the version.
        let found = scan_tech(
            &[],
            r#"<meta name="generator" content="Drupal 10"><script src="/drupal.js"></script>"#,
        );
        assert_eq!(found, vec![tech("Drupal", Some("10".into()), 90)]);
    }

    #[test]
    fn empty_input_no_findings() {
        assert!(scan_tech(&[], "").is_empty());
    }

    #[tokio::test]
    async fn oversized_bundle_body_is_recorded_as_failed_endpoint() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(r#"<script src="/bundle.js"></script>"#),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/bundle.js"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![
                b'a';
                riftlock_core::body::MAX_BODY_BYTES
                    + 1
            ]))
            .mount(&server)
            .await;

        let url = Url::parse(&server.uri()).expect("fixture URL");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("fixture scope");
        let coverage = riftlock_core::Coverage::default();
        let matches = tech_url(
            &Client::new_lab(),
            &url,
            &guard,
            &coverage,
            &FetchCache::default(),
        )
        .await
        .expect("fingerprint local fixture");

        assert!(matches.is_empty());
        let snapshot = coverage.snapshot(0);
        assert_eq!(snapshot.endpoints_failed, 1);
        assert_eq!(snapshot.vulnerability_checks_attempted, 0);
    }

    #[test]
    fn bundle_urls_deduplicate_before_the_fifty_bundle_limit() {
        let base = Url::parse("https://example.test/").expect("url");
        let scripts = (0..55)
            .map(|i| format!(r#"<script src="/bundle-{i}.js"></script>"#))
            .collect::<String>();
        let html = format!(
            r#"<script src="/same.js#first"></script><script src="/same.js#second"></script>{scripts}"#
        );
        let bundles = bundle_urls(&html, &base);
        assert_eq!(bundles.len(), 50);
        assert_eq!(bundles[0].as_str(), "https://example.test/same.js");
        assert_eq!(bundles[49].as_str(), "https://example.test/bundle-48.js");
    }
}
