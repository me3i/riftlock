//! Breadth-first authenticated crawler: maps an application's attack
//! surface (links, script sources, form actions) with the operator's
//! session, feeding [`crate`] results into the discovery context.

use crate::Discovery;
use futures_util::stream::StreamExt;
use regex::Regex;
use riftlock_core::ScopedClient as Client;
use riftlock_core::{canonical_url, CrawlMetrics, ScanError, ScopeGuard};
use riftlock_fingerprint::FetchCache;
use scraper::{Html, Selector};
use std::collections::{HashSet, VecDeque};
use url::Url;

/// A bounded BFS crawler. `max_depth` counts navigation hops from the start
/// page; `max_pages` bounds the number of pages fetched.
#[derive(Debug, Clone)]
pub struct Crawler {
    /// Navigation hops from the start page to still fetch pages.
    pub max_depth: usize,
    /// Maximum number of pages fetched in one crawl.
    pub max_pages: usize,
    /// Wall-clock soft deadline: past it the crawl returns the pages mapped
    /// so far instead of grinding on — a caller with a hard timeout would
    /// otherwise cancel the crawl and lose every endpoint found so far.
    pub deadline: Option<std::time::Instant>,
    /// Whether the bounded directory brute-force pass runs. Normal turns it
    /// off; Read and Godmode leave it on.
    pub wordlist: bool,
}

/// The attribute each extracted element carries.
const EXTRACTORS: [(&str, &str); 3] = [("a", "href"), ("script", "src"), ("form", "action")];

/// Endpoint patterns that would end the operator's session if fetched.
const AUTH_KILLERS: &[&str] = &[
    "/logout",
    "/signout",
    "/sign-out",
    "/api/auth/logout",
    "/api/auth/signout",
];

/// Schemes that are not fetchable pages.
const SKIP_SCHEMES: [&str; 3] = ["mailto", "tel", "javascript"];

/// Maximum number of script bundles fetched and AST-scanned per crawl.
const MAX_BUNDLES: usize = 50;

/// Maximum number of script bundles fetched concurrently per page.
const BUNDLE_CONCURRENCY: usize = 6;

/// Safety cap on nested `<sitemapindex>` sitemaps fetched per crawl.
const MAX_SITEMAPS: usize = 10;

/// Common hidden paths probed once per crawl against the start origin.
const WORDLIST: &[&str] = &[
    "admin",
    "admin/login",
    "api",
    "api/v1",
    "api/v2",
    "rest",
    "graphql",
    "backup",
    "config",
    "debug",
    "actuator",
    "swagger",
    "api-docs",
    "console",
    "wp-admin",
    "login",
    "register",
    "profile",
    "settings",
    "dashboard",
    "user",
    "users",
    "orders",
    "items",
    "search",
    "upload",
    "download",
    "fetch",
    "files",
    ".env",
    ".git/HEAD",
    "package.json",
    "robots.txt",
    "sitemap.xml",
    "server-status",
    "phpinfo.php",
    "administrator",
    "manager",
    "jenkins",
    "metrics",
    "health",
    "api/search",
    "api/blind",
    "api/login",
    "api/users",
    "api/admin",
    "auth",
    "protected",
    "proxy",
    "users/update",
    "admin/dashboard",
    "render",
    "auth/ldap",
    "internal/config",
];

/// API path prefixes joined with every wordlist entry: real API routes live
/// under versioned prefixes (`/api/v1/proxy`, `/api/v2/admin/dashboard`),
/// which flat single-word probes never reach.
const API_PREFIXES: &[&str] = &["api/v1", "api/v2", "rest/v1"];

/// Maximum number of queued pages fetched concurrently by one crawl batch.
const CRAWL_CONCURRENCY: usize = 8;

/// Outcome of one page fetch in a concurrent crawl batch. Fetching is
/// concurrent, but classification, parsing and queue mutation stay
/// sequential so the inventory and its metrics arrive in link order.
enum PageFetch {
    /// Served from the scan-wide fetch cache; no request was made.
    Cached(String),
    /// A successful response whose size-capped body is ready to parse.
    Body {
        body: String,
        headers: Vec<(String, String)>,
    },
    /// A non-success status: the page is classified, not crawled.
    Status(u16),
    /// The request itself failed (DNS, connect, timeout).
    Transport(ScanError),
    /// The response arrived but its body could not be read.
    BodyError(ScanError),
}

impl Crawler {
    /// Crawl from `start_url` (breadth-first), authenticated with `token`
    /// (the raw `Cookie` header value, when present). Returns every
    /// in-scope URL extracted from fetched pages, first-seen order, deduped.
    ///
    /// Fetch failures on linked pages (404, dead link) are skipped — the
    /// crawl maps what is reachable, one broken link is not a transport
    /// failure of the crawl.
    ///
    /// # Errors
    /// Scope violations on the start URL, or a request, non-success status,
    /// or body failure on the start page.
    pub async fn crawl(
        &self,
        start_url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        token: Option<&str>,
    ) -> Result<Vec<String>, ScanError> {
        Ok(self
            .crawl_with_metrics(start_url, client, guard, token, &FetchCache::default())
            .await?
            .0)
    }

    /// Crawl and return the stage-by-stage accounting for the inventory.
    /// `crawl` delegates here so existing callers keep the list-only shape.
    ///
    /// # Errors
    /// Same failures as [`Self::crawl`].
    pub async fn crawl_with_metrics(
        &self,
        start_url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        token: Option<&str>,
        fetch_cache: &FetchCache,
    ) -> Result<(Vec<String>, CrawlMetrics), ScanError> {
        let mut metrics = CrawlMetrics {
            budget_configured: self.max_pages as u64,
            ..CrawlMetrics::default()
        };
        let mut page_budget_hit = false;
        guard.check_active(start_url)?;
        guard.check(start_url)?;
        let mut selectors = Vec::with_capacity(EXTRACTORS.len());
        for (tag, attr) in EXTRACTORS {
            // Hardcoded valid selectors; an unusable one just skips that tag.
            if let Ok(sel) = Selector::parse(&format!("{tag}[{attr}]")) {
                selectors.push((sel, attr));
            }
        }
        let mut found: Vec<String> = Vec::new();
        let mut visited: HashSet<Url> = HashSet::new();
        // Script bundles already fetched for AST scanning (once per crawl).
        let mut scanned = HashSet::new();
        // Fragments are client-side only and never reach the server.
        let start_url = without_fragment(start_url);
        // Navigate `<a href>` and `<form action>` targets; script sources are
        // scanned as bundles but are not treated as HTML pages.
        let mut queue: VecDeque<(Url, usize)> = VecDeque::new();
        queue.push_back((start_url.clone(), 0));
        metrics.scheduled += 1;
        // Seed from robots.txt and sitemap.xml first: they advertise paths no
        // page links to, at depth 0 so their own links stay within reach.
        if let Ok(origin) = start_url.join("/") {
            seed(
                &origin,
                client,
                guard,
                token,
                self.deadline,
                &mut SeedState {
                    found: &mut found,
                    queue: &mut queue,
                    metrics: &mut metrics,
                },
            )
            .await;
        }
        while !queue.is_empty() {
            if past_deadline(self.deadline) {
                // Nothing has been popped: every queued URL is scheduled but
                // never classified.
                metrics.remaining = queue.len() as u64;
                metrics.termination_reason = "deadline".to_owned();
                break;
            }
            // Reserve up to one batch of pages, then fetch the batch
            // concurrently. Dedupe, depth and page-cap checks run while
            // reserving, so `visited` keeps the serial order semantics.
            let mut batch: Vec<(Url, usize)> = Vec::with_capacity(CRAWL_CONCURRENCY);
            while batch.len() < CRAWL_CONCURRENCY {
                let Some((url, depth)) = queue.pop_front() else {
                    break;
                };
                let url = without_fragment(&url);
                if visited.contains(&url)
                    || depth > self.max_depth
                    || visited.len() >= self.max_pages
                {
                    if visited.len() >= self.max_pages {
                        page_budget_hit = true;
                    }
                    metrics.skipped += 1;
                    continue;
                }
                visited.insert(url.clone());
                metrics.budget_consumed = visited.len() as u64;
                batch.push((url, depth));
            }
            // A page already fetched earlier in this scan is reused instead of
            // spending a second request on it.
            let mut fetched: Vec<(usize, Url, usize, PageFetch)> =
                futures_util::stream::iter(batch.into_iter().enumerate())
                    .map(|(index, (url, depth))| {
                        let client = client.clone();
                        let fetch_cache = fetch_cache.clone();
                        async move {
                            let fetch = match fetch_cache.get(&url) {
                                Some(resource) => PageFetch::Cached(resource.body.clone()),
                                None => fetch_page(&client, &url, token).await,
                            };
                            (index, url, depth, fetch)
                        }
                    })
                    .buffer_unordered(CRAWL_CONCURRENCY)
                    .collect()
                    .await;
            // Results arrive in completion order; re-order by batch index so
            // link extraction and the inventory stay deterministic.
            fetched.sort_by_key(|(index, _, _, _)| *index);
            for (_, url, depth, fetch) in fetched {
                let body = match fetch {
                    PageFetch::Cached(body) => {
                        metrics.tested += 1;
                        body
                    }
                    PageFetch::Transport(error) => {
                        if url == start_url {
                            return Err(error);
                        }
                        if error.is_timeout() {
                            metrics.timed_out += 1;
                        } else {
                            metrics.failed += 1;
                        }
                        continue;
                    }
                    PageFetch::Status(status) => {
                        if url == start_url {
                            return Err(ScanError::HttpStatus(status));
                        }
                        if matches!(status, 401 | 403 | 406 | 429 | 503) {
                            metrics.blocked += 1;
                        } else {
                            metrics.skipped += 1;
                        }
                        continue;
                    }
                    PageFetch::BodyError(error) => {
                        // The start page's body is required; a linked page's
                        // failure is a skipped leaf.
                        if url == start_url {
                            return Err(error);
                        }
                        metrics.failed += 1;
                        riftlock_core::logln!("[!] Skipping {url}: {error}");
                        continue;
                    }
                    PageFetch::Body { body, headers } => {
                        fetch_cache.insert(url.clone(), body.clone(), headers);
                        metrics.tested += 1;
                        body
                    }
                };
                // The root doubles as the WAF tripwire: an interstitial there
                // means every later fetch hits the same wall.
                if url == start_url && riftlock_core::looks_like_waf(&body) {
                    riftlock_core::logln!("[!] WAF Challenge detected. Discovery may be limited.");
                }
                // scraper::Html is not Send: extract all targets sync and drop
                // the tree before the bundle await below.
                let (links, parameters) = {
                    let doc = Html::parse_document(&body);
                    let mut links = Vec::new();
                    let mut parameters = url.query_pairs().count();
                    for selector in ["input[name]", "textarea[name]", "select[name]"] {
                        if let Ok(selector) = Selector::parse(selector) {
                            parameters += doc
                                .select(&selector)
                                .filter(|el| el.value().attr("name").is_some())
                                .count();
                        }
                    }
                    for (sel, attr) in &selectors {
                        for el in doc.select(sel) {
                            let Some(raw) = el.value().attr(attr) else {
                                continue;
                            };
                            metrics.raw_extracted += 1;
                            match canonical_url(&url, raw) {
                                Err(_) => metrics.malformed_rejected += 1,
                                Ok(resolved) => {
                                    metrics.normalization_accepted += 1;
                                    parameters += resolved.query_pairs().count();
                                    links.push((
                                        without_fragment(&resolved),
                                        attr != &"src",
                                        attr == &"src",
                                    ));
                                }
                            }
                        }
                    }
                    (links, parameters)
                };
                let mut new_links = 0;
                // Bundles referenced by this page, fetched together after the link
                // scan so a page with many scripts does not serialize them.
                let mut bundles: Vec<Url> = Vec::new();
                for (resolved, should_crawl, is_src) in links {
                    // Out-of-scope targets are recorded nowhere and crawled never.
                    if guard.check(&resolved).is_err() {
                        metrics.external_excluded += 1;
                        continue;
                    }
                    // A logout link must be neither recorded nor queued:
                    // fetching it ends the session the crawl is running on.
                    if SKIP_SCHEMES.contains(&resolved.scheme())
                        || AUTH_KILLERS.iter().any(|k| resolved.as_str().contains(k))
                    {
                        metrics.policy_excluded += 1;
                        continue;
                    }
                    if !record(&mut found, &resolved) {
                        metrics.duplicates_removed += 1;
                        continue;
                    }
                    metrics.unique_in_scope += 1;
                    if should_crawl {
                        queue.push_back((resolved, depth + 1));
                        metrics.scheduled += 1;
                        new_links += 1;
                    } else if is_src {
                        // Reserve each bundle once per crawl, in link order, before
                        // any of them is fetched.
                        if scanned.contains(&resolved) || scanned.len() >= MAX_BUNDLES {
                            continue;
                        }
                        scanned.insert(resolved.clone());
                        bundles.push(resolved);
                    }
                }
                if !bundles.is_empty() {
                    // At most `BUNDLE_CONCURRENCY` fetches are in flight; results
                    // are re-ordered by link index so extraction stays deterministic.
                    let mut fetched: Vec<(usize, Url, Option<String>)> =
                        futures_util::stream::iter(bundles.into_iter().enumerate())
                            .map(|(index, bundle)| {
                                let client = client.clone();
                                let fetch_cache = fetch_cache.clone();
                                async move {
                                    let source =
                                        fetch_bundle_source(&client, &bundle, token, &fetch_cache)
                                            .await;
                                    (index, bundle, source)
                                }
                            })
                            .buffer_unordered(BUNDLE_CONCURRENCY)
                            .collect()
                            .await;
                    fetched.sort_by_key(|(index, _, _)| *index);
                    for (_, bundle, source) in fetched {
                        // Fetch failures keep the recorded bundle URL and skip AST.
                        let Some(source) = source else {
                            continue;
                        };
                        riftlock_core::logln!("[Discovery] Analyzing bundle: {bundle}");
                        // Bundle AST endpoints are crawlable pages/API routes too.
                        for endpoint in bundle_endpoints(&source, &url, guard, &mut found) {
                            queue.push_back((endpoint, depth + 1));
                            metrics.scheduled += 1;
                        }
                    }
                }
                riftlock_core::logln!(
                "[Discovery] Crawled {url} -> Extracted {new_links} new links, {parameters} parameters"
            );
            }
        }
        // Directory brute-force: one bounded pass against the start origin,
        // once per crawl — anything that does not 404 is attack surface.
        if self.wordlist {
            if let Ok(origin) = start_url.join("/") {
                let mut targets = Vec::new();
                for word in WORDLIST {
                    if let Ok(target) = origin.join(word) {
                        if guard.check(&target).is_ok() {
                            targets.push(target);
                        }
                    }
                }
                // Same pass under each versioned API prefix; `record` dedups
                // the overlap with the flat words.
                for prefix in API_PREFIXES {
                    for word in WORDLIST {
                        if let Ok(target) = origin.join(&format!("{prefix}/{word}")) {
                            if guard.check(&target).is_ok() {
                                targets.push(target);
                            }
                        }
                    }
                }
                for target in targets {
                    if past_deadline(self.deadline) {
                        break;
                    }
                    probe_word(client, &target, token, &mut found, self.deadline).await;
                }
            }
        }
        if metrics.termination_reason.is_empty() {
            metrics.termination_reason = if page_budget_hit {
                "page_budget".to_owned()
            } else if !queue.is_empty() {
                "deadline".to_owned()
            } else {
                "queue_exhausted".to_owned()
            };
        }
        if metrics.termination_reason != "deadline" {
            metrics.remaining = queue.len() as u64;
        }
        Ok((found, metrics))
    }
}

/// Wordlist entries whose endpoints commonly take a file parameter: such
/// endpoints often answer 404 to a param-less GET but read files once the
/// param carries a real path, so they get one canary retry before being
/// written off.
const FILE_WORDS: &[&str] = &["download", "export", "import"];
/// The canary query for [`FILE_WORDS`]: a traversal the target either
/// resolves (non-404 → surface) or rejects. Probing for surface only —
/// the proof payloads live in `riftlock-core` and the scanners.
const LFI_CANARY: &str = "file=../../../../etc/passwd";

/// One wordlist probe: a plain GET; on 404, a file-shaped final path
/// segment gets one LFI-canary retry. A non-404 either way records the
/// (query-less) target as attack surface. Past the soft deadline nothing
/// new is fetched: the wordlist is the crawl's biggest sequential fan-out,
/// and a slow target must yield the surface found so far, not a timeout.
async fn probe_word(
    client: &Client,
    target: &Url,
    token: Option<&str>,
    found: &mut Vec<String>,
    deadline: Option<std::time::Instant>,
) {
    if past_deadline(deadline) {
        return;
    }
    let get = |u: &Url| {
        let mut req = client.get(u.clone());
        if let Some(token) = token {
            req = req.header("cookie", token);
        }
        req
    };
    if let Ok(resp) = get(target).send().await {
        if resp.status() != reqwest::StatusCode::NOT_FOUND {
            record(found, target);
            return;
        }
    }
    let file_shaped = target
        .path()
        .rsplit('/')
        .next()
        .is_some_and(|last| FILE_WORDS.contains(&last));
    if !file_shaped {
        return;
    }
    let Ok(canary) = Url::parse(&format!("{target}?{LFI_CANARY}")) else {
        return;
    };
    if past_deadline(deadline) {
        return;
    }
    if let Ok(resp) = get(&canary).send().await {
        if resp.status() != reqwest::StatusCode::NOT_FOUND {
            record(found, target);
        }
    }
}

/// Remove the fragment: it is never sent in an HTTP request.
fn without_fragment(url: &Url) -> Url {
    let mut url = url.clone();
    url.set_fragment(None);
    url
}

/// Record `url` in `found`, first-seen order, deduped. Returns whether it was
/// newly added.
fn record(found: &mut Vec<String>, url: &Url) -> bool {
    let url = without_fragment(url);
    if found.iter().any(|u| u == url.as_str()) {
        return false;
    }
    found.push(url.to_string());
    true
}

/// Mutable discovery state shared by the robots/sitemap seeder.
struct SeedState<'a> {
    found: &'a mut Vec<String>,
    queue: &'a mut VecDeque<(Url, usize)>,
    metrics: &'a mut CrawlMetrics,
}

/// Seed the queue from `<origin>/robots.txt` and `<origin>/sitemap.xml`
/// before BFS: paths and pages a site never links to are still attack surface.
async fn seed(
    origin: &Url,
    client: &Client,
    guard: &ScopeGuard,
    token: Option<&str>,
    deadline: Option<std::time::Instant>,
    state: &mut SeedState<'_>,
) {
    // robots.txt: Allow/Disallow paths and declared sitemap documents.
    let robots_url = origin.join("robots.txt").ok();
    let robots_body = match robots_url {
        Some(url) if !past_deadline(deadline) && guard.check(&url).is_ok() => {
            fetch_text(client, &url, token).await
        }
        _ => None,
    };
    let mut robots_paths = 0;
    let mut declared_sitemaps: Vec<Url> = Vec::new();
    if let Some(body) = robots_body {
        for line in body.lines() {
            let Some((directive, value)) = line.split_once(':') else {
                continue;
            };
            let directive = directive.trim();
            let value = value.trim();
            if directive.eq_ignore_ascii_case("sitemap") {
                if let Ok(url) = resolve(origin, value) {
                    if !declared_sitemaps.contains(&url) {
                        declared_sitemaps.push(url);
                    }
                }
                continue;
            }
            if !directive.eq_ignore_ascii_case("disallow")
                && !directive.eq_ignore_ascii_case("allow")
            {
                continue;
            }
            // Empty values and wildcard patterns (`*`, `$`) are unsupported.
            if value.is_empty() || value.contains('*') || value.contains('$') {
                continue;
            }
            if let Ok(path) = origin.join(value) {
                if seed_url(state, guard, &path) {
                    robots_paths += 1;
                }
            }
        }
    }
    riftlock_core::logln!("[Discovery] Checking robots.txt... Found {robots_paths} paths.");

    // sitemap.xml plus every document robots.txt declared; a declared URL may
    // be cross-origin and is scope-checked like any fetch.
    let mut sitemap_urls: Vec<Url> = Vec::new();
    if let Ok(default) = origin.join("sitemap.xml") {
        sitemap_urls.push(default);
    }
    for url in declared_sitemaps {
        if !sitemap_urls.contains(&url) {
            sitemap_urls.push(url);
        }
    }
    let mut sitemap_pages = 0;
    let mut nested_fetched = 0;
    for sitemap in sitemap_urls {
        if past_deadline(deadline) || guard.check(&sitemap).is_err() {
            continue;
        }
        let Some(body) = fetch_text(client, &sitemap, token).await else {
            continue;
        };
        let locs = sitemap_locs(&body);
        if !body.contains("<sitemapindex") {
            for loc in locs {
                if let Ok(page) = resolve(origin, &loc) {
                    if seed_url(state, guard, &page) {
                        sitemap_pages += 1;
                    }
                }
            }
            continue;
        }
        for loc in locs {
            if nested_fetched >= MAX_SITEMAPS || past_deadline(deadline) {
                break;
            }
            let Ok(nested) = resolve(origin, &loc) else {
                continue;
            };
            if guard.check(&nested).is_err() {
                continue;
            }
            nested_fetched += 1;
            let Some(nested_body) = fetch_text(client, &nested, token).await else {
                continue;
            };
            for page_loc in sitemap_locs(&nested_body) {
                if let Ok(page) = resolve(origin, &page_loc) {
                    if seed_url(state, guard, &page) {
                        sitemap_pages += 1;
                    }
                }
            }
        }
    }
    riftlock_core::logln!("[Discovery] Checking sitemap.xml... Found {sitemap_pages} URLs.");
}

/// Record and enqueue a seeded URL at depth 0, on the same first-seen path as
/// crawled links. Out-of-scope, session-killing and already-seen URLs are
/// dropped. Returns whether it was newly added.
fn seed_url(state: &mut SeedState<'_>, guard: &ScopeGuard, url: &Url) -> bool {
    if guard.check(url).is_err() || AUTH_KILLERS.iter().any(|k| url.as_str().contains(k)) {
        return false;
    }
    if !record(state.found, url) {
        return false;
    }
    state.queue.push_back((url.clone(), 0));
    state.metrics.scheduled += 1;
    true
}

/// A sitemap `<loc>` value as an absolute URL; a relative value resolves
/// against `origin`.
fn resolve(origin: &Url, loc: &str) -> Result<Url, url::ParseError> {
    Url::parse(loc).or_else(|_| origin.join(loc))
}

/// Every `<loc>` value in a sitemap document, `&amp;` unescaped.
fn sitemap_locs(body: &str) -> Vec<String> {
    // Rebuilt per document: a static Regex would need `expect` outside tests.
    let Ok(re) = Regex::new(r"(?i)<loc>\s*([^<]*?)\s*</loc>") else {
        return Vec::new();
    };
    re.captures_iter(body)
        .filter_map(|c| c.get(1))
        .map(|m| m.as_str().replace("&amp;", "&"))
        .collect()
}

/// Fetch `url` with the crawl's session cookie; `None` on transport failure
/// or a non-success status. The body is capped by [`riftlock_core::text_limited`].
async fn fetch_text(client: &Client, url: &Url, token: Option<&str>) -> Option<String> {
    let mut req = client.get(url.clone());
    if let Some(token) = token {
        req = req.header("cookie", token);
    }
    let resp = match req.send().await {
        Ok(resp) => resp,
        Err(error) => {
            riftlock_core::logln!("[!] Skipping {url}: fetch failed: {error}");
            return None;
        }
    };
    if !resp.status().is_success() {
        return None;
    }
    match riftlock_core::body::text_limited_result(resp).await {
        Ok(body) => Some(body),
        Err(error) => {
            riftlock_core::logln!("[!] Skipping {url}: {error}");
            None
        }
    }
}

/// Whether the crawl's soft deadline has passed.
fn past_deadline(deadline: Option<std::time::Instant>) -> bool {
    deadline.is_some_and(|d| std::time::Instant::now() >= d)
}

/// Copy response headers into the cache-friendly string representation.
fn response_headers(response: &reqwest::Response) -> Vec<(String, String)> {
    response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Fetch one crawl page: cookie-authenticated GET, status classification and
/// a size-capped body buffer. Pure with respect to crawl accounting — the
/// caller applies the batch result to [`CrawlMetrics`] in link order.
async fn fetch_page(client: &Client, url: &Url, token: Option<&str>) -> PageFetch {
    let mut request = client.get(url.clone()).bypass_adaptive_timeout();
    if let Some(token) = token {
        request = request.header("cookie", token);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => return PageFetch::Transport(error),
    };
    if !response.status().is_success() {
        return PageFetch::Status(response.status().as_u16());
    }
    let headers = response_headers(&response);
    // Cap the buffered body: a hostile page must not OOM the crawl.
    match riftlock_core::body::text_limited_result(response).await {
        Ok(body) => PageFetch::Body { body, headers },
        Err(error) => PageFetch::BodyError(error.into()),
    }
}

/// Fetch a bundle source, reusing a response already cached in this scan.
pub async fn fetch_bundle_source(
    client: &Client,
    bundle: &Url,
    token: Option<&str>,
    fetch_cache: &FetchCache,
) -> Option<String> {
    if let Some(resource) = fetch_cache.get(bundle) {
        return Some(resource.body.clone());
    }
    let mut identity_retry = false;
    loop {
        let mut request = client
            .get(bundle.clone())
            .timeout(std::time::Duration::from_secs(30))
            .bypass_adaptive_timeout();
        if let Some(token) = token {
            request = request.header("cookie", token);
        }
        if identity_retry {
            request = request.header("accept-encoding", "identity");
        }
        let response = match request.send().await {
            Ok(response) if response.status().is_success() => response,
            Ok(_) => return None,
            Err(error) => {
                riftlock_core::logln!(
                    "[!] Skipping {bundle}: fetch failed: {error}; received 0 bytes"
                );
                return None;
            }
        };
        let headers = response_headers(&response);
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        let mut received = 0usize;
        let mut read_error = None;
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) => {
                    received += chunk.len();
                    bytes.extend_from_slice(&chunk);
                }
                Err(error) => {
                    read_error = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = read_error {
            if !identity_retry {
                riftlock_core::logln!(
                    "[!] Retrying bundle {bundle} after receiving {received} bytes with identity encoding: {error}"
                );
                identity_retry = true;
                continue;
            }
            riftlock_core::logln!(
                "[!] Skipping bundle {bundle}: body read failed after receiving {received} bytes: {error}"
            );
            return None;
        }
        riftlock_core::logln!("[Discovery] Fetched bundle {bundle}: {received} bytes");
        let source = String::from_utf8_lossy(&bytes).into_owned();
        fetch_cache.insert(bundle.clone(), source.clone(), headers);
        return Some(source);
    }
}

/// Extract and record bundle endpoints, resolved against the containing page.
fn bundle_endpoints(
    source: &str,
    page: &Url,
    guard: &ScopeGuard,
    found: &mut Vec<String>,
) -> Vec<Url> {
    let mut endpoints = Vec::new();
    for discovery in crate::discover(source) {
        let Discovery::Endpoint { path, .. } = discovery else {
            continue;
        };
        let Ok(endpoint) = Url::parse(&path).or_else(|_| page.join(&path)) else {
            continue;
        };
        if guard.check(&endpoint).is_err() {
            continue;
        }
        record(found, &endpoint);
        endpoints.push(endpoint);
    }
    riftlock_core::logln!(
        "[Discovery] Extracted {} endpoints from bundle",
        endpoints.len()
    );
    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Page at `/` linking to `/about` (link), `/app.js` (script) and a
    /// form posting to `/login`; `/about` links back to `/` and to
    /// `https://evil.example/leave`. Returns the base URL; the caller
    /// keeps the `MockServer` alive.
    async fn spawn_site(server: &MockServer) -> Url {
        let index = "<html><body>\
             <a href='/about'>about</a>\
             <script src='/app.js'></script>\
             <form action='/login'><input name='user'></form>\
             </body></html>";
        let about = "<html><body><a href='/'>home</a>\
                     <a href='/deeper/level3'>deeper</a>\
                     <a href='https://evil.example/leave'>out</a></body></html>";
        for (p, body) in [
            ("/", index),
            ("/about", about),
            (
                "/deeper/level3",
                "<html><body><a href='/deepest'>fourth</a></body></html>",
            ),
            (
                "/deepest",
                "<html><body><a href='/deepest/fetched'>fifth</a></body></html>",
            ),
            ("/deepest/fetched", "<html><body>last</body></html>"),
            ("/login", "<html><body>form destination</body></html>"),
            ("/app.js", "fetch('/api/ast-endpoint');"),
            (
                "/api/ast-endpoint",
                "<html><body>bundled endpoint</body></html>",
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(p))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "text/html")
                        .set_body_string(body),
                )
                .with_priority(10)
                .mount(server)
                .await;
        }
        // Authenticated variant of /about: only a crawler carrying the
        // session cookie sees the /admin link.
        Mock::given(method("GET"))
            .and(path("/about"))
            .and(header("cookie", "session=token-a"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(
                        "<html><body><a href='/'>home</a>\
                         <a href='/admin/settings'>admin</a></body></html>",
                    ),
            )
            .with_priority(1)
            .mount(server)
            .await;
        Url::parse(&server.uri()).expect("url")
    }

    async fn crawl_from(base: &Url, path: &str, token: Option<&str>) -> Vec<String> {
        let start = base.join(path).expect("url");
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let crawler = Crawler {
            deadline: None,
            max_depth: 3,
            max_pages: 50,
            wordlist: true,
        };
        crawler
            .crawl(&start, &Client::new_lab(), &guard, token)
            .await
            .expect("crawl")
    }

    /// A quoted or HTML-encoded external URL must never become a malformed
    /// target-relative path; it must be rejected by the scope guard.
    #[tokio::test]
    async fn quoted_and_encoded_external_links_are_never_recorded() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<html><body>
                       <a href='"https://steamcommunity.com/sharedfiles/filedetails"' >x</a>
                       <a href="https://github.com/Neo23x0/sigma/">y</a>
                       <a href="/%22/ftp/legal.md/%22">z</a>
                       <a href="/in-scope?a=1&amp;b=2#frag">ok</a>
                       </body></html>"#,
            ))
            .mount(&server)
            .await;
        let base = Url::parse(&server.uri()).expect("url");
        let urls = crawl_from(&base, "/", None).await;
        assert!(
            !urls.iter().any(|u| u.contains("steamcommunity")
                || u.contains("github.com")
                || u.contains("%22")),
            "malformed/external URL entered the inventory: {urls:?}"
        );
        assert!(
            urls.iter().any(|u| u.contains("a=1&b=2")),
            "query parameters were not preserved: {urls:?}"
        );
        let requests = server.received_requests().await.expect("requests");
        assert!(
            !requests.iter().any(|r| r.url.path().contains("%22")),
            "a malformed request was sent"
        );
    }

    #[tokio::test]
    async fn crawl_reports_a_failing_start_page_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let crawler = Crawler {
            deadline: None,
            max_depth: 1,
            max_pages: 10,
            wordlist: true,
        };
        let error = crawler
            .crawl(&base, &Client::new_lab(), &guard, None)
            .await
            .expect_err("a start-page status failure is not an empty crawl");
        assert!(matches!(error, ScanError::HttpStatus(503)), "{error:?}");
    }

    #[tokio::test]
    async fn crawl_extracts_links_scripts_and_forms_in_scope() {
        let server = MockServer::start().await;
        let base = spawn_site(&server).await;
        let root = base.as_str().trim_end_matches('/');
        let urls = crawl_from(&base, "/", None).await;
        for expected in ["/about", "/app.js", "/login"] {
            assert!(
                urls.contains(&format!("{root}{expected}")),
                "missing {expected} in {urls:?}"
            );
        }
        // The out-of-scope link is neither returned nor crawled.
        assert!(!urls.iter().any(|u| u.contains("evil.example")));
        assert!(urls.contains(&format!("{root}/deeper/level3")), "{urls:?}");
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().any(|r| r.url.path() == "/login"));
        assert!(requests.iter().any(|r| r.url.path() == "/deeper/level3"));
        // AST endpoint extracted from /app.js was queued and fetched.
        assert!(requests.iter().any(|r| r.url.path() == "/api/ast-endpoint"));
        assert!(!requests.iter().any(|r| r.url.path() == "/deepest/fetched"));
    }

    #[tokio::test]
    async fn crawl_reaches_linked_pages_within_depth() {
        let server = MockServer::start().await;
        let base = spawn_site(&server).await;
        // /about is depth 1; its backlink to / must not re-crawl.
        let urls = crawl_from(&base, "/", None).await;
        assert_eq!(
            urls.iter()
                .filter(|u| u.as_str().ends_with("/about"))
                .count(),
            1
        );
    }

    /// A fragment never reaches the server: `/about#a`, `/about#b` and
    /// `/about` are one page, fetched once and recorded without the fragment.
    #[tokio::test]
    async fn crawl_deduplicates_fragment_variants() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(
                        "<html><body>\
                         <a href='/about#first'>one</a>\
                         <a href='/about#second'>two</a>\
                         <a href='/about'>three</a>\
                         <script src='/app.js#a'></script>\
                         <script src='/app.js#b'></script>\
                         </body></html>",
                    ),
            )
            .mount(&server)
            .await;
        for p in ["/about", "/app.js"] {
            Mock::given(method("GET"))
                .and(path(p))
                .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
                .mount(&server)
                .await;
        }
        let base = Url::parse(&server.uri()).expect("url");
        let urls = crawl_from(&base, "/", None).await;
        let requests = server.received_requests().await.expect("requests");
        let fetches = |p: &str| requests.iter().filter(|r| r.url.path() == p).count();
        assert_eq!(fetches("/about"), 1, "fragment variants refetched /about");
        assert_eq!(fetches("/app.js"), 1, "fragment variants refetched /app.js");
        assert!(urls.iter().all(|u| !u.contains('#')), "{urls:?}");
    }

    #[tokio::test]
    async fn crawl_with_token_sees_authed_pages() {
        let server = MockServer::start().await;
        let base = spawn_site(&server).await;
        let root = base.as_str().trim_end_matches('/');
        let urls = crawl_from(&base, "/", Some("session=token-a")).await;
        assert!(urls.contains(&format!("{root}/admin/settings")), "{urls:?}");
    }

    #[tokio::test]
    async fn crawl_without_token_misses_authed_pages() {
        let server = MockServer::start().await;
        let base = spawn_site(&server).await;
        let urls = crawl_from(&base, "/", None).await;
        assert!(!urls.iter().any(|u| u.contains("/admin")));
    }

    #[tokio::test]
    async fn crawl_never_touches_logout_or_unfetchable_links() {
        let server = MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        let root = base.as_str().trim_end_matches('/');
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(
                        "<html><body><a href='/logout'>bye</a>\
                 <a href='/api/auth/signout'>signout</a>\
                 <a href='mailto:x@y.z'>mail</a>\
                 <a href='/home'>home</a></body></html>",
                    ),
            )
            .mount(&server)
            .await;
        // Only the legitimate page is ever fetched; /logout must not be.
        let logout = Mock::given(method("GET"))
            .and(path("/logout"))
            .respond_with(ResponseTemplate::new(200))
            .mount_as_scoped(&server)
            .await;
        let urls = crawl_from(&base, "/", None).await;
        assert!(
            logout.received_requests().await.is_empty(),
            "crawler fetched /logout"
        );
        assert!(urls.contains(&format!("{root}/home")), "{urls:?}");
        assert!(
            !urls
                .iter()
                .any(|u| u.contains("logout") || u.contains("signout") || u.contains("mailto")),
            "{urls:?}"
        );
    }

    /// A bare site with no links: only its wordlist hits are discoverable.
    async fn spawn_bare(server: &MockServer) -> Url {
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body><p>hi</p></body></html>"),
            )
            .mount(server)
            .await;
        Url::parse(&server.uri()).expect("url")
    }

    #[tokio::test]
    async fn wordlist_discovers_mounted_hidden_path() {
        let server = MockServer::start().await;
        let base = spawn_bare(&server).await;
        Mock::given(method("GET"))
            .and(path("/admin"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body>admin</body></html>"),
            )
            .mount(&server)
            .await;
        let urls = crawl_from(&base, "/", None).await;
        let root = base.as_str().trim_end_matches('/');
        assert!(urls.contains(&format!("{root}/admin")), "{urls:?}");
    }

    #[tokio::test]
    async fn wordlist_404_paths_are_not_recorded() {
        let server = MockServer::start().await;
        let base = spawn_bare(&server).await;
        let urls = crawl_from(&base, "/", None).await;
        // Every wordlist probe 404s (wiremock default), so nothing extra is found.
        assert!(
            !urls
                .iter()
                .any(|u| u.contains("/config") || u.contains("/metrics") || u.contains("/admin")),
            "{urls:?}"
        );
    }

    #[tokio::test]
    async fn file_words_get_an_lfi_canary_probe() {
        // /api/v1/download 404s a param-less GET but reads a file once the
        // file param carries a traversal: the canary retry must record it.
        let server = MockServer::start().await;
        let base = spawn_bare(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/v1/download"))
            .and(query_param("file", "../../../../etc/passwd"))
            .respond_with(ResponseTemplate::new(200).set_body_string("root:x:0:0"))
            .mount(&server)
            .await;
        let urls = crawl_from(&base, "/", None).await;
        let root = base.as_str().trim_end_matches('/');
        assert!(
            urls.contains(&format!("{root}/api/v1/download")),
            "{urls:?}"
        );
    }

    #[tokio::test]
    async fn bundle_fetch_decodes_invalid_utf8_lossily() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bundle.js"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/javascript")
                    .set_body_bytes(vec![b'f', b'e', b't', b'c', b'h', b'(', 0xff, b')', b';']),
            )
            .mount(&server)
            .await;
        let bundle = Url::parse(&format!("{}/bundle.js", server.uri())).expect("bundle URL");
        let source = fetch_bundle_source(&Client::new_lab(), &bundle, None, &FetchCache::default())
            .await
            .expect("lossy decode must preserve the bundle");
        assert!(source.contains('\u{fffd}'), "{source:?}");
    }

    #[tokio::test]
    async fn bundle_body_read_failure_retries_with_identity_encoding() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("local address");
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("first request");
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            loop {
                let read = first.read(&mut chunk).await.expect("read first request");
                request.extend_from_slice(&chunk[..read]);
                if read == 0 || request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            first
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial",
                )
                .await
                .expect("write truncated response");
            drop(first);

            let (mut second, _) = listener.accept().await.expect("retry request");
            let mut request = Vec::new();
            loop {
                let read = second.read(&mut chunk).await.expect("read retry request");
                request.extend_from_slice(&chunk[..read]);
                if read == 0 || request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let source = b"fetch('/retry');";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                source.len(),
                String::from_utf8_lossy(source)
            );
            second
                .write_all(response.as_bytes())
                .await
                .expect("write retry response");
            String::from_utf8_lossy(&request).to_ascii_lowercase()
        });

        let bundle = Url::parse(&format!("http://{address}/bundle.js")).expect("bundle URL");
        let source = fetch_bundle_source(&Client::new_lab(), &bundle, None, &FetchCache::default())
            .await
            .expect("retry response must be retained");
        let retry_request = server.await.expect("server task");
        assert_eq!(source, "fetch('/retry');");
        assert!(
            retry_request.contains("accept-encoding: identity"),
            "{retry_request}"
        );
    }

    #[tokio::test]
    async fn bundle_fetch_endpoints_are_resolved_and_recorded() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(
                        "<html><body><script src='/bundle.js'></script></body></html>",
                    ),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/bundle.js"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/javascript")
                    .set_body_string("fetch('/api/orders');"),
            )
            .mount(&server)
            .await;
        let base = Url::parse(&server.uri()).expect("url");
        let urls = crawl_from(&base, "/", None).await;
        let root = base.as_str().trim_end_matches('/');
        assert!(urls.contains(&format!("{root}/api/orders")), "{urls:?}");
    }

    #[tokio::test]
    async fn robots_txt_paths_are_seeded() {
        let server = MockServer::start().await;
        let base = spawn_bare(&server).await;
        Mock::given(method("GET"))
            .and(path("/robots.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "User-agent: *\n\
                 Disallow: /internal-only\n\
                 Allow: /public\n\
                 Disallow: /wild/*\n\
                 Sitemap: /unused-sitemap.xml\n",
            ))
            .mount(&server)
            .await;
        let urls = crawl_from(&base, "/", None).await;
        let root = base.as_str().trim_end_matches('/');
        assert!(urls.contains(&format!("{root}/internal-only")), "{urls:?}");
        assert!(urls.contains(&format!("{root}/public")), "{urls:?}");
        // Wildcard patterns cannot be matched, so they are skipped whole.
        assert!(!urls.iter().any(|u| u.contains("/wild/")), "{urls:?}");
    }

    #[tokio::test]
    async fn sitemap_locs_are_seeded() {
        let server = MockServer::start().await;
        let base = spawn_bare(&server).await;
        let root = base.as_str().trim_end_matches('/');
        let sitemap = format!(
            "<?xml version='1.0'?><urlset>\
             <url><loc>{root}/sitemap-a</loc></url>\
             <url><loc>{root}/sitemap-b?x=1&amp;y=2</loc></url>\
             </urlset>"
        );
        Mock::given(method("GET"))
            .and(path("/sitemap.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sitemap))
            .mount(&server)
            .await;
        let urls = crawl_from(&base, "/", None).await;
        assert!(urls.contains(&format!("{root}/sitemap-a")), "{urls:?}");
        assert!(
            urls.contains(&format!("{root}/sitemap-b?x=1&y=2")),
            "{urls:?}"
        );
    }

    #[tokio::test]
    async fn sitemap_index_nested_sitemap_pages_are_seeded() {
        let server = MockServer::start().await;
        let base = spawn_bare(&server).await;
        let root = base.as_str().trim_end_matches('/');
        Mock::given(method("GET"))
            .and(path("/sitemap.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                "<sitemapindex><sitemap>\
                 <loc>{root}/nested-sitemap.xml</loc>\
                 </sitemap></sitemapindex>"
            )))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/nested-sitemap.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                "<urlset><url><loc>{root}/nested-page</loc></url></urlset>"
            )))
            .mount(&server)
            .await;
        let urls = crawl_from(&base, "/", None).await;
        assert!(urls.contains(&format!("{root}/nested-page")), "{urls:?}");
    }

    #[tokio::test]
    async fn missing_robots_and_sitemap_record_nothing() {
        let server = MockServer::start().await;
        let base = spawn_bare(&server).await;
        let urls = crawl_from(&base, "/", None).await;
        // Wiremock 404s both documents; neither fetch may record a URL.
        assert!(
            !urls
                .iter()
                .any(|u| u.ends_with("/robots.txt") || u.ends_with("/sitemap.xml")),
            "{urls:?}"
        );
    }

    #[tokio::test]
    async fn crawl_metrics_classify_every_extracted_candidate() {
        let server = MockServer::start().await;
        let page = "<html><body>\
             <a href='/ok'>ok</a>\
             <a href=''>empty</a>\
             <a href='https://'>malformed</a>\
             <a href='https://evil.test/out'>external</a>\
             <a href='/ok'>duplicate</a>\
             </body></html>";
        for p in ["/", "/ok"] {
            Mock::given(method("GET"))
                .and(path(p))
                .respond_with(ResponseTemplate::new(200).set_body_string(page))
                .mount(&server)
                .await;
        }
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let crawler = Crawler {
            max_depth: 1,
            max_pages: 10,
            deadline: None,
            wordlist: true,
        };
        let (_, metrics) = crawler
            .crawl_with_metrics(
                &base,
                &Client::new_lab(),
                &guard,
                None,
                &FetchCache::default(),
            )
            .await
            .expect("crawl");
        assert!(metrics.reconciles(), "{metrics:?}");
        assert_eq!(metrics.raw_extracted, 10);
        assert_eq!(metrics.malformed_rejected, 4);
        assert_eq!(metrics.normalization_accepted, 6);
        assert_eq!(metrics.external_excluded, 2);
        assert_eq!(metrics.duplicates_removed, 3);
        assert_eq!(metrics.unique_in_scope, 1);
        assert_eq!(metrics.budget_consumed, 2);
        assert_eq!(metrics.termination_reason, "queue_exhausted");
        assert_eq!(metrics.remaining, 0);
    }

    #[tokio::test]
    async fn deadline_keeps_endpoints_found_so_far_and_counts_the_queue() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<html><body><a href='/slow'>slow</a><a href='/fast'>fast</a></body></html>",
            ))
            .mount(&server)
            .await;
        // `/slow` outlives the soft deadline and advertises `/late`. The batch
        // holding `/slow` and `/fast` was reserved before expiry, so both are
        // fetched; `/late` is only discovered after that batch finishes (past
        // expiry), so the crawl must stop without fetching it.
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(1500))
                    .set_body_string("<html><body><a href='/late'>late</a></body></html>"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/late"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/fast"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let crawler = Crawler {
            max_depth: 2,
            max_pages: 10,
            deadline: Some(std::time::Instant::now() + std::time::Duration::from_millis(300)),
            wordlist: true,
        };
        let (found, metrics) = crawler
            .crawl_with_metrics(
                &base,
                &Client::new_lab(),
                &guard,
                None,
                &FetchCache::default(),
            )
            .await
            .expect("crawl");
        // Endpoints recorded before the deadline are not discarded.
        assert!(
            found.iter().any(|u| u.ends_with("/slow")),
            "fetched page preserved: {found:?}"
        );
        assert!(
            found.iter().any(|u| u.ends_with("/fast")),
            "batch peer preserved: {found:?}"
        );
        assert!(
            found.iter().any(|u| u.ends_with("/late")),
            "link discovered past expiry still counted: {found:?}"
        );
        assert_eq!(metrics.termination_reason, "deadline");
        assert!(
            metrics.remaining > 0,
            "queued item left unclassified: {metrics:?}"
        );
        assert!(metrics.reconciles(), "schedule must balance: {metrics:?}");
        let requests = server.received_requests().await.expect("requests");
        assert!(
            requests.iter().any(|r| r.url.path() == "/fast"),
            "batch peers are fetched concurrently"
        );
        assert!(
            !requests.iter().any(|r| r.url.path() == "/late"),
            "a page queued after expiry is not fetched"
        );
    }

    #[tokio::test]
    async fn page_budget_is_reported_as_a_termination_reason() {
        let server = MockServer::start().await;
        let base = spawn_site(&server).await;
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let crawler = Crawler {
            max_depth: 3,
            max_pages: 1,
            deadline: None,
            wordlist: true,
        };
        let (_, metrics) = crawler
            .crawl_with_metrics(
                &base,
                &Client::new_lab(),
                &guard,
                None,
                &FetchCache::default(),
            )
            .await
            .expect("crawl");
        assert!(metrics.reconciles(), "{metrics:?}");
        assert_eq!(metrics.budget_configured, 1);
        assert_eq!(metrics.budget_consumed, 1);
        assert_eq!(metrics.termination_reason, "page_budget");
        assert_eq!(metrics.remaining, 0, "{metrics:?}");
        assert!(metrics.skipped > 0, "queued items are skipped at the cap");
    }
}
