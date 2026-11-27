//! Generic form-based web vulnerability scanner: CSRF token presence,
//! reflected-XSS canary, SQLi (error and time-based) signatures, SSTI
//! reflection and path-traversal/LFI reads on any HTML host.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use colored::Colorize;
use regex::Regex;
use riftlock_core::logln;
use riftlock_core::payloads::{
    param_vulns, payloads_for, payloads_for_param, Context, Payload, Verification, VulnType,
    CMDI_OUTPUT_MARKERS, HEADER_NAMES, SQLI_BOOLEAN_FALSE, SQLI_BOOLEAN_INT_FALSE,
    SQLI_BOOLEAN_INT_TRUE, SQLI_BOOLEAN_TRUE,
};
use riftlock_core::scope::ScopeGuard;
use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    classify, classify_baseline, error_outcome, looks_like_waf, merge, scan_error_outcome,
    CircuitBreaker, Coverage, Depth, EndpointOutcome, Evidence, Finding, ProofGate, ScanError,
    Scanner,
};
use riftlock_core::{CheckState, PendingCheck};
use scraper::{Html, Selector};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use url::Url;

// shortcut: only the first 10 forms are probed, a page could have hundreds; upgrade to pagination if needed
const MAX_FORMS: usize = 10;
// shortcut: only the first 6 query params are fuzzed; upgrade to a full crawl if coverage gaps show up
const MAX_URL_PARAMS: usize = 6;
const MAX_ENDPOINT_PARAMS: usize = 5;
// A parameter set this large is a search/filter form rather than an API
// surface; fuzzing all of it would spend the run on one endpoint.
const LARGE_PARAM_SET: usize = 20;
// Route concurrency scales with the selected scan tier.
const NORMAL_ENDPOINT_CONCURRENCY: usize = 4;
const READ_ENDPOINT_CONCURRENCY: usize = 16;
const GODMODE_ENDPOINT_CONCURRENCY: usize = 20;

const fn endpoint_concurrency(depth: Depth) -> usize {
    match depth {
        Depth::Normal => NORMAL_ENDPOINT_CONCURRENCY,
        Depth::Read => READ_ENDPOINT_CONCURRENCY,
        Depth::Godmode => GODMODE_ENDPOINT_CONCURRENCY,
        _ => NORMAL_ENDPOINT_CONCURRENCY,
    }
}

const fn allows_all_probes(depth: Depth) -> bool {
    matches!(depth, Depth::Godmode)
}

fn payload_enabled(depth: Depth, payload: &Payload) -> bool {
    match depth {
        Depth::Normal => false,
        // Read runs the same reflection/error payloads as before; only the
        // slow time-based probes are reserved for Godmode (the ID-shaped
        // exception is applied by `fuzz_url_params`, which knows the param).
        Depth::Read => payload.verify != Verification::TimeDelay,
        Depth::Godmode => true,
        _ => false,
    }
}
const ENDPOINT_BATCH_DELAY: std::time::Duration = std::time::Duration::from_millis(50);
const SQLI_BOOLEAN_PAIRS: [(&str, &str); 2] = [
    (SQLI_BOOLEAN_TRUE, SQLI_BOOLEAN_FALSE),
    (SQLI_BOOLEAN_INT_TRUE, SQLI_BOOLEAN_INT_FALSE),
];
// shortcut: read mode allows 640 endpoint payload requests per scan; godmode is bounded by its engine deadline.
const READ_PARAM_PROBES: usize = 640;
const DELAY_THRESHOLD_MS: u64 = 4500;
// Time-delay payloads must outlive SLEEP(5); ordinary probes inherit the
// shared client's latency-adaptive timeout.
const TIME_DELAY_CAP: std::time::Duration = std::time::Duration::from_secs(8);
// Well-known JSON keys the endpoint fuzzer fills, one payload per request.
const JSON_KEYS: [&str; 6] = ["email", "username", "password", "search", "q", "id"];
// Top hidden parameters worth guessing on an endpoint that advertises none.
const HIDDEN_PARAMS: [&str; 20] = [
    "admin", "debug", "test", "role", "id", "file", "url", "page", "callback", "redirect", "next",
    "return", "token", "key", "secret", "password", "user", "name", "email", "path",
];
// The two hidden switches probed for real, with the value that turns each on.
const HIDDEN_PARAM_SWITCHES: [(&str, &str); 2] = [("debug", "1"), ("admin", "true")];
// A hidden-parameter probe counts as a response change when the body length
// moves by more than a fixed floor plus 5% of the baseline.
const HIDDEN_PARAM_LENGTH_FLOOR: usize = 32;
const TEXT_TYPES: [&str; 6] = ["text", "search", "email", "url", "tel", "password"];
const SQLI_SIGNATURES: [&str; 11] = [
    "SQL syntax",
    "syntax error",
    "MySQL",
    "ORA-01756",
    "PostgreSQL",
    "SQLite",
    "psql:",
    "unrecognized token",
    "Sequelize",
    "unclosed quotation mark",
    "SQLSTATE",
];
// Recognized anti-CSRF field names, including framework defaults
// (`_token`, `__RequestVerificationToken`, XSRF/authenticity). A missing
// one is posture, not proof that a cross-site request is accepted.
const CSRF_KEYS: [&str; 8] = [
    "csrf",
    "xsrf",
    "token",
    "authenticity",
    "_token",
    "verificationtoken",
    "__requestverificationtoken",
    "anticsrf",
];
// UI only rendered for a signed-in user: a login page never carries these.
const AUTH_MARKERS: [&str; 4] = ["sign out", "log out", "logout", "dashboard"];
// Weaponized probes: exact payload strings, submitted as-is.
// LDAP filter bypass shares the SQL proof: denied baseline, granted session.
const AUTH_BYPASS_PAYLOADS: &[&str] = &["' OR 1=1--", "*)(uid=*))(|(uid=*"];
const XSS_PAYLOAD: &str = "<script>alert(1)</script>";
// Conventional query names on HTML pages and JSON APIs: the first raw
// reflection is proof, so the smart pass stops there.
const SMART_XSS_PARAMS: [&str; 1] = ["q"];
// Set-Cookie names that look like a session was issued on login.
const SESSION_COOKIE_KEYS: [&str; 4] = ["session", "auth", "token", "jwt"];
// Path fragments a post-login redirect target typically carries.
const POST_LOGIN_HINTS: [&str; 6] = ["dashboard", "home", "profile", "account", "admin", "index"];
// Deeper-DAST probes only fire on params whose name looks identifier-like.
const PROBE_SUFFIXES: [&str; 3] = ["id", "user", "search"];
const LFI_MARKERS: [(&str, Payload); 2] = [
    (
        "root:x:0:0",
        Payload {
            context: Context::UrlParam,
            vuln: VulnType::Lfi,
            payload: "../../../../etc/passwd",
            verify: Verification::Reflection,
        },
    ),
    (
        "[extensions]",
        Payload {
            context: Context::UrlParam,
            vuln: VulnType::Lfi,
            payload: "..\\..\\..\\..\\windows\\win.ini",
            verify: Verification::Reflection,
        },
    ),
];
// XXE canary: a DOCTYPE-declared external file entity the parser must
// resolve; `root:x:0:0` in the response is the resolved content.
const XXE_PAYLOAD: &str =
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>";
const XXE_MARKER: &str = "root:x:0:0";

/// One `<input>` of interest.
struct Input {
    name: String,
    kind: String,
    value: String,
}

/// A parsed `<form>` with its action resolved against the page URL.
struct Form {
    action: Url,
    post: bool,
    inputs: Vec<Input>,
}

// SPA shell markers: an Angular app root, Next.js internals, or the React
// mount point (exact `id="root"` attribute — `id="rootfoo"` is not a hit).
const SPA_MARKERS: [&str; 3] = ["<app-root>", "__next", "id=\"root\""];

/// True when the HTML is an SPA shell (`marker` present) carrying fewer
/// than 2 static forms: the browser-based SpaScanner owns such targets,
/// so static form scanning would only produce noise.
fn is_spa_shell(html: &str, form_count: usize) -> bool {
    form_count < 2 && SPA_MARKERS.iter().any(|m| html.contains(m))
}

/// Form-based misconfiguration scanner. The caller supplies the HTTP client;
/// redirects are followed according to that client's policy. The CLI disables
/// redirects so ScopeGuard remains the boundary for redirected requests.
#[derive(Debug, Default)]
pub struct GenericScanner {
    /// Run even when `matches()` rejects the host.
    pub force_run: bool,
    /// Probe tier controlling payload classes and endpoint concurrency.
    pub depth: Depth,
    /// The caller configured session credentials as client default headers.
    /// Only a supplied session can demonstrate cross-user object access.
    pub authenticated: bool,
    /// Crawler-discovered endpoints aggressively fuzzed in addition to the
    /// scanned URL (GET param + HTTP method probing, see `fuzz_endpoints`).
    pub endpoints: Vec<String>,
    /// Shared coverage counters: endpoints tested/skipped/blocked and
    /// vulnerability checks attempted/completed/inconclusive.
    pub coverage: riftlock_core::Coverage,
    /// Optional events for CLI progress and verified findings.
    pub events: Option<Sender<GenericEvent>>,
}

/// Live progress emitted by the Generic scanner.
#[derive(Debug, Clone)]
pub enum GenericEvent {
    /// The total endpoint work, including the base URL, and the exact list
    /// of URLs this pass will test (so the CLI can name any never reached).
    EndpointsStarted {
        total: usize,
        endpoints: Vec<String>,
    },
    /// One endpoint finished its complete probe pass. `found` is whether
    /// that endpoint produced any verified finding.
    EndpointComplete {
        completed: usize,
        total: usize,
        endpoint: String,
        found: bool,
    },
    /// A discovered endpoint the aggressive pass will not probe: another
    /// host, unparseable, a duplicate, or the scanned URL itself.
    EndpointSkipped { endpoint: String },
    /// A proof-gated finding admitted by the Generic scanner.
    Finding(Evidence),
}

fn has_key(name: &str, keys: &[&str]) -> bool {
    let lower = name.to_lowercase();
    keys.iter().any(|k| lower.contains(k))
}

fn extract_forms(doc: &Html, base: &Url) -> Vec<Form> {
    let Ok(form_sel) = Selector::parse("form") else {
        return Vec::new();
    };
    let Ok(input_sel) = Selector::parse("input") else {
        return Vec::new();
    };
    doc.select(&form_sel)
        .filter_map(|f| {
            let action = base.join(f.value().attr("action").unwrap_or("")).ok()?;
            let post = f
                .value()
                .attr("method")
                .is_some_and(|m| m.eq_ignore_ascii_case("post"));
            let inputs: Vec<Input> = f
                .select(&input_sel)
                .filter_map(|i| {
                    let name = i.value().attr("name")?;
                    Some(Input {
                        name: name.to_owned(),
                        kind: i.value().attr("type").unwrap_or("text").to_owned(),
                        value: i.value().attr("value").unwrap_or("").to_owned(),
                    })
                })
                .collect();
            (!inputs.is_empty()).then_some(Form {
                action,
                post,
                inputs,
            })
        })
        .collect()
}

/// Everything the weaponized probes need from a form submission: status,
/// redirect target, `Set-Cookie` headers, the URL the client ended on and
/// the body.
struct Resp {
    status: u16,
    location: Option<String>,
    cookies: Vec<String>,
    final_path: String,
    body: String,
    content_type: String,
    /// Request execution time, excluding the shared limiter's pacing wait.
    elapsed: std::time::Duration,
}

/// Submit `params` to the form's action; GET merges into the query string,
/// POST goes out urlencoded.
async fn submit(
    client: &Client,
    guard: &ScopeGuard,
    form: &Form,
    params: &[(String, String)],
    time_delay: bool,
) -> Result<Resp, ScanError> {
    let request = if form.post {
        // Read-only guards refuse this before the request is built.
        guard.check_request(&form.action, &reqwest::Method::POST)?;
        client.post(form.action.clone()).form(params)
    } else {
        guard.check(&form.action)?;
        client.get(form.action.clone()).query(params)
    };
    // Ordinary probes inherit the client's adaptive budget; only a
    // time-delay payload keeps an explicit cap.
    let request = if time_delay {
        request.timeout(TIME_DELAY_CAP)
    } else {
        request
    };
    let Some((resp, elapsed)) = send_unless_limited(request).await? else {
        return Err(ScanError::Io(std::io::Error::other(
            "rate limited endpoint",
        )));
    };
    collect(resp, elapsed).await
}

/// POST `body` as JSON to `url` (JSON endpoint fuzzing). Time-delay payload
/// posts keep an explicit cap — they are supposed to be slow.
async fn post_json(
    client: &Client,
    guard: &ScopeGuard,
    url: &Url,
    body: &str,
    time_delay: bool,
) -> Result<Resp, ScanError> {
    guard.check_request(url, &reqwest::Method::POST)?;
    let req = client
        .post(url.clone())
        .header("content-type", "application/json")
        .body(body.to_owned());
    let req = if time_delay {
        req.timeout(TIME_DELAY_CAP)
    } else {
        req
    };
    let Some((resp, elapsed)) = send_unless_limited(req).await? else {
        return Err(ScanError::Io(std::io::Error::other(
            "rate limited endpoint",
        )));
    };
    collect(resp, elapsed).await
}

/// A GET probe. `anonymous` suppresses the client's default auth headers with
/// explicit empty values, so the server sees no usable credentials while the
/// TLS, resolver and timeout configuration stay identical.
async fn get_probe(
    client: &Client,
    guard: &ScopeGuard,
    url: &Url,
    anonymous: bool,
) -> Result<Resp, ScanError> {
    guard.check_request(url, &reqwest::Method::GET)?;
    let mut req = client.get(url.clone());
    if anonymous {
        req = req
            .header(reqwest::header::AUTHORIZATION, "")
            .header(reqwest::header::COOKIE, "");
    }
    let Some((resp, elapsed)) = send_unless_limited(req).await? else {
        return Err(ScanError::Io(std::io::Error::other(
            "rate limited endpoint",
        )));
    };
    collect(resp, elapsed).await
}

/// The numeric id in the URL's last non-empty path segment, bumped by one.
/// Returns `None` when the tail is not a positive decimal resource id.
fn bumped_resource_id(url: &Url) -> Option<(u64, Url)> {
    let path = url.path().trim_end_matches('/');
    let (head, segment) = path.rsplit_once('/')?;
    let id: u64 = segment.parse().ok()?;
    let next = id.checked_add(1)?;
    let mut mutated = url.clone();
    mutated.set_path(&format!("{head}/{next}"));
    Some((id, mutated))
}

/// Does this body read as a data record rather than an error or empty shell?
/// Deliberately conservative: a generic denial page is never other-user data.
fn looks_like_record(resp: &Resp) -> bool {
    let body = resp.body.trim();
    if body.is_empty() {
        return false;
    }
    let lower = resp.body.to_ascii_lowercase();
    const ERROR_MARKERS: [&str; 8] = [
        "not found",
        "unauthorized",
        "forbidden",
        "does not exist",
        "no such",
        "access denied",
        "permission denied",
        "invalid token",
    ];
    if ERROR_MARKERS.iter().any(|marker| lower.contains(marker)) {
        return false;
    }
    resp.content_type.contains("json") || body.starts_with('{') || body.starts_with('[')
}

/// Drain a finished response into a [`Resp`] (status, redirect, cookies, body).
async fn collect(resp: reqwest::Response, elapsed: std::time::Duration) -> Result<Resp, ScanError> {
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let cookies = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let final_path = resp.url().path().to_owned();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let body = riftlock_core::body::text_limited_result(resp).await?;
    Ok(Resp {
        status,
        location,
        cookies,
        final_path,
        body,
        content_type,
        elapsed,
    })
}

/// One payload-probe send, counted for coverage: attempted before the
/// request goes out, then completed — or inconclusive on a WAF block
/// (403/406) or transport failure. Inconclusive is reported, never
/// fabricated into a finding.
async fn counted_send(
    fut: impl Future<Output = Result<Resp, ScanError>>,
    coverage: &Coverage,
) -> Result<Resp, ScanError> {
    let check = coverage.begin_check();
    match fut.await {
        Ok(resp) => {
            let state = if matches!(resp.status, 403 | 406 | 429 | 503) {
                CheckState::Inconclusive
            } else {
                CheckState::Completed
            };
            let _ = check.finish(state);
            Ok(resp)
        }
        Err(e) => {
            let state = if matches!(&e, ScanError::Http(e) if e.is_timeout()) {
                CheckState::TimedOut
            } else if matches!(e, ScanError::Http(_) | ScanError::Io(_)) {
                CheckState::Failed
            } else {
                CheckState::Inconclusive
            };
            let _ = check.finish(state);
            Err(e)
        }
    }
}

/// Cookie name from a `Set-Cookie` header value (`"SID=abc; Path=/"`).
fn cookie_name(value: &str) -> &str {
    value.split('=').next().unwrap_or("").trim()
}

/// Is `path` a post-login page a successful login would redirect to?
fn post_login(path: &str) -> bool {
    let lower = path.to_lowercase();
    POST_LOGIN_HINTS.iter().any(|h| lower.contains(h))
}

/// Path fragments marking a login-shaped endpoint (the auth-bypass
/// mini-pass feeds these the credential bypasses as JSON). Deliberately
/// wider than [`post_login`], which classifies redirect *targets* — a
/// redirect to /login is a denial, not a login endpoint.
fn is_login_endpoint(path: &str) -> bool {
    let lower = path.to_lowercase();
    ["login", "signin", "auth", "session", "ldap"]
        .iter()
        .any(|h| lower.contains(h))
}

/// Did this response grant a session? Either a session-looking
/// `Set-Cookie`, or a redirect to a post-login path (a `Location` header,
/// or the final URL when the client already followed redirects).
fn session_granted(cookies: &[String], redirect_path: Option<&str>) -> bool {
    cookies
        .iter()
        .any(|c| has_key(cookie_name(c), &SESSION_COOKIE_KEYS))
        || redirect_path.is_some_and(post_login)
}

/// JSON login APIs issue the session as a body token instead of a cookie
/// (OWASP Juice Shop returns `{"authentication":{"token":...}}`). Only
/// meaningful against a denied baseline, so a plain `{"token":...}` page
/// cannot fabricate a bypass.
fn body_session_granted(resp: &Resp) -> bool {
    resp.status / 100 == 2 && resp.body.contains("\"token\"")
}

/// Login body with both credential fields carrying the same bypass payload:
/// Juice Shop matches on `email`, other stacks echo `password` into their
/// own query.
fn login_body(payload: &str) -> String {
    serde_json::json!({ "email": payload, "password": payload }).to_string()
}

/// [`session_granted`] applied to a submission: the redirect target is the
/// `Location` header on a 3xx, otherwise the final path when the client
/// was redirected somewhere other than the form action itself.
fn granted(resp: &Resp, action_path: &str) -> bool {
    let redirect = if (300..400).contains(&resp.status) {
        resp.location.clone()
    } else if resp.final_path != action_path {
        Some(resp.final_path.clone())
    } else {
        None
    };
    session_granted(&resp.cookies, redirect.as_deref())
}

/// Does `body` place `payload` in a position the HTML parser makes
/// executable: a script element's source or an `on*` handler attribute?
fn executable_html(body: &str, payload: &str) -> bool {
    let any = Selector::parse("*").expect("static selector");
    let script = Selector::parse("script").expect("static selector");
    let fragment = Html::parse_fragment(payload);
    let scripts: Vec<String> = fragment.select(&script).map(|e| e.inner_html()).collect();
    let handlers: Vec<(String, String)> = fragment
        .select(&any)
        .flat_map(|e| {
            e.value()
                .attrs()
                .filter(|(n, _)| n.starts_with("on"))
                .map(|(n, v)| (n.to_owned(), v.to_owned()))
                .collect::<Vec<_>>()
        })
        .collect();
    if scripts.is_empty() && handlers.is_empty() {
        return false;
    }
    let doc = Html::parse_fragment(body);
    doc.select(&any).any(|e| {
        (e.value().name() == "script"
            && scripts.iter().any(|s| e.inner_html().contains(s.as_str())))
            || e.value()
                .attrs()
                .any(|(n, v)| handlers.iter().any(|(hn, hv)| n == hn && v == hv))
    })
}

/// Is `payload` present verbatim (unescaped) in `body` but absent from the
/// clean `baseline`, on an HTML response, in an executable position?
/// Escaped echoes and raw text in JSON/plain bodies are negatives: the
/// browser does not execute them.
#[cfg(test)]
fn reflected_raw(body: &str, payload: &str, baseline: &str, content_type: &str) -> bool {
    matches!(
        xss_proof(body, payload, baseline, content_type),
        Some(Proof::Xss)
    )
}

/// XSS proof for one reflected payload: executable HTML is a confirmed
/// `Xss`; any other raw reflection is informational (`XssReflection`) —
/// detection is kept, but JSON/plain text and inert HTML never reach High.
fn xss_proof(body: &str, payload: &str, baseline: &str, content_type: &str) -> Option<Proof> {
    if !(body.contains(payload) && !baseline.contains(payload)) {
        return None;
    }
    let kind = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if kind == "text/html" && executable_html(body, payload) {
        return Some(Proof::Xss);
    }
    Some(Proof::XssReflection(if kind.contains("json") {
        "json"
    } else if kind == "text/html" {
        "html-inert"
    } else {
        "text"
    }))
}

/// Names of the username (first non-password text-like input) and password
/// inputs of a login form, or `None` if this is not one.
fn login_fields(form: &Form) -> Option<(String, String)> {
    let pass = form
        .inputs
        .iter()
        .find(|i| i.kind.eq_ignore_ascii_case("password"))
        .map(|i| i.name.clone())?;
    let user = form
        .inputs
        .iter()
        .find(|i| {
            !i.kind.eq_ignore_ascii_case("password")
                && !i.kind.eq_ignore_ascii_case("hidden")
                && TEXT_TYPES.contains(&i.kind.to_lowercase().as_str())
        })
        .map(|i| i.name.clone())?;
    Some((user, pass))
}

/// `params` with both credential fields set to `value`.
fn creds(form: &Form, user: &str, pass: &str, value: &str) -> Vec<(String, String)> {
    form.inputs
        .iter()
        .map(|i| {
            let v = if i.name == user || i.name == pass {
                value.to_owned()
            } else {
                i.value.clone()
            };
            (i.name.clone(), v)
        })
        .collect()
}

/// Does the param name look identifier-like (`id`/`user`/`search` suffix)?
fn probe_param(name: &str) -> bool {
    let lower = name.to_lowercase();
    PROBE_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// `params` with `name`'s value replaced, everything else untouched.
fn with_value(params: &[(String, String)], name: &str, value: &str) -> Vec<(String, String)> {
    params
        .iter()
        .map(|(n, v)| {
            if n == name {
                (n.clone(), value.to_owned())
            } else {
                (n.clone(), v.clone())
            }
        })
        .collect()
}

/// Time-based blind SQLi is proven only when the injected request is more
/// than 4.5 s slower than baseline (SLEEP(5), not jitter); returns the
/// measured extra delay.
fn time_delay_finding(baseline_ms: u64, injected_ms: u64) -> Option<u64> {
    delay_finding_ms(baseline_ms, injected_ms, DELAY_THRESHOLD_MS)
}

/// Delay proof with a threshold parameter, so tests can drive it with mock
/// delays far below the production 4.5 s floor.
fn delay_finding_ms(baseline_ms: u64, injected_ms: u64, threshold_ms: u64) -> Option<u64> {
    if injected_ms > baseline_ms.saturating_add(threshold_ms) {
        Some(injected_ms - baseline_ms)
    } else {
        None
    }
}

/// What one injected response proved against the clean baseline.
#[derive(Debug)]
enum Proof {
    /// Database error signature matched.
    Error(&'static str),
    /// Measured extra delay over baseline, in milliseconds.
    Delay(u64),
    /// Raw unescaped payload reflection.
    Xss,
    /// Raw payload in a non-executable context (`json`, `text`, `html-inert`).
    XssReflection(&'static str),
    /// Template expression evaluated to `49`.
    Ssti,
    /// File-content marker came back.
    Lfi(&'static str),
    /// Real command output (uid=, passwd, shell path, ping) absent from the
    /// baseline.
    Cmdi,
    /// JSON query operator granted a session the baseline was denied.
    NoSql,
    /// Internal/metadata content came back for an injected URL.
    Ssrf,
    /// The `1=1` and `1=2` responses diverged while `1=1` tracked the
    /// baseline: boolean-blind injection.
    Boolean,
}

impl Proof {
    /// Vulnerability class, the dedup key alongside url and param.
    fn class(&self) -> &'static str {
        match self {
            Proof::Error(_) | Proof::Delay(_) | Proof::Boolean => "SqlInjection",
            Proof::Xss => "Xss",
            Proof::XssReflection(_) => "XssReflection",
            Proof::Ssti => "Ssti",
            Proof::Lfi(_) => "Lfi",
            Proof::Cmdi => "CommandInjection",
            Proof::NoSql => "NoSqlInjection",
            Proof::Ssrf => "Ssrf",
        }
    }
}

/// Differential verification of one injected response against the clean
/// baseline, per the payload's cataloged verification method.
fn proof_vs_baseline(
    baseline: &str,
    baseline_ms: u64,
    body: &str,
    elapsed_ms: u64,
    p: &Payload,
    threshold_ms: u64,
    content_type: &str,
) -> Option<Proof> {
    match (p.vuln, p.verify) {
        (VulnType::SqlInjection, Verification::ErrorSignature) => {
            let lower = body.to_lowercase();
            let base = baseline.to_lowercase();
            SQLI_SIGNATURES
                .iter()
                // Injection-induced only: the clean baseline must not
                // already carry the signature (docs pages name engines).
                .find(|s| lower.contains(&s.to_lowercase()) && !base.contains(&s.to_lowercase()))
                .map(|sig| Proof::Error(sig))
        }
        (VulnType::SqlInjection, Verification::TimeDelay) => {
            delay_finding_ms(baseline_ms, elapsed_ms, threshold_ms).map(Proof::Delay)
        }
        (VulnType::Xss, Verification::Reflection) => {
            xss_proof(body, p.payload, baseline, content_type)
        }
        (VulnType::Ssti, Verification::Reflection) => {
            (body.contains("49") && !body.contains("7*7") && !baseline.contains("49"))
                .then_some(Proof::Ssti)
        }
        (VulnType::Lfi, Verification::Reflection) => LFI_MARKERS
            .iter()
            .find(|(m, _)| body.contains(m) && !baseline.contains(m))
            .map(|(m, _)| Proof::Lfi(m)),
        // Confirmed only by real command output, never by reflection: a page
        // echoing the payload's `;`, `|`, or marker text is not execution.
        (VulnType::CommandInjection, Verification::Reflection) => CMDI_OUTPUT_MARKERS
            .iter()
            .find(|marker| body.contains(**marker) && !baseline.contains(**marker))
            .map(|_| Proof::Cmdi),
        // Metadata or passwd content came back for the injected URL but was
        // absent from the clean baseline (is_ssrf semantics, differential).
        (VulnType::Ssrf, Verification::Reflection) => {
            let hit = |b: &str| b.contains("ami-id") || b.contains("root:x:0:0");
            (hit(body) && !hit(baseline)).then_some(Proof::Ssrf)
        }
        _ => None,
    }
}

fn boolean_pair_index(payload: &str) -> Option<usize> {
    SQLI_BOOLEAN_PAIRS
        .iter()
        .enumerate()
        .find_map(|(pair, (truth, falsity))| {
            if payload == *truth {
                Some(pair * 2)
            } else if payload == *falsity {
                Some(pair * 2 + 1)
            } else {
                None
            }
        })
}

fn prove_boolean_pairs(baseline: &str, probes: &[Option<Probe>; 4]) -> Option<&'static str> {
    [(0, 1), (2, 3)].into_iter().find_map(|(truth, falsity)| {
        probes[truth]
            .as_ref()
            .zip(probes[falsity].as_ref())
            .is_some_and(|(truth, falsity)| boolean_proof(baseline, truth, falsity))
            .then_some(SQLI_BOOLEAN_PAIRS[truth / 2].0)
    })
}

/// True only when both branches return the same successful status, the truthy
/// branch tracks the clean baseline, and the false branch's body diverges.
/// A status change (200 vs 500 or 403) is an error or block page, not proof;
/// echoing either payload back is reflection, not SQL evaluation.
fn boolean_proof(baseline: &str, truthy: &Probe, falsy: &Probe) -> bool {
    (200..300).contains(&truthy.status)
        && truthy.status == falsy.status
        && !truthy.body.contains(&truthy.payload)
        && !falsy.body.contains(&falsy.payload)
        && !bodies_diverge(baseline, &truthy.body)
        && bodies_diverge(&truthy.body, &falsy.body)
}

/// Status-independent page weight: charset bytes outside whitespace.
fn body_weight(body: &str) -> usize {
    body.split_whitespace().map(str::len).sum()
}

/// True when the bodies differ by more than a quarter of the larger weight.
fn bodies_diverge(a: &str, b: &str) -> bool {
    let (a, b) = (body_weight(a), body_weight(b));
    a.max(b) > 0 && a.min(b) * 4 < a.max(b) * 3
}

/// Sensitive paths that must never serve content anonymously.
fn is_sensitive_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    let sensitive = [
        "/admin",
        "/my-account",
        "/account",
        "/dashboard",
        "/internal",
        "/manage",
        "/wp-admin",
    ];
    sensitive.iter().any(|prefix| {
        p == *prefix
            || p.strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }) && !["login", "signin", "sign-in", "register", "signup"]
        .iter()
        .any(|word| p.contains(word))
}

/// Signed-in-only marker present in `body`.
fn dashboard_marker(body: &str) -> Option<&'static str> {
    let lower = body.to_ascii_lowercase();
    AUTH_MARKERS.iter().copied().find(|m| lower.contains(m))
}

/// Select a proof marker for an anonymously exposed sensitive path. Only a
/// 200 carrying a signed-in UI marker proves protected content was served;
/// a bare 200, a 403, a redirect, or a generic SPA shell proves nothing.
fn access_marker(status: u16, body: &str) -> Option<&'static str> {
    (status == 200).then(|| dashboard_marker(body)).flatten()
}

/// Push `evidence` unless (class, url, param) already produced a finding:
/// first proof wins, heuristics never reach the report.
fn emit_unique(
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, String, &'static str)>,
    class: &'static str,
    url: &str,
    param: &str,
    evidence: Evidence,
) -> Result<(), ScanError> {
    if seen.insert((url.to_owned(), param.to_owned(), class)) {
        findings.push(ProofGate::admit(evidence)?);
        if !matches!(class, "Xss" | "XssReflection") {
            if param.is_empty() {
                logln!(
                    "{} on {url}",
                    format!("[!] {class} Found").truecolor(255, 105, 180)
                );
            } else {
                logln!(
                    "{} on {url} (param {param})",
                    format!("[!] {class} Found").truecolor(255, 105, 180)
                );
            }
        }
    }
    Ok(())
}

/// Live Stripe secret keys: `sk_live_` plus 24+ alphanumeric chars.
static STRIPE_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk_live_[0-9A-Za-z]{24}").expect("static regex"));
/// Google API keys: `AIza` plus 35 chars of the key alphabet.
static GOOGLE_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"AIza[0-9A-Za-z\-_]{35}").expect("static regex"));
/// AWS access key ids: `AKIA` plus 16 uppercase alphanumerics.
static AWS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("static regex"));
/// US SSN with strict non-digit boundaries on both sides.
static SSN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\A|[^\d])\d{3}-\d{2}-\d{4}(?:[^\d]|\z)").expect("static regex")
});
/// JWT-shaped token: three dot-separated base64url segments.
static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").expect("static regex")
});

/// Scan one fetched body for live secrets and sensitive JWT claims: the
/// exact secret pattern or a decoded sensitive claim is the proof, never a
/// keyword heuristic. Dedup per (url, data_type) / (url, issue) through the
/// shared emit path. Public because the SpaScanner's static fallback
/// fetches script bundles — the surfaces where leaked secrets live — and
/// this crate owns the pass.
///
/// # Errors
/// Emitting a finding failed (gate admission or dedup bookkeeping).
pub fn scan_secrets(
    url: &str,
    body: &str,
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, String, &'static str)>,
) -> Result<(), ScanError> {
    for (data_type, re) in [
        ("stripe_secret_key", &*STRIPE_KEY),
        ("google_api_key", &*GOOGLE_KEY),
        ("aws_access_key_id", &*AWS_KEY),
        ("ssn", &*SSN),
    ] {
        if re.is_match(body) {
            emit_unique(
                findings,
                seen,
                "SensitiveDataExposure",
                url,
                data_type,
                Evidence::SensitiveDataExposure {
                    url: url.to_owned(),
                    data_type: data_type.to_owned(),
                },
            )?;
        }
    }
    // A JWT whose decoded payload carries `role: "admin"` or a password
    // field leaks an authorization decision in a forgeable token.
    for m in JWT.find_iter(body) {
        let sensitive = m
            .as_str()
            .split('.')
            .nth(1)
            .and_then(|seg| URL_SAFE_NO_PAD.decode(seg).ok())
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|claims| {
                claims.get("role").and_then(|r| r.as_str()) == Some("admin")
                    || claims.get("password").is_some()
            });
        if sensitive {
            emit_unique(
                findings,
                seen,
                "JwtVulnerability",
                url,
                "sensitive_claim",
                Evidence::JwtVulnerability {
                    endpoint: url.to_owned(),
                    issue: "sensitive_claim".to_owned(),
                },
            )?;
            break;
        }
    }
    Ok(())
}

/// Turn a proven differential into a deduped finding.
fn admit_proof(
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, String, &'static str)>,
    url: &str,
    param: &str,
    proof: Proof,
    payload: &str,
) -> Result<(), ScanError> {
    let evidence = match proof {
        Proof::Error(sig) => Evidence::SqliError {
            url: url.to_owned(),
            param: param.to_owned(),
            error_signature: sig.to_owned(),
        },
        Proof::Delay(delay_ms) => Evidence::SqliTimeDelay {
            url: url.to_owned(),
            param: param.to_owned(),
            delay_ms,
        },
        Proof::Xss => Evidence::ReflectedXss {
            url: url.to_owned(),
            param: param.to_owned(),
            payload: payload.to_owned(),
        },
        Proof::XssReflection(context) => Evidence::XssReflection {
            url: url.to_owned(),
            param: param.to_owned(),
            context: context.to_owned(),
        },
        Proof::Ssti => Evidence::SstiReflection {
            url: url.to_owned(),
            param: param.to_owned(),
            evaluated_string: "49".to_owned(),
        },
        Proof::Lfi(marker) => Evidence::LfiRead {
            url: url.to_owned(),
            param: param.to_owned(),
            file_read: marker.to_owned(),
        },
        Proof::Cmdi => Evidence::CommandInjection {
            url: url.to_owned(),
            param: param.to_owned(),
            payload: payload.to_owned(),
        },
        Proof::NoSql => Evidence::NoSqlInjection {
            url: url.to_owned(),
            param: param.to_owned(),
            payload: payload.to_owned(),
        },
        Proof::Ssrf => Evidence::SsrF {
            endpoint: url.to_owned(),
            payload: payload.to_owned(),
        },
        Proof::Boolean => Evidence::SqlInjection {
            url: url.to_owned(),
            param: param.to_owned(),
            payload: payload.to_owned(),
        },
    };
    emit_unique(findings, seen, proof.class(), url, param, evidence)
}

/// Query string with `name` set to `value`, pairs joined raw (`&` escaped in
/// values only). The URL crate applies its minimal transport encoding on
/// `set_query`, keeping payloads like `../` readable on the wire — that is
/// what makes the percent-encoded WAF-evasion retry a different request.
fn raw_query(url: &Url, name: &str, value: &str) -> String {
    let mut found = false;
    let mut pairs: Vec<String> = url
        .query_pairs()
        .map(|(k, v)| {
            let v = if k == name {
                found = true;
                value.to_owned()
            } else {
                v.into_owned()
            };
            format!(
                "{}={}",
                k.as_ref().replace('&', "%26"),
                v.replace('&', "%26")
            )
        })
        .collect();
    // Endpoint fuzzing appends params the URL does not carry yet.
    if !found {
        pairs.push(format!(
            "{}={}",
            name.replace('&', "%26"),
            value.replace('&', "%26")
        ));
    }
    pairs.join("&")
}

/// `url` with query param `name` set to `value`, all other params untouched.
fn url_with_param(url: &Url, name: &str, value: &str) -> Url {
    let mut out = url.clone();
    out.set_query(Some(&raw_query(url, name, value)));
    out
}

/// `s` with every byte outside `[A-Za-z0-9-_.~]` percent-encoded: the
/// fully-encoded WAF-evasion variant of a payload.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// True when the response looks like a JSON API endpoint.
fn looks_like_json(content_type: &str, body: &str) -> bool {
    let t = body.trim_start();
    content_type.contains("json") || t.starts_with('{') || t.starts_with('[')
}

/// One clean-baseline measurement shared by the fuzz stages: body, elapsed
/// time and the delay threshold (production 4.5 s, test-time lowered).
struct Baseline<'a> {
    body: &'a str,
    ms: u64,
    threshold_ms: u64,
}

/// What one fired param probe sent and got back: the probed URL, status and
/// `Location` (an open redirect is proven from the redirect, not the body),
/// the response body, elapsed ms and the payload string for the evidence
/// (the encoded retry's is suffixed " (URL-encoded)" — that is the note).
struct Probe {
    target: String,
    status: u16,
    location: Option<String>,
    body: String,
    content_type: String,
    elapsed_ms: u64,
    payload: String,
}

/// A 429/503 means back off the whole endpoint: `None` marks the probe
/// inconclusive and the caller stops firing at that target.
/// Send unless the endpoint answers 429/503, keeping the request-only elapsed
/// time for time-delay proofs. The limiter's pacing wait is excluded.
async fn send_unless_limited(
    request: riftlock_core::ScopedRequestBuilder,
) -> Result<Option<(reqwest::Response, std::time::Duration)>, ScanError> {
    let (response, elapsed) = request.send_timed().await?;
    if matches!(response.status().as_u16(), 429 | 503) {
        drop(response);
        return Ok(None);
    }
    Ok(Some((response, elapsed)))
}

/// One endpoint's clean baseline: a full-body GET with no explicit timeout,
/// so the shared client's adaptive budget (root latency × 3, floor 1 s)
/// applies instead of a fixed probe cap.
async fn baseline_get(client: &Client, endpoint: &Url) -> Result<Resp, ScanError> {
    let (response, elapsed) = client.get(endpoint.clone()).send_once_timed().await?;
    collect(response, elapsed).await
}

/// A WAF answer: a rate-limit status, a challenge page served with 403, or a
/// 2xx interstitial. The body is what separates a WAF block page from an
/// ordinary forbidden response.
fn waf_answer(resp: &Resp) -> bool {
    // Baseline 401/403 are authentication-required even when the denial page
    // mentions a WAF; do not override that explicit endpoint classification.
    !matches!(resp.status, 401 | 403 | 404 | 410)
        && (matches!(resp.status, 406 | 429 | 503)
            || ((200..=299).contains(&resp.status) && looks_like_waf(&resp.body)))
}

/// The same check for a page already read by `run`.
/// Baseline verdict: a usable response, or two WAF answers in a row.
enum BaselineRead {
    Ready(Resp),
    WafBlocked,
}

/// Fetch the baseline and confirm a WAF answer exactly once. An isolated
/// block (one challenge page, one 429) proceeds with the confirming
/// response; two in a row close the endpoint before any payload is sent.
async fn baseline_with_waf_guard(
    client: &Client,
    endpoint: &Url,
    first: Resp,
) -> Result<BaselineRead, ScanError> {
    debug_assert!(waf_answer(&first));
    let second = baseline_get(client, endpoint).await?;
    if waf_answer(&second) {
        return Ok(BaselineRead::WafBlocked);
    }
    Ok(BaselineRead::Ready(second))
}

/// Outcome of one counted send: a response with its still-open check guard,
/// or a rate-limited endpoint whose check is already terminal.
enum CountedSend<'a> {
    Response(reqwest::Response, std::time::Duration, PendingCheck<'a>),
    Limited,
}

/// Count one logical probe and flag its endpoint as rate limited.
async fn send_counted<'a>(
    request: riftlock_core::ScopedRequestBuilder,
    coverage: &'a Coverage,
    limited: &AtomicBool,
) -> Result<CountedSend<'a>, ScanError> {
    let check = coverage.begin_check();
    match send_unless_limited(request).await {
        Ok(Some((response, elapsed))) => Ok(CountedSend::Response(response, elapsed, check)),
        Ok(None) => {
            limited.store(true, Ordering::Relaxed);
            let _ = check.finish(CheckState::Inconclusive);
            Ok(CountedSend::Limited)
        }
        Err(error) => {
            let state = if matches!(&error, ScanError::Http(e) if e.is_timeout()) {
                CheckState::TimedOut
            } else {
                CheckState::Failed
            };
            let _ = check.finish(state);
            Err(error)
        }
    }
}

/// One GET param probe with the WAF-evasion retry: the payload fires as-is,
/// and on a 403/406 block the exact same request is retried once with the
/// payload fully percent-encoded. Each request spends one unit of `budget`
/// (0 = nothing fires).
#[allow(clippy::too_many_arguments)] // probe shape, same as fuzz_headers
async fn fire_param_probe(
    client: &Client,
    guard: &ScopeGuard,
    coverage: &Coverage,
    url: &Url,
    name: &str,
    p: &Payload,
    budget: &AtomicUsize,
    baseline: &str,
    limited: &AtomicBool,
    depth: Depth,
) -> Result<Option<Probe>, ScanError> {
    let payload = p.payload;
    let time_delay = p.verify == Verification::TimeDelay;
    if time_delay
        && !allows_all_probes(depth)
        && !read_time_delay_allowed(depth, name, url, baseline)
    {
        return Ok(None);
    }
    if !spend(budget) {
        return Ok(None);
    }
    let value = if p.vuln == VulnType::SqlInjection
        && (payload.starts_with('\'') || payload.starts_with('"'))
    {
        let original = url
            .query_pairs()
            .find(|(key, _)| key == name)
            .map_or_else(String::new, |(_, value)| value.into_owned());
        format!("{original}{payload}")
    } else {
        payload.to_owned()
    };
    let target = url_with_param(url, name, &value);
    if let Err(error) = guard.check(&target) {
        if !matches!(error, riftlock_core::ScopeError::ReadOnly { .. }) {
            coverage.scope_rejected_check();
        }
        return Ok(None);
    }
    let (resp, elapsed, check) = match send_counted(
        if time_delay {
            client.get(target.clone()).timeout(TIME_DELAY_CAP)
        } else {
            client.get(target.clone())
        },
        coverage,
        limited,
    )
    .await?
    {
        CountedSend::Response(response, elapsed, guard) => (response, elapsed, guard),
        CountedSend::Limited => return Ok(None),
    };
    let elapsed = elapsed.as_millis() as u64;
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    // A failed or oversized body read is one inconclusive probe.
    let Ok(body) = riftlock_core::body::text_limited_result(resp).await else {
        let _ = check.finish(CheckState::Inconclusive);
        return Ok(None);
    };
    // For a boolean pair, a 403/406 on the false half is the database's
    // answer, not a WAF block: report it as the differential and skip the
    // encoded retry.
    if (status != 403 && status != 406) || p.verify == Verification::Boolean {
        let _ = check.finish(CheckState::Completed);
        return Ok(Some(Probe {
            target: target.as_str().to_owned(),
            status,
            location,
            body,
            content_type,
            elapsed_ms: elapsed,
            payload: payload.to_owned(),
        }));
    }
    let _ = check.finish(CheckState::Inconclusive);
    // Blocked: the WAF saw the raw pattern; try the encoded variant once.
    if !spend(budget) {
        return Ok(None);
    }
    let target = url_with_param(url, name, &pct_encode(payload));
    if let Err(error) = guard.check(&target) {
        if !matches!(error, riftlock_core::ScopeError::ReadOnly { .. }) {
            coverage.scope_rejected_check();
        }
        return Ok(None);
    }
    let (resp, elapsed, check) = match send_counted(
        if time_delay {
            client.get(target.clone()).timeout(TIME_DELAY_CAP)
        } else {
            client.get(target.clone())
        },
        coverage,
        limited,
    )
    .await?
    {
        CountedSend::Response(response, elapsed, guard) => (response, elapsed, guard),
        CountedSend::Limited => return Ok(None),
    };
    let elapsed = elapsed.as_millis() as u64;
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let Ok(body) = riftlock_core::body::text_limited_result(resp).await else {
        let _ = check.finish(CheckState::Inconclusive);
        return Ok(None);
    };
    let state = if status == 403 || status == 406 {
        CheckState::Inconclusive
    } else {
        CheckState::Completed
    };
    let _ = check.finish(state);
    Ok(Some(Probe {
        target: target.as_str().to_owned(),
        status,
        location,
        body,
        content_type,
        elapsed_ms: elapsed,
        payload: format!("{payload} (URL-encoded)"),
    }))
}

/// Charge one request against `budget`; false when nothing is left.
fn spend(budget: &AtomicUsize) -> bool {
    budget
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
        .is_ok()
}

/// Fire one endpoint's payload jobs sequentially, so requests go out one at
/// a time; the caller proofs them after this batch finishes.
#[allow(clippy::too_many_arguments)] // probe shape, same as fuzz_headers
async fn fire_batch<'a>(
    client: &'a Client,
    guard: &'a ScopeGuard,
    coverage: &'a Coverage,
    url: &'a Url,
    budget: &'a AtomicUsize,
    baseline: &'a str,
    limited: &'a AtomicBool,
    depth: Depth,
    jobs: Vec<(&'a str, &'static Payload)>,
) -> Vec<(&'a str, &'static Payload, Result<Option<Probe>, ScanError>)> {
    let mut results = Vec::with_capacity(jobs.len());
    for (name, p) in jobs {
        if limited.load(Ordering::Relaxed) {
            break;
        }
        let result = fire_param_probe(
            client, guard, coverage, url, name, p, budget, baseline, limited, depth,
        )
        .await;
        results.push((name, p, result));
        // Rate limited: stop hitting this endpoint rather than get banned.
        if limited.load(Ordering::Relaxed) {
            break;
        }
    }
    results
}

/// Resolve redirect candidates like a browser and require the destination to
/// match the external host supplied by the payload.
fn redirects_to_payload_host(target: &str, destination: &str, payload: &str) -> bool {
    let Ok(base) = Url::parse(target) else {
        return false;
    };
    let resolve = |value: &str| base.join(&value.replace('\\', "/")).ok();
    let (Some(destination), Some(expected)) = (resolve(destination), resolve(payload)) else {
        return false;
    };
    matches!(destination.scheme(), "http" | "https")
        && matches!(expected.scheme(), "http" | "https")
        && destination.origin() != base.origin()
        && expected.origin() != base.origin()
        && destination.host_str() == expected.host_str()
}

/// Extract the URL from a refresh meta element, if present.
fn meta_refresh_destination(body: &str) -> Option<String> {
    let document = Html::parse_fragment(body);
    let selector = Selector::parse("meta[http-equiv]").ok()?;
    for element in document.select(&selector) {
        if !element
            .value()
            .attr("http-equiv")
            .is_some_and(|value| value.eq_ignore_ascii_case("refresh"))
        {
            continue;
        }
        let content = element.value().attr("content")?;
        let (_, refresh) = content.split_once(';')?;
        let (key, value) = refresh.trim().split_once('=')?;
        if key.trim().eq_ignore_ascii_case("url") {
            return Some(
                value
                    .trim()
                    .trim_matches(|ch| ch == '\'' || ch == '\"')
                    .to_owned(),
            );
        }
    }
    None
}

/// An [`VulnType::OpenRedirect`] requires a 3xx or meta-refresh navigation to
/// the external host injected by the payload; reflection alone is not proof.
fn admit_redirect(
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, String, &'static str)>,
    param: &str,
    p: &Payload,
    probe: &Probe,
) -> Result<(), ScanError> {
    let redirected = (300..400).contains(&probe.status)
        && probe
            .location
            .as_deref()
            .is_some_and(|location| redirects_to_payload_host(&probe.target, location, p.payload));
    let meta_refresh = probe.status == 200
        && meta_refresh_destination(&probe.body).is_some_and(|destination| {
            redirects_to_payload_host(&probe.target, &destination, p.payload)
        });
    if p.vuln == VulnType::OpenRedirect && (redirected || meta_refresh) {
        emit_unique(
            findings,
            seen,
            "OpenRedirect",
            &probe.target,
            param,
            Evidence::OpenRedirect {
                url: probe.target.clone(),
                param: param.to_owned(),
            },
        )?;
    }
    Ok(())
}

/// Fuzz each query param of `url` with the URL-param payload set, one param
/// mutated at a time, against one clean baseline measurement. Read-depth time
/// delays are limited to unreflected ID-like params.
#[allow(clippy::too_many_arguments)] // scan-pass shape, same as fuzz_endpoints
async fn fuzz_url_params(
    client: &Client,
    guard: &ScopeGuard,
    coverage: &Coverage,
    url: &Url,
    baseline: &Baseline<'_>,
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, String, &'static str)>,
    deadline: Option<Instant>,
    depth: Depth,
) -> Result<(), ScanError> {
    let params: Vec<(String, String)> = url
        .query_pairs()
        .take(MAX_URL_PARAMS)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    // Existing pass stays uncapped: MAX_URL_PARAMS already bounds it.
    let budget = AtomicUsize::new(usize::MAX);
    let limited = AtomicBool::new(false);
    for (name, _) in &params {
        if limited.load(Ordering::Relaxed) {
            break;
        }
        if overdue(deadline) {
            return Ok(());
        }
        let jobs: Vec<(&str, &'static Payload)> = payloads_for(Context::UrlParam)
            .filter(|p| {
                payload_enabled(depth, p)
                    || read_time_delay_allowed(depth, name, url, baseline.body)
            })
            .map(|p| (name.as_str(), p))
            .collect();
        let mut pairs: [Option<Probe>; 4] = [None, None, None, None];
        for (param, p, result) in fire_batch(
            client,
            guard,
            coverage,
            url,
            &budget,
            baseline.body,
            &limited,
            depth,
            jobs,
        )
        .await
        {
            let pr = match result {
                Ok(Some(pr)) => pr,
                Ok(None) => {
                    if limited.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }
                // Probe-sized timeout: likely WAF/rate limiting — stop
                // firing payloads at this URL.
                Err(ScanError::Http(e)) if e.is_timeout() => break,
                Err(e) => return Err(e),
            };
            // The pair is proofed only once both halves are in hand.
            if p.verify == Verification::Boolean {
                if let Some(pair_slot) = boolean_pair_index(p.payload) {
                    pairs[pair_slot] = Some(pr);
                }
                continue;
            }
            if let Some(proof) = proof_vs_baseline(
                baseline.body,
                baseline.ms,
                &pr.body,
                pr.elapsed_ms,
                p,
                baseline.threshold_ms,
                &pr.content_type,
            ) {
                admit_proof(findings, seen, url.as_str(), param, proof, &pr.payload)?;
            }
            admit_redirect(findings, seen, param, p, &pr)?;
        }
        if let Some(payload) = prove_boolean_pairs(baseline.body, &pairs) {
            admit_proof(findings, seen, url.as_str(), name, Proof::Boolean, payload)?;
        }
    }
    Ok(())
}

/// Fuzz the blind header surface (`X-Forwarded-For`, `User-Agent`, `Referer`)
/// with the header payload set (SQLi + XSS) against the same clean baseline
/// the URL-param stage used.
#[allow(clippy::too_many_arguments)] // scan-pass shape, same as fuzz_endpoints
async fn fuzz_headers(
    client: &Client,
    guard: &ScopeGuard,
    coverage: &Coverage,
    url: &Url,
    baseline: &Baseline<'_>,
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, String, &'static str)>,
    deadline: Option<Instant>,
    depth: Depth,
) -> Result<(), ScanError> {
    let payloads: Vec<_> = payloads_for(Context::Header)
        .filter(|p| payload_enabled(depth, p))
        .collect();
    let limited = AtomicBool::new(false);
    for name in HEADER_NAMES {
        for p in &payloads {
            if limited.load(Ordering::Relaxed) {
                break;
            }
            if limited.load(Ordering::Relaxed) {
                break;
            }
            if overdue(deadline) {
                return Ok(());
            }
            guard.check(url)?;
            let req = client.get(url.clone()).header(name, p.payload);
            let req = if p.verify == Verification::TimeDelay {
                req.timeout(TIME_DELAY_CAP)
            } else {
                req
            };
            let (resp, elapsed, check) = match send_counted(req, coverage, &limited).await {
                Ok(CountedSend::Response(resp, elapsed, guard)) => (resp, elapsed, guard),
                Ok(CountedSend::Limited) => continue,
                // A stalled header probe is the WAF, not a scan failure.
                Err(ScanError::Http(e)) if e.is_timeout() => break,
                Err(e) => return Err(e),
            };
            let status = resp.status().as_u16();
            if status == 403 || status == 406 {
                let _ = check.finish(CheckState::Inconclusive);
                continue;
            }
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let Ok(body) = riftlock_core::body::text_limited_result(resp).await else {
                let _ = check.finish(CheckState::Inconclusive);
                break;
            };
            let _ = check.finish(CheckState::Completed);
            let elapsed = elapsed.as_millis() as u64;
            if let Some(proof) = proof_vs_baseline(
                baseline.body,
                baseline.ms,
                &body,
                elapsed,
                p,
                baseline.threshold_ms,
                &content_type,
            ) {
                admit_proof(findings, seen, url.as_str(), name, proof, p.payload)?;
            }
        }
    }
    Ok(())
}

/// Discovered endpoints in scope for the aggressive pass: resolved against
/// `base`, same scheme and host, deduped, the scanned URL itself excluded,
/// everything kept (the deadline, not a slot cap, bounds the pass).
fn probe_endpoints(base: &Url, endpoints: &[String]) -> Vec<Url> {
    // Form actions reach the engine as plain URLs, so login-, search- and
    // API-shaped paths stand in for them: those are the highest-value probes.
    // Query-bearing endpoints come first of all: they accept input directly,
    // no guessing a parameter name.
    let looks_api = |u: &Url| {
        let p = u.path();
        p.starts_with("/api")
            || p.starts_with("/rest")
            || p.contains("graphql")
            || p.contains("search")
            || p.contains("product")
    };
    let mut out: Vec<Url> = Vec::new();
    for e in endpoints {
        if let Ok(u) = base.join(e) {
            // Keep foreign origins in the plan so the endpoint worker can
            // make the authoritative ScopeGuard decision and record an
            // explicit skipped disposition instead of silently dropping it.
            if u.as_str() != base.as_str() && !out.contains(&u) {
                out.push(u);
            }
        }
    }
    let tier = |u: &Url| {
        if u.query().is_some_and(|q| !q.is_empty()) {
            0
        } else if is_login_endpoint(u.path()) || looks_api(u) {
            1
        } else {
            2
        }
    };
    out.sort_by_key(|u| (tier(u), !is_login_endpoint(u.path()), !looks_api(u)));
    out
}

/// POST `body` urlencoded to `url` (endpoint method fuzzing).
async fn post_form(
    client: &Client,
    guard: &ScopeGuard,
    url: &Url,
    body: &str,
    time_delay: bool,
) -> Result<Resp, ScanError> {
    guard.check_request(url, &reqwest::Method::POST)?;
    let req = client
        .post(url.clone())
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body.to_owned());
    let req = if time_delay {
        req.timeout(TIME_DELAY_CAP)
    } else {
        req
    };
    let Some((resp, elapsed)) = send_unless_limited(req).await? else {
        return Err(ScanError::Io(std::io::Error::other(
            "rate limited endpoint",
        )));
    };
    collect(resp, elapsed).await
}

/// POST `body` as XML to `url` (XXE probing).
async fn post_xml(
    client: &Client,
    guard: &ScopeGuard,
    url: &Url,
    body: &str,
) -> Result<Resp, ScanError> {
    guard.check_request(url, &reqwest::Method::POST)?;
    let req = client
        .post(url.clone())
        .header("content-type", "application/xml")
        .body(body.to_owned());
    let Some((resp, elapsed)) = send_unless_limited(req).await? else {
        return Err(ScanError::Io(std::io::Error::other(
            "rate limited endpoint",
        )));
    };
    collect(resp, elapsed).await
}

/// Use the endpoint's real query names in URL order. A queryless endpoint
/// yields no parameters (it gets baseline-only treatment); a large set is
/// capped to the first five so one form cannot consume the run.
fn endpoint_params(url: &Url) -> Vec<String> {
    let mut params: Vec<String> = url
        .query_pairs()
        .map(|(name, _)| name.into_owned())
        .collect();
    if params.len() >= LARGE_PARAM_SET {
        params.truncate(MAX_ENDPOINT_PARAMS);
    }
    params
}

fn neon_orange(text: &str) -> String {
    text.truecolor(255, 165, 0).to_string()
}

fn static_asset(url: &Url) -> bool {
    ["js", "css", "png", "jpg"].iter().any(|extension| {
        url.path()
            .to_ascii_lowercase()
            .ends_with(&format!(".{extension}"))
    })
}

fn supports_active_payloads(url: &Url, content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    !static_asset(url)
        && (media_type.eq_ignore_ascii_case("text/html")
            || media_type.eq_ignore_ascii_case("application/json")
            || media_type
                .to_ascii_lowercase()
                .strip_suffix("+json")
                .is_some())
}

fn active_payload_allowed(payload: &Payload, active_supported: bool) -> bool {
    active_supported
        || !matches!(
            payload.vuln,
            VulnType::Xss | VulnType::SqlInjection | VulnType::Lfi
        )
}

/// Whether a blind time-based probe is safe enough for Read depth: the param
/// must look like an identifier and its value must not be reflected, so a
/// slow response is the only observable difference.
fn id_time_delay_allowed(name: &str, url: &Url, baseline: &str) -> bool {
    name.to_ascii_lowercase().contains("id")
        && url
            .query_pairs()
            .all(|(key, value)| key != name || !baseline.contains(value.as_ref()))
}

/// Read depth sends the blind time probe only for an unreflective ID-shaped
/// param; Godmode sends it everywhere and Normal sends no payloads at all.
fn read_time_delay_allowed(depth: Depth, name: &str, url: &Url, baseline: &str) -> bool {
    matches!(depth, Depth::Read) && id_time_delay_allowed(name, url, baseline)
}

/// Interleave vulnerability classes so a bounded endpoint budget reaches each
/// class before spending requests on additional payload variants.
fn ordered_payloads(context: Context) -> Vec<&'static Payload> {
    let mut first_by_class = Vec::new();
    let mut repeats = Vec::new();
    let mut slow = Vec::new();
    let mut classes = Vec::new();
    for payload in payloads_for(context) {
        if matches!(
            payload.verify,
            Verification::TimeDelay | Verification::Boolean
        ) {
            slow.push(payload);
        } else if classes.contains(&payload.vuln) {
            repeats.push(payload);
        } else {
            classes.push(payload.vuln);
            first_by_class.push(payload);
        }
    }
    first_by_class.extend(repeats);
    first_by_class.extend(slow);
    first_by_class
}

/// True once the CLI's wall-clock deadline has passed: stop starting new
/// probes and return what was already proven — the CLI cancels an engine
/// that overruns, and a cancelled future loses its findings.
fn overdue(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

/// Aggressive fuzzing of the discovered endpoints plus the scanned URL: GET
/// param injection (`endpoint_params` × `payloads_for_param`) on each
/// endpoint, and POST body injection on endpoints whose `Allow` header
/// advertises POST. Endpoints run at depth-specific concurrency;
/// `budget` is split evenly across targets so one endpoint cannot starve the
/// rest. `coverage` records every
/// non-base endpoint exactly once, after its passes have run.
#[allow(clippy::too_many_arguments)] // scan-pass shape, same as crates/scanners/misconfig
async fn fuzz_endpoints(
    client: &Client,
    guard: &ScopeGuard,
    base: &Url,
    endpoints: &[String],
    budget: usize,
    coverage: &Coverage,
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, String, &'static str)>,
    deadline: Option<Instant>,
    events: Option<&Sender<GenericEvent>>,
    depth: Depth,
    authenticated: bool,
) -> Result<(), ScanError> {
    let targets = probe_endpoints(base, endpoints);
    // Discovery may include script bundles and foreign/unprobeable URLs; the
    // progress denominator is the exact same in-scope plan as coverage tests.
    let planned: Vec<String> = std::iter::once(base)
        .chain(targets.iter())
        .map(ToString::to_string)
        .collect();
    let n = planned.len();
    let get_allowance = (budget / n).max(1);
    let post_allowance = (budget / (2 * n)).max(1);
    // A WAF-blocked target answers every request with a 6 s timeout: three
    // consecutive failures (counted across the concurrent tasks) end the
    // pass instead of burning the 40 s engine budget. It ends with Ok: the
    // CLI drops an engine's findings on Err, and proven findings must
    // survive a target that dies mid-scan.
    let failures = Arc::new(AtomicU32::new(0));
    if let Some(events) = events {
        let _ = events
            .send(GenericEvent::EndpointsStarted {
                total: n,
                endpoints: planned,
            })
            .await;
        // Report the discovered names this pass cannot probe, so every
        // discovered endpoint appears in the live test list.
        for endpoint in endpoints {
            let tested = base
                .join(endpoint)
                .ok()
                .is_some_and(|u| u.as_str() == base.as_str() || targets.contains(&u));
            if !tested {
                let _ = events
                    .send(GenericEvent::EndpointSkipped {
                        endpoint: endpoint.clone(),
                    })
                    .await;
            }
        }
    }
    let endpoints: Vec<Url> = std::iter::once(base.clone()).chain(targets).collect();
    let mut set = JoinSet::new();
    let mut next = 0usize;
    let mut completed = 0usize;
    let started = Instant::now();
    while next < endpoints.len() || !set.is_empty() {
        // Keep spawning after the deadline: each endpoint's own payload loops
        // honour it, so the remaining fast endpoints still get their baseline.
        let mut spawned = false;
        let concurrency = endpoint_concurrency(depth);
        while next < endpoints.len() && set.len() < concurrency {
            let client = client.clone();
            let guard = guard.clone();
            let coverage = coverage.clone();
            let base = base.clone();
            let endpoint = endpoints[next].clone();
            let params = endpoint_params(&endpoint);
            let failures = Arc::clone(&failures);
            // Seeded with the caller's dedupe set so the scanned URL cannot
            // re-emit a finding an earlier stage already proved.
            let task_seen = seen.clone();
            set.spawn(async move {
                let endpoint_url = endpoint.to_string();
                let result = fuzz_one_endpoint(
                    &client,
                    &guard,
                    &coverage,
                    &base,
                    endpoint,
                    &params,
                    get_allowance,
                    post_allowance,
                    deadline,
                    &failures,
                    depth,
                    authenticated,
                    next + 1,
                    n,
                    started,
                    task_seen,
                )
                .await;
                (endpoint_url, result)
            });
            next += 1;
            spawned = true;
        }
        // Space concurrency windows so a rate-limited host gets a breather
        // between bursts instead of one continuous flood.
        if spawned {
            tokio::time::sleep(ENDPOINT_BATCH_DELAY).await;
        }
        let Some(joined) = set.join_next().await else {
            break;
        };
        match joined {
            Ok((endpoint, Ok((mut proved, mut task_seen, outcome)))) => {
                let found = !proved.is_empty();
                // One disposition per planned endpoint, whatever path the
                // per-endpoint pass took (including `break 'endpoint`).
                if endpoint != base.as_str() {
                    coverage.endpoint_at(&endpoint, outcome);
                }
                for finding in &proved {
                    if let Some(events) = events {
                        let _ = events
                            .send(GenericEvent::Finding(finding.evidence().clone()))
                            .await;
                    }
                }
                findings.append(&mut proved);
                seen.extend(task_seen.drain());
                completed += 1;
                if let Some(events) = events {
                    let _ = events
                        .send(GenericEvent::EndpointComplete {
                            completed,
                            total: n,
                            endpoint,
                            found,
                        })
                        .await;
                }
            }
            Ok((endpoint, Err(ScanError::Http(e)))) if e.is_timeout() => {
                logln!("[-] Skipping {endpoint}: timed out");
                if endpoint != base.as_str() {
                    coverage.endpoint_at(&endpoint, EndpointOutcome::TimedOut);
                }
                completed += 1;
                if let Some(events) = events {
                    let _ = events
                        .send(GenericEvent::EndpointComplete {
                            completed,
                            total: n,
                            endpoint,
                            found: false,
                        })
                        .await;
                }
            }
            Ok((endpoint, Err(e))) => {
                // A scope rejection applies only to this discovered endpoint:
                // account for it, then let the rest of the plan continue.
                // A rejection of the run's actual target is still fatal in
                // `run`, before any endpoint task can be spawned.
                logln!("[-] Skipping {endpoint}: {e}");
                if endpoint != base.as_str() {
                    if matches!(e, ScanError::Scope(_)) {
                        coverage.out_of_scope_endpoint_at(&endpoint);
                    } else {
                        coverage.endpoint_at(&endpoint, EndpointOutcome::Failed);
                    }
                }
                completed += 1;
                if let Some(events) = events {
                    let _ = events
                        .send(GenericEvent::EndpointComplete {
                            completed,
                            total: n,
                            endpoint,
                            found: false,
                        })
                        .await;
                }
            }
            Err(e) => {
                return Err(ScanError::Io(std::io::Error::other(format!(
                    "endpoint task failed: {e}"
                ))))
            }
        }
    }
    Ok(())
}

/// [`CircuitBreaker`] shared by the concurrent endpoint tasks: one atomic
/// count, so three consecutive failures anywhere end the pass.
struct SharedBreaker<'a>(&'a AtomicU32);

impl SharedBreaker<'_> {
    fn failed(&self) -> bool {
        self.0.fetch_add(1, Ordering::Relaxed) + 1 >= CircuitBreaker::TRIP_AT
    }

    fn healthy(&self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

/// Hidden-parameter discovery for an endpoint that advertises no parameters:
/// two switch probes (`?debug=1`, `?admin=true`) compared against the baseline
/// response. A status change or a significant body-length change names a
/// parameter; the evidence is informational attack-surface metadata, never a
/// flaw, so it is admitted as a potential finding.
#[allow(clippy::too_many_arguments)] // probe shape, same as fuzz_one_endpoint
async fn probe_hidden_params(
    client: &Client,
    guard: &ScopeGuard,
    coverage: &Coverage,
    endpoint: &Url,
    baseline_status: u16,
    baseline_body: &str,
    endpoint_limited: &AtomicBool,
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, String, &'static str)>,
    deadline: Option<Instant>,
) -> Result<(), ScanError> {
    if endpoint.query_pairs().next().is_some()
        || guard.is_read_only()
        || guard.check_active(endpoint).is_err()
    {
        return Ok(());
    }
    let baseline_len = baseline_body.len();
    let length_floor = HIDDEN_PARAM_LENGTH_FLOOR + baseline_len / 20;
    for (param, value) in HIDDEN_PARAM_SWITCHES {
        if !HIDDEN_PARAMS.contains(&param) || overdue(deadline) {
            continue;
        }
        let check = coverage.begin_check();
        let request = client.get(endpoint.clone()).query(&[(param, value)]);
        let (resp, _elapsed) = match send_unless_limited(request).await {
            Ok(Some(response)) => response,
            Ok(None) => {
                endpoint_limited.store(true, Ordering::Relaxed);
                let _ = check.finish(CheckState::Inconclusive);
                break;
            }
            Err(_) => {
                let _ = check.finish(CheckState::Inconclusive);
                break;
            }
        };
        let status = resp.status().as_u16();
        let body = match riftlock_core::body::text_limited_result(resp).await {
            Ok(body) => body,
            Err(_) => {
                let _ = check.finish(CheckState::Inconclusive);
                break;
            }
        };
        if status == 403 && looks_like_waf(&body) {
            let _ = check.finish(CheckState::Inconclusive);
            continue;
        }
        let _ = check.finish(CheckState::Completed);
        // A transport-level status change or a body that grew/shrank past the
        // noise floor means the switch reached something.
        if status != baseline_status || body.len().abs_diff(baseline_len) > length_floor {
            emit_unique(
                findings,
                seen,
                "ParameterDiscovery",
                endpoint.as_str(),
                param,
                Evidence::ParameterDiscovery {
                    url: endpoint.as_str().to_owned(),
                    param: param.to_owned(),
                },
            )?;
        }
    }
    Ok(())
}

/// One endpoint's pass: query-bearing targets get GET-param (with the smart
/// HTML XSS canary), login bypass, OPTIONS and POST probes; queryless targets
/// get only their clean baseline. Runs as one concurrent task; its findings
/// and coverage outcome come back to [`fuzz_endpoints`].
#[allow(clippy::too_many_arguments)] // scan-pass shape, same as fuzz_endpoints
async fn fuzz_one_endpoint(
    client: &Client,
    guard: &ScopeGuard,
    coverage: &Coverage,
    base: &Url,
    endpoint: Url,
    params: &[String],
    get_allowance: usize,
    post_allowance: usize,
    deadline: Option<Instant>,
    failures: &AtomicU32,
    depth: Depth,
    authenticated: bool,
    idx: usize,
    total: usize,
    started: Instant,
    mut seen: HashSet<(String, String, &'static str)>,
) -> Result<
    (
        Vec<Finding>,
        HashSet<(String, String, &'static str)>,
        EndpointOutcome,
    ),
    ScanError,
> {
    let elapsed = started.elapsed().as_secs();
    logln!(
        "{} Actively testing [{idx}/{total}] {elapsed}s elapsed: {endpoint}...",
        neon_orange("[>]")
    );
    let mut findings = Vec::new();
    let breaker = SharedBreaker(failures);
    // Per-endpoint coverage: recorded exactly once, after both passes. The
    // scanned URL itself is classified by the caller (`scan`).
    let mut outcome = EndpointOutcome::Skipped;
    'endpoint: {
        if coverage.is_blocked(endpoint.as_str()) {
            outcome = EndpointOutcome::Skipped;
            break 'endpoint;
        }
        let endpoint_limited = AtomicBool::new(false);
        // GET refused the route: a POST-only auth surface can still parse JSON.
        let mut get_unavailable = false;
        // GET param pass (the scanned URL itself stays fuzz_url_params' job).
        // A 405 still permits a POST-only endpoint; terminal auth, missing,
        // and WAF baselines stop all methods before payloads are considered.
        if endpoint.as_str() != base.as_str() {
            'get_pass: {
                if let Err(error) = guard.check(&endpoint) {
                    if matches!(error, riftlock_core::ScopeError::ReadOnly { .. }) {
                        break 'get_pass;
                    }
                    coverage.scope_rejected_check();
                    outcome = EndpointOutcome::Skipped;
                    break 'endpoint;
                }
                let first = match baseline_get(client, &endpoint).await {
                    Ok(response) => response,
                    Err(error) => {
                        // The request reached a live route but its body could
                        // not be read: the baseline is usable for classification
                        // only, so the endpoint is an inconclusive check rather
                        // than a silent gap.
                        if matches!(error, ScanError::Body(_)) {
                            let check = coverage.begin_check();
                            let _ = check.finish(CheckState::Inconclusive);
                        }
                        outcome = merge(outcome, scan_error_outcome(&error));
                        if matches!(&error, ScanError::Http(err) if err.is_timeout()) {
                            logln!("[-] Skipping {endpoint}: timed out");
                            break 'endpoint;
                        }
                        if breaker.failed() {
                            break 'endpoint;
                        }
                        break 'get_pass;
                    }
                };
                let resp = if waf_answer(&first) {
                    match baseline_with_waf_guard(client, &endpoint, first).await {
                        Ok(BaselineRead::WafBlocked) => {
                            logln!("[-] Skipping {endpoint}: repeated WAF block");
                            // Recorded once by `fuzz_endpoints` from `outcome`;
                            // marking here makes the endpoint O(1)-skippable by
                            // any later pass without double-counting it.
                            coverage.mark_blocked(endpoint.as_str());
                            outcome = EndpointOutcome::WafBlocked;
                            break 'endpoint;
                        }
                        Ok(BaselineRead::Ready(response)) => {
                            breaker.healthy();
                            response
                        }
                        Err(error) => {
                            outcome = merge(outcome, scan_error_outcome(&error));
                            break 'endpoint;
                        }
                    }
                } else {
                    breaker.healthy();
                    first
                };
                let status_code = resp.status;
                let status = reqwest::StatusCode::from_u16(status_code)
                    .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR);
                let baseline_outcome = classify_baseline(status_code, resp.location.as_deref());
                match baseline_outcome {
                    EndpointOutcome::AuthRequired => {
                        // Keep the passive sensitive-path disclosure, but never
                        // send a payload after an auth wall.
                        if is_sensitive_path(endpoint.path()) && matches!(status_code, 401 | 403) {
                            emit_unique(
                                &mut findings,
                                &mut seen,
                                "SensitivePathDisclosed",
                                endpoint.as_str(),
                                "",
                                Evidence::SensitivePathDisclosed {
                                    url: endpoint.as_str().to_owned(),
                                    status: status_code,
                                },
                            )?;
                        }
                        outcome = EndpointOutcome::AuthRequired;
                        coverage.mark_blocked(endpoint.as_str());
                        break 'endpoint;
                    }
                    // A POST-only login route answers GET with 404: the route
                    // exists for the credential-bypass pass below.
                    EndpointOutcome::Skipped
                        if matches!(status_code, 404 | 410)
                            && is_login_endpoint(endpoint.path()) =>
                    {
                        get_unavailable = true;
                        outcome = EndpointOutcome::Tested;
                        break 'get_pass;
                    }
                    EndpointOutcome::Skipped if matches!(status_code, 404 | 410) => {
                        outcome = EndpointOutcome::Skipped;
                        coverage.mark_blocked(endpoint.as_str());
                        break 'endpoint;
                    }
                    EndpointOutcome::WafBlocked => {
                        // baseline_with_waf_guard has already made the second
                        // consecutive status/challenge request.
                        outcome = EndpointOutcome::WafBlocked;
                        coverage.mark_blocked(endpoint.as_str());
                        break 'endpoint;
                    }
                    _ => {}
                }
                if status == reqwest::StatusCode::METHOD_NOT_ALLOWED {
                    get_unavailable = true;
                }
                if status.is_redirection() {
                    if let Some(location) = resp.location.as_deref() {
                        if let Ok(destination) = endpoint.join(location) {
                            if let Err(error) = guard.check(&destination) {
                                if !matches!(error, riftlock_core::ScopeError::ReadOnly { .. }) {
                                    coverage.scope_rejected_check();
                                    outcome = EndpointOutcome::Skipped;
                                    logln!("[~] Skipping out-of-scope redirect from {endpoint}");
                                    break 'endpoint;
                                }
                            }
                        }
                    }
                }
                if matches!(status.as_u16(), 429 | 503) {
                    logln!(
                        "[-] Skipping {endpoint}: Rate limited (HTTP {})",
                        status.as_u16()
                    );
                    // The endpoint itself is rate limited: skip every pass.
                    // Record the disposition now: `break 'endpoint` bypasses
                    // the single classification at the end of the pass.
                    outcome = merge(outcome, classify(status.as_u16()));
                    break 'endpoint;
                }
                // A sensitive path that answers 401/403 still confirms the
                // route exists; report the disclosure, never broken access.
                if is_sensitive_path(endpoint.path()) && matches!(status.as_u16(), 401 | 403) {
                    emit_unique(
                        &mut findings,
                        &mut seen,
                        "SensitivePathDisclosed",
                        endpoint.as_str(),
                        "",
                        Evidence::SensitivePathDisclosed {
                            url: endpoint.as_str().to_owned(),
                            status: status.as_u16(),
                        },
                    )?;
                }
                if !(status.is_success() || status.is_redirection()) {
                    outcome = merge(outcome, classify(status.as_u16()));
                    break 'get_pass;
                }
                let content_type = resp.content_type;
                let active_supported = supports_active_payloads(&endpoint, &content_type);
                let baseline_ms = resp.elapsed.as_millis() as u64;
                let baseline_body = resp.body;
                outcome = EndpointOutcome::Tested;
                endpoint_limited.store(false, Ordering::Relaxed);
                // The baseline GET is the one full-body fetch of this endpoint:
                // scan it for live secrets and sensitive JWT claims.
                scan_secrets(endpoint.as_str(), &baseline_body, &mut findings, &mut seen)?;
                // Anonymous by construction (no session is ever sent): a
                // sensitive path serving signed-in UI is the proof.
                if is_sensitive_path(endpoint.path()) {
                    if let Some(marker) = access_marker(status.as_u16(), &baseline_body) {
                        emit_unique(
                            &mut findings,
                            &mut seen,
                            "BrokenAccessControl",
                            endpoint.as_str(),
                            marker,
                            Evidence::BrokenAccessControl {
                                url: endpoint.as_str().to_owned(),
                                dashboard_marker: marker.to_owned(),
                            },
                        )?;
                    }
                }
                // No real parameters means nothing active to fuzz: the
                // baseline request above is this endpoint's only traffic.
                // A login-shaped route is the exception — its credential
                // bypass carries the payload in the POST body.
                if params.is_empty() {
                    if is_login_endpoint(endpoint.path()) {
                        break 'get_pass;
                    }
                    break 'endpoint;
                }
                // Endpoints that take no parameters still sometimes honour
                // debug/admin switches: a differential probe names them.
                if allows_all_probes(depth) && looks_like_json(&content_type, &baseline_body) {
                    probe_hidden_params(
                        client,
                        guard,
                        coverage,
                        &endpoint,
                        status.as_u16(),
                        &baseline_body,
                        &endpoint_limited,
                        &mut findings,
                        &mut seen,
                        deadline,
                    )
                    .await?;
                }
                // Try conventional XSS query names first on HTML and JSON
                // endpoints; the shared allowance also caps the wider pass.
                let left = AtomicUsize::new(get_allowance);
                if active_supported && !overdue(deadline) && !baseline_body.contains(XSS_PAYLOAD) {
                    let canary = Payload {
                        context: Context::UrlParam,
                        vuln: VulnType::Xss,
                        payload: XSS_PAYLOAD,
                        verify: Verification::Reflection,
                    };
                    for param in SMART_XSS_PARAMS {
                        if overdue(deadline) || left.load(Ordering::Relaxed) == 0 {
                            break;
                        }
                        if endpoint
                            .query_pairs()
                            .any(|(name, _)| name.eq_ignore_ascii_case(param))
                        {
                            continue;
                        }
                        let pr = match fire_param_probe(
                            client,
                            guard,
                            coverage,
                            &endpoint,
                            param,
                            &canary,
                            &left,
                            &baseline_body,
                            &endpoint_limited,
                            depth,
                        )
                        .await
                        {
                            Ok(Some(pr)) => pr,
                            Ok(None) if endpoint_limited.load(Ordering::Relaxed) => break 'endpoint,
                            Ok(None) => break,
                            Err(ScanError::Http(e)) if e.is_timeout() => {
                                logln!("[-] Skipping {endpoint}: timed out");
                                break 'endpoint;
                            }
                            Err(e) => return Err(e),
                        };
                        if let Some(proof) =
                            xss_proof(&pr.body, XSS_PAYLOAD, &baseline_body, &pr.content_type)
                        {
                            admit_proof(
                                &mut findings,
                                &mut seen,
                                endpoint.as_str(),
                                param,
                                proof,
                                &pr.payload,
                            )?;
                            break;
                        }
                    }
                }
                // Round-robin over the endpoint's real query params.
                let payload_lists: Vec<Vec<&Payload>> = params
                    .iter()
                    .map(|_| {
                        ordered_payloads(Context::UrlParam)
                            .into_iter()
                            .filter(|p| active_payload_allowed(p, active_supported))
                            .filter(|p| payload_enabled(depth, p))
                            .collect()
                    })
                    .collect();
                let rounds = payload_lists.iter().map(Vec::len).max().unwrap_or_default();
                let mut booleans: HashMap<String, [Option<Probe>; 4]> = HashMap::new();
                'rounds: for i in 0..rounds {
                    if overdue(deadline) {
                        break 'rounds;
                    }
                    let jobs: Vec<(&str, &'static Payload)> = params
                        .iter()
                        .zip(&payload_lists)
                        .filter_map(|(param, pls)| pls.get(i).map(|p| (param.as_str(), *p)))
                        .collect();
                    if jobs.is_empty() {
                        continue;
                    }
                    for (param, p, result) in fire_batch(
                        client,
                        guard,
                        coverage,
                        &endpoint,
                        &left,
                        &baseline_body,
                        &endpoint_limited,
                        depth,
                        jobs,
                    )
                    .await
                    {
                        let pr = match result {
                            Ok(Some(pr)) => pr,
                            Ok(None) => {
                                if endpoint_limited.load(Ordering::Relaxed)
                                    || left.load(Ordering::Relaxed) == 0
                                {
                                    break 'rounds;
                                }
                                continue;
                            }
                            // Probe-sized timeout: skip the stalled endpoint.
                            Err(ScanError::Http(e)) if e.is_timeout() => {
                                logln!("[-] Skipping {endpoint}: timed out");
                                break 'endpoint;
                            }
                            Err(e) => return Err(e),
                        };
                        // The pair is proofed only once both halves are in hand.
                        if p.verify == Verification::Boolean {
                            if let Some(pair_slot) = boolean_pair_index(p.payload) {
                                booleans
                                    .entry(param.to_owned())
                                    .or_insert([None, None, None, None])[pair_slot] = Some(pr);
                            }
                            continue;
                        }
                        if let Some(proof) = proof_vs_baseline(
                            &baseline_body,
                            baseline_ms,
                            &pr.body,
                            pr.elapsed_ms,
                            p,
                            DELAY_THRESHOLD_MS,
                            &pr.content_type,
                        ) {
                            admit_proof(
                                &mut findings,
                                &mut seen,
                                endpoint.as_str(),
                                param,
                                proof,
                                &pr.payload,
                            )?;
                        }
                        admit_redirect(&mut findings, &mut seen, param, p, &pr)?;
                    }
                }
                for (param, probes) in booleans {
                    if let Some(payload) = prove_boolean_pairs(&baseline_body, &probes) {
                        admit_proof(
                            &mut findings,
                            &mut seen,
                            endpoint.as_str(),
                            &param,
                            Proof::Boolean,
                            payload,
                        )?;
                    }
                }
            }
        }
        // The scanned base target skips the GET pass above, so it needs the
        // same baseline-only rule here: no params, no active passes. Login
        // routes reach the body-carried credential bypass below instead.
        if params.is_empty() && !is_login_endpoint(endpoint.path()) {
            break 'endpoint;
        }
        // Auth-bypass pass: login-shaped endpoints get the credential
        // bypasses as raw JSON regardless of the OPTIONS/Allow answer (Juice
        // Shop advertises no POST there), and with no session required — the
        // payload is the login. Proof is the session differential: the
        // payload grants a session the baseline was denied.
        'login_pass: {
            if overdue(deadline)
                || !is_login_endpoint(endpoint.path())
                || !supports_active_payloads(&endpoint, "application/json")
                || guard.is_read_only()
                || guard.check_active(&endpoint).is_err()
            {
                break 'login_pass;
            }
            let baseline_check = coverage.begin_check();
            let baseline = match post_json(
                client,
                guard,
                &endpoint,
                &json_body(&json_fields(Vec::new()), None),
                false,
            )
            .await
            {
                Ok(baseline) => {
                    let _ = baseline_check.finish(CheckState::Completed);
                    baseline
                }
                Err(_) => {
                    let _ = baseline_check.finish(CheckState::Inconclusive);
                    break 'login_pass;
                }
            };
            if session_granted(&baseline.cookies, None) || body_session_granted(&baseline) {
                break 'login_pass;
            }
            for payload in AUTH_BYPASS_PAYLOADS {
                let Ok(resp) = counted_send(
                    post_json(client, guard, &endpoint, &login_body(payload), false),
                    coverage,
                )
                .await
                else {
                    // Rate limited or transport failure: stop this endpoint.
                    break;
                };
                if session_granted(&resp.cookies, None) || body_session_granted(&resp) {
                    outcome = EndpointOutcome::Tested;
                    emit_unique(
                        &mut findings,
                        &mut seen,
                        "SqlInjection",
                        endpoint.as_str(),
                        "email",
                        Evidence::SqlInjection {
                            url: endpoint.as_str().to_owned(),
                            param: "email".to_owned(),
                            payload: (*payload).to_owned(),
                        },
                    )?;
                    break;
                }
            }
        }
        // Known user/order collection reads are explicitly anonymous: make
        // a fresh request with no auth headers and require an array response.
        if ["/api/v1/users", "/api/v1/orders"]
            .iter()
            .any(|path| endpoint.path().trim_end_matches('/') == *path)
            && guard.check(&endpoint).is_ok()
        {
            let check = coverage.begin_check();
            match client.get(endpoint.clone()).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    match riftlock_core::body::text_limited_result(resp).await {
                        Ok(body) => {
                            let array_data = body.trim_start().starts_with("[{")
                                || body.contains("\\\"data\\\":[{");
                            let _ = check.finish(CheckState::Completed);
                            if status == 200 && array_data {
                                emit_unique(
                                    &mut findings,
                                    &mut seen,
                                    "UnauthenticatedRead",
                                    endpoint.as_str(),
                                    "",
                                    Evidence::UnauthenticatedRead {
                                        endpoint: endpoint.as_str().to_owned(),
                                        row_sample: "[redacted array data]".to_owned(),
                                    },
                                )?;
                            }
                        }
                        Err(_) => {
                            let _ = check.finish(CheckState::Inconclusive);
                        }
                    }
                }
                Err(_) => {
                    let _ = check.finish(CheckState::Failed);
                }
            }
        }
        // Authenticated object-level access: only a supplied session can prove
        // it, and only against another user's numeric resource. Anonymous
        // access must be denied, the session must see a distinct record, and
        // the caller's own record must be readable for the comparison to mean
        // anything.
        if allows_all_probes(depth)
            && authenticated
            && !overdue(deadline)
            && guard.check_active(&endpoint).is_ok()
        {
            if let Some((id, mutated)) = bumped_resource_id(&endpoint) {
                if guard.check(&mutated).is_ok() {
                    let anon =
                        counted_send(get_probe(client, guard, &mutated, true), coverage).await;
                    if let Ok(anon) = anon {
                        if matches!(anon.status, 401 | 403) {
                            let own =
                                counted_send(get_probe(client, guard, &endpoint, false), coverage)
                                    .await;
                            let other =
                                counted_send(get_probe(client, guard, &mutated, false), coverage)
                                    .await;
                            if let (Ok(own), Ok(other)) = (own, other) {
                                if own.status == 200
                                    && other.status == 200
                                    && looks_like_record(&own)
                                    && looks_like_record(&other)
                                    && other.body != own.body
                                {
                                    emit_unique(
                                        &mut findings,
                                        &mut seen,
                                        "BrokenAccessControl",
                                        mutated.as_str(),
                                        "id",
                                        Evidence::BrokenAccessControl {
                                            url: mutated.as_str().to_owned(),
                                            dashboard_marker: format!("id {id} -> {}", id + 1),
                                        },
                                    )?;
                                }
                            }
                        }
                    }
                }
            }
        }
        // Auth-style endpoints and routes that reject GET get JSON body
        // probes. A clean benign POST is the baseline: a SQL engine signature
        // it already carries is not injection-induced, and XSS counts only in
        // an executable HTML context.
        let auth_style = ["/login", "/signup", "/register", "/api/auth"]
            .iter()
            .any(|marker| endpoint.path().contains(marker));
        if allows_all_probes(depth)
            && (auth_style || get_unavailable)
            && guard.check_active(&endpoint).is_ok()
            && !matches!(outcome, EndpointOutcome::Failed | EndpointOutcome::TimedOut)
        {
            let benign_body =
                serde_json::json!({"username": "test", "password": "test"}).to_string();
            if let Ok(benign) = counted_send(
                post_json(client, guard, &endpoint, &benign_body, false),
                coverage,
            )
            .await
            {
                let benign_lower = benign.body.to_ascii_lowercase();
                for (field, payload, is_xss) in [
                    ("email", "admin' OR 1=1--", false),
                    ("username", "admin' OR 1=1--", false),
                    ("email", "<script>alert(1)</script>", true),
                ] {
                    if overdue(deadline) {
                        break;
                    }
                    let mut fields = serde_json::Map::new();
                    fields.insert(
                        field.to_owned(),
                        serde_json::Value::String(payload.to_owned()),
                    );
                    fields.insert(
                        "password".to_owned(),
                        serde_json::Value::String("test".to_owned()),
                    );
                    let probe_body = serde_json::Value::Object(fields).to_string();
                    let Ok(resp) = counted_send(
                        post_json(client, guard, &endpoint, &probe_body, false),
                        coverage,
                    )
                    .await
                    else {
                        break;
                    };
                    if is_xss {
                        // Executable context only: JSON and inert HTML
                        // reflections are not proof.
                        if resp.status < 500 {
                            if let Some(proof) =
                                xss_proof(&resp.body, payload, &benign.body, &resp.content_type)
                            {
                                if matches!(proof, Proof::Xss) {
                                    admit_proof(
                                        &mut findings,
                                        &mut seen,
                                        endpoint.as_str(),
                                        field,
                                        proof,
                                        payload,
                                    )?;
                                }
                            }
                        }
                        continue;
                    }
                    if session_granted(&resp.cookies, resp.location.as_deref())
                        || body_session_granted(&resp)
                    {
                        admit_proof(
                            &mut findings,
                            &mut seen,
                            endpoint.as_str(),
                            field,
                            Proof::Boolean,
                            payload,
                        )?;
                        continue;
                    }
                    if resp.status >= 400 {
                        let lower = resp.body.to_ascii_lowercase();
                        if let Some(sig) = SQLI_SIGNATURES.iter().copied().find(|sig| {
                            let sig = sig.to_ascii_lowercase();
                            lower.contains(&sig) && !benign_lower.contains(&sig)
                        }) {
                            admit_proof(
                                &mut findings,
                                &mut seen,
                                endpoint.as_str(),
                                field,
                                Proof::Error(sig),
                                payload,
                            )?;
                        }
                    }
                }
            }
        }
        // OPTIONS → POST pass, on every target including the scanned URL.
        // One labeled block: its body-level early exits must not skip the
        // per-endpoint coverage recording below.
        'post_pass: {
            if guard.check(&endpoint).is_err() {
                break 'post_pass;
            }
            let resp = match client
                .request(reqwest::Method::OPTIONS, endpoint.clone())
                .send()
                .await
            {
                Ok(r) => {
                    breaker.healthy();
                    r
                }
                Err(e) => {
                    if e.is_timeout() {
                        logln!("[-] Skipping {endpoint}: timed out");
                        break 'endpoint;
                    }
                    if breaker.failed() {
                        break 'endpoint;
                    }
                    break 'post_pass;
                }
            };
            let allow = resp
                .headers()
                .get("allow")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            // An `Allow` header advertising write/delete methods on an
            // unauthenticated endpoint invites resource tampering.
            let dangerous: Vec<&str> = ["PUT", "DELETE", "PATCH"]
                .into_iter()
                .filter(|m| allow.split(',').any(|a| a.trim().eq_ignore_ascii_case(m)))
                .collect();
            if !dangerous.is_empty() {
                emit_unique(
                    &mut findings,
                    &mut seen,
                    "SecurityMisconfiguration",
                    endpoint.as_str(),
                    "",
                    Evidence::SecurityMisconfiguration {
                        url: endpoint.as_str().to_owned(),
                        issue: format!("dangerous_methods_allowed: {}", dangerous.join(", ")),
                        severity: "Medium".to_owned(),
                    },
                )?;
            }
            if !allow
                .split(',')
                .any(|m| m.trim().eq_ignore_ascii_case("POST"))
            {
                break 'post_pass;
            }
            // Read depth honours OPTIONS/Allow but never sends the POST pass.
            if !allows_all_probes(depth)
                || guard.is_read_only()
                || guard.check_active(&endpoint).is_err()
            {
                break 'post_pass;
            }
            let baseline = match post_form(client, guard, &endpoint, "", false).await {
                Ok(b) => {
                    outcome = merge(outcome, classify(b.status));
                    b
                }
                Err(ScanError::Http(e)) if e.is_timeout() => {
                    logln!("[-] Skipping {endpoint}: timed out");
                    break 'endpoint;
                }
                Err(ScanError::Http(e)) => {
                    outcome = merge(outcome, error_outcome(&e));
                    if breaker.failed() {
                        break 'endpoint;
                    }
                    break 'post_pass;
                }
                Err(_) => break 'post_pass,
            };
            let active_supported = supports_active_payloads(&endpoint, &baseline.content_type);
            let mut left = post_allowance;
            for param in params {
                for p in payloads_for_param(param, Context::FormData)
                    .into_iter()
                    .filter(|p| active_payload_allowed(p, active_supported))
                    .filter(|p| payload_enabled(depth, p))
                {
                    if overdue(deadline) {
                        break 'endpoint;
                    }
                    // Time-based payloads skipped at read depth: a 5 s stall per POST
                    // would burn the allowance for no different a proof.
                    if p.verify == Verification::TimeDelay && !allows_all_probes(depth) {
                        continue;
                    }
                    if left == 0 {
                        break;
                    }
                    let body = url::form_urlencoded::Serializer::new(String::new())
                        .append_pair(param, p.payload)
                        .finish();
                    let Ok(resp) = counted_send(
                        post_form(
                            client,
                            guard,
                            &endpoint,
                            &body,
                            p.verify == Verification::TimeDelay,
                        ),
                        coverage,
                    )
                    .await
                    else {
                        // Rate limited or transport failure: stop this endpoint.
                        break 'post_pass;
                    };
                    let elapsed = resp.elapsed.as_millis() as u64;
                    left -= 1;
                    if let Some(proof) = proof_vs_baseline(
                        &baseline.body,
                        0,
                        &resp.body,
                        elapsed,
                        p,
                        DELAY_THRESHOLD_MS,
                        &resp.content_type,
                    ) {
                        admit_proof(
                            &mut findings,
                            &mut seen,
                            endpoint.as_str(),
                            param,
                            proof,
                            p.payload,
                        )?;
                    }
                }
            }
            // XXE probe: upload/parse-shaped endpoints fed the external-entity
            // canary; resolved file content absent from the baseline is the
            // proof. One request per endpoint, after the form loop's POST
            // gate (Allow + check_active) has already run.
            let path = endpoint.path().to_ascii_lowercase();
            if path.contains("upload")
                || path.contains("import")
                || path.contains("parse")
                || path.contains("xml")
            {
                let Ok(resp) =
                    counted_send(post_xml(client, guard, &endpoint, XXE_PAYLOAD), coverage).await
                else {
                    break 'post_pass;
                };
                if resp.body.contains(XXE_MARKER) && !baseline.body.contains(XXE_MARKER) {
                    emit_unique(
                        &mut findings,
                        &mut seen,
                        "XxeExtraction",
                        endpoint.as_str(),
                        "",
                        Evidence::XxeExtraction {
                            url: endpoint.as_str().to_owned(),
                            file_read: XXE_MARKER.to_owned(),
                        },
                    )?;
                }
            }
        }
    }
    Ok((findings, seen, outcome))
}

/// Top-level scalar fields of an observed JSON body (capped), used so the
/// generated request body resembles the endpoint's own schema.
fn observed_json_fields(body: &str) -> Vec<(String, String)> {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(body.trim())
    else {
        return Vec::new();
    };
    map.into_iter()
        .filter_map(|(key, value)| match value {
            serde_json::Value::String(text) => Some((key, text)),
            serde_json::Value::Number(number) => Some((key, number.to_string())),
            _ => None,
        })
        .take(JSON_KEYS.len())
        .collect()
}

/// The fuzzable field set: fields parsed from the observed JSON body first,
/// then the conventional keys the endpoint did not show.
fn json_fields(observed: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut fields = observed;
    for key in JSON_KEYS {
        if !fields
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(key))
        {
            let filler = if key == "email" {
                "test@example.com"
            } else {
                "test"
            };
            fields.push((key.to_owned(), filler.to_owned()));
        }
    }
    fields
}

/// JSON body for the endpoint fuzzer: every field keeps its observed value,
/// except the one under test, into which `payload` is injected. Operator
/// payloads (`{"$ne": null}`) become real JSON values; string payloads are
/// appended to the field's value, as a user would type them.
fn json_body(fields: &[(String, String)], payload: Option<(&str, &str)>) -> String {
    let mut obj = serde_json::Map::new();
    for (key, observed) in fields {
        let value = match payload {
            Some((target, p)) if target == key => {
                match serde_json::from_str::<serde_json::Value>(p) {
                    Ok(operator) if operator.is_object() || operator.is_array() => operator,
                    _ => serde_json::Value::String(format!("{observed}{p}")),
                }
            }
            _ => serde_json::Value::String(observed.clone()),
        };
        obj.insert(key.clone(), value);
    }
    serde_json::Value::Object(obj).to_string()
}

/// Fuzz a JSON endpoint: baseline POST with plain strings first, then one
/// payload per well-known key. NoSQL is proven only by the session
/// differential (injected POST grants a session the baseline was denied).
#[allow(clippy::too_many_arguments)] // scan-pass shape, same as fuzz_endpoints
async fn fuzz_json(
    client: &Client,
    guard: &ScopeGuard,
    coverage: &Coverage,
    url: &Url,
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, String, &'static str)>,
    deadline: Option<Instant>,
    depth: Depth,
) -> Result<(), ScanError> {
    // Write-class probe: a scope or read-only rejection means skip, never an error.
    if !allows_all_probes(depth) || guard.is_read_only() || guard.check_active(url).is_err() {
        return Ok(());
    }
    let baseline = post_json(
        client,
        guard,
        url,
        &json_body(&json_fields(Vec::new()), None),
        false,
    )
    .await?;
    // Parse the endpoint's own response body so payloads land in its real
    // field names and values, not only the conventional guesses.
    let fields = json_fields(observed_json_fields(&baseline.body));
    let baseline_session = session_granted(&baseline.cookies, None);
    for (key, _) in &fields {
        for p in payloads_for(Context::JsonBody) {
            if overdue(deadline) {
                return Ok(());
            }
            let resp = counted_send(
                post_json(
                    client,
                    guard,
                    url,
                    &json_body(&fields, Some((key.as_str(), p.payload))),
                    p.verify == Verification::TimeDelay,
                ),
                coverage,
            )
            .await?;
            if p.vuln == VulnType::NoSqlInjection {
                if resp.status / 100 == 2
                    && !baseline_session
                    && session_granted(&resp.cookies, None)
                {
                    admit_proof(
                        findings,
                        seen,
                        url.as_str(),
                        key.as_str(),
                        Proof::NoSql,
                        p.payload,
                    )?;
                }
            } else if let Some(proof) = proof_vs_baseline(
                &baseline.body,
                0,
                &resp.body,
                0,
                p,
                DELAY_THRESHOLD_MS,
                &resp.content_type,
            ) {
                admit_proof(findings, seen, url.as_str(), key, proof, p.payload)?;
            }
        }
    }
    Ok(())
}

impl Scanner for GenericScanner {
    fn id(&self) -> &'static str {
        "generic"
    }

    fn matches(&self, _url: &Url) -> bool {
        true
    }

    async fn scan(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        self.run(url, client, guard, passive, None).await
    }

    async fn scan_until(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        passive: bool,
        deadline: Option<Instant>,
    ) -> Result<Vec<Finding>, ScanError> {
        self.run(url, client, guard, passive, deadline).await
    }
}

impl GenericScanner {
    /// The whole scan. `deadline` is the CLI's wall clock: stop starting
    /// requests once it passes and return what was proven — a cancelled
    /// engine loses its findings.
    async fn run(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        passive: bool,
        deadline: Option<Instant>,
    ) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();
        // The fuzz stages below push into `findings` as they prove things; a
        // target that dies mid-scan must not erase them (the CLI drops an
        // engine's findings when it returns Err), so transport failures end
        // the run with whatever was already proven.
        let res = async {
            if passive || (!self.force_run && !self.matches(url)) {
                return Ok(());
            }
            guard.check(url)?;
            let mut seen: HashSet<(String, String, &'static str)> = HashSet::new();
            // This one clean GET is the shared baseline for the URL-param,
            // JSON-sniff and header fuzz stages at the bottom of the scan.
            let first = match baseline_get(client, url).await {
                Ok(response) => response,
                Err(ScanError::Http(e)) if e.is_timeout() => {
                    // A slow root is retained as an untested outcome; discovered
                    // endpoints still get independent adaptive baselines.
                    logln!("[!] Base page timed out; scanning discovered endpoints only.");
                    self.coverage.endpoint_at(url.as_str(), error_outcome(&e));
                    fuzz_endpoints(
                        client,
                        guard,
                        url,
                        &self.endpoints,
                        if allows_all_probes(self.depth) {
                            usize::MAX
                        } else {
                            READ_PARAM_PROBES
                        },
                        &self.coverage,
                        &mut findings,
                        &mut seen,
                        deadline,
                        self.events.as_ref(),
                        self.depth,
                        self.authenticated,
                    )
                    .await?;
                    return Ok(());
                }
                Err(ScanError::Http(e)) => {
                    self.coverage.endpoint_at(url.as_str(), error_outcome(&e));
                    return Err(ScanError::Http(e));
                }
                Err(error @ ScanError::Body(_)) => {
                    // An undecodable or oversized baseline is unavailable
                    // evidence, not a scan-wide failure. Record one failed
                    // endpoint and one inconclusive check; never fuzz unread
                    // page content.
                    self.coverage.unreadable_endpoint_at(url.as_str());
                    logln!(
                        "[!] Base page body unreadable; skipping probes for this endpoint: {error}"
                    );
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let page = if waf_answer(&first) {
                match baseline_with_waf_guard(client, url, first).await {
                    Ok(BaselineRead::WafBlocked) => {
                        self.coverage
                            .endpoint_at(url.as_str(), EndpointOutcome::WafBlocked);
                        self.coverage.mark_blocked(url.as_str());
                        fuzz_endpoints(
                            client,
                            guard,
                            url,
                            &self.endpoints,
                            if allows_all_probes(self.depth) {
                                usize::MAX
                            } else {
                                READ_PARAM_PROBES
                            },
                            &self.coverage,
                            &mut findings,
                            &mut seen,
                            deadline,
                            self.events.as_ref(),
                            self.depth,
                            self.authenticated,
                        )
                        .await?;
                        return Ok(());
                    }
                    Ok(BaselineRead::Ready(response)) => response,
                    Err(error) => {
                        self.coverage
                            .endpoint_at(url.as_str(), scan_error_outcome(&error));
                        return Err(error);
                    }
                }
            } else {
                first
            };
            let page_status = reqwest::StatusCode::from_u16(page.status)
                .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR);
            let content_type = page.content_type.clone();
            let baseline_ms = page.elapsed.as_millis() as u64;
            let page_status_code = page.status;
            let page_location = page.location.as_deref();
            let baseline_outcome = classify_baseline(page_status_code, page_location);
            if matches!(
                baseline_outcome,
                EndpointOutcome::AuthRequired
                    | EndpointOutcome::Failed
                    | EndpointOutcome::WafBlocked
            ) {
                // Existence disclosure only: a denial is not access proof, and no
                // payload follows a terminal baseline.
                if is_sensitive_path(url.path()) && matches!(page_status_code, 401 | 403) {
                    emit_unique(
                        &mut findings,
                        &mut seen,
                        "SensitivePathDisclosed",
                        url.as_str(),
                        "",
                        Evidence::SensitivePathDisclosed {
                            url: url.as_str().to_owned(),
                            status: page_status_code,
                        },
                    )?;
                }
                self.coverage.endpoint_at(url.as_str(), baseline_outcome);
                self.coverage.mark_blocked(url.as_str());
                return Ok(());
            }
            let page = page.body;
            // The scanned URL is classified here, once, by the caller.
            self.coverage.endpoint_at(url.as_str(), baseline_outcome);
            // Same anonymous sensitive-path check for the scanned URL itself.
            // A 401/403 baseline returned above, so only access markers remain.
            if is_sensitive_path(url.path()) {
                if let Some(marker) = access_marker(page_status.as_u16(), &page) {
                    emit_unique(
                        &mut findings,
                        &mut seen,
                        "BrokenAccessControl",
                        url.as_str(),
                        marker,
                        Evidence::BrokenAccessControl {
                            url: url.as_str().to_owned(),
                            dashboard_marker: marker.to_owned(),
                        },
                    )?;
                }
            }
            // scraper::Html is not Send: parse and extract before any await.
            let forms = {
                let doc = Html::parse_document(&page);
                extract_forms(&doc, url)
            };
            // The page GET is a full body the scan already paid for: scan it for
            // live secrets before the SPA check can skip the rest of the run.
            scan_secrets(url.as_str(), &page, &mut findings, &mut seen)?;
            // Aggressive pass on the crawler-discovered endpoints (GET params +
            // OPTIONS→POST), sharing one request budget across the whole scan.
            // Runs before the SPA-shell skip below: the shell hands static form
            // probing to the SpaScanner, but API routes live in the crawl and
            // only this pass fuzzes them.
            fuzz_endpoints(
                client,
                guard,
                url,
                &self.endpoints,
                if allows_all_probes(self.depth) {
                    usize::MAX
                } else {
                    READ_PARAM_PROBES
                },
                &self.coverage,
                &mut findings,
                &mut seen,
                deadline,
                self.events.as_ref(),
                self.depth,
                self.authenticated,
            )
            .await?;
            // SPA shells render their forms in the browser; skip the static
            // probes so the SpaScanner owns the target without duplicate noise.
            if is_spa_shell(&page, forms.len()) {
                return Ok(());
            }
            if overdue(deadline) {
                return Ok(());
            }
            for form in forms.into_iter().take(MAX_FORMS) {
                // A cross-host form action (SSO, newsletter) is out of scope:
                // skip the form, never abort the whole scan run.
                if form.post {
                    // Read depth never submits a POST form (login bypass, SQLi,
                    // XXE and CSRF submission all ride this branch).
                    if guard.is_read_only() || guard.check_active(&form.action).is_err() {
                        continue;
                    }
                } else if guard.check(&form.action).is_err() {
                    continue;
                }
                if form.post
                    && form
                        .inputs
                        .iter()
                        .any(|i| has_key(&i.name, &["password", "email"]))
                    && !form.inputs.iter().any(|i| {
                        i.kind.eq_ignore_ascii_case("hidden") && has_key(&i.name, &CSRF_KEYS)
                    })
                {
                    findings.push(ProofGate::admit(Evidence::CsrfMissingToken {
                        url: url.as_str().to_owned(),
                        form_action: form.action.as_str().to_owned(),
                    })?);
                }
                // Weaponized SQLi auth bypass: wrong credentials must fail
                // first, else the form is a backdoor, not SQLi evidence.
                if allows_all_probes(self.depth) {
                    if let Some((user, pass)) = login_fields(&form) {
                        let action_path = form.action.path().to_owned();
                        let baseline = submit(
                            client,
                            guard,
                            &form,
                            &creds(&form, &user, &pass, "riftlock_baseline"),
                            false,
                        )
                        .await?;
                        if !granted(&baseline, &action_path) {
                            for payload in AUTH_BYPASS_PAYLOADS {
                                let injected = counted_send(
                                    submit(
                                        client,
                                        guard,
                                        &form,
                                        &creds(&form, &user, &pass, payload),
                                        false,
                                    ),
                                    &self.coverage,
                                )
                                .await?;
                                if granted(&injected, &action_path) {
                                    emit_unique(
                                        &mut findings,
                                        &mut seen,
                                        "SqlInjection",
                                        form.action.as_str(),
                                        &user,
                                        Evidence::SqlInjection {
                                            url: form.action.as_str().to_owned(),
                                            param: user.clone(),
                                            payload: (*payload).to_owned(),
                                        },
                                    )?;
                                    break;
                                }
                            }
                        }
                    }
                }
                let first_text = form
                    .inputs
                    .iter()
                    .find(|i| TEXT_TYPES.contains(&i.kind.to_lowercase().as_str()))
                    .map(|i| i.name.clone());
                let Some(first_text) = first_text else {
                    continue;
                };
                let originals: Vec<(String, String)> = form
                    .inputs
                    .iter()
                    .map(|i| (i.name.clone(), i.value.clone()))
                    .collect();
                // SQLi probe: single quote into the same text inputs. The
                // signature must be injection-induced: absent from a clean
                // submit, else any page naming its database is a false hit.
                let clean = submit(client, guard, &form, &[], false).await?;
                let clean_lower = clean.body.to_lowercase();
                let active_supported = supports_active_payloads(&form.action, &clean.content_type);
                if active_supported {
                    let mut params = originals.clone();
                    for p in &mut params {
                        if form.inputs.iter().any(|i| {
                            i.name == p.0 && TEXT_TYPES.contains(&i.kind.to_lowercase().as_str())
                        }) {
                            p.1 = "'".to_owned();
                        }
                    }
                    let body =
                        counted_send(submit(client, guard, &form, &params, false), &self.coverage)
                            .await?
                            .body;
                    let lower = body.to_lowercase();
                    if let Some(sig) = SQLI_SIGNATURES.iter().find(|s| {
                        lower.contains(&s.to_lowercase())
                            && !clean_lower.contains(&s.to_lowercase())
                    }) {
                        emit_unique(
                            &mut findings,
                            &mut seen,
                            "SqlInjection",
                            form.action.as_str(),
                            &first_text,
                            Evidence::SqliError {
                                url: form.action.as_str().to_owned(),
                                param: first_text.clone(),
                                error_signature: (*sig).to_owned(),
                            },
                        )?;
                    }
                }
                // Weaponized reflected-XSS: the raw payload must be absent
                // from a clean GET of the action, else a page legitimately
                // containing its own scripts would be a false positive.
                let originals: Vec<(String, String)> = form
                    .inputs
                    .iter()
                    .map(|i| (i.name.clone(), i.value.clone()))
                    .collect();
                if active_supported {
                    if let Some(name) = form
                        .inputs
                        .iter()
                        .find(|i| {
                            !i.kind.eq_ignore_ascii_case("password")
                                && TEXT_TYPES.contains(&i.kind.to_lowercase().as_str())
                        })
                        .map(|i| i.name.clone())
                    {
                        let resp = counted_send(
                            submit(
                                client,
                                guard,
                                &form,
                                &with_value(&originals, &name, XSS_PAYLOAD),
                                false,
                            ),
                            &self.coverage,
                        )
                        .await?;
                        if let Some(proof) =
                            xss_proof(&resp.body, XSS_PAYLOAD, &clean.body, &resp.content_type)
                        {
                            admit_proof(
                                &mut findings,
                                &mut seen,
                                form.action.as_str(),
                                &name,
                                proof,
                                XSS_PAYLOAD,
                            )?;
                        }
                    }
                }
                // Deeper-DAST probes: time-based SQLi, SSTI and LFI, one
                // injected request per target param at a time (attribution).
                let targets: Vec<String> = form
                    .inputs
                    .iter()
                    .filter(|i| {
                        probe_param(&i.name)
                            || !param_vulns(&i.name).is_empty()
                            || TEXT_TYPES.contains(&i.kind.to_lowercase().as_str())
                    })
                    .map(|i| i.name.clone())
                    .collect();
                if targets.is_empty() {
                    continue;
                }
                let baseline = submit(client, guard, &form, &originals, false).await?;
                let baseline_ms = baseline.elapsed.as_millis() as u64;
                let baseline_body = baseline.body;
                if allows_all_probes(self.depth) && active_supported {
                    for name in &targets {
                        let params = with_value(&originals, name, "' OR SLEEP(5)--");
                        let resp = counted_send(
                            submit(client, guard, &form, &params, true),
                            &self.coverage,
                        )
                        .await?;
                        if let Some(delay) =
                            time_delay_finding(baseline_ms, resp.elapsed.as_millis() as u64)
                        {
                            emit_unique(
                                &mut findings,
                                &mut seen,
                                "SqlInjection",
                                form.action.as_str(),
                                name,
                                Evidence::SqliTimeDelay {
                                    url: form.action.as_str().to_owned(),
                                    param: name.clone(),
                                    delay_ms: delay,
                                },
                            )?;
                        }
                    }
                }
                if allows_all_probes(self.depth) && active_supported {
                    for name in &targets {
                        for payload in ["${7*7}", "{{7*7}}"] {
                            let body = counted_send(
                                submit(
                                    client,
                                    guard,
                                    &form,
                                    &with_value(&originals, name, payload),
                                    false,
                                ),
                                &self.coverage,
                            )
                            .await?
                            .body;
                            // Baseline must be clean of "49", or the page just
                            // happens to contain it (false positive).
                            if body.contains("49")
                                && !body.contains(payload)
                                && !baseline_body.contains("49")
                            {
                                emit_unique(
                                    &mut findings,
                                    &mut seen,
                                    "Ssti",
                                    form.action.as_str(),
                                    name,
                                    Evidence::SstiReflection {
                                        url: form.action.as_str().to_owned(),
                                        param: name.clone(),
                                        evaluated_string: "49".to_owned(),
                                    },
                                )?;
                                break;
                            }
                        }
                    }
                }
                if allows_all_probes(self.depth) && active_supported {
                    for name in &targets {
                        for (marker, payload) in LFI_MARKERS {
                            let body = counted_send(
                                submit(
                                    client,
                                    guard,
                                    &form,
                                    &with_value(&originals, name, payload.payload),
                                    false,
                                ),
                                &self.coverage,
                            )
                            .await?
                            .body;
                            if body.contains(marker) && !baseline_body.contains(marker) {
                                emit_unique(
                                    &mut findings,
                                    &mut seen,
                                    "Lfi",
                                    form.action.as_str(),
                                    name,
                                    Evidence::LfiRead {
                                        url: form.action.as_str().to_owned(),
                                        param: name.clone(),
                                        file_read: marker.to_owned(),
                                    },
                                )?;
                                break;
                            }
                        }
                    }
                }
                // Payload-engine fuzz of the same probe targets: one param at a
                // time, the full FormData catalog (adds XSS polyglots, CMDi and
                // per-param error signatures on top of the probes above),
                // reusing the measured clean baseline.
                for name in &targets {
                    for p in payloads_for(Context::FormData)
                        .filter(|p| active_payload_allowed(p, active_supported))
                        .filter(|p| payload_enabled(self.depth, p))
                    {
                        if p.verify == Verification::TimeDelay && !allows_all_probes(self.depth) {
                            continue;
                        }
                        let resp = counted_send(
                            submit(
                                client,
                                guard,
                                &form,
                                &with_value(&originals, name, p.payload),
                                p.verify == Verification::TimeDelay,
                            ),
                            &self.coverage,
                        )
                        .await?;
                        let elapsed = resp.elapsed.as_millis() as u64;
                        if let Some(proof) = proof_vs_baseline(
                            &baseline_body,
                            baseline_ms,
                            &resp.body,
                            elapsed,
                            p,
                            DELAY_THRESHOLD_MS,
                            &resp.content_type,
                        ) {
                            admit_proof(
                                &mut findings,
                                &mut seen,
                                form.action.as_str(),
                                name,
                                proof,
                                p.payload,
                            )?;
                        }
                        admit_redirect(
                            &mut findings,
                            &mut seen,
                            name,
                            p,
                            &Probe {
                                target: form.action.as_str().to_owned(),
                                status: resp.status,
                                location: resp.location,
                                body: resp.body,
                                content_type: resp.content_type,
                                elapsed_ms: elapsed,
                                payload: p.payload.to_owned(),
                            },
                        )?;
                    }
                }
            }
            // Universal fuzz stages on the scanned URL itself: query params,
            // JSON endpoints (when the page looks like one) and headers — all
            // differential against the one clean GET taken at the top.
            let baseline = Baseline {
                body: &page,
                ms: baseline_ms,
                threshold_ms: DELAY_THRESHOLD_MS,
            };
            if supports_active_payloads(url, &content_type) {
                fuzz_url_params(
                    client,
                    guard,
                    &self.coverage,
                    url,
                    &baseline,
                    &mut findings,
                    &mut seen,
                    deadline,
                    self.depth,
                )
                .await?;
            }
            if looks_like_json(&content_type, &page) {
                fuzz_json(
                    client,
                    guard,
                    &self.coverage,
                    url,
                    &mut findings,
                    &mut seen,
                    deadline,
                    self.depth,
                )
                .await?;
            }
            fuzz_headers(
                client,
                guard,
                &self.coverage,
                url,
                &baseline,
                &mut findings,
                &mut seen,
                deadline,
                self.depth,
            )
            .await?;
            Ok(())
        }
        .await;
        keep_proven(res, findings)
    }
}

/// A target that dies mid-scan must not cost the engine the findings it
/// already proved: the CLI drops everything an engine returns on `Err`.
/// Transport failures are downgraded once there is proof; scope and internal
/// errors still abort, and a failure with nothing to show is still reported.
fn keep_proven(
    res: Result<(), ScanError>,
    findings: Vec<Finding>,
) -> Result<Vec<Finding>, ScanError> {
    match res {
        Ok(()) => Ok(findings),
        Err(
            ScanError::Http(_) | ScanError::Io(_) | ScanError::HttpStatus(_) | ScanError::Body(_),
        ) if !findings.is_empty() => Ok(findings),
        Err(e) => Err(e),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    #[test]
    fn endpoint_params_use_real_names_and_cap_large_sets() {
        let url = Url::parse("https://example.test/search?term=cat&file=manual").expect("url");
        assert_eq!(endpoint_params(&url), ["term", "file"]);
        let url = Url::parse("https://example.test/search?q=cat").expect("url");
        assert_eq!(endpoint_params(&url), ["q"]);
        let url = Url::parse("https://example.test/search?Q=cat").expect("url");
        assert_eq!(endpoint_params(&url), ["Q"]);
        let url = Url::parse("https://example.test/search").expect("url");
        assert!(endpoint_params(&url).is_empty());
        let nineteen: Vec<String> = (0..19).map(|index| format!("id{index}")).collect();
        let url = Url::parse(&format!(
            "https://example.test/search?{}",
            nineteen
                .iter()
                .map(|name| format!("{name}=s"))
                .collect::<Vec<_>>()
                .join("&")
        ))
        .expect("url");
        assert_eq!(endpoint_params(&url), nineteen, "under 20 keeps every name");
        let twenty: Vec<String> = (0..20).map(|index| format!("id{index}")).collect();
        let url = Url::parse(&format!(
            "https://example.test/search?{}",
            twenty
                .iter()
                .map(|name| format!("{name}=s"))
                .collect::<Vec<_>>()
                .join("&")
        ))
        .expect("url");
        assert_eq!(
            endpoint_params(&url),
            ["id0", "id1", "id2", "id3", "id4"],
            "20 names keep the first five in URL order"
        );
    }

    #[test]
    fn static_and_unsupported_endpoints_skip_active_payloads() {
        for path in ["/app.js", "/style.css", "/logo.png", "/photo.jpg"] {
            let url = Url::parse(&format!("https://example.test{path}")).expect("url");
            assert!(!supports_active_payloads(&url, "text/html"));
        }
        let url = Url::parse("https://example.test/page").expect("url");
        assert!(!supports_active_payloads(&url, "text/plain"));
        assert!(supports_active_payloads(&url, "application/json"));
        assert!(supports_active_payloads(&url, "text/html; charset=utf-8"));
        let sql = Payload {
            context: Context::UrlParam,
            vuln: VulnType::SqlInjection,
            payload: "'",
            verify: Verification::ErrorSignature,
        };
        assert!(!active_payload_allowed(&sql, false));
        assert!(active_payload_allowed(&sql, true));
    }

    /// Lab guard + base URL (`{uri}/`) for a running mock server.
    fn lab(server: &MockServer) -> (Url, ScopeGuard) {
        let host = Url::parse(&server.uri())
            .expect("url")
            .host_str()
            .unwrap_or_default()
            .to_owned();
        let origin = format!("https://{host}");
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        (
            base,
            ScopeGuard::new_lab(&[origin.as_str()]).expect("guard"),
        )
    }

    /// The production client surfaces 3xx responses instead of following
    /// them (the open-redirect proof needs the raw `Location`); mirror that
    /// here so mock 302s are not chased out of scope.
    fn scan_client() -> Client {
        Client::new_lab()
    }

    /// Serve `html` at "/"; returns the server so tests can mount handlers
    /// for the form's action path before scanning.
    async fn start_page(html: &str) -> (MockServer, Url, ScopeGuard) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(html.to_owned(), "text/html"))
            .mount(&server)
            .await;
        let (base, guard) = lab(&server);
        (server, base, guard)
    }

    async fn scan_at_depth(
        base: &Url,
        guard: &ScopeGuard,
        passive: bool,
        depth: Depth,
    ) -> Result<Vec<Finding>, ScanError> {
        GenericScanner {
            force_run: true,
            depth,
            ..Default::default()
        }
        .scan(base, &scan_client(), guard, passive)
        .await
    }

    async fn scan(
        base: &Url,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        scan_at_depth(base, guard, passive, Depth::Read).await
    }

    async fn mount_post(server: &MockServer, handler: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(handler)
            .mount(server)
            .await;
    }

    /// Echo the submitted form params back, decoded (values include `<`).
    fn echo_handler(escape_lt: bool) -> impl Fn(&Request) -> ResponseTemplate {
        move |req: &Request| {
            let echoed: String = url::form_urlencoded::parse(&req.body)
                .map(|(k, v)| {
                    let v = if escape_lt {
                        v.replace('<', "&lt;")
                    } else {
                        v.into_owned()
                    };
                    format!("{k}={v}")
                })
                .collect::<Vec<_>>()
                .join("&");
            ResponseTemplate::new(200).set_body_raw(echoed, "text/html")
        }
    }

    async fn echo_form(escape_lt: bool) -> Result<Vec<Finding>, ScanError> {
        let html = r#"<html><body><form method="POST" action="/login">
            <input type="text" name="q"></form></body></html>"#;
        let (server, base, guard) = start_page(html).await;
        Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(echo_handler(escape_lt))
            .mount(&server)
            .await;
        scan(&base, &guard, false).await
    }

    fn login_form(token: Option<&str>) -> String {
        let hidden = token
            .map(|t| format!(r#"<input type="hidden" name="csrf_token" value="{t}">"#))
            .unwrap_or_default();
        format!(
            r#"<html><body><form method="POST" action="/login">
            <input type="text" name="email"><input type="password" name="password">
            {hidden}<input type="submit"></form></body></html>"#
        )
    }

    #[test]
    fn boolean_proof_requires_equal_success_and_body_divergence() {
        let probe = |status, body: &str, payload: &str| Probe {
            target: String::new(),
            status,
            location: None,
            body: body.to_owned(),
            content_type: "text/html".to_owned(),
            elapsed_ms: 0,
            payload: payload.to_owned(),
        };
        let baseline = "product details page";
        // Same 2xx on both halves, truthy tracks the baseline, falsy does not.
        assert!(boolean_proof(
            baseline,
            &probe(200, "product details page", "1 AND 1=1"),
            &probe(200, "no results", "1 AND 1=2"),
        ));
        // An error or a block page on the false half is not SQL evaluation.
        assert!(!boolean_proof(
            baseline,
            &probe(200, "product details page", "1 AND 1=1"),
            &probe(500, "server error", "1 AND 1=2"),
        ));
        assert!(!boolean_proof(
            baseline,
            &probe(200, "product details page", "1 AND 1=1"),
            &probe(403, "blocked", "1 AND 1=2"),
        ));
        // An echoed payload explains the divergence as reflection, not SQL.
        assert!(!boolean_proof(
            baseline,
            &probe(200, "product details page", "1 AND 1=1"),
            &probe(200, "1 AND 1=2", "1 AND 1=2"),
        ));
    }

    #[test]
    fn access_markers_require_protected_content() {
        assert_eq!(access_marker(200, "Dashboard"), Some("dashboard"));
        assert_eq!(access_marker(200, "<app-root></app-root>"), None);
        assert_eq!(access_marker(200, "private page"), None);
        assert_eq!(access_marker(403, "denied"), None);
        assert_eq!(access_marker(302, ""), None);
    }

    #[test]
    fn read_payload_policy_reserves_time_delay_for_godmode() {
        for payload in payloads_for(Context::UrlParam) {
            assert_eq!(
                payload_enabled(Depth::Read, payload),
                payload.verify != Verification::TimeDelay,
                "unexpected read policy for {payload:?}"
            );
            assert!(
                payload_enabled(Depth::Godmode, payload),
                "godmode must run every class: {payload:?}"
            );
            assert!(
                !payload_enabled(Depth::Normal, payload),
                "normal must send no payloads: {payload:?}"
            );
        }
    }

    #[test]
    fn endpoint_concurrency_tracks_scan_depth() {
        assert_eq!(endpoint_concurrency(Depth::Normal), 4);
        assert_eq!(endpoint_concurrency(Depth::Read), 16);
        assert_eq!(endpoint_concurrency(Depth::Godmode), 20);
    }

    #[tokio::test]
    async fn csrf_missing_token_emits_finding() {
        let html = login_form(None);
        let (server, base, guard) = start_page(&html).await;
        mount_post(&server, ResponseTemplate::new(200)).await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::CsrfMissingToken { .. }
        ));
    }

    #[tokio::test]
    async fn csrf_present_is_no_finding() {
        let html = login_form(Some("abc"));
        let (server, base, guard) = start_page(&html).await;
        mount_post(&server, ResponseTemplate::new(200)).await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
    }

    #[tokio::test]
    async fn framework_csrf_fields_and_observations_are_respected() {
        // Alternative framework defenses are recognized, not assumed absent.
        for field in [
            "_token",
            "xsrf-token",
            "__RequestVerificationToken",
            "authenticity_token",
        ] {
            let html = format!(
                r#"<html><body><form method="POST" action="/login">
                <input type="text" name="email"><input type="password" name="password">
                <input type="hidden" name="{field}" value="t"></form></body></html>"#
            );
            let (server, base, guard) = start_page(&html).await;
            mount_post(&server, ResponseTemplate::new(200)).await;
            assert!(
                scan(&base, &guard, false).await.expect("scan").is_empty(),
                "{field}"
            );
        }
        // A missing token is a passive posture observation, never a
        // confirmed exploit.
        let (server, base, guard) = start_page(&login_form(None)).await;
        mount_post(&server, ResponseTemplate::new(200)).await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        let csrf = findings
            .iter()
            .find(|f| matches!(f.evidence(), Evidence::CsrfMissingToken { .. }))
            .expect("observation");
        assert_eq!(
            csrf.confidence(),
            riftlock_core::proof::Confidence::Potential
        );
    }

    #[tokio::test]
    async fn unescaped_executable_payload_emits_xss() {
        let findings = echo_form(false).await.expect("scan");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::ReflectedXss { param, payload, .. } => {
                assert_eq!(param, "q");
                assert_eq!(payload, XSS_PAYLOAD);
            }
            other => panic!("expected ReflectedXss, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inert_custom_tag_reflection_is_not_xss() {
        let html = r#"<html><body><form method="POST" action="/login">
            <input type="text" name="q"></form></body></html>"#;
        let (server, base, guard) = start_page(html).await;
        Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(|request: &Request| {
                let value = url::form_urlencoded::parse(&request.body)
                    .find(|(name, _)| name == "q")
                    .map(|(_, value)| value.into_owned())
                    .unwrap_or_default();
                let escaped = value.replace('<', "&lt;");
                ResponseTemplate::new(200).set_body_raw(
                    format!("<html><xss>inert marker</xss>{escaped}</html>"),
                    "text/html",
                )
            })
            .mount(&server)
            .await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert!(!findings.iter().any(|finding| matches!(
            finding.evidence(),
            Evidence::XssReflection { .. } | Evidence::ReflectedXss { .. }
        )));
    }

    #[tokio::test]
    async fn escaped_canary_is_no_finding() {
        assert!(echo_form(true).await.expect("scan").is_empty());
    }

    #[tokio::test]
    async fn sqli_signature_emits_sqli_error() {
        let html = r#"<html><body><form method="POST" action="/login">
            <input type="text" name="user"></form></body></html>"#;
        let (server, base, guard) = start_page(html).await;
        Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(|req: &Request| {
                let quoted = url::form_urlencoded::parse(&req.body).any(|(_, v)| v.contains('\''));
                let body = if quoted {
                    "MySQL: SQL syntax error"
                } else {
                    "ok"
                };
                ResponseTemplate::new(200).set_body_raw(body, "text/html")
            })
            .mount(&server)
            .await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::SqliError {
                param,
                error_signature,
                ..
            } => {
                assert_eq!(param, "user");
                assert_eq!(error_signature, "SQL syntax");
            }
            other => panic!("expected SqliError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn passive_mode_sends_no_requests() {
        let html = login_form(None);
        let (server, base, guard) = start_page(&html).await;
        assert!(scan(&base, &guard, true).await.expect("scan").is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }

    /// Grant a session (302 + Set-Cookie) only when a credential value
    /// contains a bypass payload; wrong credentials get a plain 200.
    fn auth_bypass_handler() -> impl Fn(&Request) -> ResponseTemplate {
        |req: &Request| {
            let bypass = url::form_urlencoded::parse(&req.body)
                .any(|(_, v)| v.contains("OR 1=1") || v.contains("uid=*"));
            if bypass {
                ResponseTemplate::new(302)
                    .insert_header("set-cookie", "SESSIONID=riftlock")
                    .set_body_string("")
            } else {
                ResponseTemplate::new(200).set_body_string("invalid credentials")
            }
        }
    }

    #[tokio::test]
    async fn sqli_auth_bypass_emits_sql_injection() {
        let (server, base, guard) = start_page(&login_form(Some("abc"))).await;
        Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(auth_bypass_handler())
            .mount(&server)
            .await;
        let findings = scan_at_depth(&base, &guard, false, Depth::Godmode)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::SqlInjection {
                url,
                param,
                payload,
            } => {
                assert_eq!(param, "email");
                assert_eq!(payload, AUTH_BYPASS_PAYLOADS[0]);
                assert!(url.ends_with("/login"));
            }
            other => panic!("expected SqlInjection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ldap_auth_bypass_proves_like_the_sql_payload() {
        let (server, base, guard) = start_page(&login_form(Some("abc"))).await;
        Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(|req: &Request| {
                let grants =
                    url::form_urlencoded::parse(&req.body).any(|(_, v)| v.contains("uid=*"));
                if grants {
                    ResponseTemplate::new(302)
                        .insert_header("set-cookie", "SESSIONID=riftlock")
                        .set_body_string("")
                } else {
                    ResponseTemplate::new(200).set_body_string("invalid credentials")
                }
            })
            .mount(&server)
            .await;
        let findings = scan_at_depth(&base, &guard, false, Depth::Godmode)
            .await
            .expect("scan");
        match findings[0].evidence() {
            Evidence::SqlInjection { payload, .. } => {
                assert_eq!(payload, AUTH_BYPASS_PAYLOADS[1])
            }
            other => panic!("expected SqlInjection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn xxe_probe_proves_file_extraction_on_upload_endpoints() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("OPTIONS"))
            .respond_with(ResponseTemplate::new(200).insert_header("allow", "GET, POST"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/upload"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"status\":\"ok\"}"))
            .mount(&server)
            .await;
        // XML body reads /etc/passwd; every other POST is a plain upload.
        Mock::given(method("POST"))
            .and(path("/api/v1/upload"))
            .respond_with(|req: &Request| {
                if String::from_utf8_lossy(&req.body).contains("DOCTYPE") {
                    ResponseTemplate::new(200).set_body_string("root:x:0:0:root:/root:/bin/bash\n")
                } else {
                    ResponseTemplate::new(200).set_body_string("{\"status\":\"uploaded\"}")
                }
            })
            .mount(&server)
            .await;
        let findings = fuzz_at_depth(
            &base,
            &guard,
            &[format!("{}/api/v1/upload?id=1", server.uri())],
            Depth::Godmode,
        )
        .await
        .expect("fuzz");
        match findings
            .iter()
            .find(|f| matches!(f.evidence(), Evidence::XxeExtraction { .. }))
        {
            Some(f) => match f.evidence() {
                Evidence::XxeExtraction { url, file_read } => {
                    assert_eq!(Url::parse(url).expect("url").path(), "/api/v1/upload");
                    assert_eq!(file_read, "root:x:0:0");
                }
                _ => unreachable!(),
            },
            None => panic!(
                "expected XxeExtraction, got {:?}",
                findings.iter().map(|f| f.evidence()).collect::<Vec<_>>()
            ),
        }
    }

    #[tokio::test]
    async fn auth_bypass_json_proves_on_ldap_shaped_endpoints() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("OPTIONS"))
            .respond_with(ResponseTemplate::new(200).insert_header("allow", "GET, POST"))
            .mount(&server)
            .await;
        // POST-only login route: GET is refused with 405, not 404, so the
        // endpoint is not a dead end and the login pass still runs.
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/ldap"))
            .respond_with(ResponseTemplate::new(405).insert_header("allow", "POST"))
            .mount(&server)
            .await;
        // Raw JSON body: the bypass payload reaches the handler verbatim.
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/ldap"))
            .respond_with(|req: &Request| {
                let body = String::from_utf8_lossy(&req.body);
                if body.contains("uid=*") {
                    ResponseTemplate::new(200)
                        .insert_header("set-cookie", "session=riftlock")
                        .set_body_string("{\"status\":\"success\",\"role\":\"admin\"}")
                } else {
                    ResponseTemplate::new(401).set_body_string("{\"error\":\"invalid\"}")
                }
            })
            .mount(&server)
            .await;
        let findings = fuzz_at_depth(
            &base,
            &guard,
            &[format!("{}/api/v1/auth/ldap?id=1", server.uri())],
            Depth::Godmode,
        )
        .await
        .expect("fuzz");
        match findings
            .iter()
            .find(|f| matches!(f.evidence(), Evidence::SqlInjection { .. }))
        {
            Some(f) => match f.evidence() {
                Evidence::SqlInjection {
                    url,
                    param,
                    payload,
                } => {
                    assert_eq!(Url::parse(url).expect("url").path(), "/api/v1/auth/ldap");
                    assert_eq!(param, "email");
                    assert_eq!(payload, AUTH_BYPASS_PAYLOADS[1]);
                }
                _ => unreachable!(),
            },
            None => panic!(
                "expected SqlInjection, got {:?}",
                findings.iter().map(|f| f.evidence()).collect::<Vec<_>>()
            ),
        }
    }

    #[tokio::test]
    async fn baseline_404_is_terminal_and_sends_no_lfi_payload() {
        // Even though a traversal would read a file, a 404 baseline proves
        // the endpoint is a dead end: it is recorded Failed and no payload
        // is sent.
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/download"))
            .and(query_param("file", "../../../../etc/passwd"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("root:x:0:0:root", "text/html"))
            .mount(&server)
            .await;
        let findings = fuzz(
            &base,
            &guard,
            &[format!("{}/api/v1/download?file=manual", server.uri())],
        )
        .await
        .expect("fuzz");
        assert!(
            findings.is_empty(),
            "a 404 baseline must not be fuzzed: {:?}",
            findings.iter().map(|f| f.evidence()).collect::<Vec<_>>()
        );
        let hits = server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .filter(|r| r.url.path() == "/api/v1/download")
            .count();
        assert_eq!(hits, 1, "only the 404 baseline GET; no payloads follow");
    }

    #[tokio::test]
    async fn auth_bypass_json_proves_on_login_api_endpoints() {
        // The lab shape: a bare JSON login API (no form on the page) whose
        // POST /api/v1/auth/login grants a session on the bypass payload.
        // post_login's redirect-target hints never match this path — the
        // mini-pass must gate on the endpoint itself.
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("OPTIONS"))
            .respond_with(ResponseTemplate::new(200).insert_header("allow", "GET, POST"))
            .mount(&server)
            .await;
        // POST-only login route: GET is refused with 405, not 404, so the
        // endpoint is not a dead end and the login pass still runs.
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/login"))
            .respond_with(ResponseTemplate::new(405).insert_header("allow", "POST"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/login"))
            .respond_with(|req: &Request| {
                let body = String::from_utf8_lossy(&req.body);
                if body.contains("OR 1=1") {
                    ResponseTemplate::new(200)
                        .insert_header("set-cookie", "session=admin_token_999")
                        .set_body_string("{\"status\":\"success\"}")
                } else {
                    ResponseTemplate::new(401).set_body_string("{\"error\":\"invalid\"}")
                }
            })
            .mount(&server)
            .await;
        let findings = fuzz_at_depth(
            &base,
            &guard,
            &[format!("{}/api/v1/auth/login?id=1", server.uri())],
            Depth::Godmode,
        )
        .await
        .expect("fuzz");
        match findings
            .iter()
            .find(|f| matches!(f.evidence(), Evidence::SqlInjection { .. }))
        {
            Some(f) => match f.evidence() {
                Evidence::SqlInjection { url, payload, .. } => {
                    assert_eq!(Url::parse(url).expect("url").path(), "/api/v1/auth/login");
                    assert_eq!(payload, AUTH_BYPASS_PAYLOADS[0]);
                }
                _ => unreachable!(),
            },
            None => panic!(
                "expected SqlInjection on the login API, got {:?}",
                findings.iter().map(|f| f.evidence()).collect::<Vec<_>>()
            ),
        }
    }

    #[tokio::test]
    async fn auth_bypass_runs_without_allow_header_and_accepts_body_token() {
        // Juice Shop shape: OPTIONS advertises nothing (404), and the session
        // is a JSON body token, not a Set-Cookie. Neither may suppress the
        // login pass or hide the proof.
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        // POST-only route: GET is refused with 405, not 404, so the endpoint
        // is not a dead end and the login pass still runs.
        Mock::given(method("GET"))
            .and(path("/rest/user/login"))
            .respond_with(ResponseTemplate::new(405).insert_header("allow", "POST"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/rest/user/login"))
            .respond_with(|req: &Request| {
                let body = String::from_utf8_lossy(&req.body);
                if body.contains("\"password\":\"' OR 1=1--\"") {
                    ResponseTemplate::new(200).set_body_string(
                        "{\"authentication\":{\"token\":\"eyJhbGciOiJIUzI1NiJ9.x.y\"}}",
                    )
                } else {
                    ResponseTemplate::new(401).set_body_string("{\"error\":\"Invalid email\"}")
                }
            })
            .mount(&server)
            .await;
        let findings = fuzz_at_depth(
            &base,
            &guard,
            &[format!("{}/rest/user/login?id=1", server.uri())],
            Depth::Godmode,
        )
        .await
        .expect("fuzz");
        match findings
            .iter()
            .find(|f| matches!(f.evidence(), Evidence::SqlInjection { .. }))
        {
            Some(f) => match f.evidence() {
                Evidence::SqlInjection { url, payload, .. } => {
                    assert_eq!(Url::parse(url).expect("url").path(), "/rest/user/login");
                    assert_eq!(payload, AUTH_BYPASS_PAYLOADS[0]);
                }
                _ => unreachable!(),
            },
            None => panic!(
                "expected SqlInjection with no Allow header, got {:?}",
                findings.iter().map(|f| f.evidence()).collect::<Vec<_>>()
            ),
        }
    }

    #[tokio::test]
    async fn backdoored_login_is_not_sqli_evidence() {
        let (server, base, guard) = start_page(&login_form(Some("abc"))).await;
        // Wrong credentials also grant a session: skip, no finding.
        Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(ResponseTemplate::new(302).insert_header("set-cookie", "SESSIONID=x"))
            .mount(&server)
            .await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
    }

    #[test]
    fn spa_shell_detection() {
        for marker in SPA_MARKERS {
            assert!(is_spa_shell(&format!("<html>{marker}</html>"), 0));
            assert!(is_spa_shell(&format!("<html>{marker}</html>"), 1));
            // Two or more static forms: not an SPA shell for our purposes.
            assert!(!is_spa_shell(&format!("<html>{marker}</html>"), 2));
        }
        assert!(!is_spa_shell("<html><body></body></html>", 0));
        // `id="root"` must be the exact attribute, not a prefix match.
        assert!(!is_spa_shell(r#"<div id="rootfoo"></div>"#, 0));
    }

    #[tokio::test]
    async fn spa_shell_page_is_skipped() {
        // One csrf-less login form would emit a finding if not skipped;
        // the SPA marker hands the target to the SpaScanner instead.
        let html = r#"<html><body><div id="root"></div>
            <form method="POST" action="/login">
            <input type="text" name="email"><input type="password" name="password">
            </form></body></html>"#;
        let (server, base, guard) = start_page(html).await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
        assert!(!server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .any(|r| r.url.path() == "/login"));
    }

    #[test]
    fn extract_forms_parses_action_and_inputs() {
        let base = Url::parse("https://t.example/app/").expect("url");
        let html = r#"<form method="POST" action="login">
            <input type="text" name="email">
            <input type="password" name="password">
            <input type="hidden" name="csrf" value="t"></form>"#;
        let forms = extract_forms(&Html::parse_document(html), &base);
        assert_eq!(forms.len(), 1);
        assert!(forms[0].post);
        assert_eq!(forms[0].action.as_str(), "https://t.example/app/login");
        assert_eq!(forms[0].inputs.len(), 3);
        assert_eq!(forms[0].inputs[0].name, "email");
        assert_eq!(forms[0].inputs[1].kind, "password");
    }

    #[test]
    fn session_cookie_detection() {
        assert!(session_granted(&["SESSIONID=abc".to_owned()], None));
        assert!(session_granted(
            &["theme=dark".to_owned()],
            Some("/dashboard")
        ));
        assert!(!session_granted(&["theme=dark".to_owned()], Some("/login")));
        assert!(!session_granted(&[], None));
    }

    #[test]
    fn json_reflection_is_informational_and_html_is_confirmed() {
        let p = "<script>alert(1)</script>";
        let json = format!(r#"{{"echo":"{p}"}}"#);
        // T1: JSON content type never becomes a confirmed XSS.
        assert!(matches!(
            xss_proof(&json, p, r#"{"echo":"ok"}"#, "application/json"),
            Some(Proof::XssReflection("json"))
        ));
        // T2: the same payload parsed as HTML is executable.
        assert!(matches!(
            xss_proof(&format!("<html>{p}</html>"), p, "clean", "text/html"),
            Some(Proof::Xss)
        ));
    }

    #[test]
    fn reflected_raw_requires_clean_baseline() {
        let p = "<script>alert(1)</script>";
        assert!(reflected_raw(
            &format!("hi {p} bye"),
            p,
            "clean page",
            "text/html"
        ));
        // An entity-escaped echo never matches the raw payload.
        assert!(!reflected_raw(
            "hi &lt;script&gt;alert(1)&lt;/script&gt;",
            p,
            "clean",
            "text/html"
        ));
        // Payload already in the baseline: not an injection.
        assert!(!reflected_raw(p, p, p, "text/html"));
        // A JSON body is reflection, not executable markup.
        assert!(!reflected_raw(
            &format!(r#"{{"echo":"{p}"}}"#),
            p,
            r#"{"echo":"ok"}"#,
            "application/json"
        ));
        // Raw markup in an HTML text element is inert, not executable.
        assert!(!reflected_raw(
            &format!("<textarea>{p}</textarea>"),
            p,
            "clean",
            "text/html"
        ));
        // An event handler is executable.
        assert!(reflected_raw(
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "clean",
            "text/html"
        ));
    }

    fn form_with(kinds: &[(&str, &str)]) -> Form {
        Form {
            action: Url::parse("https://t.example/login").expect("url"),
            post: true,
            inputs: kinds
                .iter()
                .map(|(k, n)| Input {
                    name: (*n).to_owned(),
                    kind: (*k).to_owned(),
                    value: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn login_fields_selects_user_and_password() {
        let f = form_with(&[
            ("text", "email"),
            ("password", "password"),
            ("hidden", "csrf"),
        ]);
        assert_eq!(
            login_fields(&f),
            Some(("email".to_owned(), "password".to_owned()))
        );
        assert_eq!(login_fields(&form_with(&[("text", "q")])), None);
    }

    /// A page with one GET form carrying a probe-target param (`search`).
    fn probe_page() -> &'static str {
        r#"<html><body><form method="GET" action="/item">
            <input type="text" name="search" value="laptop"></form></body></html>"#
    }

    /// Return `hit` body when query param `key` contains `needle`, else `miss`.
    fn query_body(
        key: &'static str,
        needle: &'static str,
        hit: &'static str,
        miss: &'static str,
    ) -> impl Fn(&Request) -> ResponseTemplate {
        move |req: &Request| {
            let hit_req = req
                .url
                .query_pairs()
                .any(|(k, v)| k == key && v.contains(needle));
            ResponseTemplate::new(200).set_body_raw(if hit_req { hit } else { miss }, "text/html")
        }
    }

    #[test]
    fn time_delay_threshold() {
        assert_eq!(time_delay_finding(100, 5200), Some(5100));
        assert_eq!(time_delay_finding(100, 4600), None);
        assert_eq!(time_delay_finding(100, 4601), Some(4501));
        assert_eq!(time_delay_finding(0, 4500), None);
    }

    #[tokio::test]
    async fn ssti_evaluated_expression_emits_finding() {
        let (server, base, guard) = start_page(probe_page()).await;
        Mock::given(method("GET"))
            .and(path("/item"))
            .respond_with(query_body(
                "search",
                "${7*7}",
                "user 49 profile",
                "user profile",
            ))
            .mount(&server)
            .await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::SstiReflection {
                param,
                evaluated_string,
                ..
            } => {
                assert_eq!(param, "search");
                assert_eq!(evaluated_string, "49");
            }
            other => panic!("expected SstiReflection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ssti_in_baseline_is_no_finding() {
        let (server, base, guard) = start_page(probe_page()).await;
        // The page always contains "49": the baseline check suppresses it.
        Mock::given(method("GET"))
            .and(path("/item"))
            .respond_with(query_body("search", "${7*7}", "49 users", "49 items"))
            .mount(&server)
            .await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
    }

    #[tokio::test]
    async fn lfi_passwd_marker_emits_finding() {
        let (server, base, guard) = start_page(probe_page()).await;
        Mock::given(method("GET"))
            .and(path("/item"))
            .respond_with(query_body(
                "search",
                "etc/passwd",
                "root:x:0:0:0:root:/root:/bin/bash",
                "no results",
            ))
            .mount(&server)
            .await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::LfiRead {
                param, file_read, ..
            } => {
                assert_eq!(param, "search");
                assert_eq!(file_read, "root:x:0:0");
            }
            other => panic!("expected LfiRead, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn lfi_marker_absent_is_no_finding() {
        let (server, base, guard) = start_page(probe_page()).await;
        // The traversal payload is echoed back but no file content: no proof.
        Mock::given(method("GET"))
            .and(path("/item"))
            .respond_with(query_body(
                "search",
                "etc/passwd",
                "path tried: /etc/passwd",
                "no results",
            ))
            .mount(&server)
            .await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
    }

    #[tokio::test]
    async fn rate_limit_skips_probe_after_bounded_retries() {
        let server = MockServer::start().await;
        let ok_url = Url::parse(&format!("{}/ok", server.uri())).expect("url");
        let limited_url = Url::parse(&format!("{}/limited", server.uri())).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let client = scan_client();
        let attempts = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path("/ok"))
            .respond_with({
                let attempts = Arc::clone(&attempts);
                move |_req: &Request| {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    ResponseTemplate::new(429)
                }
            })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/limited"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        guard.check(&ok_url).expect("scope");
        let limited = AtomicBool::new(false);
        let cov = Coverage::default();
        let response = send_counted(client.get(ok_url.clone()), &cov, &limited)
            .await
            .expect("rate limit");
        assert!(matches!(response, CountedSend::Limited));
        assert!(limited.load(Ordering::Relaxed));
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("requests")
                .iter()
                .filter(|r| r.url.path() == "/ok")
                .count(),
            4
        );

        guard.check(&limited_url).expect("scope");
        let coverage = Coverage::default();
        let limited = AtomicBool::new(false);
        assert!(matches!(
            send_counted(client.get(limited_url), &coverage, &limited)
                .await
                .expect("inconclusive result"),
            CountedSend::Limited
        ));
        let snapshot = coverage.snapshot(0);
        assert_eq!(snapshot.vulnerability_checks_attempted, 1);
        assert_eq!(snapshot.vulnerability_checks_inconclusive, 1);
    }

    #[tokio::test]
    async fn read_depth_allows_time_delay_for_unreflective_id_only() {
        let (server, base, guard) = start_page(probe_page()).await;
        Mock::given(method("GET"))
            .and(path("/item"))
            .respond_with(|req: &Request| {
                let delay = req
                    .url
                    .query_pairs()
                    .any(|(name, value)| name == "productId" && value.contains("SLEEP"));
                let body = req
                    .url
                    .query_pairs()
                    .find(|(name, _)| name == "productId")
                    .map_or_else(|| "ok".to_owned(), |(_, value)| format!("product {value}"));
                let response = ResponseTemplate::new(200).set_body_raw(body, "text/html");
                if delay {
                    response.set_delay(Duration::from_millis(60))
                } else {
                    response
                }
            })
            .mount(&server)
            .await;
        let url = Url::parse(&format!("{}?productId=7&q=hello", base)).expect("url");
        scan_at_depth(&url, &guard, false, Depth::Read)
            .await
            .expect("scan");
        let requests = server.received_requests().await.expect("requests");
        assert!(requests.iter().any(|r| r
            .url
            .query_pairs()
            .any(|(name, value)| { name == "productId" && value.contains("SLEEP") })));
        assert!(!requests.iter().any(|r| r
            .url
            .query_pairs()
            .any(|(name, value)| { name == "q" && value.contains("SLEEP") })));
    }

    #[tokio::test]
    async fn read_depth_skips_time_delay_when_id_value_is_reflected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/item"))
            .respond_with(|req: &Request| {
                let body = req
                    .url
                    .query_pairs()
                    .find(|(name, _)| name == "productId")
                    .map_or_else(|| "ok".to_owned(), |(_, value)| format!("product {value}"));
                ResponseTemplate::new(200).set_body_string(body)
            })
            .mount(&server)
            .await;
        let (_, guard) = lab(&server);
        let url = Url::parse(&format!("{}/item?productId=7", server.uri())).expect("url");
        scan_at_depth(&url, &guard, false, Depth::Read)
            .await
            .expect("scan");
        let requests = server.received_requests().await.expect("requests");
        assert!(
            !requests.iter().any(|r| {
                r.url
                    .query_pairs()
                    .any(|(name, value)| name == "productId" && value.contains("SLEEP"))
            }),
            "unexpected time-delay probe: {requests:?}"
        );
    }

    #[tokio::test]
    async fn tiny_delay_is_no_finding_and_probe_fires() {
        let (server, base, guard) = start_page(probe_page()).await;
        Mock::given(method("GET"))
            .and(path("/item"))
            .respond_with(|req: &Request| {
                let injected = req.url.query_pairs().any(|(_, v)| v.contains("SLEEP"));
                let t = ResponseTemplate::new(200).set_body_raw("ok", "text/html");
                if injected {
                    t.set_delay(Duration::from_millis(60))
                } else {
                    t
                }
            })
            .mount(&server)
            .await;
        // Deep scans include sleep probes, but a sub-threshold delay is not proof.
        assert!(scan_at_depth(&base, &guard, false, Depth::Godmode)
            .await
            .expect("scan")
            .is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .any(|r| r.url.query_pairs().any(|(_, v)| v.contains("SLEEP"))));
    }

    /// GET "/" returning `hit` when any query value contains `needle`, else
    /// `miss` (which doubles as the clean scan baseline).
    fn query_or_page(
        needle: &'static str,
        hit: &'static str,
        miss: &'static str,
    ) -> impl Fn(&Request) -> ResponseTemplate {
        move |req: &Request| {
            let hit_req = req.url.query_pairs().any(|(_, v)| v.contains(needle));
            ResponseTemplate::new(200).set_body_raw(
                if hit_req {
                    hit.to_owned()
                } else {
                    miss.to_owned()
                },
                "text/html",
            )
        }
    }

    /// Scan a URL with one query param `?q=probe`, answered by a
    /// [`query_or_page`] handler.
    async fn param_scan(
        needle: &'static str,
        hit: &'static str,
    ) -> Result<Vec<Finding>, ScanError> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(query_or_page(
                needle,
                hit,
                "<html><body>clean</body></html>",
            ))
            .mount(&server)
            .await;
        let (base, guard) = lab(&server);
        let url = Url::parse(&format!("{}?q=probe", base.as_str())).expect("url");
        GenericScanner {
            force_run: true,
            ..Default::default()
        }
        .scan(&url, &Client::new_lab(), &guard, false)
        .await
    }

    #[tokio::test]
    async fn url_param_xss_reflection_emits_finding() {
        let findings = param_scan("<script>", "echo <script>alert(1)</script> here")
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::ReflectedXss { param, payload, .. } => {
                assert_eq!(param, "q");
                assert_eq!(payload, "<script>alert(1)</script>");
            }
            other => panic!("expected ReflectedXss, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn url_param_ssti_emits_finding() {
        let findings = param_scan("7*7", "total is 49 units").await.expect("scan");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::SstiReflection {
                param,
                evaluated_string,
                ..
            } => {
                assert_eq!(param, "q");
                assert_eq!(evaluated_string, "49");
            }
            other => panic!("expected SstiReflection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn url_param_ssti_raw_reflection_is_no_finding() {
        let findings = param_scan("7*7", "template input was 7*7")
            .await
            .expect("scan");
        assert!(
            findings.is_empty(),
            "raw expression reflection is not evaluation: {findings:?}"
        );
    }

    #[tokio::test]
    async fn cmdi_command_output_emits_finding() {
        // The handler strips the payload syntax and returns only the command
        // output: `id` output proves execution.
        let findings = param_scan("id;", "uid=1000(user) gid=1000(user)")
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::CommandInjection { param, payload, .. } => {
                assert_eq!(param, "q");
                assert!(payload.contains("id"), "{payload}");
            }
            other => panic!("expected CommandInjection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cmdi_payload_reflection_is_no_finding() {
        // The payload echoed verbatim is reflection, not execution: no real
        // command output appears, so nothing is reported.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(|req: &Request| {
                let q = req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "q")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
                let body = if q.contains("id;") {
                    q
                } else {
                    "<html>clean</html>".to_owned()
                };
                ResponseTemplate::new(200).set_body_string(body)
            })
            .mount(&server)
            .await;
        let (base, guard) = lab(&server);
        let url = Url::parse(&format!("{}?q=probe", base.as_str())).expect("url");
        assert!(GenericScanner {
            force_run: true,
            ..Default::default()
        }
        .scan(&url, &Client::new_lab(), &guard, false)
        .await
        .expect("scan")
        .is_empty());
    }

    #[tokio::test]
    async fn escaped_reflection_is_no_finding() {
        assert!(
            param_scan("<script>", "&lt;script&gt;alert(1)&lt;/script&gt;")
                .await
                .expect("scan")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn header_time_delay_emits_finding() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(|req: &Request| {
                let sleep = req
                    .headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.contains("SLEEP"));
                let t = ResponseTemplate::new(200).set_body_string("ok");
                if sleep {
                    t.set_delay(Duration::from_millis(60))
                } else {
                    t
                }
            })
            .mount(&server)
            .await;
        let (url, guard) = lab(&server);
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        // Baseline GET is instant; the 30 ms threshold sits below the 60 ms
        // injected delay so the differential is observable in test time.
        let baseline = Baseline {
            body: "ok",
            ms: 0,
            threshold_ms: 30,
        };
        fuzz_headers(
            &Client::new_lab(),
            &guard,
            &riftlock_core::Coverage::default(),
            &url,
            &baseline,
            &mut findings,
            &mut seen,
            None,
            Depth::Godmode,
        )
        .await
        .expect("fuzz");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::SqliTimeDelay { param, .. } => assert_eq!(param, "X-Forwarded-For"),
            other => panic!("expected SqliTimeDelay, got {other:?}"),
        }
    }

    /// A body that dies mid-read is one inconclusive check, not a completed
    /// one: the read failure must not be counted in both columns.
    #[tokio::test]
    async fn header_body_read_failure_is_inconclusive_not_completed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = [0u8; 2048];
                    let _ = socket.read(&mut request).await;
                    // Declares 64 bytes, delivers 5, closes: a stream error.
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\nshort")
                        .await;
                });
            }
        });
        let url = Url::parse(&format!("http://{addr}/")).expect("url");
        let guard = ScopeGuard::new_lab(&[url.as_str()]).expect("guard");
        let coverage = riftlock_core::Coverage::default();
        let baseline = Baseline {
            body: "short",
            ms: 0,
            threshold_ms: 30,
        };
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        fuzz_headers(
            &Client::new_lab(),
            &guard,
            &coverage,
            &url,
            &baseline,
            &mut findings,
            &mut seen,
            None,
            Depth::Read,
        )
        .await
        .expect("fuzz");
        let snapshot = coverage.snapshot(0);
        assert!(findings.is_empty());
        assert!(snapshot.vulnerability_checks_attempted > 0);
        assert_eq!(snapshot.vulnerability_checks_completed, 0);
        assert_eq!(
            snapshot.vulnerability_checks_inconclusive,
            snapshot.vulnerability_checks_attempted
        );
    }

    #[tokio::test]
    async fn unreadable_discovered_baseline_is_failed_and_inconclusive() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/users"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(b"not a gzip stream".to_vec()),
            )
            .mount(&server)
            .await;
        let (base, guard) = lab(&server);
        let coverage = riftlock_core::Coverage::default();
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        fuzz_endpoints(
            &scan_client(),
            &guard,
            &base,
            &[format!("{base}api/users")],
            20,
            &coverage,
            &mut findings,
            &mut seen,
            None,
            None,
            Depth::Read,
            false,
        )
        .await
        .expect("unreadable baseline is an incomplete endpoint, not a scan error");

        let snapshot = coverage.snapshot(2);
        assert!(findings.is_empty());
        assert_eq!(snapshot.endpoints_failed, 1);
        assert_eq!(snapshot.endpoints_tested_successfully, 0);
        assert_eq!(snapshot.vulnerability_checks_attempted, 1);
        assert_eq!(snapshot.vulnerability_checks_completed, 0);
        assert_eq!(snapshot.vulnerability_checks_inconclusive, 1);
        assert!(snapshot.check_accounting_invariant());
        assert!(coverage.finalize().reconciles());
    }

    /// The progress plan (base + discovered endpoints) is exactly the set
    /// coverage classifies: the denominator and outcome counters must agree,
    /// and out-of-scope discoveries are reported as skipped.
    #[tokio::test]
    async fn planned_endpoint_denominator_matches_classified_outcomes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>ok</html>"))
            .mount(&server)
            .await;
        let (base, guard) = lab(&server);
        let endpoints = vec![
            base.to_string(),
            format!("{base}api/users"),
            "https://elsewhere.example/app.js".to_owned(),
        ];
        let coverage = riftlock_core::Coverage::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        GenericScanner {
            force_run: true,
            endpoints,
            coverage: coverage.clone(),
            events: Some(tx),
            ..Default::default()
        }
        .scan(&base, &scan_client(), &guard, false)
        .await
        .expect("scan");
        let mut planned = None;
        let mut skipped = Vec::new();
        while let Ok(event) = rx.try_recv() {
            match event {
                GenericEvent::EndpointsStarted { total, .. } => planned = Some(total),
                GenericEvent::EndpointSkipped { endpoint } => skipped.push(endpoint),
                _ => {}
            }
        }
        let planned = planned.expect("the endpoint plan is announced");
        assert_eq!(planned, 3, "base + both discovered endpoints");
        assert!(
            skipped.is_empty(),
            "out-of-scope endpoints remain in the accounted plan"
        );
        let snapshot = coverage.snapshot(planned as u64);
        let classified = snapshot.endpoints_tested_successfully
            + snapshot.endpoints_timed_out
            + snapshot.endpoints_failed
            + snapshot.endpoints_auth_required
            + snapshot.endpoints_waf_blocked
            + snapshot.endpoints_skipped
            + snapshot.endpoints_circuit_open;
        assert_eq!(
            classified as usize, planned,
            "coverage outcomes must account for every planned endpoint: {snapshot:?}"
        );
    }

    #[tokio::test]
    async fn json_nosql_session_differential_emits_finding() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"app": "api"})),
            )
            .mount(&server)
            .await;
        // Only the email field carrying the NoSQL operator authenticates.
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(|req: &Request| {
                let body = String::from_utf8_lossy(&req.body);
                let t = ResponseTemplate::new(200).set_body_string("result");
                if body.contains(r#""email":{"$ne""#) {
                    t.insert_header("set-cookie", "SESSIONID=riftlock")
                } else {
                    t
                }
            })
            .mount(&server)
            .await;
        let (base, guard) = lab(&server);
        let findings = GenericScanner {
            force_run: true,
            depth: Depth::Godmode,
            ..Default::default()
        }
        .scan(&base, &Client::new_lab(), &guard, false)
        .await
        .expect("scan");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::NoSqlInjection { param, payload, .. } => {
                assert_eq!(param, "email");
                assert_eq!(payload, r#"{"$ne": null}"#);
            }
            other => panic!("expected NoSqlInjection, got {other:?}"),
        }
    }

    #[test]
    fn id_param_payload_contract() {
        // SQLi catalog entries must be exact (no "admin"-prefixed variant)
        // and every surface keeps a SLEEP(5) time-based fallback.
        let payloads = payloads_for_param("id", Context::UrlParam);
        assert!(payloads.iter().any(|p| p.payload.contains("SLEEP(5)")));
        assert!(!payloads.iter().any(|p| p.payload.starts_with("admin")));
        assert!(payloads_for_param("id", Context::JsonBody)
            .iter()
            .any(|p| p.payload == "' OR 1=1--"));
    }

    #[tokio::test]
    async fn endpoint_query_pass_sends_all_vulnerability_classes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("ok", "text/html"))
            .mount(&server)
            .await;
        let (base, guard) = lab(&server);
        fuzz(&base, &guard, &[format!("{}/api?id=1", server.uri())])
            .await
            .expect("fuzz");
        let requests = server.received_requests().await.expect("request log");
        let payloads: Vec<String> = requests
            .iter()
            .flat_map(|request| {
                request
                    .url
                    .query_pairs()
                    .map(|(_, value)| value.into_owned())
            })
            .collect();
        assert!(
            payloads.iter().any(|value| value.ends_with("' OR 1=1--")),
            "SQLi payload not sent"
        );
        assert!(
            payloads.iter().any(|value| value.contains("etc/passwd")),
            "LFI payload not sent"
        );
        assert!(
            payloads
                .iter()
                .any(|value| value.contains("riftlock.evil.com")),
            "redirect payload not sent"
        );
    }

    /// Run the endpoint pass at an explicit scan depth.
    async fn fuzz_at_depth(
        base: &Url,
        guard: &ScopeGuard,
        endpoints: &[String],
        depth: Depth,
    ) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        fuzz_endpoints(
            &scan_client(),
            guard,
            base,
            endpoints,
            600,
            &riftlock_core::Coverage::default(),
            &mut findings,
            &mut seen,
            None,
            None,
            depth,
            false,
        )
        .await?;
        Ok(findings)
    }

    /// Run only the endpoint pass against `endpoints` at Read depth.
    async fn fuzz(
        base: &Url,
        guard: &ScopeGuard,
        endpoints: &[String],
    ) -> Result<Vec<Finding>, ScanError> {
        fuzz_at_depth(base, guard, endpoints, Depth::Read).await
    }

    #[test]
    fn probe_endpoints_puts_login_endpoints_first() {
        let base = Url::parse("https://t.example/").expect("url");
        let eps = vec![
            "https://t.example/about".to_owned(),
            "https://t.example/api/Challenges".to_owned(),
            "https://t.example/rest/products/search".to_owned(),
            "https://t.example/rest/user/login".to_owned(),
            "https://t.example/rest/baskets/1".to_owned(),
        ];
        let got = probe_endpoints(&base, &eps);
        assert_eq!(got[0].path(), "/rest/user/login", "{got:?}");
        assert_eq!(got[1].path(), "/api/Challenges", "{got:?}");
        assert_eq!(got.last().map(url::Url::path), Some("/about"), "{got:?}");
    }

    #[test]
    fn bumped_resource_id_mutates_only_numeric_tails() {
        let url = Url::parse("https://t.example/api/users/41").expect("url");
        let (id, mutated) = bumped_resource_id(&url).expect("numeric tail");
        assert_eq!(id, 41);
        assert_eq!(mutated.as_str(), "https://t.example/api/users/42");
        let trailing = Url::parse("https://t.example/api/users/41/").expect("url");
        assert_eq!(
            bumped_resource_id(&trailing).map(|(_, u)| u.to_string()),
            Some("https://t.example/api/users/42".to_owned())
        );
        let named = Url::parse("https://t.example/api/users").expect("url");
        assert!(bumped_resource_id(&named).is_none());
    }

    /// A target that dies mid-scan must not cost the engine its findings: the
    /// CLI drops a scanner's findings when it returns Err, so the breaker
    /// ends this pass with Ok.
    #[tokio::test]
    async fn breaker_trip_ends_pass_without_dropping_findings() {
        // Reserve and release a port so every request fails to connect fast.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr");
        let origin = format!("http://{addr}");
        let base = Url::parse(&format!("{origin}/")).expect("url");
        let guard = ScopeGuard::new_lab(&[origin.as_str()]).expect("guard");
        let eps: Vec<String> = ["/a", "/b", "/c", "/d", "/e"]
            .into_iter()
            .map(|p| format!("{origin}{p}"))
            .collect();
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let res = fuzz_endpoints(
            &scan_client(),
            &guard,
            &base,
            &eps,
            600,
            &riftlock_core::Coverage::default(),
            &mut findings,
            &mut seen,
            None,
            None,
            Depth::Read,
            false,
        )
        .await;
        assert!(res.is_ok(), "breaker trip must keep findings: {res:?}");
    }

    #[test]
    fn transport_failure_after_proof_keeps_findings_but_not_before() {
        fn died() -> ScanError {
            ScanError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "target died",
            ))
        }
        let proven = vec![ProofGate::admit(Evidence::SecurityMisconfiguration {
            url: "https://t.example/".to_owned(),
            issue: "missing_csp".to_owned(),
            severity: "Low".to_owned(),
        })
        .expect("admitted")];
        let kept = keep_proven(Err(died()), proven.clone()).expect("proof survives a dead target");
        assert_eq!(kept.len(), 1);
        assert!(keep_proven(Err(died()), Vec::new()).is_err());
        assert!(keep_proven(Ok(()), Vec::new()).is_ok());
        // A bad status or an unreadable/oversized body is the target's
        // failure too: proven findings must survive it, as with transport.
        for killed in [
            ScanError::HttpStatus(502),
            ScanError::Body(riftlock_core::body::BodyReadError::TooLarge),
        ] {
            assert_eq!(
                keep_proven(Err(killed), proven.clone())
                    .expect("proof survives a target-side failure")
                    .len(),
                1
            );
        }
    }

    /// The CLI cancels an engine at its budget and a cancelled future loses
    /// its findings: past the deadline only the fast per-endpoint
    /// classification runs — no payload probe — and the pass still returns
    /// Ok with whatever it already proved.
    #[tokio::test]
    async fn past_deadline_skips_payloads_but_classifies_remaining_endpoints() {
        let server = MockServer::start().await;
        let (base, guard) = lab(&server);
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let coverage = riftlock_core::Coverage::default();
        let res = fuzz_endpoints(
            &scan_client(),
            &guard,
            &base,
            &[format!("{}/x", server.uri())],
            600,
            &coverage,
            &mut findings,
            &mut seen,
            Some(Instant::now() - Duration::from_secs(1)),
            None,
            Depth::Read,
            false,
        )
        .await;
        assert!(res.is_ok(), "deadline stop is not an error: {res:?}");
        assert!(findings.is_empty());
        let snap = coverage.snapshot(0);
        let classified = snap.endpoints_tested_successfully
            + snap.endpoints_timed_out
            + snap.endpoints_failed
            + snap.endpoints_auth_required
            + snap.endpoints_waf_blocked
            + snap.endpoints_skipped
            + snap.endpoints_circuit_open;
        assert_eq!(
            classified, 1,
            "the remaining endpoint still gets one disposition past the deadline: {snap:?}"
        );
        let requests = server.received_requests().await.expect("requests");
        assert!(
            !requests.is_empty(),
            "remaining endpoints still get their baseline"
        );
        assert!(
            requests.iter().all(|request| request.url.query().is_none()),
            "no payload probe may fire past the deadline: {requests:?}"
        );
    }

    /// A `break 'endpoint` (here on HTTP 429) used to jump past coverage
    /// recording, leaving a planned endpoint with no disposition at all.
    #[tokio::test]
    async fn rate_limited_endpoint_still_receives_one_disposition() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>ok</html>"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/limited"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let (base, guard) = lab(&server);
        let coverage = riftlock_core::Coverage::default();
        GenericScanner {
            force_run: true,
            endpoints: vec![format!("{base}limited")],
            coverage: coverage.clone(),
            ..Default::default()
        }
        .scan(&base, &scan_client(), &guard, false)
        .await
        .expect("scan");
        let snap = coverage.snapshot(2);
        let classified = snap.endpoints_tested_successfully
            + snap.endpoints_timed_out
            + snap.endpoints_failed
            + snap.endpoints_auth_required
            + snap.endpoints_waf_blocked
            + snap.endpoints_skipped
            + snap.endpoints_circuit_open;
        assert_eq!(
            classified, 2,
            "base and limited endpoint both classified: {snap:?}"
        );
        assert_eq!(
            snap.endpoints_waf_blocked, 1,
            "429 is a WAF block, not a silent gap"
        );
    }

    #[tokio::test]
    async fn endpoint_param_lfi_emits_finding() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("GET"))
            .and(path("/download"))
            .respond_with(query_body(
                "file",
                "etc/passwd",
                "root:x:0:0:0:root:/root:/bin/bash",
                "file listing",
            ))
            .mount(&server)
            .await;
        let findings = fuzz(
            &base,
            &guard,
            &[format!("{}/download?file=manual", server.uri())],
        )
        .await
        .expect("fuzz");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::LfiRead {
                url,
                param,
                file_read,
            } => {
                assert_eq!(param, "file");
                assert_eq!(file_read, "root:x:0:0");
                assert!(url.contains("/download"));
            }
            other => panic!("expected LfiRead, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn html_endpoint_gets_the_smart_query_xss_canary() {
        let server = MockServer::start().await;
        // A plain reflecting page: whatever `q` carries is echoed back raw.
        Mock::given(method("GET"))
            .and(path("/page"))
            .respond_with(|req: &Request| {
                let q = req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "q")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
                ResponseTemplate::new(200).set_body_raw(
                    format!("<html><body>result: {q}</body></html>"),
                    "text/html",
                )
            })
            .mount(&server)
            .await;
        let (base, guard) = lab(&server);
        let findings = fuzz(&base, &guard, &[format!("{}/page?id=1", server.uri())])
            .await
            .expect("fuzz");
        assert!(
            findings.iter().any(|f| matches!(
                f.evidence(),
                Evidence::ReflectedXss { param, .. } if param == "q"
            )),
            "expected the q canary to prove XSS: {findings:?}"
        );
    }

    #[tokio::test]
    async fn json_api_endpoint_gets_smart_query_xss_parameters() {
        for param in SMART_XSS_PARAMS {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/rest/products/search"))
                .respond_with(move |req: &Request| {
                    let value = req
                        .url
                        .query_pairs()
                        .find(|(name, _)| name == param)
                        .map(|(_, value)| value.into_owned())
                        .unwrap_or_default();
                    ResponseTemplate::new(200).set_body_raw(
                        if value.contains(XSS_PAYLOAD) {
                            format!(r#"{{"result":"{XSS_PAYLOAD}"}}"#)
                        } else {
                            r#"{"result":"clean"}"#.to_owned()
                        },
                        "application/json",
                    )
                })
                .mount(&server)
                .await;
            let (base, guard) = lab(&server);
            let findings = fuzz(
                &base,
                &guard,
                &[format!("{}/rest/products/search?id=1", server.uri())],
            )
            .await
            .expect("fuzz");
            assert!(
                findings.iter().any(|finding| matches!(
                    finding.evidence(),
                    Evidence::XssReflection { param: found, context, .. }
                        if found == param && context == "json"
                )),
                "expected informational JSON reflection for {param}: {findings:?}"
            );
        }
    }

    #[tokio::test]
    async fn endpoint_param_ssrf_emits_finding() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("GET"))
            .and(path("/fetch"))
            .respond_with(query_body(
                "url",
                "169.254.169.254",
                "ami-id\nami-0abc123",
                "no fetch",
            ))
            .mount(&server)
            .await;
        let findings = fuzz(
            &base,
            &guard,
            &[format!("{}/fetch?url=manual", server.uri())],
        )
        .await
        .expect("fuzz");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::SsrF { endpoint, payload } => {
                assert!(endpoint.contains("/fetch"));
                assert_eq!(payload, "http://169.254.169.254/latest/meta-data/");
            }
            other => panic!("expected SsrF, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn options_post_fuzz_emits_finding() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("OPTIONS"))
            .and(path("/api"))
            .respond_with(ResponseTemplate::new(200).insert_header("allow", "GET, POST"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api"))
            .respond_with(ResponseTemplate::new(200).set_body_string("api docs"))
            .mount(&server)
            .await;
        // Only the `id` field reflects the raw payload; everything else
        // stays clean so exactly one (param, class) pair is proven.
        Mock::given(method("POST"))
            .and(path("/api"))
            .respond_with(|req: &Request| {
                let hit = url::form_urlencoded::parse(&req.body)
                    .any(|(k, v)| k == "q" && v.contains("alert(1)"));
                let body = if hit {
                    "<script>alert(1)</script> reflected"
                } else {
                    "clean"
                };
                ResponseTemplate::new(200).set_body_raw(body, "text/html")
            })
            .mount(&server)
            .await;
        let findings = fuzz_at_depth(
            &base,
            &guard,
            &[format!("{}/api?q=1", server.uri())],
            Depth::Godmode,
        )
        .await
        .expect("fuzz");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::ReflectedXss {
                url,
                param,
                payload,
            } => {
                assert_eq!(Url::parse(url).expect("url").path(), "/api");
                assert_eq!(param, "q");
                assert_eq!(payload, "<script>alert(1)</script>");
            }
            other => panic!("expected ReflectedXss, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn waf_block_retried_url_encoded() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("GET"))
            .and(path("/dl"))
            .respond_with(|req: &Request| {
                let raw = req.url.query().unwrap_or("");
                if raw.contains("alert(1)") {
                    // WAF: the raw payload on the wire is denied.
                    ResponseTemplate::new(403).set_body_string("denied")
                } else if raw.contains("%3Cscript") {
                    // Encoded variant passes and the app decodes + reflects.
                    ResponseTemplate::new(200)
                        .set_body_raw("<script>alert(1)</script> done", "text/html")
                } else {
                    ResponseTemplate::new(200).set_body_raw("clean", "text/html")
                }
            })
            .mount(&server)
            .await;
        let findings = fuzz(&base, &guard, &[format!("{}/dl?id=1", server.uri())])
            .await
            .expect("fuzz");
        assert!(findings.iter().any(|f| match f.evidence() {
            Evidence::ReflectedXss { payload, .. } => payload.ends_with(" (URL-encoded)"),
            _ => false,
        }));
    }

    #[tokio::test]
    async fn dead_endpoint_skipped_after_baseline() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        // No handler for /missing: wiremock answers 404.
        assert!(fuzz(&base, &guard, &[format!("{}/missing", server.uri())])
            .await
            .expect("fuzz")
            .is_empty());
        let hits = server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .filter(|r| r.url.path() == "/missing")
            .count();
        // Only the baseline GET: a 404 baseline is terminal, so no payload,
        // OPTIONS, or hidden-parameter probe follows.
        assert_eq!(hits, 1);
    }

    #[tokio::test]
    async fn queryless_endpoint_is_baseline_only() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        // Echoes q (an unguarded canary would prove XSS) and advertises POST
        // (an unguarded body pass would send a POST).
        Mock::given(method("GET"))
            .and(path("/quiet"))
            .respond_with(|req: &Request| {
                let q = req
                    .url
                    .query_pairs()
                    .find(|(name, _)| name == "q")
                    .map(|(_, value)| value.into_owned());
                let body = q.map_or_else(
                    || "<html><body>quiet</body></html>".to_owned(),
                    |value| format!("<html><body>{value}</body></html>"),
                );
                ResponseTemplate::new(200).set_body_raw(body, "text/html")
            })
            .mount(&server)
            .await;
        Mock::given(method("OPTIONS"))
            .and(path("/quiet"))
            .respond_with(ResponseTemplate::new(200).insert_header("allow", "GET, POST"))
            .mount(&server)
            .await;
        let coverage = riftlock_core::Coverage::default();
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        fuzz_endpoints(
            &scan_client(),
            &guard,
            &base,
            &[format!("{}/quiet", server.uri())],
            600,
            &coverage,
            &mut findings,
            &mut seen,
            None,
            None,
            Depth::Read,
            false,
        )
        .await
        .expect("fuzz");
        assert!(
            findings.is_empty(),
            "a queryless endpoint may only yield baseline observations: {findings:?}"
        );
        let requests = server.received_requests().await.expect("requests");
        let quiet: Vec<_> = requests
            .iter()
            .filter(|request| request.url.path() == "/quiet")
            .collect();
        assert_eq!(quiet.len(), 1, "only the baseline GET may reach /quiet");
        assert_eq!(quiet[0].method.as_str(), "GET");
        assert!(
            requests
                .iter()
                .all(|request| matches!(request.url.path(), "/" | "/quiet")),
            "no other path may be touched"
        );
        let snapshot = coverage.snapshot(2);
        assert_eq!(snapshot.endpoints_tested_successfully, 1, "{snapshot:?}");
    }

    #[tokio::test]
    async fn large_param_set_fuzzes_only_the_first_five_names() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("GET"))
            .and(path("/search"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("clean", "text/html"))
            .mount(&server)
            .await;
        let query = (0..20)
            .map(|index| format!("id{index}=s"))
            .collect::<Vec<_>>()
            .join("&");
        let endpoint = format!("{}/search?{query}", server.uri());
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        fuzz_endpoints(
            &scan_client(),
            &guard,
            &base,
            &[endpoint],
            600,
            &riftlock_core::Coverage::default(),
            &mut findings,
            &mut seen,
            None,
            None,
            Depth::Read,
            false,
        )
        .await
        .expect("fuzz");
        assert!(findings.is_empty(), "{findings:?}");
        let requests = server.received_requests().await.expect("requests");
        let on_search: Vec<_> = requests
            .iter()
            .filter(|request| request.url.path() == "/search")
            .collect();
        for index in 0..20 {
            let name = format!("id{index}");
            let observed: Vec<String> = on_search
                .iter()
                .filter_map(|request| {
                    request
                        .url
                        .query_pairs()
                        .find(|(key, _)| *key == name)
                        .map(|(_, value)| value.into_owned())
                })
                .collect();
            assert!(!observed.is_empty(), "{name} must reach the baseline");
            if index < 5 {
                assert!(
                    observed.iter().any(|value| value != "s"),
                    "{name} is in the first five and must be fuzzed: {observed:?}"
                );
            } else {
                assert!(
                    observed.iter().all(|value| value == "s"),
                    "{name} is past the cap and must never be mutated: {observed:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn ten_endpoints_five_auth_walls_skipped_in_o1() {
        // Five 401 endpoints and five 200 endpoints: every auth wall gets
        // exactly its baseline GET and nothing else, while every open
        // endpoint is probed. Nothing depends on the payload count, so the
        // skip is O(1) per blocked endpoint.
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        for i in 0..5 {
            Mock::given(method("GET"))
                .and(path(format!("/deny{i}")))
                .respond_with(ResponseTemplate::new(401).set_body_string("denied"))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/open{i}")))
                .respond_with(ResponseTemplate::new(200).set_body_string("clean"))
                .mount(&server)
                .await;
        }
        let endpoints: Vec<String> = (0..5)
            .map(|i| format!("{}/deny{i}", server.uri()))
            .chain((0..5).map(|i| format!("{}/open{i}?id=1", server.uri())))
            .collect();
        let coverage = riftlock_core::Coverage::default();
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        fuzz_endpoints(
            &scan_client(),
            &guard,
            &base,
            &endpoints,
            40,
            &coverage,
            &mut findings,
            &mut seen,
            None,
            None,
            Depth::Read,
            false,
        )
        .await
        .expect("fuzz");
        assert!(findings.is_empty());
        let snap = coverage.snapshot(10);
        assert_eq!(snap.endpoints_auth_required, 5, "{snap:?}");
        assert_eq!(snap.endpoints_tested_successfully, 5, "{snap:?}");
        let requests = server.received_requests().await.expect("requests");
        for i in 0..5 {
            let denied = format!("/deny{i}");
            let hits = requests
                .iter()
                .filter(|request| request.url.path() == denied)
                .count();
            assert_eq!(hits, 1, "{denied} must receive only its baseline GET");
            let open = format!("/open{i}");
            let hits = requests
                .iter()
                .filter(|request| request.url.path() == open)
                .count();
            assert!(hits > 1, "{open} must be fuzzed, got {hits} requests");
        }
    }

    #[tokio::test]
    async fn allow_without_post_skips_body_fuzz() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("OPTIONS"))
            .and(path("/e"))
            .respond_with(ResponseTemplate::new(200).insert_header("allow", "GET, HEAD"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/e"))
            .respond_with(ResponseTemplate::new(200).set_body_string("static"))
            .mount(&server)
            .await;
        assert!(fuzz(&base, &guard, &[format!("{}/e?id=1", server.uri())])
            .await
            .expect("fuzz")
            .is_empty());
        let requests = server.received_requests().await.expect("requests");
        assert!(
            requests
                .iter()
                .any(|r| r.method.as_str() == "OPTIONS" && r.url.path() == "/e"),
            "the endpoint pass must reach its OPTIONS check"
        );
        assert!(!requests
            .iter()
            .any(|r| r.method.as_str() == "POST" && r.url.path() == "/e"));
    }

    #[tokio::test]
    async fn foreign_host_endpoints_filtered_out() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        assert!(
            fuzz(&base, &guard, &["https://evil.example/steal".to_owned()])
                .await
                .expect("fuzz")
                .is_empty()
        );
        assert!(!server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .any(|r| r.url.path() == "/steal"));
    }

    #[tokio::test]
    async fn out_of_scope_redirect_endpoint_is_skipped_and_remaining_endpoint_runs() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "https://outside.invalid/blocked"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/healthy"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ordinary page"))
            .mount(&server)
            .await;

        let coverage = Coverage::default();
        let scanner = GenericScanner {
            force_run: true,
            endpoints: vec![format!("{base}redirect"), format!("{base}healthy")],
            coverage: coverage.clone(),
            ..Default::default()
        };
        let findings = scanner
            .scan(&base, &scan_client(), &guard, false)
            .await
            .expect("one out-of-scope redirect must not abort endpoint scanning");
        assert!(findings.is_empty());
        let snapshot = coverage.snapshot(3);
        assert_eq!(snapshot.endpoints_skipped, 1, "{snapshot:?}");
        assert_eq!(snapshot.endpoints_tested_successfully, 2, "{snapshot:?}");
        assert_eq!(
            snapshot.endpoints_tested_successfully
                + snapshot.endpoints_timed_out
                + snapshot.endpoints_failed
                + snapshot.endpoints_auth_required
                + snapshot.endpoints_waf_blocked
                + snapshot.endpoints_skipped
                + snapshot.endpoints_circuit_open,
            3,
            "base + both planned endpoints must be accounted for: {snapshot:?}"
        );
        assert_eq!(
            snapshot.vulnerability_checks_inconclusive, 1,
            "{snapshot:?}"
        );
        assert_eq!(coverage.finalize().in_flight, 0);
        let requests = server.received_requests().await.expect("requests");
        assert!(requests
            .iter()
            .any(|request| request.url.path() == "/healthy"));
    }

    #[tokio::test]
    async fn clean_endpoint_no_findings() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("GET"))
            .and(path("/e"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello world"))
            .mount(&server)
            .await;
        assert!(fuzz(&base, &guard, &[format!("{}/e?id=1", server.uri())])
            .await
            .expect("fuzz")
            .is_empty());
    }

    #[test]
    fn secret_pattern_boundaries() {
        // Split the synthetic fixture so push protection does not mistake it
        // for an actual Stripe credential.
        let stripe_key = ["sk_", "live_", "51H8xYzABCdefGHIjklMNOpqr"].concat();
        assert!(STRIPE_KEY.is_match(&format!("key: {stripe_key} end")));
        assert!(!STRIPE_KEY.is_match("sk_live_tooshort"));
        assert!(GOOGLE_KEY.is_match("AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"));
        assert!(AWS_KEY.is_match("aws_access_key: AKIAIOSFODNN7EXAMPLE end"));
        // One character short of the 16-char id body.
        assert!(!AWS_KEY.is_match("AKIAIOSFODNN7EXAMP"));
        // Digit on either side is not an SSN boundary.
        assert!(SSN.is_match("ssn 123-45-6789."));
        assert!(!SSN.is_match("9123-45-6789"));
        assert!(!SSN.is_match("123-45-67890"));
    }

    #[tokio::test]
    async fn page_secret_and_jwt_emits_findings() {
        let stripe_key = ["sk_", "live_", "51H8xYzABCdefGHIjklMNOpqr"].concat();
        let body = format!("var cfg = {{key: '{stripe_key}', tok: 'eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJwYXNzd29yZCI6InNlY3JldDEyMyJ9.sig'}};");
        let (_server, base, guard) = start_page(&format!("<html><body>{body}</body></html>")).await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert_eq!(findings.len(), 2);
        match findings[0].evidence() {
            Evidence::SensitiveDataExposure { url, data_type } => {
                assert_eq!(data_type, "stripe_secret_key");
                assert_eq!(url, base.as_str());
            }
            other => panic!("expected SensitiveDataExposure, got {other:?}"),
        }
        match findings[1].evidence() {
            Evidence::JwtVulnerability { endpoint, issue } => {
                assert_eq!(endpoint, base.as_str());
                assert_eq!(issue, "sensitive_claim");
            }
            other => panic!("expected JwtVulnerability, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn options_dangerous_methods_emits_finding() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("OPTIONS"))
            .and(path("/api"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("allow", "GET, POST, PUT, DELETE, OPTIONS"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api"))
            .respond_with(ResponseTemplate::new(200).set_body_string("api docs"))
            .mount(&server)
            .await;
        let findings = fuzz(&base, &guard, &[format!("{}/api?id=1", server.uri())])
            .await
            .expect("fuzz");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::SecurityMisconfiguration {
                url,
                issue,
                severity,
            } => {
                assert_eq!(Url::parse(url).expect("url").path(), "/api");
                assert_eq!(issue, "dangerous_methods_allowed: PUT, DELETE");
                assert_eq!(severity, "Medium");
            }
            other => panic!("expected SecurityMisconfiguration, got {other:?}"),
        }
    }

    /// Coverage counters: a payload probe answered by a WAF (403) is
    /// Inconclusive, never a finding, and a 403-to-GET endpoint is recorded
    /// as WafBlocked exactly once.
    #[tokio::test]
    async fn waf_block_counts_inconclusive_and_records_endpoint() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        // Clean baseline GET on /dl; any other query (a payload) is blocked.
        Mock::given(method("GET"))
            .and(path("/dl"))
            .respond_with(|req: &Request| {
                if req.url.query().is_some_and(|query| query != "id=1") {
                    ResponseTemplate::new(403).set_body_string("blocked")
                } else {
                    ResponseTemplate::new(200).set_body_string("file listing")
                }
            })
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/block"))
            .respond_with(ResponseTemplate::new(503).set_body_string("blocked"))
            .mount(&server)
            .await;
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let coverage = riftlock_core::Coverage::default();
        // Budget 1: each endpoint fires exactly one probe (the encoded
        // retry is budget-gated off), so the counts stay deterministic.
        let (events, mut received) = tokio::sync::mpsc::channel(16);
        fuzz_endpoints(
            &scan_client(),
            &guard,
            &base,
            &[
                format!("{}/dl?id=1", server.uri()),
                format!("{}/block", server.uri()),
            ],
            1,
            &coverage,
            &mut findings,
            &mut seen,
            None,
            Some(&events),
            Depth::Read,
            false,
        )
        .await
        .expect("fuzz");
        drop(events);
        let mut completed = Vec::new();
        while let Some(event) = received.recv().await {
            if let GenericEvent::EndpointComplete {
                completed: n,
                total,
                endpoint,
                ..
            } = event
            {
                assert_eq!(n, completed.len() + 1);
                assert_eq!(total, 3);
                completed.push(endpoint);
            }
        }
        completed.sort();
        assert_eq!(
            completed,
            vec![
                base.to_string(),
                format!("{}/block", server.uri()),
                format!("{}/dl?id=1", server.uri())
            ]
        );
        // A WAF block is a checked negative: no finding may be fabricated.
        assert!(findings.is_empty());
        let snap = coverage.snapshot(0);
        // /dl answered its baseline GET (tested), /block is WafBlocked after
        // two consecutive 503s. Only /dl reaches its probe loop: its one
        // payload probe is 403'd (Inconclusive), /block never gets past its
        // baseline GETs.
        assert_eq!(snap.endpoints_tested_successfully, 1);
        assert_eq!(snap.endpoints_waf_blocked, 1);
        assert_eq!(snap.vulnerability_checks_attempted, 1);
        assert_eq!(snap.vulnerability_checks_inconclusive, 1);
        assert_eq!(snap.vulnerability_checks_completed, 0);
        // The WAF endpoint sees the two confirming baselines, then nothing.
        let requests = server.received_requests().await.expect("requests");
        let block_hits = requests
            .iter()
            .filter(|request| request.url.path() == "/block")
            .count();
        assert_eq!(block_hits, 2, "two WAF baselines, then an O(1) skip");
    }

    #[tokio::test]
    async fn get_form_parameters_receive_open_redirect_payloads() {
        let html = r#"<form method="GET" action="/redirect">
            <input type="text" name="destination"></form>"#;
        let (server, base, guard) = start_page(html).await;
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .respond_with(|req: &Request| {
                let evil = req.url.query_pairs().any(|(key, value)| {
                    key == "destination" && value.contains("riftlock.evil.com")
                });
                if evil {
                    ResponseTemplate::new(302)
                        .insert_header("content-type", "text/html")
                        .insert_header("location", "https://riftlock.evil.com/x")
                } else {
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "text/html")
                        .set_body_string("stay here")
                }
            })
            .mount(&server)
            .await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert!(findings.iter().any(|finding| matches!(
            finding.evidence(),
            Evidence::OpenRedirect { param, .. } if param == "destination"
        )));
    }

    #[tokio::test]
    async fn redirect_location_proves_open_redirect() {
        let (server, base, guard) = start_page("<html><body>home</body></html>").await;
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .respond_with(|req: &Request| {
                // Only the `url` param redirects, like the real /api/redirect;
                // other appended params get a plain 200.
                let evil = req
                    .url
                    .query_pairs()
                    .any(|(k, v)| k == "url" && v.contains("riftlock.evil.com"));
                if evil {
                    ResponseTemplate::new(302)
                        .insert_header("content-type", "text/html")
                        .insert_header("location", "https://riftlock.evil.com/x")
                } else {
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "text/html")
                        .set_body_string("stay here")
                }
            })
            .mount(&server)
            .await;
        let findings = fuzz(
            &base,
            &guard,
            &[format!("{}/redirect?url=manual", server.uri())],
        )
        .await
        .expect("fuzz");
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|finding| matches!(
            finding.evidence(),
            Evidence::OpenRedirect { param, .. } if param == "url"
        )));
    }

    #[test]
    fn redirect_proof_requires_external_navigation_to_payload_host() {
        let p = Payload {
            context: Context::UrlParam,
            vuln: VulnType::OpenRedirect,
            payload: "https://riftlock.evil.com/path",
            verify: Verification::Reflection,
        };
        let probe = |status: u16, location: Option<&str>, body: &str| Probe {
            target: "https://example.test/redirect?url=payload".into(),
            status,
            location: location.map(str::to_owned),
            body: body.into(),
            content_type: "text/html".into(),
            elapsed_ms: 0,
            payload: p.payload.into(),
        };
        for location in ["/", "https://example.test/path", "https://other.test/path"] {
            let mut findings = Vec::new();
            let mut seen = HashSet::new();
            admit_redirect(
                &mut findings,
                &mut seen,
                "url",
                &p,
                &probe(302, Some(location), ""),
            )
            .expect("negative redirect");
            assert!(findings.is_empty(), "accepted {location}");
        }
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        admit_redirect(
            &mut findings,
            &mut seen,
            "url",
            &p,
            &probe(302, Some("https://riftlock.evil.com/path"), ""),
        )
        .expect("external redirect");
        assert_eq!(findings.len(), 1);

        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        admit_redirect(
            &mut findings,
            &mut seen,
            "url",
            &p,
            &probe(
                200,
                None,
                "<meta http-equiv=\"refresh\" content=\"0;url=https://riftlock.evil.com/path\">",
            ),
        )
        .expect("external meta refresh");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn redirect_proof_rejects_relative_meta_refresh_and_malformed_targets() {
        let p = Payload {
            context: Context::UrlParam,
            vuln: VulnType::OpenRedirect,
            payload: "/",
            verify: Verification::Reflection,
        };
        let probe = Probe {
            target: "not a URL".into(),
            status: 200,
            location: None,
            body: "<meta http-equiv=\"refresh\" content=\"0;url=/\">".into(),
            content_type: "text/html".into(),
            elapsed_ms: 0,
            payload: "/".into(),
        };
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        admit_redirect(&mut findings, &mut seen, "url", &p, &probe).expect("no proof");
        assert!(findings.is_empty());
    }
}
