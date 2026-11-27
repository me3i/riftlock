//! Supabase scanner: table probes with a `limit=1`-enforcing builder,
//! status classification, differential proof against key tiers, auth-surface
//! probes, storage and RPC checks.

pub mod auth;
pub mod escalate;
pub mod logic;
pub mod write;

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    text_limited_result, Coverage, DiscoveryContext, DynamicScanner, EndpointOutcome, Evidence,
    Finding, LabGuard, ProbeStatus, ProofGate, ScanError, Scanner, ScopeGuard,
};
use riftlock_engine::default_verifier;
use riftlock_fingerprint::fingerprint_url;
use serde_json::Value;
use std::borrow::Cow;
use std::pin::Pin;
use url::Url;

/// Errors specific to probe construction.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("select=* requires limit=1")]
pub struct LimitError;

/// A PostgREST query. Construction rejects `select=*` without `limit=1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeQuery {
    select: String,
    limit: u32,
}

impl ProbeQuery {
    /// Build a probe query.
    ///
    /// # Errors
    /// [`LimitError`] when `select` includes `*` and `limit` is not `Some(1)`.
    pub fn new(select: &str, limit: Option<u32>) -> Result<Self, LimitError> {
        let star = select.split(',').any(|s| s.trim() == "*");
        if star && limit != Some(1) {
            return Err(LimitError);
        }
        Ok(Self {
            select: select.to_owned(),
            limit: limit.unwrap_or(1),
        })
    }

    /// The canonical single-row probe query.
    pub fn single_row() -> Self {
        Self {
            select: "*".to_owned(),
            limit: 1,
        }
    }

    /// Query string form: `select=<cols>&limit=<n>`.
    pub fn to_query(&self) -> String {
        format!("select={}&limit={}", self.select, self.limit)
    }
}

/// A validated table name for probe URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableProbe(String);

impl TableProbe {
    /// Validate a table identifier (alphanumeric/underscore, non-empty).
    pub fn new(table: &str) -> Option<Self> {
        let ok = !table.is_empty() && table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        ok.then_some(Self(table.to_owned()))
    }

    /// The validated table name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Supabase keys supplied out-of-band (never harvested into reports).
#[derive(Debug, Clone, Default)]
pub struct SupabaseKeys {
    /// Low-privilege tier (anon or publishable).
    pub low: Option<String>,
    /// Admin tier (`RIFTLOCK_SB_ADMIN`).
    pub admin: Option<String>,
    /// High-privilege tier (service_role or secret).
    pub high: Option<String>,
}

impl SupabaseKeys {
    /// Read keys from `RIFTLOCK_SB_LOW`, `RIFTLOCK_SB_ADMIN`,
    /// `RIFTLOCK_SB_HIGH`.
    pub fn from_env() -> Self {
        Self {
            low: std::env::var("RIFTLOCK_SB_LOW").ok(),
            admin: std::env::var("RIFTLOCK_SB_ADMIN").ok(),
            high: std::env::var("RIFTLOCK_SB_HIGH").ok(),
        }
    }
}

/// Outcome of one probe: raw status + classification + body text.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    /// Raw HTTP status code.
    pub status: u16,
    /// Classified outcome.
    pub classified: ProbeStatus,
    /// Response body (for single-row redaction on 2xx).
    pub body: String,
}

/// Map an HTTP status to a [`ProbeStatus`].
pub fn classify(status: u16) -> ProbeStatus {
    match status {
        200..=299 => ProbeStatus::Readable,
        401 | 403 => ProbeStatus::Denied,
        404 => ProbeStatus::NotFound,
        _ => ProbeStatus::Error,
    }
}

/// Redact a value by type. Never dumps row contents.
pub fn redact(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut parts = Vec::new();
            for (k, val) in map.iter().take(8) {
                parts.push(format!("{k}={}", redact_scalar(val)));
            }
            format!("{{{}}}", parts.join(", "))
        }
        Value::Array(rows) => match rows.first() {
            Some(row) => redact(row),
            None => "<table exists, zero rows>".to_owned(),
        },
        other => redact_scalar(other).into_owned(),
    }
}

fn redact_scalar(v: &Value) -> Cow<'static, str> {
    match v {
        Value::String(s) if s.contains('@') => Cow::Borrowed("<email>"),
        Value::String(s) if s.len() > 32 => Cow::Borrowed("<string:32>"),
        Value::String(_) => Cow::Borrowed("<string>"),
        Value::Number(_) => Cow::Borrowed("<int>"),
        Value::Bool(b) => Cow::Owned(b.to_string()),
        Value::Null => Cow::Borrowed("null"),
        _ => Cow::Borrowed("<json>"),
    }
}

/// Probe one table: `GET <base>/rest/v1/<table>?select=*&limit=1`.
///
/// # Errors
/// Transport or body-read failures; scope violations are not possible here
/// because the URL is constructed from an already-checked base.
pub async fn probe_table(
    client: &Client,
    base: &Url,
    key: Option<&str>,
    table: &TableProbe,
) -> Result<ProbeOutcome, ScanError> {
    let path = format!("rest/v1/{}", table.as_str());
    let mut url = base.join(&path).map_err(|_| ScanError::InvalidUrl)?;
    url.query_pairs_mut()
        .append_pair("select", "*")
        .append_pair("limit", "1");

    let mut req = client.get(url);
    if let Some(k) = key {
        req = req
            .header("apikey", k)
            .header("Authorization", format!("Bearer {k}"));
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let body = text_limited_result(resp).await?;
    let classified = classify(status);
    Ok(ProbeOutcome {
        status,
        classified,
        body,
    })
}

/// Default table wordlist used when no schema recovery is possible.
pub const DEFAULT_TABLES: &[&str] = &["users", "profiles", "posts", "orders", "messages"];

/// The Supabase scanner.
#[derive(Debug, Clone, Default)]
pub struct SupabaseScanner {
    /// Keys for the differential proof.
    pub keys: SupabaseKeys,
    /// RPC function names extracted by AST discovery.
    pub rpc_functions: Vec<String>,
    /// Whether the auth phase (signup/weak-login probes) may run.
    /// Set when the CLI depth is `auth` or deeper.
    pub auth_depth: bool,
    /// Lab guard from a verified scope file; when present, write and
    /// business-logic probes may run.
    pub lab_guard: Option<LabGuard>,
    /// Shared ledger; passive bundle body-read failures land here.
    pub coverage: Coverage,
    /// Per-scan successful GET responses reused by passive fingerprinting.
    pub fetch_cache: riftlock_fingerprint::FetchCache,
}

/// List storage bucket names with a high-privilege key.
///
/// # Errors
/// Transport or body-read failures, or an invalid base URL.
pub async fn list_buckets(
    client: &Client,
    base: &Url,
    key: &str,
) -> Result<Vec<String>, ScanError> {
    let url = base
        .join("storage/v1/bucket")
        .map_err(|_| ScanError::InvalidUrl)?;
    let resp = client
        .get(url)
        .header("apikey", key)
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }
    let body = text_limited_result(resp).await?;
    let names = serde_json::from_str::<Vec<serde_json::Value>>(&body)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|b| b.get("name").and_then(|n| n.as_str()).map(str::to_owned))
        .collect();
    Ok(names)
}

/// Probe one bucket's object listing. Returns the raw status and body.
///
/// # Errors
/// Transport or body-read failures, or an invalid bucket name.
pub async fn probe_bucket(
    client: &Client,
    base: &Url,
    key: &str,
    bucket: &str,
) -> Result<(u16, String), ScanError> {
    let path = format!("storage/v1/object/list/{bucket}");
    let url = base.join(&path).map_err(|_| ScanError::InvalidUrl)?;
    let resp = client
        .post(url)
        .header("apikey", key)
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({"prefix": "", "limit": 1}))
        .send()
        .await?;
    let status = resp.status().as_u16();
    let body = text_limited_result(resp).await?;
    Ok((status, body))
}

/// Probe an RPC function with an empty payload. Returns the raw status and
/// body.
///
/// # Errors
/// Transport or body-read failures, or an invalid function name.
pub async fn probe_rpc(
    client: &Client,
    base: &Url,
    key: Option<&str>,
    function: &str,
) -> Result<(u16, String), ScanError> {
    let Some(table) = TableProbe::new(function) else {
        return Ok((0, String::new()));
    };
    let path = format!("rest/v1/rpc/{}", table.as_str());
    let url = base.join(&path).map_err(|_| ScanError::InvalidUrl)?;
    let mut req = client.post(url).json(&serde_json::json!({}));
    if let Some(k) = key {
        req = req
            .header("apikey", k)
            .header("Authorization", format!("Bearer {k}"));
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let body = text_limited_result(resp).await?;
    Ok((status, body))
}

/// Redact a storage object listing body into one safe sample.
fn object_sample(body: &str) -> String {
    match serde_json::from_str::<Vec<serde_json::Value>>(body) {
        Ok(objects) if objects.is_empty() => "<bucket exists, zero objects>".to_owned(),
        Ok(objects) => objects
            .first()
            .and_then(|o| o.get("name").and_then(|n| n.as_str()))
            .map(|name| {
                if name.len() > 32 {
                    "<string:32>".to_owned()
                } else {
                    "<string>".to_owned()
                }
            })
            .unwrap_or_else(|| "<object>".to_owned()),
        Err(_) => "<unparseable body>".to_owned(),
    }
}

/// Describe an RPC response shape without dumping the payload.
fn response_shape(body: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => match &v {
            serde_json::Value::Array(a) => format!("array[{}]", a.len()),
            serde_json::Value::Object(m) => format!("object[{}]", m.len()),
            _ => "scalar".to_owned(),
        },
        Err(_) => "<non-json>".to_owned(),
    }
}

/// Decode a JWT's payload-only `sub` claim (no signature verification).
pub fn jwt_sub(token: &str) -> Option<String> {
    use base64::Engine as _;

    let segment = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("sub")
        .and_then(|s| s.as_str())
        .map(str::to_owned)
}

/// Extract `user_id` from the first row of a probe body, if present.
fn row_user_id(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .as_array()?
        .first()?
        .get("user_id")?
        .as_str()
        .map(str::to_owned)
}

fn bounded_prefix(body: &str) -> &str {
    match body.get(..4_096) {
        Some(prefix) => prefix,
        None => {
            let end = body
                .char_indices()
                .take_while(|(index, ch)| index + ch.len_utf8() <= 4_096)
                .last()
                .map_or(0, |(index, ch)| index + ch.len_utf8());
            &body[..end]
        }
    }
}

fn response_is_html(body: &str) -> bool {
    body.trim_start()
        .to_ascii_lowercase()
        .starts_with("<!doctype html")
        || body.trim_start().to_ascii_lowercase().starts_with("<html")
}

fn waf_marker(body: &str) -> Option<&'static str> {
    let lower = body.to_ascii_lowercase();
    [
        "cloudflare",
        "captcha",
        "access denied",
        "waf",
        "blocked",
        "challenge",
    ]
    .into_iter()
    .find(|marker| lower.contains(marker))
}

impl SupabaseScanner {
    fn admit_ambiguous(
        &self,
        mut evidence: Evidence,
        endpoint: &Url,
        responses: &[(u16, &str)],
    ) -> Result<Option<Finding>, ScanError> {
        let mut claim = format!("url={endpoint}");
        let mut marker = None;
        for (status, body) in responses {
            let bounded = bounded_prefix(body);
            if *status == 206 && serde_json::from_str::<Value>(body).is_err() {
                self.coverage.check_attempted();
                self.coverage.check_inconclusive();
                self.coverage
                    .endpoint_at(endpoint.as_str(), EndpointOutcome::WafBlocked);
                return Ok(None);
            }
            claim.push_str(&format!(" status={status}"));
            if response_is_html(bounded) {
                claim.push_str(" body=html");
            }
            marker = marker.or_else(|| waf_marker(bounded));
            if let Some(matched) = waf_marker(bounded) {
                claim.push_str(&format!(" marker={matched}"));
            } else {
                claim.push(' ');
                claim.push_str(bounded);
            }
        }
        if let Some(marker) = marker {
            match &mut evidence {
                Evidence::UnauthenticatedRead { row_sample, .. } => {
                    *row_sample = format!("<WAF marker: {marker}>");
                }
                Evidence::Differential { note, .. } => {
                    *note = Some(format!("endpoint={endpoint} marker={marker}"));
                }
                _ => {}
            }
        }
        match ProofGate::admit_with_verifier(evidence, default_verifier().as_ref(), &claim) {
            Ok(finding) => Ok(Some(finding)),
            Err(riftlock_core::ProofError::Heuristic) => {
                self.coverage.check_attempted();
                self.coverage.check_inconclusive();
                self.coverage
                    .endpoint_at(endpoint.as_str(), EndpointOutcome::WafBlocked);
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Auth phase (depth >= auth): probe signup and weak login, emit
    /// `AuthBypass` for each success, and return the acquired user token.
    async fn auth_phase(
        &self,
        url: &Url,
        client: &Client,
        findings: &mut Vec<Finding>,
    ) -> Result<Option<String>, ScanError> {
        let mut acquired = None;
        let (status, token) = auth::probe_signup(client, url, &self.coverage).await?;
        if status == 200 && token.is_some() {
            findings.push(ProofGate::admit(Evidence::AuthBypass {
                endpoint: format!("{url}auth/v1/signup"),
                method: "POST".to_owned(),
            })?);
            acquired = token;
        }
        if let Some(token) = auth::probe_weak_login(client, url, &self.coverage).await? {
            findings.push(ProofGate::admit(Evidence::AuthBypass {
                endpoint: format!("{url}auth/v1/token"),
                method: "POST".to_owned(),
            })?);
            acquired = Some(token);
        }
        Ok(acquired)
    }

    /// Whether the fetched in-scope page or one of its in-scope bundles
    /// identifies a Supabase application. A Supabase-looking hostname alone
    /// is not sufficient to authorize API probes.
    fn fingerprints_as_supabase_app(&self, url: &Url) -> bool {
        let Some(page) = self.fetch_cache.get(url) else {
            return false;
        };
        let markers = [
            "@supabase/",
            "supabase-js",
            "supabaseclient",
            "supabase.createclient",
            ".supabase.co",
            ".supabase.in",
            "supabase.from(",
            "supabase.auth.",
            "supabaseurl",
        ];
        let identifies_supabase = |text: &str| {
            let text = text.to_ascii_lowercase();
            markers.iter().any(|marker| text.contains(marker))
        };
        identifies_supabase(&page.body)
            || riftlock_fingerprint::bundle_urls(&page.body, url)
                .iter()
                .filter_map(|bundle| self.fetch_cache.get(bundle))
                .any(|bundle| identifies_supabase(&bundle.body))
    }

    /// Collect leaked keys passively and emit `LeakedSecret` findings.
    async fn passive_part(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
    ) -> Result<Vec<Finding>, ScanError> {
        let fps = fingerprint_url(client, url, guard, &self.coverage, &self.fetch_cache)
            .await
            .map_err(|e| match e {
                riftlock_fingerprint::FingerprintError::Http(h) => ScanError::Http(h),
                riftlock_fingerprint::FingerprintError::Scope(s) => ScanError::Scope(s),
                riftlock_fingerprint::FingerprintError::InvalidUrl => ScanError::InvalidUrl,
                riftlock_fingerprint::FingerprintError::Scan(e) => e,
                _ => ScanError::InvalidUrl,
            })?;
        fps.into_iter()
            .map(|fp| {
                ProofGate::admit(Evidence::LeakedSecret {
                    key_type: fp.key_type,
                    location: fp.location,
                    masked: fp.masked,
                    full: fp.full,
                })
            })
            .collect::<Result<Vec<Finding>, _>>()
            .map_err(ScanError::from)
    }
}

impl DynamicScanner for SupabaseScanner {
    fn scan_dynamic(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        ctx: &DiscoveryContext,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<Finding>, ScanError>> + Send + '_>>
    {
        // Clone inputs so the boxed future is self-contained: the trait's
        // elided return ties the future to &self only.
        let url = url.clone();
        let client = client.clone();
        let guard = guard.clone();
        let ctx = ctx.clone();
        Box::pin(async move {
            // Endpoint×param differential probing is Supabase-specific; it
            // requires the same in-scope page/bundle fingerprint as static API
            // probes. Run passive fingerprinting first so the cache is filled.
            if guard.check(&url).is_err() {
                self.coverage.out_of_scope_endpoint_at(url.as_str());
                return Ok(Vec::new());
            }
            let _ = self.passive_part(&url, &client, &guard).await?;
            if !self.fingerprints_as_supabase_app(&url) {
                return Ok(Vec::new());
            }
            guard.check_active(&url)?;
            self.dynamic_probe_loop(&url, &client, &guard, &ctx).await
        })
    }
}

impl SupabaseScanner {
    /// Endpoint×param differential loop, shared by `scan_dynamic` (after
    /// its host gate) and its tests.
    ///
    /// # Errors
    /// Transport failures on the baseline or keyed probes.
    async fn dynamic_probe_loop(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        ctx: &DiscoveryContext,
    ) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();
        let with_key = self.keys.high.as_deref().or(self.keys.low.as_deref());
        for endpoint in &ctx.endpoints {
            let base = match url.join(endpoint) {
                Ok(u) => u,
                Err(_) => continue,
            };
            // Endpoints discovered from bundles may point at hosts outside
            // the operator's scope; record the skip and keep probing.
            if guard.check(&base).is_err() {
                self.coverage.out_of_scope_endpoint_at(base.as_str());
                continue;
            }
            let mut emitted = false;
            for param in &ctx.params {
                let mut probe = base.clone();
                probe.query_pairs_mut().append_pair(param, "test");
                let probe_key = probe.as_str().to_owned();

                let baseline = match client.get(probe.clone()).send().await {
                    Ok(response) => response,
                    Err(_) => {
                        self.coverage.unreadable_endpoint_at(&probe_key);
                        continue;
                    }
                };
                let without = baseline.status().as_u16();
                if without != 401 {
                    continue;
                }
                let Some(key) = with_key else { continue };
                let keyed = match client
                    .get(probe)
                    .header("apikey", key)
                    .header("Authorization", format!("Bearer {key}"))
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => {
                        self.coverage.unreadable_endpoint_at(&probe_key);
                        continue;
                    }
                };
                let with = keyed.status().as_u16();
                let body = match text_limited_result(keyed).await {
                    Ok(body) => body,
                    Err(_) => {
                        self.coverage.unreadable_endpoint_at(&probe_key);
                        continue;
                    }
                };
                // The evidence variant carries no endpoint field, so one
                // differential per endpoint is emitted (first trigger).
                if with == 200 && !emitted {
                    if let Some(finding) = self.admit_ambiguous(
                        Evidence::Differential {
                            without_key: without,
                            with_key: with,
                            inverted: false,
                            cross_tenant: false,
                            note: None,
                        },
                        &base,
                        &[(with, &body)],
                    )? {
                        findings.push(finding);
                    }
                    emitted = true;
                }
            }
        }
        Ok(findings)
    }
}

impl Scanner for SupabaseScanner {
    fn id(&self) -> &'static str {
        "supabase"
    }

    fn matches(&self, url: &Url) -> bool {
        url.host_str()
            .is_some_and(|host| host.ends_with(".supabase.co") || host.ends_with(".supabase.in"))
    }

    async fn scan(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        if guard.check(url).is_err() {
            self.coverage.out_of_scope_endpoint_at(url.as_str());
            return Ok(Vec::new());
        }
        let mut findings = self.passive_part(url, client, guard).await?;

        // Explicit provider selection does not bypass app fingerprinting: it
        // authorizes running the engine but cannot justify sending Supabase
        // API requests to an unrelated target. Passive key leaks already
        // found on the page are real findings, so keep them and stop here.
        if !self.fingerprints_as_supabase_app(url) {
            return Ok(findings);
        }
        if passive {
            return Ok(findings);
        }
        guard.check_active(url)?;
        // Bucket listing, RPC probes, signup/login and the lab write phase
        // all POST; read depth keeps the GET table/key checks only.
        let read_only = guard.is_read_only();

        // Auth phase: acquire a user token when depth reaches auth level.
        let mut findings_acq = Vec::new();
        let auth_token = if self.auth_depth && !read_only {
            self.auth_phase(url, client, &mut findings_acq).await?
        } else {
            None
        };
        findings.extend(findings_acq);

        // Four tiers: guest (no key), user (acquired/env low), admin
        // (RIFTLOCK_SB_ADMIN), service (RIFTLOCK_SB_HIGH).
        let user_token = auth_token.clone().or_else(|| self.keys.low.clone());
        let user_sub = user_token.as_deref().and_then(jwt_sub);
        let mut first_readable: Option<String> = None;
        macro_rules! probe_or_skip {
            ($endpoint:expr, $probe:expr) => {
                match ($probe).await {
                    Ok(outcome) => Some(outcome),
                    Err(error) if error.transport_category().is_some() => {
                        self.coverage.unreadable_endpoint_at($endpoint);
                        None
                    }
                    Err(error) => return Err(error),
                }
            };
        }

        for name in DEFAULT_TABLES {
            let Some(table) = TableProbe::new(name) else {
                continue;
            };
            let table_url = url
                .join(&format!("rest/v1/{}", table.as_str()))
                .map_err(|_| ScanError::InvalidUrl)?
                .to_string();

            let Some(guest) = probe_or_skip!(&table_url, probe_table(client, url, None, &table))
            else {
                continue;
            };
            if first_readable.is_none() && guest.classified == ProbeStatus::Readable {
                first_readable = Some(table.as_str().to_owned());
            }
            if guest.classified == ProbeStatus::Readable {
                let endpoint = url
                    .join(&format!("rest/v1/{}", table.as_str()))
                    .map_err(|_| ScanError::InvalidUrl)?;
                if let Some(finding) = self.admit_ambiguous(
                    Evidence::UnauthenticatedRead {
                        endpoint: endpoint.to_string(),
                        row_sample: row_sample(&guest.body),
                    },
                    &endpoint,
                    &[(guest.status, &guest.body)],
                )? {
                    findings.push(finding);
                }
            }

            let user = match user_token.as_deref() {
                Some(t) => {
                    match probe_or_skip!(&table_url, probe_table(client, url, Some(t), &table)) {
                        Some(outcome) => outcome,
                        None => continue,
                    }
                }
                None => guest.clone(),
            };
            let admin = match self.keys.admin.as_deref() {
                Some(t) => probe_or_skip!(&table_url, probe_table(client, url, Some(t), &table)),
                None => None,
            };
            let service = match self.keys.high.as_deref() {
                Some(t) => probe_or_skip!(&table_url, probe_table(client, url, Some(t), &table)),
                None => None,
            };

            // Inverted: guest readable while an authenticated user is blocked.
            if guest.classified == ProbeStatus::Readable && user.classified == ProbeStatus::Denied {
                let endpoint = url
                    .join(&format!("rest/v1/{}", table.as_str()))
                    .map_err(|_| ScanError::InvalidUrl)?;
                if let Some(finding) = self.admit_ambiguous(
                    Evidence::Differential {
                        without_key: guest.status,
                        with_key: user.status,
                        inverted: true,
                        cross_tenant: false,
                        note: None,
                    },
                    &endpoint,
                    &[(guest.status, &guest.body), (user.status, &user.body)],
                )? {
                    findings.push(finding);
                }
            }

            // Cross-tenant: user reads a row whose owner differs from the
            // user's own identity (sub claim), while admin also reads it.
            if user.classified == ProbeStatus::Readable {
                if let Some(admin) = admin
                    .as_ref()
                    .filter(|a| a.classified == ProbeStatus::Readable)
                {
                    if row_user_id(&user.body)
                        .zip(user_sub.as_deref())
                        .is_some_and(|(row_owner, me)| row_owner != me)
                    {
                        let endpoint = url
                            .join(&format!("rest/v1/{}", table.as_str()))
                            .map_err(|_| ScanError::InvalidUrl)?;
                        if let Some(finding) = self.admit_ambiguous(
                            Evidence::Differential {
                                without_key: user.status,
                                with_key: admin.status,
                                inverted: false,
                                cross_tenant: true,
                                note: None,
                            },
                            &endpoint,
                            &[(user.status, &user.body), (admin.status, &admin.body)],
                        )? {
                            findings.push(finding);
                        }
                    }
                }
            }

            // Classic privilege differential: service reads what user cannot.
            if let Some(service) = service {
                if service.classified == ProbeStatus::Readable
                    && user.classified != ProbeStatus::Readable
                {
                    let endpoint = url
                        .join(&format!("rest/v1/{}", table.as_str()))
                        .map_err(|_| ScanError::InvalidUrl)?;
                    if let Some(finding) = self.admit_ambiguous(
                        Evidence::Differential {
                            without_key: guest.status,
                            with_key: service.status,
                            inverted: false,
                            cross_tenant: false,
                            note: None,
                        },
                        &endpoint,
                        &[(guest.status, &guest.body), (service.status, &service.body)],
                    )? {
                        findings.push(finding);
                    }
                }
            }
        }

        // Storage probing (high-priv key required). The object-list request
        // is a POST, so read depth skips it.
        if let Some(high) = self.keys.high.as_deref().filter(|_| !read_only) {
            let bucket_list_url = url
                .join("storage/v1/bucket")
                .map_or_else(|_| format!("{url}storage/v1/bucket"), |u| u.to_string());
            let buckets = match list_buckets(client, url, high).await {
                Ok(buckets) => buckets,
                Err(error) if error.transport_category().is_some() => {
                    self.coverage.unreadable_endpoint_at(&bucket_list_url);
                    Vec::new()
                }
                Err(error) => return Err(error),
            };
            for bucket in buckets {
                let bucket_url = url
                    .join(&format!("storage/v1/object/list/{bucket}"))
                    .map_or_else(
                        |_| format!("{url}storage/v1/object/list/{bucket}"),
                        |u| u.to_string(),
                    );
                let Some((status, body)) =
                    probe_or_skip!(&bucket_url, probe_bucket(client, url, high, &bucket))
                else {
                    continue;
                };
                if status == 200 {
                    findings.push(ProofGate::admit(Evidence::StorageLeak {
                        bucket: bucket.clone(),
                        object_sample: object_sample(&body),
                    })?);
                }
            }
        }

        // RPC probing for functions found by AST discovery. The probe is a
        // POST, so read depth skips it.
        if !read_only {
            for function in &self.rpc_functions {
                let rpc_url = format!("{url}rest/v1/rpc/{function}");
                let Some((status, body)) = probe_or_skip!(
                    &rpc_url,
                    probe_rpc(client, url, self.keys.low.as_deref(), function)
                ) else {
                    continue;
                };
                if status == 200 {
                    findings.push(ProofGate::admit(Evidence::FunctionExposed {
                        endpoint: format!("{url}rest/v1/rpc/{function}"),
                        response_shape: response_shape(&body),
                    })?);
                }
            }
        }

        // Lab phase: write + business-logic probes. Only when the CLI
        // verified a scope file and constructed a lab guard.
        if let Some(lab) = self.lab_guard.as_ref().filter(|_| !read_only) {
            let write_key = self.keys.high.as_deref().or(user_token.as_deref());
            // Write probe against the first readable table.
            if let (Some(table), Some(wkey)) = (first_readable.as_deref(), write_key) {
                if let Some(probe) = TableProbe::new(table) {
                    let evidence = write::probe_insert(client, url, wkey, &probe, lab).await?;
                    findings.push(ProofGate::admit_lab(evidence, lab)?);
                }
            }
            // Escalation probe: crack the acquired/anon token offline and
            // verify the forged service_role token against the API.
            if let Some(token) = auth_token
                .as_deref()
                .or(self.keys.low.as_deref())
                .or(self.keys.high.as_deref())
            {
                if let Some(forged) = escalate::probe_jwt_escalation(client, url, token).await? {
                    findings.push(ProofGate::admit_lab(
                        Evidence::PrivilegeEscalation {
                            from_role: "anon".to_owned(),
                            to_role: "service_role".to_owned(),
                            method: "jwt_crack".to_owned(),
                        },
                        lab,
                    )?);
                    let _ = forged;
                }
            }

            // Logic probes against the first discovered RPC endpoint, if any.
            if let Some(function) = self.rpc_functions.first() {
                let endpoint = format!("rest/v1/rpc/{function}");
                let key = self.keys.high.as_deref().or(user_token.as_deref());
                if let Some(key) = key {
                    if logic::probe_race_condition(client, url, key, &endpoint).await? {
                        findings.push(ProofGate::admit_lab(
                            Evidence::BusinessLogicBypass {
                                endpoint: endpoint.clone(),
                                kind: "race".to_owned(),
                            },
                            lab,
                        )?);
                    }
                    if logic::probe_price_manipulation(client, url, key, &endpoint).await? {
                        findings.push(ProofGate::admit_lab(
                            Evidence::BusinessLogicBypass {
                                endpoint: endpoint.clone(),
                                kind: "price".to_owned(),
                            },
                            lab,
                        )?);
                    }
                }
            }
        }

        Ok(findings)
    }
}

/// Redact the first row of a probe response body into a safe sample.
fn row_sample(body: &str) -> String {
    match serde_json::from_str::<Value>(body) {
        Ok(v) => redact(&v),
        Err(_) => "<unparseable body>".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn scan_users_response(status: u16, body: &str) -> (SupabaseScanner, Vec<Finding>) {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(
                r#"<script>const client = supabase.createClient("https://project.supabase.co", "key")</script>"#,
            ))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/rest/v1/users"))
            .respond_with(wiremock::ResponseTemplate::new(status).set_body_string(body))
            .mount(&server)
            .await;
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SupabaseScanner::default();
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan continues after verifier decision");
        (scanner, findings)
    }

    #[tokio::test]
    async fn non_supabase_target_skips_out_of_scope_bundle_without_scope_error() {
        let page_server = wiremock::MockServer::start().await;
        let other = wiremock::MockServer::start().await;
        // Same loopback IP, different host spelling: the guard allows
        // 127.0.0.1 only, so localhost is outside the scan boundary.
        let outside = other.uri().replace("127.0.0.1", "localhost");
        let outside_bundle = format!("{outside}/app.js");
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(format!(
                        r#"<html><script src="{outside_bundle}"></script></html>"#
                    )),
            )
            .mount(&page_server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/app.js"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("app"))
            .mount(&other)
            .await;
        let base = Url::parse(&page_server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[page_server.uri().as_str()]).expect("guard");
        let scanner = SupabaseScanner::default();

        for passive in [false, true] {
            let result = scanner
                .scan(&base, &Client::new_lab(), &guard, passive)
                .await;
            assert!(
                matches!(result, Ok(ref findings) if findings.is_empty()),
                "non-Supabase target must be cleanly skipped: {result:?}"
            );
        }
        let requests = page_server.received_requests().await.expect("requests");
        assert!(
            requests.iter().all(|request| request.url.path() == "/"),
            "non-Supabase target triggered API probes: {requests:?}"
        );
        assert_eq!(
            other.received_requests().await.expect("requests").len(),
            0,
            "the out-of-scope bundle host is never contacted"
        );
        assert!(scanner.coverage.endpoint_records().iter().any(|record| {
            record.url == outside_bundle && record.outcome == EndpointOutcome::Skipped
        }));
    }

    #[tokio::test]
    async fn out_of_scope_target_returns_cleanly_without_request() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[]).expect("empty guard");

        let result = SupabaseScanner::default()
            .scan(&base, &Client::new_lab(), &guard, false)
            .await;

        assert!(matches!(result, Ok(ref findings) if findings.is_empty()));
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }

    #[tokio::test]
    async fn forced_provider_does_not_probe_non_supabase_target() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><title>Ordinary application</title></html>"),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/rest/v1/users"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SupabaseScanner::default();

        let result = scanner.scan(&base, &Client::new_lab(), &guard, false).await;

        assert!(matches!(result, Ok(ref findings) if findings.is_empty()));
        assert!(!scanner.fingerprints_as_supabase_app(&base));
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1, "only the page fingerprint is allowed");
        assert_eq!(requests[0].url.path(), "/");
    }

    #[tokio::test]
    async fn corrupt_gzip_table_body_is_failed_and_inconclusive() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(
                r#"<script>const client = supabase.createClient("https://project.supabase.co", "key")</script>"#,
            ))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/rest/v1/users"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(b"not a gzip stream".to_vec()),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SupabaseScanner::default();

        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("unreadable table body is not a scanner error");

        assert!(findings.is_empty());
        let coverage = scanner.coverage.snapshot(0);
        assert_eq!(coverage.vulnerability_checks_attempted, 1);
        assert_eq!(coverage.vulnerability_checks_inconclusive, 1);
        assert_eq!(coverage.endpoints_failed, 1);
    }

    #[tokio::test]
    async fn html_200_waf_interstitial_is_inconclusive() {
        let (scanner, findings) = scan_users_response(
            200,
            "<!doctype html><html><title>Cloudflare challenge</title></html>",
        )
        .await;
        assert!(findings.is_empty());
        let coverage = scanner.coverage.snapshot(0);
        assert_eq!(coverage.vulnerability_checks_inconclusive, 1);
        assert_eq!(coverage.endpoints_waf_blocked, 1);
    }

    #[tokio::test]
    async fn valid_json_206_passes_the_verifier() {
        let (scanner, findings) = scan_users_response(206, r#"[{"id":1}]"#).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence(), riftlock_core::Confidence::High);
        assert_eq!(
            scanner
                .coverage
                .snapshot(0)
                .vulnerability_checks_inconclusive,
            0
        );
    }

    #[tokio::test]
    async fn garbage_206_is_inconclusive() {
        let (scanner, findings) = scan_users_response(206, "not JSON").await;
        assert!(findings.is_empty());
        let coverage = scanner.coverage.snapshot(0);
        assert_eq!(coverage.vulnerability_checks_inconclusive, 1);
        assert_eq!(coverage.endpoints_waf_blocked, 1);
    }

    /// Read depth keeps the GET table probes but skips signup/login, storage
    /// object listing and RPC invocation — all POSTs.
    #[tokio::test]
    async fn read_only_scan_never_posts_auth_storage_or_rpc() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(
                r#"<script>const client = supabase.createClient("https://project.supabase.co", "key")</script>"#,
            ))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex("/rest/v1/.*"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;
        // Any write that escapes the policy succeeds and would emit findings.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()])
            .expect("guard")
            .with_policy(riftlock_core::ScanPolicy::ReadOnly);
        let scanner = SupabaseScanner {
            keys: SupabaseKeys {
                low: Some("sb_publishable_test".to_owned()),
                high: Some("sb_secret_test".to_owned()),
                ..Default::default()
            },
            rpc_functions: vec!["get_stats".to_owned()],
            auth_depth: true,
            ..Default::default()
        };
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty(), "{findings:?}");
        let requests = server.received_requests().await.expect("requests");
        let methods: Vec<&str> = requests.iter().map(|r| r.method.as_str()).collect();
        assert!(
            requests.iter().all(|r| r.method == "GET"),
            "read scan wrote: {methods:?}"
        );
    }

    #[test]
    fn builder_rejects_star_without_limit() {
        assert_eq!(ProbeQuery::new("*", None), Err(LimitError));
        assert_eq!(ProbeQuery::new("*", Some(10)), Err(LimitError));
        assert_eq!(
            ProbeQuery::new("id,name", None).map(|q| q.to_query()),
            Ok("select=id,name&limit=1".to_owned())
        );
    }

    #[test]
    fn builder_allows_star_with_limit_1() {
        let q = ProbeQuery::new("*", Some(1)).expect("valid");
        assert_eq!(q.to_query(), "select=*&limit=1");
    }

    #[test]
    fn classification() {
        assert_eq!(classify(200), ProbeStatus::Readable);
        assert_eq!(classify(403), ProbeStatus::Denied);
        assert_eq!(classify(401), ProbeStatus::Denied);
        assert_eq!(classify(404), ProbeStatus::NotFound);
        assert_eq!(classify(500), ProbeStatus::Error);
    }

    #[test]
    fn redaction() {
        assert_eq!(
            redact(
                &serde_json::json!([{"email": "a@b.com", "name": "short", "bio": "x".repeat(40)}])
            ),
            // serde_json preserve_order (workspace feature) serializes
            // objects in insertion order.
            "{email=<email>, name=<string>, bio=<string:32>}"
        );
        assert_eq!(redact(&serde_json::json!([])), "<table exists, zero rows>");
    }

    #[tokio::test]
    async fn probes_cover_denied_not_found_empty() {
        let denied = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/rest/v1/users"))
            .respond_with(wiremock::ResponseTemplate::new(403))
            .mount(&denied)
            .await;
        let not_found = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&not_found)
            .await;
        let empty = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&empty)
            .await;

        let client = Client::new_lab();
        let table = TableProbe::new("users").expect("valid");

        let base = Url::parse(&denied.uri()).expect("url");
        let out = probe_table(&client, &base, None, &table)
            .await
            .expect("probe");
        assert_eq!(out.classified, ProbeStatus::Denied);

        let base = Url::parse(&not_found.uri()).expect("url");
        let out = probe_table(&client, &base, None, &table)
            .await
            .expect("probe");
        assert_eq!(out.classified, ProbeStatus::NotFound);

        let base = Url::parse(&empty.uri()).expect("url");
        let out = probe_table(&client, &base, None, &table)
            .await
            .expect("probe");
        assert_eq!(out.classified, ProbeStatus::Readable);
    }

    #[tokio::test]
    async fn storage_and_rpc_probes() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/bucket"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"[{"id":"1","name":"photos"}]"#),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/storage/v1/object/list/photos"))
            .and(body_partial_json(serde_json::json!({"limit": 1})))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"[{"name":"a/b.jpg"}]"#))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/rest/v1/rpc/get_stats"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"rows": 3}"#))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let client = Client::new_lab();
        let key = "sb_secret_test";

        let buckets = list_buckets(&client, &base, key).await.expect("buckets");
        assert_eq!(buckets, vec!["photos".to_owned()]);

        let (status, body) = probe_bucket(&client, &base, key, "photos")
            .await
            .expect("bucket probe");
        assert_eq!(status, 200);
        assert_eq!(object_sample(&body), "<string>");

        let (status, body) = probe_rpc(&client, &base, None, "get_stats")
            .await
            .expect("rpc probe");
        assert_eq!(status, 200);
        assert_eq!(response_shape(&body), "object[1]");
    }

    #[tokio::test]
    async fn dynamic_probe_proves_401_to_200() {
        let server = wiremock::MockServer::start().await;
        // Keyed request hits the 200 mock first; unkeyed falls through to 401.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::header("apikey", "sb_secret_test"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = SupabaseScanner {
            keys: SupabaseKeys {
                high: Some("sb_secret_test".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };
        let page = Url::parse(server.uri().as_str()).expect("page URL");
        scanner.fetch_cache.insert(
            page,
            r#"<script>const client = supabase.createClient("https://project.supabase.co", "key")</script>"#.to_owned(),
            Vec::new(),
        );
        let ctx = DiscoveryContext {
            endpoints: vec!["/rest/v1/users".to_owned()],
            params: vec!["admin".to_owned(), "role".to_owned()],
            ..DiscoveryContext::default()
        };
        let findings = scanner
            .dynamic_probe_loop(&base, &Client::new_lab(), &guard, &ctx)
            .await
            .expect("dynamic_probe_loop");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::Differential {
                without_key: 401,
                with_key: 200,
                inverted: false,
                cross_tenant: false,
                note: None
            }
        ));
    }

    #[tokio::test]
    async fn dynamic_probe_no_differential_without_change() {
        // Always 401: blocked, checked negative — no finding.
        let denied = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&denied)
            .await;
        // Always 200 without a key: no change, no finding.
        let open = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&open)
            .await;

        let ctx = DiscoveryContext {
            endpoints: vec!["/rest/v1/users".to_owned()],
            params: vec!["admin".to_owned()],
            ..DiscoveryContext::default()
        };
        for server in [&denied, &open] {
            let base = Url::parse(server.uri().as_str()).expect("url");
            let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
            let findings = SupabaseScanner::default()
                .dynamic_probe_loop(&base, &Client::new_lab(), &guard, &ctx)
                .await
                .expect("dynamic_probe_loop");
            assert!(findings.is_empty());
        }
    }

    #[tokio::test]
    async fn dynamic_probe_does_not_probe_non_supabase_target() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string("<html><title>Ordinary application</title></html>"),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/rest/v1/users"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let ctx = DiscoveryContext {
            endpoints: vec!["/rest/v1/users".to_owned()],
            params: vec!["admin".to_owned()],
            ..DiscoveryContext::default()
        };
        let result = DynamicScanner::scan_dynamic(
            &SupabaseScanner::default(),
            &base,
            &Client::new_lab(),
            &guard,
            &ctx,
        )
        .await;
        assert!(matches!(result, Ok(ref findings) if findings.is_empty()));
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.path(), "/");
    }

    #[tokio::test]
    async fn dynamic_probe_skips_out_of_scope_target_before_request() {
        let base = Url::parse("https://proj.supabase.co").expect("url");
        let guard = ScopeGuard::new_lab(&[]).expect("guard");
        let result = DynamicScanner::scan_dynamic(
            &SupabaseScanner::default(),
            &base,
            &Client::new_lab(),
            &guard,
            &DiscoveryContext::default(),
        )
        .await;
        assert!(matches!(result, Ok(ref findings) if findings.is_empty()));
    }
}
