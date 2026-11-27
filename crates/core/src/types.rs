//! Shared value types: key classification, evidence, probe status.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A full secret value held in memory only for interactive opt-in reveal.
/// `Debug` is redacted and serde skips the field, so it can never reach logs,
/// reports, NDJSON, SARIF or checkpoints.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretValue(pub String);

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Probe depth requested for a scan.
///
/// `Normal` permits passive discovery only, `Read` adds lower-impact active
/// checks, and `Godmode` enables all probe classes subject to scope policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Depth {
    /// Passive reconnaissance without active payloads.
    Normal,
    /// Safe active checks without high-impact payload classes.
    #[default]
    Read,
    /// All probe classes, only with explicit authorization.
    Godmode,
}

impl Depth {
    /// Whether this tier enables the authorized high-impact probe set.
    #[must_use]
    pub const fn is_godmode(self) -> bool {
        matches!(self, Self::Godmode)
    }

    /// Whether this tier is passive-only.
    #[must_use]
    pub const fn is_normal(self) -> bool {
        matches!(self, Self::Normal)
    }

    /// CLI/report label for this tier.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Read => "Read",
            Self::Godmode => "Godmode",
        }
    }
}

/// Supabase key types recognized by fingerprinting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyType {
    /// Legacy anon JWT (`role: "anon"`). Public by design; INFO.
    SupabaseAnonLegacy,
    /// Legacy service_role JWT (`role: "service_role"`). CRITICAL.
    SupabaseServiceRoleLegacy,
    /// New publishable key `sb_publishable_…`. Public by design; INFO.
    SupabasePublishable,
    /// New secret key `sb_secret_…`. CRITICAL.
    SupabaseSecret,
}

impl KeyType {
    /// Human-readable label used in reports.
    pub fn label(self) -> &'static str {
        match self {
            KeyType::SupabaseAnonLegacy => "supabase-anon-legacy",
            KeyType::SupabaseServiceRoleLegacy => "supabase-service-role-legacy",
            KeyType::SupabasePublishable => "supabase-publishable",
            KeyType::SupabaseSecret => "supabase-secret",
        }
    }

    /// Whether the key type grants privileged (write/override-RLS) access.
    pub fn is_privileged(self) -> bool {
        matches!(
            self,
            KeyType::SupabaseServiceRoleLegacy | KeyType::SupabaseSecret
        )
    }
}

/// The evidence carried by a [`crate::Finding`]. Exactly three variants;
/// anything else is a heuristic and must never become a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Evidence {
    /// A secret-material key observed in a fetchable location.
    LeakedSecret {
        /// Classified key type.
        key_type: KeyType,
        /// Where the key was observed (URL or bundle path).
        location: String,
        /// Masked display value (prefix kept, remainder starred). Safe to
        /// serialize; never the full secret.
        #[serde(default)]
        masked: String,
        /// Full value, held in memory only for interactive `--show-secrets`.
        /// Never serialized and redacted in `Debug`.
        #[serde(skip)]
        full: SecretValue,
    },
    /// A table readable with no credentials at all.
    UnauthenticatedRead {
        /// The probed endpoint URL.
        endpoint: String,
        /// One row, redacted by type.
        row_sample: String,
    },
    /// A sensitive path answered an anonymous request with signed-in-only UI:
    /// the page was served without a session.
    BrokenAccessControl {
        /// The sensitive URL that answered.
        url: String,
        /// The signed-in-only marker found in the body (`logout`, ...).
        dashboard_marker: String,
    },
    /// A sensitive path (`/admin`, `/dashboard`, `/my-account`) exists and
    /// answered an anonymous request with `401`/`403`. This is disclosure of
    /// the path's existence, not proof of anonymous access: a denial is
    /// reported as a low-tier observation, never as broken access control.
    SensitivePathDisclosed {
        /// The sensitive URL that answered.
        url: String,
        /// HTTP status of the anonymous denial (`401` or `403`).
        status: u16,
    },
    /// High-privilege key reads a row the low-privilege tier cannot, or an
    /// inverted/cross-tenant relationship was proven.
    Differential {
        /// HTTP status without a (high-privilege) key.
        without_key: u16,
        /// HTTP status with the high-privilege key.
        with_key: u16,
        /// True when the *lower*-privilege tier was blocked but an
        /// unauthenticated tier was readable (RLS inverted).
        inverted: bool,
        /// True when a user could read a row it does not own.
        cross_tenant: bool,
        /// Probe provenance for non-key-tier differentials (e.g.
        /// `nextjs_action`, `batching`); `None` for classic key differentials.
        note: Option<String>,
    },
    /// An auth surface allowed token acquisition or use it should not have.
    AuthBypass {
        /// The auth endpoint (e.g. `/auth/v1/signup`).
        endpoint: String,
        /// HTTP method used.
        method: String,
    },
    /// A write (insert) was accepted on a table it should not be.
    WriteProof {
        /// The table written to.
        table: String,
        /// The marker row id inserted by the probe.
        marker_id: String,
        /// Whether the marker row was deleted again.
        cleaned_up: bool,
    },
    /// A row belonging to another principal is readable/writable.
    IdorProof {
        /// The table where the IDOR was proven.
        table: String,
        /// Redacted reference to the caller's own row.
        own_row: String,
        /// Redacted reference to the foreign row accessed.
        other_row: String,
    },
    /// A business-logic control was bypassed.
    BusinessLogicBypass {
        /// The endpoint exercised.
        endpoint: String,
        /// Which control failed: `race`, `price`, or `negative_qty`.
        kind: String,
    },
    /// Privilege was escalated from one role to another.
    PrivilegeEscalation {
        /// Role the probe started from.
        from_role: String,
        /// Role the probe reached.
        to_role: String,
        /// How the escalation was achieved (e.g. `jwt_crack`).
        method: String,
    },
    /// A linked sequence of findings forming an attack path. Steps hold
    /// stringified evidence of the chained findings.
    Chain {
        /// Stringified evidence of each linked step, in order.
        steps: Vec<String>,
        /// Overall verdict (e.g. `full_compromise`).
        verdict: String,
    },
    /// Source-control or build-artifact material disclosed over HTTP.
    SourceDisclosure {
        /// URL where the source artifact was found.
        url: String,
        /// What kind of artifact was disclosed.
        kind: SourceKind,
    },
    /// A storage bucket readable with the available credentials.
    StorageLeak {
        /// Bucket name.
        bucket: String,
        /// One object key, redacted.
        object_sample: String,
    },
    /// An RPC function callable with the available credentials.
    FunctionExposed {
        /// The RPC endpoint URL.
        endpoint: String,
        /// Shape of the response (redacted description).
        response_shape: String,
    },
    /// A web-cache deception bypass: an authenticated response was served
    /// from the cache to an unauthenticated request on a cacheable extension.
    CacheDeception {
        /// The protected endpoint where the bypass was proven.
        endpoint: String,
    },
    /// A path-normalization bypass: an authorization check was skipped via
    /// an encoded/normalized path variant.
    PathNormalizationBypass {
        /// The path variant that bypassed the check.
        path: String,
    },
    /// A GraphQL endpoint accepted and executed a batched request array.
    GraphQLBatching {
        /// The GraphQL endpoint.
        endpoint: String,
    },
    /// A server-side request was redirected to an attacker-controlled URL:
    /// the app fetched an injected internal/metadata address.
    SsrF {
        /// The endpoint that accepted the injected URL.
        endpoint: String,
        /// The injected payload (the internal URL).
        payload: String,
    },
    /// A signed storage URL was modified to grant access to another user's
    /// object (path swap or traversal accepted after signature).
    SignedUrlBypass {
        /// The storage sign/serve endpoint exercised.
        endpoint: String,
        /// The foreign object accessed through the modified signed URL.
        object_id: String,
    },
    /// A JSON body polluted the prototype chain: an injected
    /// `__proto__`/`constructor.prototype` key elevated the caller's profile.
    PrototypePollution {
        /// The endpoint that accepted the polluted payload.
        endpoint: String,
        /// The pollution payload sent.
        payload: String,
    },
    /// A raw HTTP/1.1 request with conflicting framing headers
    /// (`Content-Length` + `Transfer-Encoding`) was mishandled by the server,
    /// opening a request-smuggling window.
    HttpSmuggling {
        /// The endpoint the malformed request was sent to.
        endpoint: String,
        /// HTTP method used for the smuggled request.
        method: String,
    },
    /// A WebSocket kept (or accepted) channel subscriptions after the
    /// authenticating session was revoked: auth desync.
    WebSocketDesync {
        /// The WebSocket endpoint where the desync was proven.
        endpoint: String,
    },
    /// An OAuth endpoint misbehaved: an open redirect through `redirect_uri`,
    /// or an authorization flow that proceeds without a `state` parameter.
    OAuthMisconfig {
        /// The OAuth endpoint where the flaw was proven.
        endpoint: String,
        /// Which flaw was proven (`open_redirect`, `missing_state`).
        flaw: String,
    },
    /// A server-sent events stream served valid event data without an
    /// `Authorization` header: the stream bypasses API auth.
    SseDesync {
        /// The SSE endpoint serving unauthenticated event data.
        endpoint: String,
    },
    /// Concurrent identical writes all succeeded where the action should be
    /// single-shot (no idempotency/locking).
    RaceCondition {
        /// The endpoint where the race was proven.
        endpoint: String,
        /// How many of the concurrent writes succeeded.
        successful_requests: usize,
    },
    /// A static client-side signal found in a served JS bundle. These sink
    /// patterns are not browser-execution or source-to-sink proof.
    ClientSideFlaw {
        /// The bundle URL the flaw was found in.
        endpoint: String,
        /// Which static signal matched (`dom_xss`, `postmessage`, `insecure_storage`).
        flaw_type: String,
        /// The matching source line, trimmed.
        snippet: String,
    },
    /// A dependency manifest is publicly served and pins a known-vulnerable
    /// package version: the supply chain is exposed end to end.
    SupplyChainVulnerability {
        /// The manifest URL (e.g. `https://host/package-lock.json`).
        manifest: String,
        /// The vulnerable package name.
        package: String,
        /// The pinned version of that package.
        version: String,
    },
    /// An LLM chat endpoint followed injected instructions and echoed the
    /// canary string: prompt injection is not neutralized.
    PromptInjection {
        /// The chat/generate endpoint that accepted the injection.
        endpoint: String,
        /// The injected payload (the canary instruction).
        payload: String,
    },
    /// A WebSocket handshake with a foreign `Origin` was accepted
    /// (CSWSH): the server does not validate the requesting origin.
    WebSocketCswh {
        /// The WebSocket endpoint that accepted the spoofed origin.
        endpoint: String,
    },
    /// A gRPC endpoint answered the reflection service probe: server
    /// reflection is reachable and exposes the service schema.
    GrpcExposed {
        /// The gRPC endpoint that answered the reflection probe.
        endpoint: String,
        /// The reflected service family (currently `reflection`).
        service: String,
    },
    /// An injected canary came back in the response unescaped in an
    /// executable context (HTML body, attribute, or script block).
    XssReflection {
        /// The endpoint that reflected the canary.
        url: String,
        /// The parameter the canary was injected into.
        param: String,
        /// Reflection context: `html`, `attribute`, or `script`.
        context: String,
    },
    /// A database engine error signature surfaced in the response after a
    /// quote injection: the parameter reaches a SQL parser.
    SqliError {
        /// The endpoint whose parameter was injected.
        url: String,
        /// The parameter that was injected.
        param: String,
        /// The engine error signature matched (e.g. `SQL syntax`).
        error_signature: String,
    },
    /// The endpoint's response was delayed by the injected sleep payload by
    /// a margin far above the baseline: time-based blind SQLi.
    SqliTimeDelay {
        /// The endpoint whose parameter was injected.
        url: String,
        /// The parameter that was injected.
        param: String,
        /// Measured extra delay over the baseline, in milliseconds.
        delay_ms: u64,
    },
    /// A state-changing form posts without any CSRF token field.
    CsrfMissingToken {
        /// The URL where the form was found.
        url: String,
        /// The form's `action` attribute.
        form_action: String,
    },
    /// An API route used by a running SPA was discovered from its runtime
    /// activity (XHR/fetch calls or DOM links).
    SpaEndpoint {
        /// The discovered API route URL.
        url: String,
        /// Discovery source: `xhr`, `fetch`, or `dom_link`.
        source: String,
    },
    /// A response header/CORS/cookie configuration issue was observed
    /// (missing security header, permissive CORS, insecure cookie flags).
    SecurityMisconfiguration {
        /// The URL whose response exhibited the issue.
        url: String,
        /// Which issue: `cors_wildcard_credentials`, `cors_wildcard`,
        /// `cors_reflect_credentials`, `cors_reflect`, `missing_hsts`,
        /// `missing_csp`, `missing_xfo`, `cookie_insecure`.
        issue: String,
        /// Severity label: `High`, `Medium`, or `Low`.
        severity: String,
    },
    /// An injected template expression (`${7*7}` / `{{7*7}}`) came back
    /// evaluated (`49`): the parameter reaches a server-side template engine.
    SstiReflection {
        /// The endpoint whose parameter was injected.
        url: String,
        /// The parameter that was injected.
        param: String,
        /// The evaluated result observed in the response.
        evaluated_string: String,
    },
    /// An injected traversal path returned file contents: the parameter
    /// reaches a filesystem read (`root:x:0:0`, `[extensions]`).
    LfiRead {
        /// The endpoint whose parameter was injected.
        url: String,
        /// The parameter that was injected.
        param: String,
        /// Marker proving the file content came back.
        file_read: String,
    },
    /// An injected command marker (`riftlock_cmdi`) came back in the
    /// response without the payload syntax itself: the input reaches an OS
    /// command execution sink and its output is reflected.
    CommandInjection {
        /// The endpoint whose parameter was injected.
        url: String,
        /// The parameter (or header) that was injected.
        param: String,
        /// The payload that was executed.
        payload: String,
    },
    /// A URL parameter flowed from a browser source (`location.search`)
    /// into an execution sink (`document.write`, `innerHTML`, `eval`),
    /// observed at runtime in a headless browser.
    DomXssTaint {
        /// The page URL whose parameter was traced.
        url: String,
        /// The tainted source (e.g. `location.search.q`).
        source: String,
        /// The execution sink reached (e.g. `innerHTML`).
        sink: String,
    },
    /// A login form accepted an authentication-bypass payload
    /// (`' OR 1=1--`) and granted a session: the backend concatenated
    /// the input into its credential lookup query.
    SqlInjection {
        /// The login endpoint that was exploited.
        url: String,
        /// The form field that was injected.
        param: String,
        /// The payload that was accepted.
        payload: String,
    },
    /// A form-submitted value came back unescaped and executable in the
    /// response HTML: the input is reflected into the page without
    /// output encoding.
    ReflectedXss {
        /// The endpoint that reflected the payload.
        url: String,
        /// The form field that was reflected.
        param: String,
        /// The payload that came back unescaped.
        payload: String,
    },
    /// An unauthenticated request for an incremented resource id
    /// returned another user's data: object-level authorization is
    /// missing on the endpoint.
    Idor {
        /// The endpoint where the id was swapped.
        url: String,
        /// The id the scan originally observed.
        original_id: String,
        /// The id that was accessed without authorization.
        accessed_id: String,
    },
    /// A replayed XHR/fetch body with a NoSQL operator (`{"$ne": null}`)
    /// granted a session the original request's plain credentials were
    /// denied: the backend feeds JSON query operators into its lookup.
    NoSqlInjection {
        /// The endpoint whose request body was mutated.
        url: String,
        /// The field the operator was injected into.
        param: String,
        /// The operator payload that was accepted.
        payload: String,
    },
    /// A replayed request body with an added privilege field
    /// (`"isAdmin": true`) was accepted and persisted: the API trusts
    /// client-controlled authorization fields. Write-class — requires a
    /// [`LabGuard`](crate::LabGuard).
    MassAssignment {
        /// The endpoint whose request body was mutated.
        url: String,
        /// The privilege field that was injected.
        param: String,
        /// The value assigned to the privilege field.
        payload: String,
    },
    /// A decoded JWT revealed a sensitive claim (`role: "admin"`, a
    /// password) or an accepted `alg: none` token proved an auth bypass.
    JwtVulnerability {
        /// Where the token was found or the protected endpoint attacked.
        endpoint: String,
        /// What is wrong: `sensitive_claim` or `alg_none`.
        issue: String,
    },
    /// A live third-party credential (Stripe `sk_live_`, Google API key,
    /// SSN pattern) surfaced in an HTTP response.
    SensitiveDataExposure {
        /// The URL the secret was found at.
        url: String,
        /// What leaked: `stripe_secret_key`, `google_api_key`, `ssn`, ...
        data_type: String,
    },
    /// A GraphQL endpoint answered an introspection query, disclosing the
    /// full schema including private operations.
    GraphQLIntrospection {
        /// The GraphQL endpoint that leaked its schema.
        endpoint: String,
    },
    /// A URL parameter redirected the response to an attacker-chosen
    /// host (3xx `Location` pointing outside the target's domain).
    OpenRedirect {
        /// The endpoint that performed the redirect.
        url: String,
        /// The parameter that carried the attacker URL.
        param: String,
    },
    /// An HTTPS page references an `http://` resource: the asset can be
    /// swapped in transit (mixed content).
    MixedContent {
        /// The HTTPS page containing the reference.
        page_url: String,
        /// The insecure `http://` resource URL.
        resource_url: String,
    },
    /// A cloud/infrastructure API answered without credentials (Docker
    /// daemon, Kubernetes API, listing S3/Azure bucket endpoints).
    CloudExposure {
        /// The exposed endpoint URL.
        url: String,
        /// Which service answered (`aws_s3`, `azure_blob`, `docker`,
        /// `kubernetes`).
        provider: String,
    },
    /// A query parameter was discovered by a differential response probe.
    /// Informational attack-surface metadata, not a vulnerability.
    ParameterDiscovery {
        /// The endpoint where the parameter was tested.
        url: String,
        /// The discovered parameter name.
        param: String,
    },
    /// A technology was identified from response headers, cookies, or HTML
    /// meta/bundle markers. Informational — attack-surface mapping, not a
    /// flaw.
    TechFingerprint {
        /// Technology name (e.g. `Next.js`, `nginx`, `React`).
        technology: String,
        /// Version string when determinable.
        version: Option<String>,
        /// Detection confidence 0–100.
        confidence: u8,
    },
    /// A DNS-adjacent info source disclosed internals: `robots.txt` naming
    /// hidden paths, `sitemap.xml` enumerating routes, or
    /// `.well-known/security.txt` exposing contact identities.
    DnsMisconfiguration {
        /// The domain the issue was found on.
        domain: String,
        /// What leaked (`robots_hidden_path`, `sitemap_routes`,
        /// `security_txt_contacts`).
        issue: String,
    },
    /// An XML upload/parse endpoint resolved an external entity: file
    /// contents (`file:///etc/passwd`) came back in the response.
    XxeExtraction {
        /// The endpoint that parsed the crafted XML.
        url: String,
        /// Marker proving the entity resolved (file content signature).
        file_read: String,
    },
}

/// Where an [`Evidence`] value came from, used by the proof gate to keep
/// observations and fingerprints out of the confirmed-vulnerability tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProvenanceKind {
    /// Passive observation: response content, posture or fingerprint.
    PassiveObservation,
    /// Fingerprint or discovery metadata, never a vulnerability.
    Fingerprint,
    /// Evidence produced by an active probe (one or more requests).
    ProbeDerived,
    /// Active verification with a control/baseline comparison.
    ActivelyVerified,
}

impl Evidence {
    /// Whether this finding is a passive observation or static indicator
    /// rather than a completed active vulnerability probe. Such findings are
    /// kept and reported, but never counted as executed checks.
    #[must_use]
    pub fn is_passive_observation(&self) -> bool {
        match self {
            // Fingerprinting and discovery material.
            Self::LeakedSecret { .. }
            | Self::TechFingerprint { .. }
            | Self::ParameterDiscovery { .. }
            | Self::SpaEndpoint { .. }
            | Self::DnsMisconfiguration { .. }
            // Posture and regex/static-analysis signals.
            | Self::CsrfMissingToken { .. }
            | Self::SecurityMisconfiguration { .. }
            | Self::SensitiveDataExposure { .. }
            | Self::ClientSideFlaw { .. }
            | Self::SensitivePathDisclosed { .. }
            | Self::DomXssTaint { .. } => true,
            // Reflection or a static source-to-sink flow is not executable
            // XSS proof; only ReflectedXss carries executable context.
            Self::XssReflection { .. } => true,
            _ => false,
        }
    }

    /// Whether this is fingerprint/discovery metadata rather than a flaw.
    #[must_use]
    pub fn is_fingerprint(&self) -> bool {
        matches!(
            self,
            Self::TechFingerprint { .. } | Self::SpaEndpoint { .. }
        )
    }

    /// The provenance category of this evidence. Passive observations and
    /// fingerprints are reportable but never confirmed vulnerabilities.
    #[must_use]
    pub fn provenance(&self) -> ProvenanceKind {
        if self.is_fingerprint() {
            return ProvenanceKind::Fingerprint;
        }
        if self.is_passive_observation() {
            return ProvenanceKind::PassiveObservation;
        }
        if self.is_actively_verified() {
            return ProvenanceKind::ActivelyVerified;
        }
        ProvenanceKind::ProbeDerived
    }

    /// Variants that carry a control/baseline comparison rather than a single
    /// probe response. JWT `alg_none` is only emitted after the 401/403
    /// baseline, the bad-signature control and the forged-token acceptance.
    #[must_use]
    pub fn is_actively_verified(&self) -> bool {
        match self {
            Self::Differential { .. }
            | Self::AuthBypass { .. }
            | Self::CacheDeception { .. }
            | Self::PathNormalizationBypass { .. }
            | Self::SignedUrlBypass { .. }
            | Self::RaceCondition { .. }
            | Self::PrototypePollution { .. }
            | Self::SqlInjection { .. }
            | Self::ReflectedXss { .. }
            | Self::NoSqlInjection { .. }
            | Self::CommandInjection { .. }
            | Self::LfiRead { .. }
            | Self::SstiReflection { .. }
            | Self::XxeExtraction { .. }
            | Self::SsrF { .. }
            | Self::PromptInjection { .. }
            | Self::WebSocketCswh { .. } => true,
            Self::JwtVulnerability { issue, .. } => issue == "alg_none",
            _ => false,
        }
    }
}

/// The kind of source artifact disclosed over HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SourceKind {
    /// A Git repository (`.git/HEAD` etc.) exposed.
    Git,
    /// An environment file (`.env`) with secrets.
    Env,
    /// A database or code backup (e.g. `backup.sql`).
    Backup,
    /// A source map (`.map`) exposing original source.
    SourceMap,
    /// A bundle disclosing Clerk `unsafeMetadata` handling with privilege
    /// fields (`isAdmin`/`role`/`plan`) set client-side.
    ClerkUnsafeMetadata,
}

impl SourceKind {
    /// Human-readable label used in reports.
    pub fn label(self) -> &'static str {
        match self {
            SourceKind::Git => "git",
            SourceKind::Env => "env",
            SourceKind::Backup => "backup",
            SourceKind::SourceMap => "source-map",
            SourceKind::ClerkUnsafeMetadata => "clerk-unsafe-metadata",
        }
    }
}

/// Outcome classification of a single table probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum ProbeStatus {
    /// 2xx: table responded with data.
    Readable,
    /// 401/403: RLS or auth blocked the read (checked negative).
    Denied,
    /// 404: table does not exist (checked negative).
    NotFound,
    /// Anything else: transport/protocol failure.
    Error,
}
