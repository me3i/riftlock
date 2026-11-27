//! Authoritative severity classification for [`Evidence`].
//!
//! One exhaustive mapping feeds the terminal, the report totals and SARIF.
//! The match is exhaustive inside this crate (the enum is only
//! `non_exhaustive` to outside consumers), so adding an `Evidence` variant is
//! a compile error here rather than a silent fallthrough to a default tier.

use crate::types::{Evidence, SourceKind};
use serde::{Deserialize, Serialize};

/// Severity tier shared by every renderer. Order is most to least severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Stable string used in report summaries and terminal counts.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Info => "Info",
        }
    }

    /// SARIF 2.1.0 `level` for this tier: error / warning / note.
    #[must_use]
    pub fn sarif_level(self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warning",
            Self::Low | Self::Info => "note",
        }
    }
}

/// The single source of truth for how severe an `Evidence` finding is.
#[must_use]
pub fn severity_of(evidence: &Evidence) -> Severity {
    match evidence {
        // Demonstrated compromise / privileged write.
        Evidence::LeakedSecret { .. }
        | Evidence::WriteProof { .. }
        | Evidence::IdorProof { .. }
        | Evidence::PrivilegeEscalation { .. }
        | Evidence::HttpSmuggling { .. }
        | Evidence::GrpcExposed { .. }
        | Evidence::MassAssignment { .. }
        | Evidence::SensitiveDataExposure { .. }
        | Evidence::CloudExposure { .. } => Severity::Critical,

        // A chain's tier is the grade its demonstrated steps earned.
        Evidence::Chain { verdict, .. } => {
            if verdict.contains("critical") {
                Severity::Critical
            } else if verdict.contains("high") {
                Severity::High
            } else {
                Severity::Medium
            }
        }

        // An accepted forged admin token is a full auth bypass; a decoded
        // sensitive claim alone is information disclosure. A token the target
        // never returned is an unverified observation: INFO.
        Evidence::JwtVulnerability { issue, .. } => {
            if issue == "alg_none" {
                Severity::Critical
            } else if issue.contains("not directly observed") {
                Severity::Info
            } else {
                Severity::High
            }
        }

        // Static source-to-sink suspicion is triage, not executable XSS.
        Evidence::XssReflection { context, .. } => {
            if context.ends_with(" (Potential)") {
                Severity::Medium
            } else {
                Severity::Low
            }
        }

        // Misconfigurations carry their own graded tier.
        Evidence::SecurityMisconfiguration { severity, .. } => match severity.as_str() {
            "High" => Severity::High,
            "Medium" => Severity::Medium,
            "Low" => Severity::Low,
            _ => Severity::Info,
        },

        // A published source map is build metadata, not source code: it names
        // files but does not disclose their contents. Archives, env files and
        // backups remain high severity.
        Evidence::SourceDisclosure { kind, .. } => match kind {
            SourceKind::SourceMap => Severity::Low,
            _ => Severity::High,
        },

        // Proven weaknesses with a demonstrated exploit primitive.
        Evidence::UnauthenticatedRead { .. }
        | Evidence::BrokenAccessControl { .. }
        | Evidence::Differential { .. }
        | Evidence::AuthBypass { .. }
        | Evidence::BusinessLogicBypass { .. }
        | Evidence::StorageLeak { .. }
        | Evidence::FunctionExposed { .. }
        | Evidence::CacheDeception { .. }
        | Evidence::PathNormalizationBypass { .. }
        | Evidence::GraphQLBatching { .. }
        | Evidence::SsrF { .. }
        | Evidence::SignedUrlBypass { .. }
        | Evidence::PrototypePollution { .. }
        | Evidence::WebSocketDesync { .. }
        | Evidence::OAuthMisconfig { .. }
        | Evidence::SseDesync { .. }
        | Evidence::RaceCondition { .. }
        | Evidence::SupplyChainVulnerability { .. }
        | Evidence::PromptInjection { .. }
        | Evidence::WebSocketCswh { .. }
        | Evidence::SqliError { .. }
        | Evidence::SqliTimeDelay { .. }
        | Evidence::SstiReflection { .. }
        | Evidence::LfiRead { .. }
        | Evidence::CommandInjection { .. }
        | Evidence::DomXssTaint { .. }
        | Evidence::SqlInjection { .. }
        | Evidence::ReflectedXss { .. }
        | Evidence::Idor { .. }
        | Evidence::NoSqlInjection { .. }
        | Evidence::GraphQLIntrospection { .. }
        | Evidence::XxeExtraction { .. } => Severity::High,

        // Open redirects and mixed content are posture signals with demonstrated impact
        // short of a proven server-side exploit primitive.
        Evidence::OpenRedirect { .. } | Evidence::MixedContent { .. } => Severity::Medium,

        // Client-side source patterns are static heuristics, not executable proof.
        Evidence::ClientSideFlaw { .. } => Severity::Info,

        // Observations and posture signals, not confirmed vulnerabilities.
        // A denied sensitive path discloses the route's existence only.
        Evidence::CsrfMissingToken { .. }
        | Evidence::SensitivePathDisclosed { .. }
        | Evidence::SpaEndpoint { .. }
        | Evidence::ParameterDiscovery { .. }
        | Evidence::TechFingerprint { .. }
        | Evidence::DnsMisconfiguration { .. } => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyType, SecretValue, SourceKind};

    /// One representative instance of every variant, so the table below is
    /// exhaustive: adding an `Evidence` variant without a `severity_of` arm
    /// is already a compile error, and forgetting a row here fails the test.
    fn all_variants() -> Vec<(Evidence, Severity)> {
        let secret = |key_type| Evidence::LeakedSecret {
            key_type,
            location: "app.js".into(),
            masked: "sb_secret_****".into(),
            full: SecretValue::default(),
        };
        vec![
            (secret(KeyType::SupabaseSecret), Severity::Critical),
            (
                Evidence::UnauthenticatedRead {
                    endpoint: "https://x/t".into(),
                    row_sample: "{}".into(),
                },
                Severity::High,
            ),
            (
                Evidence::BrokenAccessControl {
                    url: "https://x/admin".into(),
                    dashboard_marker: "logout".into(),
                },
                Severity::High,
            ),
            (
                Evidence::SensitivePathDisclosed {
                    url: "https://x/admin".into(),
                    status: 403,
                },
                Severity::Info,
            ),
            (
                Evidence::Differential {
                    without_key: 401,
                    with_key: 200,
                    inverted: false,
                    cross_tenant: false,
                    note: None,
                },
                Severity::High,
            ),
            (
                Evidence::AuthBypass {
                    endpoint: "https://x/auth".into(),
                    method: "POST".into(),
                },
                Severity::High,
            ),
            (
                Evidence::WriteProof {
                    table: "t".into(),
                    marker_id: "m".into(),
                    cleaned_up: true,
                },
                Severity::Critical,
            ),
            (
                Evidence::IdorProof {
                    table: "t".into(),
                    own_row: "1".into(),
                    other_row: "2".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::BusinessLogicBypass {
                    endpoint: "https://x/buy".into(),
                    kind: "race".into(),
                },
                Severity::High,
            ),
            (
                Evidence::PrivilegeEscalation {
                    from_role: "anon".into(),
                    to_role: "service_role".into(),
                    method: "jwt_crack".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::Chain {
                    steps: vec!["a".into(), "b".into()],
                    verdict: "high_exploitable_path".into(),
                },
                Severity::High,
            ),
            (
                Evidence::SourceDisclosure {
                    url: "https://x/.env".into(),
                    kind: SourceKind::Env,
                },
                Severity::High,
            ),
            (
                Evidence::SourceDisclosure {
                    url: "https://x/app.js.map".into(),
                    kind: SourceKind::SourceMap,
                },
                Severity::Low,
            ),
            (
                Evidence::StorageLeak {
                    bucket: "b".into(),
                    object_sample: "o".into(),
                },
                Severity::High,
            ),
            (
                Evidence::FunctionExposed {
                    endpoint: "https://x/rpc".into(),
                    response_shape: "{}".into(),
                },
                Severity::High,
            ),
            (
                Evidence::CacheDeception {
                    endpoint: "https://x/a.js".into(),
                },
                Severity::High,
            ),
            (
                Evidence::PathNormalizationBypass {
                    path: "/..%2f".into(),
                },
                Severity::High,
            ),
            (
                Evidence::GraphQLBatching {
                    endpoint: "https://x/graphql".into(),
                },
                Severity::High,
            ),
            (
                Evidence::SsrF {
                    endpoint: "https://x/fetch".into(),
                    payload: "http://169.254.169.254".into(),
                },
                Severity::High,
            ),
            (
                Evidence::SignedUrlBypass {
                    endpoint: "https://x/sign".into(),
                    object_id: "foreign".into(),
                },
                Severity::High,
            ),
            (
                Evidence::PrototypePollution {
                    endpoint: "https://x/api".into(),
                    payload: "__proto__".into(),
                },
                Severity::High,
            ),
            (
                Evidence::HttpSmuggling {
                    endpoint: "https://x/".into(),
                    method: "POST".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::WebSocketDesync {
                    endpoint: "wss://x/ws".into(),
                },
                Severity::High,
            ),
            (
                Evidence::OAuthMisconfig {
                    endpoint: "https://x/authorize".into(),
                    flaw: "missing_state".into(),
                },
                Severity::High,
            ),
            (
                Evidence::SseDesync {
                    endpoint: "https://x/events".into(),
                },
                Severity::High,
            ),
            (
                Evidence::RaceCondition {
                    endpoint: "https://x/buy".into(),
                    successful_requests: 5,
                },
                Severity::High,
            ),
            (
                Evidence::ClientSideFlaw {
                    endpoint: "https://x/app.js".into(),
                    flaw_type: "dom_xss".into(),
                    snippet: "x".into(),
                },
                Severity::Info,
            ),
            (
                Evidence::SupplyChainVulnerability {
                    manifest: "https://x/package-lock.json".into(),
                    package: "p".into(),
                    version: "1.0".into(),
                },
                Severity::High,
            ),
            (
                Evidence::PromptInjection {
                    endpoint: "https://x/chat".into(),
                    payload: "ignore".into(),
                },
                Severity::High,
            ),
            (
                Evidence::WebSocketCswh {
                    endpoint: "wss://x/ws".into(),
                },
                Severity::High,
            ),
            (
                Evidence::GrpcExposed {
                    endpoint: "https://x/grpc".into(),
                    service: "reflection".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::XssReflection {
                    url: "https://x/s".into(),
                    param: "q".into(),
                    context: "html".into(),
                },
                Severity::Low,
            ),
            (
                Evidence::SqliError {
                    url: "https://x/s".into(),
                    param: "q".into(),
                    error_signature: "SQL syntax".into(),
                },
                Severity::High,
            ),
            (
                Evidence::SqliTimeDelay {
                    url: "https://x/s".into(),
                    param: "q".into(),
                    delay_ms: 5_000,
                },
                Severity::High,
            ),
            (
                Evidence::CsrfMissingToken {
                    url: "https://x/login".into(),
                    form_action: "/login".into(),
                },
                Severity::Info,
            ),
            (
                Evidence::SpaEndpoint {
                    url: "https://x/api".into(),
                    source: "xhr".into(),
                },
                Severity::Info,
            ),
            (
                Evidence::ParameterDiscovery {
                    url: "https://x/api".into(),
                    param: "debug".into(),
                },
                Severity::Info,
            ),
            (
                Evidence::SecurityMisconfiguration {
                    url: "https://x/".into(),
                    issue: "missing_csp".into(),
                    severity: "Medium".into(),
                },
                Severity::Medium,
            ),
            (
                Evidence::SstiReflection {
                    url: "https://x/s".into(),
                    param: "q".into(),
                    evaluated_string: "49".into(),
                },
                Severity::High,
            ),
            (
                Evidence::LfiRead {
                    url: "https://x/s".into(),
                    param: "f".into(),
                    file_read: "root:x:0:0".into(),
                },
                Severity::High,
            ),
            (
                Evidence::CommandInjection {
                    url: "https://x/s".into(),
                    param: "c".into(),
                    payload: "id".into(),
                },
                Severity::High,
            ),
            (
                Evidence::DomXssTaint {
                    url: "https://x/s".into(),
                    source: "location.search.q".into(),
                    sink: "innerHTML".into(),
                },
                Severity::High,
            ),
            (
                Evidence::SqlInjection {
                    url: "https://x/login".into(),
                    param: "u".into(),
                    payload: "' OR 1=1--".into(),
                },
                Severity::High,
            ),
            (
                Evidence::ReflectedXss {
                    url: "https://x/s".into(),
                    param: "q".into(),
                    payload: "<script>".into(),
                },
                Severity::High,
            ),
            (
                Evidence::Idor {
                    url: "https://x/2".into(),
                    original_id: "1".into(),
                    accessed_id: "2".into(),
                },
                Severity::High,
            ),
            (
                Evidence::NoSqlInjection {
                    url: "https://x/login".into(),
                    param: "u".into(),
                    payload: "{\"$ne\":null}".into(),
                },
                Severity::High,
            ),
            (
                Evidence::MassAssignment {
                    url: "https://x/api".into(),
                    param: "isAdmin".into(),
                    payload: "true".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::JwtVulnerability {
                    endpoint: "https://x/api".into(),
                    issue: "alg_none".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::JwtVulnerability {
                    endpoint: "https://x/api".into(),
                    issue: "alg_none_unverified (token not directly observed)".into(),
                },
                Severity::Info,
            ),
            (
                Evidence::SensitiveDataExposure {
                    url: "https://x/app.js".into(),
                    data_type: "stripe_secret_key".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::GraphQLIntrospection {
                    endpoint: "https://x/graphql".into(),
                },
                Severity::High,
            ),
            (
                Evidence::OpenRedirect {
                    url: "https://x/r".into(),
                    param: "url".into(),
                },
                Severity::Medium,
            ),
            (
                Evidence::MixedContent {
                    page_url: "https://x/".into(),
                    resource_url: "http://x/a.js".into(),
                },
                Severity::Medium,
            ),
            (
                Evidence::CloudExposure {
                    url: "https://x/docker".into(),
                    provider: "docker".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::TechFingerprint {
                    technology: "nginx".into(),
                    version: None,
                    confidence: 90,
                },
                Severity::Info,
            ),
            (
                Evidence::DnsMisconfiguration {
                    domain: "x".into(),
                    issue: "robots_hidden_path".into(),
                },
                Severity::Info,
            ),
            (
                Evidence::XxeExtraction {
                    url: "https://x/xml".into(),
                    file_read: "root:x:0:0".into(),
                },
                Severity::High,
            ),
        ]
    }

    #[test]
    fn every_variant_has_an_explicit_severity() {
        let variants = all_variants();
        assert_eq!(variants.len(), 57, "table must cover every variant");
        for (evidence, expected) in &variants {
            assert_eq!(severity_of(evidence), *expected, "{evidence:?}");
        }
    }

    #[test]
    fn conditional_variants_use_their_evidence() {
        let potential = Evidence::XssReflection {
            url: "https://x/s".into(),
            param: "q".into(),
            context: "innerHTML (Potential)".into(),
        };
        assert_eq!(severity_of(&potential), Severity::Medium);

        let claim = Evidence::JwtVulnerability {
            endpoint: "https://x/api".into(),
            issue: "sensitive_claim".into(),
        };
        assert_eq!(severity_of(&claim), Severity::High);

        for (verdict, expected) in [
            ("critical_full_compromise", Severity::Critical),
            ("high_exploitable_path", Severity::High),
            ("medium_reconnaissance_path", Severity::Medium),
        ] {
            let chain = Evidence::Chain {
                steps: vec!["a".into()],
                verdict: verdict.into(),
            };
            assert_eq!(severity_of(&chain), expected, "{verdict}");
        }
    }

    #[test]
    fn tiers_map_to_stable_report_and_sarif_strings() {
        for (tier, text, level) in [
            (Severity::Critical, "Critical", "error"),
            (Severity::High, "High", "error"),
            (Severity::Medium, "Medium", "warning"),
            (Severity::Low, "Low", "note"),
            (Severity::Info, "Info", "note"),
        ] {
            assert_eq!(tier.as_str(), text);
            assert_eq!(tier.sarif_level(), level);
        }
    }

    /// The seven disagreements named in the audit, plus CSRF/Chain. Keeping
    /// them here pins the authoritative answer for each one.
    #[test]
    fn known_disagreements_resolve_to_one_tier() {
        let cases = [
            (
                Evidence::SupplyChainVulnerability {
                    manifest: "https://x/package-lock.json".into(),
                    package: "p".into(),
                    version: "1".into(),
                },
                Severity::High,
            ),
            (
                Evidence::MassAssignment {
                    url: "https://x/api".into(),
                    param: "isAdmin".into(),
                    payload: "true".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::GrpcExposed {
                    endpoint: "https://x/grpc".into(),
                    service: "reflection".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::SensitiveDataExposure {
                    url: "https://x/app.js".into(),
                    data_type: "stripe_secret_key".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::JwtVulnerability {
                    endpoint: "https://x/api".into(),
                    issue: "alg_none".into(),
                },
                Severity::Critical,
            ),
            (
                Evidence::TechFingerprint {
                    technology: "nginx".into(),
                    version: None,
                    confidence: 90,
                },
                Severity::Info,
            ),
            (
                Evidence::SpaEndpoint {
                    url: "https://x/api".into(),
                    source: "xhr".into(),
                },
                Severity::Info,
            ),
            (
                Evidence::ParameterDiscovery {
                    url: "https://x/api".into(),
                    param: "debug".into(),
                },
                Severity::Info,
            ),
            (
                Evidence::CsrfMissingToken {
                    url: "https://x/login".into(),
                    form_action: "/login".into(),
                },
                Severity::Info,
            ),
        ];
        for (evidence, expected) in cases {
            assert_eq!(severity_of(&evidence), expected, "{evidence:?}");
        }
    }
}
