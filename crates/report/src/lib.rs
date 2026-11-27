//! Output formats for Riftlock findings: HTML, Markdown, SARIF 2.1.0, NDJSON, PDF.

pub mod html;
pub mod markdown;
pub mod metadata;
pub mod ndjson;
pub mod pdf;
pub mod sarif;

pub use html::{to_html, to_html_with_context, to_html_with_status, HtmlContext, TestedSurface};
pub use markdown::{to_markdown, to_markdown_with_status};
pub use metadata::{ScanMetadata, REPORT_SCHEMA_VERSION};
pub use ndjson::to_ndjson;
pub use pdf::{to_pdf, PdfError};
pub use sarif::{to_sarif, to_sarif_with_status};

use riftlock_core::{severity_of, Confidence, Evidence, Finding, Severity, SourceKind};
use std::collections::{BTreeMap, BTreeSet};

/// The scan's coverage report: what the engines actually probed, what
/// stayed untested and why. Single source of truth is the core snapshot
/// (`riftlock_core::CoverageSnapshot`); re-exported here as the
/// report-layer name.
pub use riftlock_core::CoverageSnapshot as ScanCoverage;

/// Serialize complete finding details, including confidence and evidence provenance.
#[must_use]
pub fn finding_details(finding: &Finding) -> serde_json::Value {
    serde_json::json!({
        "evidence": finding.evidence(),
        "confidence": finding.confidence(),
        "provenance": finding.evidence().provenance(),
    })
}

/// Stable rule id: the evidence variant name (shared by every format).
#[must_use]
pub fn rule_id(evidence: &Evidence) -> &'static str {
    match evidence {
        Evidence::LeakedSecret { .. } => "LeakedSecret",
        Evidence::UnauthenticatedRead { .. } => "UnauthenticatedRead",
        Evidence::BrokenAccessControl { .. } => "BrokenAccessControl",
        Evidence::SensitivePathDisclosed { .. } => "SensitivePathDisclosed",
        Evidence::Differential { .. } => "Differential",
        Evidence::AuthBypass { .. } => "AuthBypass",
        Evidence::SourceDisclosure { .. } => "SourceDisclosure",
        Evidence::StorageLeak { .. } => "StorageLeak",
        Evidence::FunctionExposed { .. } => "FunctionExposed",
        Evidence::WriteProof { .. } => "WriteProof",
        Evidence::IdorProof { .. } => "IdorProof",
        Evidence::BusinessLogicBypass { .. } => "BusinessLogicBypass",
        Evidence::PrivilegeEscalation { .. } => "PrivilegeEscalation",
        Evidence::CacheDeception { .. } => "CacheDeception",
        Evidence::PathNormalizationBypass { .. } => "PathNormalizationBypass",
        Evidence::GraphQLBatching { .. } => "GraphQLBatching",
        Evidence::SsrF { .. } => "SsrF",
        Evidence::RaceCondition { .. } => "RaceCondition",
        Evidence::SignedUrlBypass { .. } => "SignedUrlBypass",
        Evidence::PrototypePollution { .. } => "PrototypePollution",
        Evidence::HttpSmuggling { .. } => "HttpSmuggling",
        Evidence::WebSocketDesync { .. } => "WebSocketDesync",
        Evidence::OAuthMisconfig { .. } => "OAuthMisconfig",
        Evidence::SseDesync { .. } => "SseDesync",
        Evidence::ClientSideFlaw { .. } => "ClientSideFlaw",
        Evidence::SupplyChainVulnerability { .. } => "SupplyChainVulnerability",
        Evidence::PromptInjection { .. } => "PromptInjection",
        Evidence::WebSocketCswh { .. } => "WebSocketCswh",
        Evidence::GrpcExposed { .. } => "GrpcExposed",
        Evidence::XssReflection { .. } => "XssReflection",
        Evidence::SqliError { .. } => "SqliError",
        Evidence::SqliTimeDelay { .. } => "SqliTimeDelay",
        Evidence::SstiReflection { .. } => "SstiReflection",
        Evidence::LfiRead { .. } => "LfiRead",
        Evidence::CommandInjection { .. } => "CommandInjection",
        Evidence::DomXssTaint { .. } => "DomXssTaint",
        Evidence::SqlInjection { .. } => "SqlInjection",
        Evidence::ReflectedXss { .. } => "ReflectedXss",
        Evidence::Idor { .. } => "Idor",
        Evidence::NoSqlInjection { .. } => "NoSqlInjection",
        Evidence::MassAssignment { .. } => "MassAssignment",
        Evidence::JwtVulnerability { .. } => "JwtVulnerability",
        Evidence::SensitiveDataExposure { .. } => "SensitiveDataExposure",
        Evidence::GraphQLIntrospection { .. } => "GraphQLIntrospection",
        Evidence::OpenRedirect { .. } => "OpenRedirect",
        Evidence::MixedContent { .. } => "MixedContent",
        Evidence::CloudExposure { .. } => "CloudExposure",
        Evidence::TechFingerprint { .. } => "TechFingerprint",
        Evidence::DnsMisconfiguration { .. } => "DnsMisconfiguration",
        Evidence::XxeExtraction { .. } => "XxeExtraction",
        Evidence::CsrfMissingToken { .. } => "CsrfMissingToken",
        Evidence::SpaEndpoint { .. } => "SpaEndpoint",
        Evidence::SecurityMisconfiguration { .. } => "SecurityMisconfiguration",
        Evidence::Chain { .. } => "Chain",
        _ => "Unknown",
    }
}

/// Severity tier for a finding. The single authoritative mapping lives in
/// `riftlock_core::severity_of`; this wrapper preserves the existing public
/// `&'static str` API and the same tiers the terminal uses.
#[must_use]
pub fn severity(finding: &Finding) -> &'static str {
    riftlock_core::severity_of(finding.evidence()).as_str()
}

/// Severity as the human-facing renderers present it. Passive
/// `SensitiveDataExposure` observations are shown as High until verified;
/// the machine-readable severity remains [`severity`].
#[must_use]
pub fn display_severity(finding: &Finding) -> Severity {
    if finding.confidence() == Confidence::Potential
        && matches!(finding.evidence(), Evidence::SensitiveDataExposure { .. })
    {
        Severity::High
    } else {
        severity_of(finding.evidence())
    }
}

/// Whether a finding belongs under "FIX THESE FIRST" rather than the
/// non-urgent follow-up list. Open redirects stay urgent regardless of tier.
#[must_use]
pub fn is_urgent_finding(finding: &Finding) -> bool {
    matches!(
        display_severity(finding),
        Severity::Critical | Severity::High
    ) || rule_id(finding.evidence()) == "OpenRedirect"
}

/// One non-urgent group in the human and HTML reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowUpGroup {
    /// Group label shared by both renderers.
    pub label: String,
    /// Number of findings in the group.
    pub count: usize,
    /// One-sentence consequence shown under the label.
    pub effect: &'static str,
}

/// Grouping shared by the terminal and HTML renderers. Keeping it here
/// means the two reports cannot drift apart on labels, counts or effects.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportSummary {
    /// Distinct issue groups shown under "FIX THESE FIRST".
    pub urgent_group_count: usize,
    /// Findings shown under "FIX THESE FIRST".
    pub urgent_count: usize,
    /// Non-urgent groups, ordered by label.
    pub follow_up: Vec<FollowUpGroup>,
    /// Total non-urgent findings across all groups.
    pub minor_count: usize,
    /// At least one finding came from passive observation.
    pub has_potential: bool,
}

/// Build the shared finding summary without any presentation formatting.
#[must_use]
pub fn summarize(findings: &[Finding]) -> ReportSummary {
    let mut follow_up: BTreeMap<String, (usize, &'static str)> = BTreeMap::new();
    let mut urgent_groups = BTreeSet::<String>::new();
    let mut urgent_count = 0usize;
    let mut has_potential = false;
    for finding in findings {
        has_potential |= finding.confidence() == Confidence::Potential;
        if is_urgent_finding(finding) {
            urgent_count += 1;
            let variant = rule_id(finding.evidence());
            let mut label = plain_title(variant);
            if finding.confidence() == Confidence::Potential
                && matches!(finding.evidence(), Evidence::SensitiveDataExposure { .. })
            {
                label = format!("[HIGH] {label} (needs verification)");
            }
            urgent_groups.insert(label);
            continue;
        }
        let variant = rule_id(finding.evidence());
        let label = follow_up_title(finding.evidence(), variant);
        let effect = if label == "Missing security headers" {
            "Browsers have fewer defenses against some attacks. Easy to fix."
        } else {
            follow_up_effect(variant)
        };
        follow_up.entry(label).or_insert((0, effect)).0 += 1;
    }
    let follow_up: Vec<FollowUpGroup> = follow_up
        .into_iter()
        .map(|(label, (count, effect))| FollowUpGroup {
            label,
            count,
            effect,
        })
        .collect();
    let minor_count = follow_up.iter().map(|group| group.count).sum();
    ReportSummary {
        urgent_group_count: urgent_groups.len(),
        urgent_count,
        follow_up,
        minor_count,
        has_potential,
    }
}

/// Plain-language issue title shared by the terminal and HTML reports.
#[must_use]
pub fn plain_title(variant: &str) -> String {
    match variant {
        "SqliError" | "SqliTimeDelay" | "SqlInjection" => "Unsafe database queries".into(),
        "XssReflection" | "ReflectedXss" | "DomXssTaint" => "Unsafe content shown on pages".into(),
        "SsrF" => "The site can be made to contact private services".into(),
        "SensitivePathDisclosed" | "SourceDisclosure" => {
            "Files are reachable without a login".into()
        }
        "LeakedSecret" => "A site credential is exposed".into(),
        "UnauthenticatedRead" | "BrokenAccessControl" => "Data can be read without a login".into(),
        "AuthBypass" => "Login can be bypassed".into(),
        "Idor" | "IdorProof" => "Users may access each other's records".into(),
        "CsrfMissingToken" => "Forms can be submitted without permission".into(),
        "StorageLeak" => "Private files are publicly accessible".into(),
        "CommandInjection" => "The site may run commands from user input".into(),
        "SstiReflection" => "The site may run code entered by a visitor".into(),
        "LfiRead" => "Visitors may read private server files".into(),
        "XxeExtraction" => "Uploaded XML may expose server data".into(),
        "NoSqlInjection" => "Database input may bypass access checks".into(),
        "PrivilegeEscalation" => "A basic account may gain administrator access".into(),
        "MassAssignment" => "Users may change protected account settings".into(),
        "WriteProof" => "Visitors may change information they should not control".into(),
        "BusinessLogicBypass" => "A site rule can be bypassed".into(),
        "SensitiveDataExposure" => "Files are reachable without a login".into(),
        "CloudExposure" => "Cloud files are exposed".into(),
        "HttpSmuggling" => "The site may confuse requests and skip security checks".into(),
        "GrpcExposed" => "A private service is open to visitors".into(),
        "CacheDeception" => "Private pages may be shown to other visitors".into(),
        "OpenRedirect" => "The site can send visitors to an unsafe destination".into(),
        "JwtVulnerability" => "A sign-in token may be accepted without proper checks".into(),
        _ => "Configuration improvements".into(),
    }
}

/// Non-urgent group label shared by the terminal and HTML reports.
#[must_use]
pub fn follow_up_title(evidence: &Evidence, variant: &str) -> String {
    if let Evidence::SecurityMisconfiguration { issue, .. } = evidence {
        if issue.starts_with("missing_") {
            return "Missing security headers".into();
        }
        if issue.starts_with("cors_") {
            return "CORS allows too many origins".into();
        }
    }

    match evidence {
        Evidence::SourceDisclosure {
            kind: SourceKind::SourceMap,
            ..
        } => "Source code artifacts are public".into(),
        Evidence::DnsMisconfiguration { .. } => "Server details are publicly visible".into(),
        _ => match variant {
            "SecurityMisconfiguration" => "Minor configuration issue".into(),
            "SensitivePathDisclosed" => "Sensitive paths are publicly visible".into(),
            "SpaEndpoint" => "API paths need access review".into(),
            "TechFingerprint" => "Server software details are visible".into(),
            "CsrfMissingToken" => "Forms are missing a confirmation check".into(),
            _ => "Minor configuration issue".into(),
        },
    }
}

/// Non-urgent group effect shared by the terminal and HTML reports.
#[must_use]
pub fn follow_up_effect(variant: &str) -> &'static str {
    match variant {
        "SecurityMisconfiguration" => "Some browser protections may be missing or weak.",
        "SensitivePathDisclosed" => "These paths may reveal information about the site.",
        "SpaEndpoint" => "These API paths may need a closer access check.",
        "TechFingerprint" => "Older software versions may have known weaknesses.",
        "CsrfMissingToken" => "A form may need an extra check before it makes changes.",
        "DnsMisconfiguration" => "These records may reveal details about your infrastructure.",
        _ => "This item was noticed during the scan and may be worth reviewing.",
    }
}

/// Findings plus definitive scan metadata as one JSON object.
#[must_use]
pub fn to_json_report(findings: &[Finding], meta: &ScanMetadata) -> String {
    let values: Vec<serde_json::Value> = findings.iter().map(finding_details).collect();
    serde_json::json!({
        "schema_version": REPORT_SCHEMA_VERSION,
        "metadata": meta.to_value(),
        "findings": values,
    })
    .to_string()
}

/// NDJSON: one finding per line, then the definitive scan summary as the
/// final event. Machine output contains no human progress text.
#[must_use]
pub fn to_ndjson_report(findings: &[Finding], meta: &ScanMetadata) -> String {
    let mut out = String::new();
    for finding in findings {
        out.push_str(&serde_json::to_string(&finding_details(finding)).unwrap_or_default());
        out.push('\n');
    }
    let mut summary = meta.to_value();
    summary["event"] = serde_json::Value::String("scan.summary".to_owned());
    out.push_str(&serde_json::to_string(&summary).unwrap_or_default());
    out.push('\n');
    out
}

/// One-line JSON serialization of evidence, confidence and provenance.
#[must_use]
pub fn details(finding: &Finding) -> String {
    serde_json::to_string(&finding_details(finding)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::ProofGate;

    fn make(evidence: Evidence) -> Finding {
        ProofGate::admit(evidence).expect("admitted")
    }

    #[test]
    fn severity_mirrors_summary_tiers() {
        let critical = make(Evidence::LeakedSecret {
            key_type: riftlock_core::KeyType::SupabaseSecret,
            location: "page".into(),
            masked: "sb_secret_********".into(),
            full: Default::default(),
        });
        let high = make(Evidence::SseDesync {
            endpoint: "https://x/sse".into(),
        });
        let medium = make(Evidence::SecurityMisconfiguration {
            url: "https://x/".into(),
            issue: "missing_csp".into(),
            severity: "Medium".into(),
        });
        let low = make(Evidence::XssReflection {
            url: "https://x/s".into(),
            param: "q".into(),
            context: "attribute".into(),
        });
        let csrf = make(Evidence::CsrfMissingToken {
            url: "https://x/login".into(),
            form_action: "https://x/login".into(),
        });
        let reflection = make(Evidence::XssReflection {
            url: "https://x/json".into(),
            param: "q".into(),
            context: "json".into(),
        });
        assert_eq!(severity(&critical), "Critical");
        assert_eq!(severity(&high), "High");
        assert_eq!(severity(&medium), "Medium");
        assert_eq!(severity(&low), "Low");
        assert_eq!(severity(&reflection), "Low");
        let potential = make(Evidence::XssReflection {
            url: "https://x/app.js".into(),
            param: "location (query/hash)".into(),
            context: "innerHTML (Potential)".into(),
        });
        assert_eq!(severity(&potential), "Medium");
        // Posture observation, not a confirmed vulnerability.
        assert_eq!(severity(&csrf), "Info");
    }

    #[test]
    fn machine_formats_never_leak_full_secret_or_ansi() {
        let finding = make(Evidence::LeakedSecret {
            key_type: riftlock_core::KeyType::SupabaseSecret,
            location: "https://x/app.js".into(),
            masked: "sb_secret_****".into(),
            full: riftlock_core::SecretValue("sb_secret_AbC123xYz".into()),
        });
        let full = "sb_secret_AbC123xYz";
        let slice = std::slice::from_ref(&finding);
        for output in [
            details(&finding),
            crate::to_ndjson(slice),
            crate::to_sarif(slice),
            crate::to_markdown(slice),
            crate::to_html(slice),
        ] {
            assert!(!output.contains(full), "full secret leaked: {output}");
            assert!(
                !output.contains('\u{1b}'),
                "ANSI leaked into report: {output}"
            );
            assert!(output.contains("sb_secret_****"), "masked value missing");
        }
        // Debug is redacted too, so logs cannot pick up the full value.
        assert!(!format!("{finding:?}").contains(full));
    }

    #[test]
    fn json_and_ndjson_carry_definitive_verdict_and_accounting() {
        let finding = make(Evidence::AuthBypass {
            endpoint: "https://x/auth".into(),
            method: "POST".into(),
        });
        let mut meta = ScanMetadata::new(
            "scan-1".into(),
            "https://x".into(),
            "FINDINGS + INCOMPLETE COVERAGE".into(),
            "failed — target root only".into(),
        );
        meta.accounting = riftlock_core::AccountingValidation {
            registered: 4,
            terminal: 4,
            in_flight: 0,
            duplicates_rejected: 0,
        };
        meta.unaccounted_executions = 1;

        let json = to_json_report(std::slice::from_ref(&finding), &meta);
        let doc: serde_json::Value = serde_json::from_str(&json).expect("json report");
        assert_eq!(doc["schema_version"], REPORT_SCHEMA_VERSION);
        assert_eq!(doc["metadata"]["verdict"], "FINDINGS + INCOMPLETE COVERAGE");
        assert_eq!(doc["metadata"]["accounting"]["registered"], 4);
        assert_eq!(doc["metadata"]["unaccounted_executions"], 1);
        assert_eq!(doc["findings"].as_array().expect("findings").len(), 1);
        assert_eq!(doc["findings"][0]["confidence"], "confirmed");
        assert_eq!(
            doc["findings"][0]["evidence"]["AuthBypass"]["endpoint"],
            "https://x/auth"
        );
        assert!(doc["findings"][0]["provenance"].is_string());

        let ndjson = to_ndjson_report(std::slice::from_ref(&finding), &meta);
        let lines: Vec<&str> = ndjson.lines().collect();
        assert_eq!(lines.len(), 2, "finding line + final summary event");
        let summary: serde_json::Value = serde_json::from_str(lines[1]).expect("summary json");
        assert_eq!(summary["event"], "scan.summary");
        assert_eq!(summary["verdict"], "FINDINGS + INCOMPLETE COVERAGE");
        assert_eq!(summary["schema_version"], REPORT_SCHEMA_VERSION);
    }

    #[test]
    fn rule_id_is_stable_per_variant() {
        let f = make(Evidence::AuthBypass {
            endpoint: "https://x/auth".into(),
            method: "POST".into(),
        });
        assert_eq!(rule_id(f.evidence()), "AuthBypass");
        assert!(!details(&f).is_empty());
    }
}
