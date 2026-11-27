//! SARIF 2.1.0 export for findings.

use riftlock_core::{Evidence, Finding};
use serde_sarif::sarif;

/// SARIF level derived from the single authoritative severity tier.
/// Critical/High → error, Medium → warning, Low/Info → note.
fn level(evidence: &Evidence) -> &'static str {
    riftlock_core::severity_of(evidence).sarif_level()
}

use crate::{details, rule_id};

/// Human-readable message: the finding serialized as one-line JSON.
fn message(finding: &Finding) -> String {
    details(finding)
}

/// Serialize findings as a SARIF 2.1.0 JSON string (one run, one rule per
/// evidence variant present, one result per finding).
#[must_use]
pub fn to_sarif(findings: &[Finding]) -> String {
    let mut rules: Vec<sarif::ReportingDescriptor> = Vec::new();
    let mut results: Vec<sarif::Result> = Vec::new();
    for finding in findings {
        let evidence = finding.evidence();
        let id = rule_id(evidence);
        if !rules.iter().any(|r| r.id == id) {
            rules.push(sarif::ReportingDescriptor::builder().id(id).build());
        }
        results.push(
            sarif::Result::builder()
                .rule_id(id)
                .level(match level(evidence) {
                    "error" => sarif::ResultLevel::Error,
                    "warning" => sarif::ResultLevel::Warning,
                    _ => sarif::ResultLevel::Note,
                })
                .message(message(finding).as_str())
                .build(),
        );
    }
    let tool_component = sarif::ToolComponent::builder()
        .name("riftlock")
        .rules(rules)
        .build();
    let run = sarif::Run::builder()
        .tool(sarif::Tool::from(tool_component))
        .results(results)
        .build();
    let doc = sarif::Sarif::builder()
        .version(sarif::Version::V2_1_0.to_string())
        .runs(vec![run])
        .build();
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// SARIF with the shared status under `runs[0].properties.scanStatus`, so a
/// machine report can tell findings from an incomplete assessment.
#[must_use]
pub fn to_sarif_with_status(findings: &[Finding], status: &str) -> String {
    let base = to_sarif(findings);
    let mut doc: serde_json::Value = serde_json::from_str(&base).unwrap_or_default();
    if let Some(run) = doc["runs"][0].as_object_mut() {
        let mut props = run
            .get("properties")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        props["scanStatus"] = serde_json::Value::String(status.to_owned());
        run.insert("properties".to_owned(), props);
    }
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::ProofGate;

    fn make(evidence: Evidence) -> Finding {
        ProofGate::admit(evidence).expect("admitted")
    }

    #[test]
    fn sarif_has_versions_and_levels() {
        let findings = vec![
            make(Evidence::LeakedSecret {
                key_type: riftlock_core::KeyType::SupabasePublishable,
                location: "page".into(),
                masked: "sb_secret_********".into(),
                full: Default::default(),
            }),
            make(Evidence::Differential {
                without_key: 401,
                with_key: 200,
                inverted: false,
                cross_tenant: false,
                note: None,
            }),
        ];
        let doc = to_sarif(&findings);
        let v: serde_json::Value = serde_json::from_str(&doc).expect("json");
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "riftlock");
        let results = v["runs"][0]["results"].as_array().expect("results");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["level"], "error");
        // Differential is High in the shared mapping, so SARIF level is error.
        assert_eq!(results[1]["level"], "error");
    }

    #[test]
    fn chain_maps_to_error() {
        let f = make(Evidence::Chain {
            steps: vec!["a".into(), "b".into()],
            verdict: "critical_full_compromise".into(),
        });
        let doc = to_sarif(std::slice::from_ref(&f));
        let v: serde_json::Value = serde_json::from_str(&doc).expect("json");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn misconfig_severity_drives_sarif_level() {
        let findings = vec![
            make(Evidence::SecurityMisconfiguration {
                url: "https://x/".into(),
                issue: "cors_reflect_credentials".into(),
                severity: "High".into(),
            }),
            make(Evidence::SecurityMisconfiguration {
                url: "https://x/".into(),
                issue: "missing_csp".into(),
                severity: "Medium".into(),
            }),
            make(Evidence::SecurityMisconfiguration {
                url: "https://x/".into(),
                issue: "missing_hsts".into(),
                severity: "Low".into(),
            }),
        ];
        let doc = to_sarif(&findings);
        let v: serde_json::Value = serde_json::from_str(&doc).expect("json");
        let results = v["runs"][0]["results"].as_array().expect("results");
        let levels: Vec<&str> = results
            .iter()
            .map(|r| r["level"].as_str().expect("level"))
            .collect();
        assert_eq!(levels, ["error", "warning", "note"]);
        assert_eq!(results[0]["ruleId"], "SecurityMisconfiguration");
        // One stable rule registered for the variant, not per severity.
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .expect("rules")
                .len(),
            1
        );
    }

    #[test]
    fn web_xss_sqli_error_csrf_spa_note() {
        let findings = vec![
            make(Evidence::XssReflection {
                url: "https://x/s".into(),
                param: "q".into(),
                context: "html".into(),
            }),
            make(Evidence::SqliError {
                url: "https://x/s".into(),
                param: "q".into(),
                error_signature: "SQL syntax".into(),
            }),
            make(Evidence::SqliTimeDelay {
                url: "https://x/s".into(),
                param: "q".into(),
                delay_ms: 5_000,
            }),
            make(Evidence::CsrfMissingToken {
                url: "https://x/f".into(),
                form_action: "/login".into(),
            }),
            make(Evidence::SpaEndpoint {
                url: "https://x/api/v1/users".into(),
                source: "xhr".into(),
            }),
        ];
        let doc = to_sarif(&findings);
        let v: serde_json::Value = serde_json::from_str(&doc).expect("json");
        let levels: Vec<&str> = v["runs"][0]["results"]
            .as_array()
            .expect("results")
            .iter()
            .map(|r| r["level"].as_str().expect("level"))
            .collect();
        assert_eq!(levels, ["note", "error", "error", "note", "note"]);
    }

    #[test]
    fn info_tier_evidence_is_note_not_error() {
        let findings = vec![
            make(Evidence::SensitivePathDisclosed {
                url: "https://x/admin".into(),
                status: 403,
            }),
            make(Evidence::TechFingerprint {
                technology: "React".into(),
                version: Some("19.0.0".into()),
                confidence: 90,
            }),
        ];
        let doc = to_sarif(&findings);
        let v: serde_json::Value = serde_json::from_str(&doc).expect("json");
        let levels: Vec<&str> = v["runs"][0]["results"]
            .as_array()
            .expect("results")
            .iter()
            .map(|r| r["level"].as_str().expect("level"))
            .collect();
        assert_eq!(levels, ["note", "note"]);
    }
}
