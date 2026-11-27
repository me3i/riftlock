//! Dedicated presentation of discovered credentials. Pure presentation:
//! every value shown comes from a real `LeakedSecret` finding, and the full
//! secret is revealed only on explicit opt-in in an interactive terminal.

use crate::ui::theme::{credential, warning};
use riftlock_core::{Evidence, Finding};
use std::collections::HashSet;

/// One display row derived from a `LeakedSecret` finding.
pub struct Credential {
    key_type: String,
    location: String,
    masked: String,
    confidence: String,
    full: String,
}

impl Credential {
    /// Build a display row from a finding. Non-credential findings return
    /// `None` — no credential is ever invented.
    #[must_use]
    pub fn from_finding(finding: &Finding) -> Option<Self> {
        match finding.evidence() {
            Evidence::LeakedSecret {
                key_type,
                location,
                masked,
                full,
            } => Some(Self {
                key_type: key_type.label().to_owned(),
                location: location.clone(),
                masked: masked.clone(),
                confidence: format!("{:?}", finding.confidence()),
                full: full.0.clone(),
            }),
            Evidence::SensitiveDataExposure { url, data_type } => Some(Self {
                key_type: data_type.clone(),
                location: url.clone(),
                // This detector proves a live secret pattern but does not
                // retain the matched value, so nothing more can be shown.
                masked: "<value not retained>".to_owned(),
                confidence: format!("{:?}", finding.confidence()),
                full: String::new(),
            }),
            _ => None,
        }
    }
}

/// Collect credentials, deduplicating identical (type, location, masked)
/// triples while keeping distinct source locations visible.
#[must_use]
pub fn collect(findings: &[Finding]) -> Vec<Credential> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for finding in findings {
        if let Some(c) = Credential::from_finding(finding) {
            let key = (c.key_type.clone(), c.location.clone(), c.masked.clone());
            if seen.insert(key) {
                out.push(c);
            }
        }
    }
    out
}

/// Render the `CREDENTIALS DISCOVERED` section as lines of cyan terminal
/// text. `show_secrets` reveals full values only when `interactive` is true;
/// machine-readable formats never call this function, so no ANSI reaches
/// JSON/SARIF/NDJSON.
#[must_use]
pub fn render(credentials: &[Credential], show_secrets: bool, interactive: bool) -> Vec<String> {
    let mut lines = vec![credential("CREDENTIALS DISCOVERED")];
    for c in credentials {
        lines.push(credential(&format!(
            "  {} | source {} | evidence {} | confidence {} | value {}",
            c.key_type, c.location, c.location, c.confidence, c.masked
        )));
    }
    if show_secrets {
        if !interactive {
            lines.push(warning(
                "  --show-secrets ignored: credential values reveal only in an interactive terminal.",
            ));
        } else {
            lines.push(warning(
                "  WARNING: revealing credential values. Do not share this terminal output.",
            ));
            for c in credentials {
                if !c.full.is_empty() {
                    lines.push(credential(&format!("  {} -> {}", c.key_type, c.full)));
                }
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::global_lock;
    use riftlock_core::{KeyType, ProofGate, SecretValue};

    fn leaked(location: &str, masked: &str, full: &str) -> Finding {
        ProofGate::admit(Evidence::LeakedSecret {
            key_type: KeyType::SupabaseSecret,
            location: location.to_owned(),
            masked: masked.to_owned(),
            full: SecretValue(full.to_owned()),
        })
        .expect("admitted")
    }

    #[test]
    fn renders_cyan_header_and_never_invents_credentials() {
        let _g = global_lock();
        crate::ui::theme::set_color_override(true);
        let lines = render(
            &collect(&[leaked(
                "https://x/app.js",
                "sb_secret_****",
                "sb_secret_AbC123xYz",
            )]),
            false,
            true,
        );
        assert!(lines[0].contains("CREDENTIALS DISCOVERED"));
        assert!(
            lines[0].contains("\u{1b}[36m"),
            "header must be cyan: {}",
            lines[0]
        );
        assert!(
            render(&collect(&[]), false, true).len() == 1,
            "no findings -> header only"
        );
        crate::ui::theme::unset_color_override();
    }

    #[test]
    fn masks_by_default_and_reveals_only_on_interactive_opt_in() {
        let creds = collect(&[leaked(
            "https://x/app.js",
            "sb_secret_****",
            "sb_secret_AbC123xYz",
        )]);
        let masked = render(&creds, false, true).join("\n");
        assert!(masked.contains("sb_secret_****"));
        assert!(!masked.contains("AbC123xYz"));

        let revealed = render(&creds, true, true).join("\n");
        assert!(revealed.contains("sb_secret_AbC123xYz"));
        assert!(revealed.contains("WARNING"));

        let non_interactive = render(&creds, true, false).join("\n");
        assert!(!non_interactive.contains("AbC123xYz"));
        assert!(non_interactive.contains("interactive terminal"));
    }

    #[test]
    fn includes_api_key_findings_supported_by_existing_detection() {
        let finding = ProofGate::admit(Evidence::SensitiveDataExposure {
            url: "https://x/app.js".into(),
            data_type: "aws_access_key_id".into(),
        })
        .expect("admitted");
        let creds = collect(&[finding]);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].key_type, "aws_access_key_id");
        assert_eq!(creds[0].location, "https://x/app.js");
        assert_eq!(creds[0].masked, "<value not retained>");
    }

    #[test]
    fn dedups_repeated_discovery_but_keeps_distinct_locations() {
        let findings = vec![
            leaked("https://x/a.js", "sb_secret_****", "sb_secret_AbC123xYz"),
            leaked("https://x/a.js", "sb_secret_****", "sb_secret_AbC123xYz"),
            leaked("https://x/b.js", "sb_secret_****", "sb_secret_AbC123xYz"),
        ];
        let creds = collect(&findings);
        assert_eq!(creds.len(), 2);
        assert!(creds.iter().any(|c| c.location == "https://x/a.js"));
        assert!(creds.iter().any(|c| c.location == "https://x/b.js"));
    }
}
