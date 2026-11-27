//! NDJSON export: one JSON object per line, suitable for `tail -f`.

use riftlock_core::Finding;

use crate::finding_details;

/// Serialize each finding as a single line of JSON, joined by newlines.
/// A trailing newline terminates the last line (NDJSON convention).
#[must_use]
pub fn to_ndjson(findings: &[Finding]) -> String {
    let mut out = String::new();
    for finding in findings {
        out.push_str(&serde_json::to_string(&finding_details(finding)).unwrap_or_default());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::{Evidence, ProofGate};

    #[test]
    fn one_line_per_finding() {
        let findings = vec![
            ProofGate::admit(Evidence::AuthBypass {
                endpoint: "https://x/auth/v1/signup".into(),
                method: "POST".into(),
            })
            .expect("admitted"),
            ProofGate::admit(Evidence::UnauthenticatedRead {
                endpoint: "https://x/rest/v1/users".into(),
                row_sample: "{id=<int>}".into(),
            })
            .expect("admitted"),
        ];
        let out = to_ndjson(&findings);
        assert_eq!(out.lines().count(), 2);
        assert!(out.ends_with('\n'));
        for line in out.lines() {
            serde_json::from_str::<serde_json::Value>(line).expect("json per line");
        }
    }

    #[test]
    fn empty_input_is_empty_output() {
        assert_eq!(to_ndjson(&[]), "");
    }
}
