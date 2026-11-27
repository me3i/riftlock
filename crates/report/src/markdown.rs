//! GitHub-flavored Markdown report: severity summary table plus one entry
//! per finding with its evidence details in a code fence.

use riftlock_core::Finding;

/// Length of the longest run of backticks in `s` (splitting on every
/// non-backtick char leaves exactly the backtick runs). The code fence must
/// be longer than this or attacker-controlled evidence text can break out
/// of the block.
fn longest_backtick_run(s: &str) -> usize {
    s.split(|c: char| c != '`').map(str::len).max().unwrap_or(0)
}

/// Render with the shared scan status so the report agrees with the terminal.
#[must_use]
pub fn to_markdown_with_status(findings: &[Finding], status: &str) -> String {
    to_markdown_inner(findings, Some(status))
}

/// Legacy entry point without a status. Prefer [`to_markdown_with_status`].
#[must_use]
pub fn to_markdown(findings: &[Finding]) -> String {
    to_markdown_inner(findings, None)
}

fn to_markdown_inner(findings: &[Finding], status: Option<&str>) -> String {
    let mut out = String::from("# RIFTLOCK SECURITY REPORT\n\n");
    if let Some(status) = status {
        out.push_str(&format!("**Scan status: {status}**\n\n"));
    }
    out.push_str("## Summary\n\n");
    out.push_str("| Severity | Count |\n|---|---|\n");
    for tier in ["Critical", "High", "Medium", "Low", "Info"] {
        let count = findings
            .iter()
            .filter(|f| crate::severity(f) == tier)
            .count();
        out.push_str(&format!("| {tier} | {count} |\n"));
    }
    out.push_str(&format!("\n**Total: {}**\n\n", findings.len()));
    if findings.is_empty() {
        out.push_str("No findings were produced by this scan.\n");
        return out;
    }
    out.push_str("## Findings\n\n");
    for (i, finding) in findings.iter().enumerate() {
        let details = crate::details(finding);
        // One more backtick than the longest run inside the details: the
        // fence can then never be closed early by evidence text.
        let fence = "`".repeat(longest_backtick_run(&details).max(2) + 1);
        out.push_str(&format!(
            "### {}. **{}** — {}\n\n{fence}json\n{details}\n{fence}\n\n",
            i + 1,
            crate::severity(finding),
            crate::rule_id(finding.evidence()),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::{Evidence, ProofGate};

    fn make(evidence: Evidence) -> Finding {
        ProofGate::admit(evidence).expect("admitted")
    }

    #[test]
    fn empty_findings_render_header_and_no_entries() {
        let out = to_markdown(&[]);
        assert!(out.starts_with("# RIFTLOCK SECURITY REPORT"));
        assert!(out.contains("No findings were produced"));
        assert!(!out.contains("### "));
    }

    #[test]
    fn summary_table_counts_tiers_and_lists_findings() {
        let findings = vec![
            make(Evidence::LeakedSecret {
                key_type: riftlock_core::KeyType::SupabaseSecret,
                location: "page".into(),
                masked: "sb_secret_********".into(),
                full: Default::default(),
            }),
            make(Evidence::SecurityMisconfiguration {
                url: "https://x/".into(),
                issue: "missing_csp".into(),
                severity: "Medium".into(),
            }),
        ];
        let out = to_markdown(&findings);
        assert!(out.contains("| Critical | 1 |"));
        assert!(out.contains("| High | 0 |"));
        assert!(out.contains("| Medium | 1 |"));
        assert!(out.contains("| Low | 0 |"));
        assert!(out.contains("**Total: 2**"));
        assert!(out.contains("LeakedSecret"));
        assert!(out.contains("SecurityMisconfiguration"));
        assert_eq!(out.matches("### ").count(), 2);
    }

    #[test]
    fn backticks_in_details_cannot_close_the_fence() {
        let f = make(Evidence::UnauthenticatedRead {
            endpoint: "https://x/```inject```".into(),
            row_sample: "{id=<int>}".into(),
        });
        let details = crate::details(&f);
        let run = longest_backtick_run(&details);
        let out = to_markdown(std::slice::from_ref(&f));
        let fence_len = out
            .lines()
            .find(|l| l.starts_with('`') && l.ends_with("json"))
            .expect("opening fence")
            .trim_end_matches("json")
            .len();
        assert!(fence_len > run);
    }
}
