//! Standalone HTML report: inline CSS, no external assets, no JS.

use crate::ReportSummary;
use riftlock_core::{Confidence, Evidence, Finding};

/// HTML-escape a dynamic string. Finding details carry attacker-controlled
/// data (URLs, parameters, snippets read from HTTP responses), so every
/// embedded value goes through this.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Report data the findings list cannot supply on its own: the shared
/// follow-up grouping, the coverage summary line, and the scan status.
#[derive(Debug)]
pub struct HtmlContext<'a> {
    /// Finding groups shared with the terminal report.
    pub summary: &'a ReportSummary,
    /// Whether the authoritative run verdict marked coverage incomplete.
    pub incomplete_coverage: bool,
    /// Whether the authoritative run verdict counted any findings.
    pub has_findings: bool,
    /// Coverage summary segments ("Pages: N", "Forms: ...", "APIs: ...").
    pub tested_segments: &'a [String],
    /// Endpoints skipped because they require authentication.
    pub auth_required: u64,
    /// Endpoints that timed out.
    pub timed_out: u64,
}

/// Render findings with the follow-up, tested-surface and scan-status
/// sections populated from [`HtmlContext`].
#[must_use]
pub fn to_html_with_context(findings: &[Finding], context: &HtmlContext<'_>) -> String {
    to_html_inner(findings, None, Some(context))
}

/// Render findings as a self-contained HTML report, with the shared scan
/// status so a report can never imply complete coverage when it was blocked.
#[must_use]
pub fn to_html_with_status(findings: &[Finding], status: &str) -> String {
    to_html_inner(findings, Some(status), None)
}

/// Legacy entry point without a status. Prefer [`to_html_with_status`].
#[must_use]
pub fn to_html(findings: &[Finding]) -> String {
    to_html_inner(findings, None, None)
}

fn to_html_inner(
    findings: &[Finding],
    status: Option<&str>,
    context: Option<&HtmlContext<'_>>,
) -> String {
    let display_severity = |finding: &Finding| crate::display_severity(finding).as_str();
    let count = |tier: &str| {
        findings
            .iter()
            .filter(|finding| display_severity(finding) == tier)
            .count()
    };
    let critical = count("Critical");
    let high = count("High");
    let medium = count("Medium");
    let low = count("Low");
    let info = count("Info");

    let mut rows = String::new();
    for finding in findings {
        let sev = display_severity(finding);
        let class = sev.to_lowercase();
        let label = if sev == "Critical" {
            format!(
                "<span class=\"critical-bar\">[CRITICAL] {}</span>",
                esc(crate::rule_id(finding.evidence()))
            )
        } else {
            esc(crate::rule_id(finding.evidence()))
        };
        let passive_title = if finding.confidence() == Confidence::Potential
            && matches!(finding.evidence(), Evidence::SensitiveDataExposure { .. })
        {
            " (needs verification)"
        } else {
            ""
        };
        rows.push_str(&format!(
            "<tr><td><span class=\"severity-chip sev-{class}\">{}</span></td><td>{label}{passive_title}</td><td class=\"details\">{}</td></tr>\n",
            esc(sev),
            esc(&crate::details(finding)),
        ));
    }
    let body = if findings.is_empty() {
        "<p class=\"clean\">No findings were reported for this scan.</p>".to_string()
    } else {
        format!("<table>\n<tr><th>Severity</th><th>Rule</th><th>Details</th></tr>\n{rows}</table>")
    };

    let summary = context.map_or_else(|| crate::summarize(findings), |ctx| ctx.summary.clone());
    let has_potential = summary.has_potential;
    // When a context supplies the scan status it also supplies the ABOUT
    // THIS SCAN section, so the legacy top status lines are omitted to keep
    // each statement in one place.
    let status_block = if context.is_some() {
        String::new()
    } else {
        format!(
            "{}{}",
            status
                .map(|value| format!("<p class=\"scan-status\">Scan status: {}</p>\n", esc(value)))
                .unwrap_or_default(),
            if has_potential {
                "<p class=\"scan-status\">Some findings are based on passive observation and may need manual verification.</p>\n"
            } else {
                ""
            }
        )
    };

    let check_body = context.map_or_else(String::new, |ctx| {
        if ctx.summary.follow_up.is_empty() {
            return "<p>(none)</p>\n".to_string();
        }
        ctx.summary
            .follow_up
            .iter()
            .map(|group| {
                format!(
                    "<div class=\"check-block\"><div class=\"check-label\">{} ({})</div><div class=\"check-effect\">{}</div></div>\n",
                    esc(&group.label),
                    group.count,
                    esc(group.effect),
                )
            })
            .collect()
    });

    let tested_body = context.map_or_else(String::new, |ctx| {
        let summary = ctx.tested_segments.join("  |  ");
        if summary.is_empty() {
            String::new()
        } else {
            format!("<p>{}</p>\n", esc(&summary))
        }
    });

    let issue_count = summary.urgent_group_count;
    let finding_count = summary.urgent_count;
    let (headline, section_label) = if finding_count == 0 {
        let headline = if summary.minor_count > 0 {
            format!(
                "NO URGENT ISSUES - {} minor items to review.",
                summary.minor_count
            )
        } else {
            "YOUR SITE LOOKS CLEAN - no issues found.".to_owned()
        };
        (
            headline,
            "FIX THESE FIRST (0 issues, 0 findings)".to_owned(),
        )
    } else {
        let (label, verb) = if issue_count == 1 {
            ("PROBLEM", "NEEDS")
        } else {
            ("PROBLEMS", "NEED")
        };
        (
            format!("YOUR SITE HAS {issue_count} {label} THAT {verb} FIXING ({finding_count} findings)."),
            format!("FIX THESE FIRST ({issue_count} issues, {finding_count} findings)"),
        )
    };

    let about_section = context.map_or_else(String::new, |ctx| {
        let mut out = String::from("  <h2>ABOUT THIS SCAN</h2>\n");
        let scan_status = if ctx.incomplete_coverage {
            if ctx.has_findings {
                "FINDINGS (partial coverage)"
            } else {
                "NO FINDINGS (partial coverage)"
            }
        } else if ctx.has_findings {
            "FINDINGS"
        } else {
            "NO FINDINGS"
        };
        out.push_str(&format!(
            "  <p class=\"scan-status\">Scan status: {}</p>\n",
            esc(scan_status)
        ));
        if ctx.incomplete_coverage {
            out.push_str("  <p class=\"scan-status\">Some pages were blocked by the site's firewall, required a login, or timed out and could not be tested.</p>\n");
        }
        if has_potential {
            out.push_str("  <p class=\"scan-status\">Some findings are based on passive observation and may need manual verification.</p>\n");
        }
        out.push_str("  <p class=\"scan-status\">- Urgent items are tied to evidence observed during this scan.</p>\n");
        if ctx.auth_required > 0 {
            out.push_str(
                "  <p class=\"scan-status\">- Some pages require a login and were skipped.</p>\n",
            );
        }
        let timed_out_text = if ctx.timed_out == 1 {
            "1 URL timed out".to_owned()
        } else {
            format!("{} URLs timed out", ctx.timed_out)
        };
        out.push_str(&format!(
            "  <p class=\"scan-status\">- {}</p>\n",
            esc(&format!("{timed_out_text} (see HTML report for the list)."))
        ));
        out.push_str("</section>\n");
        out
    });

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Riftlock Scan Report</title>
<style>
  :root {{
    --bg: #ffffff;
    --text: #111111;
    --muted: #555555;
    --rule: #e5e5e5;
    --accent: #c81e1e;
    --critical-bg: #0a0a0a;
    --critical-fg: #ff2d2d;
    --high: #b91c1c;
    --medium: #b45309;
    --low: #525252;
    --info: #737373;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--text);
         font: 15px -apple-system, "Segoe UI", system-ui, sans-serif; }}
  main {{ max-width: 980px; margin: 0 auto; padding: 32px 40px; }}
  h1, h2 {{ font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
            font-weight: 700; letter-spacing: -0.01em; }}
  h1 {{ position: relative; margin: 0; padding: 0 0 16px 14px; font-size: 26px; }}
  h1::before {{ position: absolute; top: 1px; bottom: 16px; left: 0; width: 4px;
                background: var(--accent); content: ""; }}
  .report-header {{ border-bottom: 1px solid var(--rule); padding-bottom: 20px; }}
  .tip {{ margin: 16px 0 0; color: var(--muted); font-size: 13px; }}
  section {{ margin-top: 32px; padding-top: 24px; border-top: 1px solid var(--rule); }}
  h2 {{ margin: 0 0 16px; font-size: 19px; }}
  .headline {{ margin: 0; color: var(--text); font-size: 22px; font-weight: 800;
               letter-spacing: -0.01em; }}
  .summary {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 20px 0 0; }}
  .summary div {{ min-width: 92px; padding: 10px 14px; border: 1px solid var(--rule); }}
  .summary b {{ display: block; font-size: 20px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 12px 10px; border-bottom: 1px solid var(--rule); text-align: left;
            vertical-align: top; }}
  th {{ color: var(--muted); font-size: 12px; font-weight: 600; }}
  .severity-chip {{ display: inline-block; padding: 3px 7px; border-radius: 3px;
                    font-size: 11px; font-weight: 700; }}
  .sev-critical {{ background: var(--critical-bg); color: var(--critical-fg); }}
  .sev-high {{ background: var(--bg); color: var(--high); }}
  .sev-medium {{ background: var(--bg); color: var(--medium); }}
  .sev-low {{ background: var(--bg); color: var(--low); }}
  .sev-info {{ background: var(--bg); color: var(--info); }}
  .critical-bar {{ display: inline-block; margin-bottom: 4px; padding: 10px 14px;
                   background: var(--critical-bg); color: var(--critical-fg);
                   font: 800 13px ui-monospace, "SF Mono", Menlo, monospace; }}
  .details, .url, code {{ color: var(--text); font: 13px ui-monospace, "SF Mono", Menlo, monospace;
                          overflow-wrap: anywhere; }}
  .url {{ text-decoration: underline dotted var(--accent); }}
  .issue-title {{ display: block; margin-top: 8px; color: var(--text); font-size: 17px;
                  font-weight: 700; }}
  .section-label {{ color: var(--muted); }}
  .check-section h2::before {{ display: inline-block; width: 4px; height: 19px;
                                margin-right: 10px; background: var(--medium); content: "";
                                vertical-align: -3px; }}
  .tested-section h2::before {{ display: inline-block; width: 4px; height: 19px;
                                 margin-right: 10px; background: var(--info); content: "";
                                 vertical-align: -3px; }}
  .scan-status, .clean {{ color: var(--text); }}
  a {{ color: var(--accent); }}
  a:focus {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
  @media (max-width: 600px) {{
    main {{ padding: 24px 16px; }}
    .summary div {{ min-width: 74px; }}
    th, td {{ padding: 9px 6px; }}
  }}
  @media print {{
    @page {{ size: A4; margin: 18mm; }}
    body {{ background: #fff; color: #000; font-size: 11pt; }}
    section, .problem-block {{ page-break-inside: avoid; }}
    a {{ color: #000; text-decoration: none; }}
    * {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  }}
</style>
</head>
<body>
<main>
<header class="report-header"><h1>RIFTLOCK SCAN RESULT</h1></header>
<p class="tip">Tip: Ctrl+P → Save as PDF to export this report.</p>
{status_block}
<section aria-label="Finding summary">
  <p class="headline">{headline}</p>
  <div class="summary">
    <div><b>{critical}</b>Critical</div>
    <div><b>{high}</b>High</div>
    <div><b>{medium}</b>Medium</div>
    <div><b>{low}</b>Low</div>
    <div><b>{info}</b>Info</div>
    <div><b>{total}</b>Total</div>
  </div>
</section>
<section class="problem-block" aria-label="Findings">
  <h2>{section_label}</h2>
  {body}
</section>
<section class="check-section" aria-label="Follow-up items">
  <h2>CHECK WHEN YOU CAN</h2>
  <p class="section-label">Review non-urgent items when convenient.</p>
  {check_body}</section>
<section class="tested-section" aria-label="Tested surface">
  <h2>WE ALSO TESTED</h2>
  {tested_body}{about_section}</section>
</main>
</body>
</html>
"#,
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        info = info,
        total = findings.len(),
        status_block = status_block,
        check_body = check_body,
        tested_body = tested_body,
        about_section = about_section,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::{Evidence, ProofGate};

    fn make(evidence: Evidence) -> Finding {
        ProofGate::admit(evidence).expect("admitted")
    }

    #[test]
    fn empty_report_renders_header_without_rows() {
        let out = to_html(&[]);
        assert!(out.contains("RIFTLOCK SCAN RESULT"));
        assert!(out.contains("No findings were reported"));
        assert!(!out.contains("<tr><td"));
    }

    #[test]
    fn counts_and_rule_ids_render() {
        let findings = vec![
            make(Evidence::LeakedSecret {
                key_type: riftlock_core::KeyType::SupabaseSecret,
                location: "https://x/app.js".into(),
                masked: "sb_secret_********".into(),
                full: Default::default(),
            }),
            make(Evidence::SecurityMisconfiguration {
                url: "https://x/".into(),
                issue: "missing_csp".into(),
                severity: "Medium".into(),
            }),
        ];
        let out = to_html(&findings);
        assert!(out.contains("RIFTLOCK SCAN RESULT"));
        assert!(out.contains("background: var(--critical-bg); color: var(--critical-fg)"));
        assert!(out.contains("class=\"critical-bar\">[CRITICAL] LeakedSecret</span>"));
        assert!(out.contains("Tip: Ctrl+P → Save as PDF to export this report."));
        assert!(out.contains("LeakedSecret"));
        assert!(out.contains("SecurityMisconfiguration"));
        assert!(out.contains("<b>1</b>Critical"));
        assert!(out.contains("<b>0</b>High"));
        assert!(out.contains("<b>1</b>Medium"));
        assert!(out.contains("<b>0</b>Low"));
        assert!(out.contains("<b>2</b>Total"));
        assert!(out.contains("YOUR SITE HAS 1 PROBLEM THAT NEEDS FIXING (1 findings)."));
        assert!(out.contains("<h2>FIX THESE FIRST (1 issues, 1 findings)</h2>"));
    }

    #[test]
    fn summary_counts_issue_groups_separately_from_findings() {
        let findings: Vec<_> = (0..3)
            .map(|index| {
                make(Evidence::AuthBypass {
                    endpoint: format!("https://x/login/{index}"),
                    method: "POST".into(),
                })
            })
            .collect();
        let out = to_html(&findings);

        assert!(out.contains("YOUR SITE HAS 1 PROBLEM THAT NEEDS FIXING (3 findings)."));
        assert!(out.contains("<h2>FIX THESE FIRST (1 issues, 3 findings)</h2>"));
        assert!(!out.contains("3 PROBLEMS"));
    }

    #[test]
    fn potential_sensitive_data_is_displayed_as_high_without_changing_machine_severity() {
        let finding = make(Evidence::SensitiveDataExposure {
            url: "https://x/config".into(),
            data_type: "api key".into(),
        });
        assert_eq!(crate::severity(&finding), "Critical");
        let out = to_html(std::slice::from_ref(&finding));
        assert!(out.contains("<b>1</b>High"));
        assert!(out.contains("class=\"severity-chip sev-high\">High</span>"));
        assert!(out.contains("SensitiveDataExposure (needs verification)"));
        assert!(out.contains("Some findings are based on passive observation"));
        assert!(!out.contains("[CRITICAL] SensitiveDataExposure"));
    }

    #[test]
    fn attacker_controlled_details_are_escaped() {
        let f = make(Evidence::UnauthenticatedRead {
            endpoint: "https://x/<script>alert(1)</script>".into(),
            row_sample: "{id=<int>}".into(),
        });
        let out = to_html(std::slice::from_ref(&f));
        assert!(!out.contains("<script>alert(1)</script>"));
        assert!(out.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn context_populates_follow_up_coverage_and_scan_status() {
        let finding = make(Evidence::SecurityMisconfiguration {
            url: "https://x/".into(),
            issue: "missing_csp".into(),
            severity: "Low".into(),
        });
        let summary = crate::summarize(std::slice::from_ref(&finding));
        let tested = vec![
            "Pages: 4".to_string(),
            "Forms: https://x/submit".to_string(),
            "APIs: https://x/graphql".to_string(),
        ];
        let context = HtmlContext {
            summary: &summary,
            incomplete_coverage: true,
            has_findings: true,
            tested_segments: &tested,
            auth_required: 2,
            timed_out: 1,
        };
        let out = to_html_with_context(std::slice::from_ref(&finding), &context);
        assert!(out.contains(
            "<div class=\"check-block\"><div class=\"check-label\">Missing security headers (1)</div><div class=\"check-effect\">Browsers have fewer defenses against some attacks. Easy to fix.</div></div>"
        ));
        assert!(
            out.contains("<p>Pages: 4  |  Forms: https://x/submit  |  APIs: https://x/graphql</p>")
        );
        assert!(out.contains("<h2>ABOUT THIS SCAN</h2>"));
        assert!(out.contains("Scan status: FINDINGS (partial coverage)"));
        assert!(out.contains("Some pages were blocked by the site's firewall, required a login, or timed out and could not be tested."));
        assert!(out.contains("Some pages require a login and were skipped."));
        assert!(out.contains("1 URL timed out"));
        // The legacy top status block is suppressed: status appears once.
        assert_eq!(out.matches("Scan status:").count(), 1);

        for (incomplete_coverage, has_findings, expected) in [
            (false, true, "FINDINGS"),
            (false, false, "NO FINDINGS"),
            (true, true, "FINDINGS (partial coverage)"),
            (true, false, "NO FINDINGS (partial coverage)"),
        ] {
            let context = HtmlContext {
                summary: &summary,
                incomplete_coverage,
                has_findings,
                tested_segments: &tested,
                auth_required: 0,
                timed_out: 0,
            };
            let rendered = if has_findings {
                to_html_with_context(std::slice::from_ref(&finding), &context)
            } else {
                to_html_with_context(&[], &context)
            };
            assert!(rendered.contains(&format!("Scan status: {expected}")));
            assert_eq!(
                rendered.contains("Some pages were blocked by the site's firewall, required a login, or timed out and could not be tested."),
                incomplete_coverage,
            );
        }
    }
}
