//! Final scan output, assembled from the run's findings and coverage ledger.

use crate::ui::theme::{aggregation, failure, scanning, term_width};
use riftlock_core::{
    Confidence, DiscoveredEndpoint, EndpointOutcome, EndpointRecord, Evidence, Finding,
};
use riftlock_report::{is_urgent_finding, plain_title, summarize, ScanCoverage};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// Inputs for the terminal's final report.
pub struct FinalReport<'a> {
    pub target: &'a str,
    pub mode: &'a str,
    pub elapsed: Duration,
    pub findings: &'a [Finding],
    pub records: &'a [EndpointRecord],
    pub unreached: &'a [String],
    pub methods: &'a [DiscoveredEndpoint],
    pub coverage: &'a ScanCoverage,
    /// Whether the authoritative run verdict marked coverage incomplete.
    pub incomplete_coverage: bool,
    /// Whether the authoritative run verdict counted any findings.
    pub has_findings: bool,
    pub discovered: usize,
}

/// Render the complete end-of-scan summary without writing to stdout.
#[must_use]
pub fn render_final_report(report: &FinalReport<'_>) -> Vec<String> {
    let width = term_width().clamp(40, 80);
    let heavy_rule = "=".repeat(width);
    let light_rule = "-".repeat(width);
    let summary = summarize(report.findings);
    let mut urgent: BTreeMap<String, (String, BTreeSet<String>, BTreeSet<String>)> =
        BTreeMap::new();
    for finding in report.findings {
        if !is_urgent_finding(finding) {
            continue;
        }
        let passive_sensitive_data = matches!(finding.confidence(), Confidence::Potential)
            && matches!(finding.evidence(), Evidence::SensitiveDataExposure { .. });
        let (variant, body) = evidence_parts(finding.evidence());
        let mut title = plain_title(&variant);
        if passive_sensitive_data {
            title = format!("[HIGH] {title} (needs verification)");
        }
        let reference = evidence_reference(&body)
            .map(|value| full_url(report.target, value))
            .unwrap_or_else(|| full_url(report.target, "/"));
        let group = urgent
            .entry(title)
            .or_insert_with(|| (variant.clone(), BTreeSet::new(), BTreeSet::new()));
        group.1.insert(variant);
        group.2.insert(reference);
    }

    let urgent_count = urgent.len();
    let urgent_finding_count = summary.urgent_count;
    let minor_count = summary.minor_count;
    let has_potential = summary.has_potential;
    let mut lines = vec![
        heavy_rule.clone(),
        aggregation("RIFTLOCK SCAN RESULT"),
        format!("Target:  {}", report.target),
        format!("Mode:    {}", report.mode),
        format!("Time:    {}s", report.elapsed.as_secs()),
        heavy_rule.clone(),
    ];

    if urgent_count > 0 {
        let (problem_label, verb) = if summary.urgent_group_count == 1 {
            ("PROBLEM", "NEEDS")
        } else {
            ("PROBLEMS", "NEED")
        };
        lines.push(failure(&format!(
            "[!] YOUR SITE HAS {} {problem_label} THAT {verb} FIXING ({urgent_finding_count} findings).",
            summary.urgent_group_count
        )));
    } else if minor_count > 0 {
        lines.push(aggregation(&format!(
            "NO URGENT ISSUES - {minor_count} minor items to review."
        )));
    } else {
        lines.push(aggregation("YOUR SITE LOOKS CLEAN - no issues found."));
    }
    lines.push("Everything else below is informational. Scroll to the bottom if you".into());
    lines.push("want the full list of what we tested.".into());

    heading(
        &mut lines,
        &format!("[!!] FIX THESE FIRST ({urgent_count} issues, {urgent_finding_count} findings)"),
        &light_rule,
    );
    if urgent.is_empty() {
        lines.push("(none)".into());
    } else {
        for (index, (title, (variant, _, urls))) in urgent.iter().enumerate() {
            lines.push(format!("-- PROBLEM {} of {} --", index + 1, urgent_count));
            lines.push(format!("Issue: {title}"));
            let (meaning, impact, action) = plain_details(variant);
            lines.push("What this means".into());
            lines.extend(wrap_words(meaning, width));
            lines.push("Why it matters".into());
            lines.extend(wrap_words(impact, width));
            lines.push("What to do".into());
            lines.extend(wrap_words(action, width));
            lines.push("Where".into());
            lines.extend(urls.iter().map(|url| format!("  {url}")));
            lines.push(String::new());
        }
        if lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
    }

    let minor_count_label = if minor_count == 1 {
        "1 thing".to_owned()
    } else {
        format!("{minor_count} items")
    };
    heading(
        &mut lines,
        &format!("[--] CHECK WHEN YOU CAN ({minor_count_label})"),
        &light_rule,
    );
    lines.push("These are non-urgent. Review when you have time.".into());
    if summary.follow_up.is_empty() {
        lines.push("(none)".into());
    } else {
        for group in &summary.follow_up {
            lines.push(format!("- {} ({})", group.label, group.count));
            lines.extend(wrap_words(&format!("  Effect: {}", group.effect), width));
        }
    }

    heading(
        &mut lines,
        "[+] WE ALSO TESTED (no problems found)",
        &light_rule,
    );
    lines.extend(wrap_words(&tested_segments(report).join("  |  "), width));
    lines.push("Full URL list is in the HTML report.".into());

    heading(&mut lines, "ABOUT THIS SCAN", &light_rule);
    let scan_status = if report.incomplete_coverage {
        if report.has_findings {
            "FINDINGS (partial coverage)"
        } else {
            "NO FINDINGS (partial coverage)"
        }
    } else if report.has_findings {
        "FINDINGS"
    } else {
        "NO FINDINGS"
    };
    lines.push(format!("Scan status: {}", scanning(scan_status)));
    if report.incomplete_coverage {
        lines.push("Some pages were blocked by the site's firewall, required a login, or timed out and could not be tested.".into());
    }
    if has_potential {
        lines.push(
            "Some findings are based on passive observation and may need manual verification."
                .into(),
        );
    }
    lines.push("- Urgent items are tied to evidence observed during this scan.".into());
    let auth_required = report.coverage.endpoints_auth_required;
    if auth_required > 0 {
        lines.push("- Some pages require a login and were skipped.".into());
    }
    let timed_out = report.coverage.endpoints_timed_out;
    let timed_out_text = if timed_out == 1 {
        "1 URL timed out".to_owned()
    } else {
        format!("{timed_out} URLs timed out")
    };
    lines.push(format!(
        "- {timed_out_text} (see HTML report for the list)."
    ));

    lines.push(heavy_rule);
    lines
}

/// Coverage summary segments ("Pages: N", "Forms: ...", "APIs: ...") shared
/// with the HTML report so both renderers describe the same tested surface.
#[must_use]
pub fn tested_segments(report: &FinalReport<'_>) -> Vec<String> {
    let method_map = methods_by_path(report.methods);
    let inventory = endpoint_inventory(report, &method_map);
    let pages = inventory
        .iter()
        .filter(|entry| category(entry) == 0)
        .count();
    let forms: BTreeSet<_> = inventory
        .iter()
        .filter(|entry| category(entry) == 1)
        .map(|entry| full_url(report.target, &entry.path))
        .collect();
    let apis: BTreeSet<_> = inventory
        .iter()
        .filter(|entry| category(entry) == 3)
        .map(|entry| full_url(report.target, &entry.path))
        .collect();
    let mut segments = vec![format!("Pages: {}", report.discovered.max(pages))];
    if !forms.is_empty() {
        segments.push(format!("Forms: {}", display_list(&forms)));
    }
    if !apis.is_empty() {
        segments.push(format!("APIs: {}", display_list(&apis)));
    }
    segments
}

fn heading(lines: &mut Vec<String>, title: &str, rule: &str) {
    lines.push(rule.to_owned());
    lines.push(aggregation(title));
    lines.push(rule.to_owned());
}

fn plain_details(variant: &str) -> (&'static str, &'static str, &'static str) {
    match variant {
        "SqliError" | "SqliTimeDelay" | "SqlInjection" => (
            "The site uses visitor input in a database request without safely separating it.",
            "Someone could view, change, or delete customer information.",
            "Ask your developer to use parameterized database queries.",
        ),
        "SensitivePathDisclosed" | "SourceDisclosure" => (
            "A private site file can be opened by visitors.",
            "The file may reveal code or details that help someone break into the site.",
            "Ask your host to block access to private files and remove them from public folders.",
        ),
        "UnauthenticatedRead" | "BrokenAccessControl" => (
            "The site shows private information without checking who is asking.",
            "Visitors may see another person's records or account details.",
            "Ask your developer to require a login and check access to each person's records.",
        ),
        "LeakedSecret" => (
            "A password or other site credential is visible on the site.",
            "Anyone who finds it could use it to access your services.",
            "Ask your developer to remove the credential and replace it with a new one.",
        ),
        "SsrF" => (
            "The site can be tricked into opening a web address supplied by a visitor.",
            "Someone could use this to reach private services connected to your site.",
            "Ask your developer to allow only approved destinations when the site fetches a URL.",
        ),
        "XssReflection" | "ReflectedXss" | "DomXssTaint" => (
            "Text supplied by a visitor can run as code in another visitor's browser.",
            "It could let someone steal a visitor's session or act as them.",
            "Ask your developer to safely display visitor text instead of treating it as code.",
        ),
        "CsrfMissingToken" => (
            "A signed-in visitor's browser can submit a change without checking that they meant to.",
            "Someone could trick a visitor into changing account details or making a purchase.",
            "Ask your developer to add a per-session confirmation token to forms that make changes.",
        ),
        "SstiReflection" => (
            "The site may treat visitor text as instructions for its page-building system.",
            "Someone could make the server expose files or run unwanted actions.",
            "Ask your developer to keep visitor text separate from page instructions.",
        ),
        "LfiRead" => (
            "A visitor may choose which file the site opens.",
            "Someone could read private settings or credentials stored on the server.",
            "Ask your developer to limit file access to an approved list of files.",
        ),
        "CommandInjection" => (
            "The site may pass visitor text to a command running on its server.",
            "Someone could make the server perform unwanted actions.",
            "Ask your developer not to run system commands using visitor-supplied text.",
        ),
        "StorageLeak" => (
            "Files stored for the site can be opened by the public.",
            "Private customer or business files could be downloaded by anyone.",
            "Ask your host to turn off public access to the storage bucket.",
        ),
        "AuthBypass" => (
            "The site may let someone sign in without valid credentials.",
            "An attacker could take over another person's account.",
            "Ask your developer to verify login details on the server before creating a session.",
        ),
        "Idor" | "IdorProof" => (
            "Changing a record number may show someone else's information.",
            "Private customer or account records could be viewed or changed.",
            "Ask your developer to check that each person owns the record they request.",
        ),
        "WriteProof" | "BusinessLogicBypass" | "MassAssignment" => (
            "The site accepted a change that should have been blocked.",
            "Someone could change records, prices, or account privileges without permission.",
            "Ask your developer to check permissions and allowed changes on the server.",
        ),
        "SensitiveDataExposure" | "CloudExposure" => (
            "Private files or customer information can be reached from the site.",
            "People who should not have access could download sensitive information.",
            "Ask your host to make the affected files private and review who can access them.",
        ),
        "HttpSmuggling" => (
            "The front end and server may disagree about where a web request ends.",
            "Someone could slip a request past security checks.",
            "Ask your host to reject unclear requests and keep request handling consistent.",
        ),
        "GrpcExposed" | "FunctionExposed" => (
            "A site service is responding to requests that should be restricted.",
            "Visitors may read information or trigger actions through that service.",
            "Ask your developer to require access checks for this service.",
        ),
        "CacheDeception" => (
            "The site may save a private page where it can be shown to others.",
            "Another visitor could see account or customer information.",
            "Ask your developer to mark signed-in pages as private so they are not shared by caches.",
        ),
        "OpenRedirect" => (
            "A link on the site can send visitors to a web address chosen by someone else.",
            "Scammers could use the trusted site address to disguise a harmful link.",
            "Ask your developer to allow redirects only to trusted destinations.",
        ),
        "JwtVulnerability" => (
            "The site may accept a sign-in token without checking it safely.",
            "Someone could pretend to be another user.",
            "Ask your developer to verify every sign-in token before accepting it.",
        ),
        _ => (
            "The scan found a security problem in how the site handles a request.",
            "Someone may use it to access information or take actions they should not be able to.",
            "Ask your developer to review this issue and make the affected request safe.",
        ),
    }
}

fn display_list(items: &BTreeSet<String>) -> String {
    if items.is_empty() {
        "none found".into()
    } else {
        items.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

fn evidence_parts(evidence: &Evidence) -> (String, Value) {
    serde_json::to_value(evidence)
        .ok()
        .and_then(|v| {
            v.as_object()
                .and_then(|o| o.iter().next().map(|(k, v)| (k.clone(), v.clone())))
        })
        .unwrap_or_else(|| ("Evidence".into(), Value::Null))
}

fn evidence_reference(body: &Value) -> Option<&str> {
    ["url", "endpoint", "path", "location", "manifest"]
        .iter()
        .find_map(|key| body.get(*key).and_then(Value::as_str))
}

/// Absolute URL for display: join relative references onto the scan target.
fn full_url(target: &str, reference: &str) -> String {
    url::Url::parse(target).map_or_else(
        |_| reference.to_owned(),
        |base| {
            base.join(reference)
                .map_or_else(|_| reference.to_owned(), |joined| joined.to_string())
        },
    )
}

#[derive(Clone)]
struct EndpointLine {
    method: String,
    path: String,
    auth: bool,
    reason: Option<(&'static str, &'static str)>,
}

fn methods_by_path(methods: &[DiscoveredEndpoint]) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for item in methods {
        let path = endpoint_path(&item.path);
        let method = item.method.to_uppercase();
        if result.get(&path).is_none_or(|old| old == "GET") {
            result.insert(path, method);
        }
    }
    result
}

fn endpoint_inventory(
    report: &FinalReport<'_>,
    methods: &BTreeMap<String, String>,
) -> Vec<EndpointLine> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for record in report.records {
        let path = endpoint_path(&record.url);
        if !seen.insert(path.clone()) || record.outcome == EndpointOutcome::Skipped {
            continue;
        }
        let reason = match record.outcome {
            EndpointOutcome::TimedOut => Some(("timed out", "retry --timeout 30")),
            EndpointOutcome::Failed => Some(("failed", "network error")),
            EndpointOutcome::CircuitOpen => Some(("circuit open", "retry")),
            EndpointOutcome::WafBlocked => Some(("WAF blocked", "retry later")),
            _ => None,
        };
        out.push(EndpointLine {
            method: methods.get(&path).cloned().unwrap_or_else(|| "GET".into()),
            path,
            auth: record.outcome == EndpointOutcome::AuthRequired,
            reason,
        });
    }
    for url in report.unreached {
        let path = endpoint_path(url);
        if seen.insert(path.clone()) {
            out.push(EndpointLine {
                method: methods.get(&path).cloned().unwrap_or_else(|| "GET".into()),
                path,
                auth: false,
                reason: Some(("not reached", "engine budget ended")),
            });
        }
    }
    out
}

fn category(entry: &EndpointLine) -> usize {
    if entry.reason.is_some() {
        return 5;
    }
    if entry.method == "POST" {
        return 1;
    }
    let p = entry.path.to_ascii_lowercase();
    if entry.auth
        || ["/admin", "/login", "/dashboard", "/api/private", "/account"]
            .iter()
            .any(|s| p.contains(s))
    {
        return 2;
    }
    let path = p.split('?').next().unwrap_or(&p);
    let ext = path
        .rsplit('/')
        .next()
        .unwrap_or("")
        .rsplit_once('.')
        .map(|(_, e)| e)
        .unwrap_or("");
    if [
        "js", "mjs", "css", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2",
        "ttf", "otf", "eot",
    ]
    .contains(&ext)
    {
        return 4;
    }
    if (entry.method != "GET" && entry.method != "HEAD")
        || ["/api/", "/graphql", ".json"]
            .iter()
            .any(|s| path.contains(s))
    {
        return 3;
    }
    0
}

fn endpoint_path(url: &str) -> String {
    url::Url::parse(url).map_or_else(
        |_| url.to_owned(),
        |parsed| {
            let mut path = parsed.path().to_owned();
            if let Some(query) = parsed.query() {
                path.push('?');
                path.push_str(query);
            }
            if path.is_empty() {
                "/".into()
            } else {
                path
            }
        },
    )
}

fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + word.len() + 1 > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::{severity_of, ProofGate, Severity, SourceKind};
    use riftlock_report::{follow_up_effect, follow_up_title};

    fn render_for(findings: &[Finding]) -> Vec<String> {
        render_for_with_verdict(
            findings,
            &ScanCoverage::default(),
            false,
            !findings.is_empty(),
        )
    }

    fn render_for_with_coverage(
        findings: &[Finding],
        coverage: &ScanCoverage,
        incomplete_coverage: bool,
    ) -> Vec<String> {
        render_for_with_verdict(
            findings,
            coverage,
            incomplete_coverage,
            !findings.is_empty(),
        )
    }

    fn render_for_with_verdict(
        findings: &[Finding],
        coverage: &ScanCoverage,
        incomplete_coverage: bool,
        has_findings: bool,
    ) -> Vec<String> {
        let report = FinalReport {
            target: "https://example.test/",
            mode: "standard",
            elapsed: Duration::ZERO,
            findings,
            records: &[],
            unreached: &[],
            methods: &[],
            coverage,
            incomplete_coverage,
            has_findings,
            discovered: 0,
        };
        render_final_report(&report)
    }

    #[test]
    fn report_headers_match_severity_tiers() {
        let redirect = ProofGate::admit(Evidence::OpenRedirect {
            url: "https://example.test/redirect".into(),
            param: "next".into(),
        })
        .expect("redirect evidence admitted");
        let redirect_report = render_for(&[redirect]);
        assert!(redirect_report
            .iter()
            .any(|line| line.contains("[!!] FIX THESE FIRST (1 issues, 1 findings)")));
        assert!(redirect_report.iter().any(
            |line| line.contains("[!] YOUR SITE HAS 1 PROBLEM THAT NEEDS FIXING (1 findings).")
        ));
        assert!(redirect_report
            .iter()
            .any(|line| line.contains("[+] WE ALSO TESTED (no problems found)")));
        assert!(redirect_report
            .iter()
            .any(|line| line.contains("[--] CHECK WHEN YOU CAN (0 items)")));
        assert!(redirect_report
            .iter()
            .any(|line| line.contains("Scan status: FINDINGS")));
        assert!(!redirect_report
            .iter()
            .any(|line| line.contains("(partial coverage)")));
        assert!(!redirect_report.iter().any(|line| line.contains(
            "Some pages were blocked by the site's firewall, required a login, or timed out and could not be tested."
        )));

        let minor = ProofGate::admit(Evidence::CsrfMissingToken {
            url: "https://example.test/form".into(),
            form_action: "/submit".into(),
        })
        .expect("minor evidence admitted");
        let minor_report = render_for(&[minor]);
        assert!(minor_report
            .iter()
            .any(|line| line.contains("NO URGENT ISSUES - 1 minor items to review.")));
        assert!(minor_report
            .iter()
            .any(|line| line.contains("Scan status: FINDINGS")));
        assert!(minor_report
            .iter()
            .any(|line| line.contains("[--] CHECK WHEN YOU CAN (1 thing)")));
        assert!(minor_report
            .iter()
            .any(|line| line.contains("These are non-urgent. Review when you have time.")));

        let mut misconfig_findings = Vec::new();
        for index in 0..6 {
            misconfig_findings.push(
                ProofGate::admit(Evidence::SecurityMisconfiguration {
                    url: format!("https://example.test/{index}"),
                    issue: if index % 2 == 0 {
                        "missing_csp"
                    } else {
                        "missing_hsts"
                    }
                    .into(),
                    severity: "Low".into(),
                })
                .expect("misconfiguration evidence admitted"),
            );
        }
        let misconfig_report = render_for(&misconfig_findings);
        assert!(misconfig_report
            .iter()
            .any(|line| line.contains("[--] CHECK WHEN YOU CAN (6 items)")));
        assert!(misconfig_report
            .iter()
            .any(|line| line.contains("- Missing security headers (6)")));
        assert!(misconfig_report.iter().any(|line| {
            line.contains("Effect: Browsers have fewer defenses against some attacks. Easy to fix.")
        }));

        let form_record = EndpointRecord {
            url: "https://example.test/submit".into(),
            outcome: EndpointOutcome::Tested,
        };
        let api_record = EndpointRecord {
            url: "https://example.test/graphql".into(),
            outcome: EndpointOutcome::Tested,
        };
        let inventory_report = FinalReport {
            target: "https://example.test/",
            mode: "standard",
            elapsed: Duration::ZERO,
            findings: &[],
            records: &[form_record, api_record],
            unreached: &[],
            methods: &[
                DiscoveredEndpoint {
                    path: "/submit".into(),
                    method: "POST".into(),
                },
                DiscoveredEndpoint {
                    path: "/graphql".into(),
                    method: "GET".into(),
                },
            ],
            coverage: &ScanCoverage::default(),
            incomplete_coverage: false,
            has_findings: false,
            discovered: 2,
        };
        let inventory_report = render_final_report(&inventory_report);
        let inventory_text = inventory_report.join(" ");
        assert!(inventory_text.contains("Forms: https://example.test/submit"));
        assert!(inventory_text.contains("APIs: https://example.test/graphql"));

        let mut coverage = ScanCoverage::default();
        coverage.endpoints_auth_required = 1;
        coverage.endpoints_timed_out = 1;
        let coverage_report = render_for_with_coverage(&[], &coverage, true);
        assert!(coverage_report
            .iter()
            .any(|line| line.contains("Some pages require a login and were skipped.")));
        assert!(coverage_report
            .iter()
            .any(|line| line.contains("1 URL timed out")));
        assert!(!coverage_report
            .iter()
            .any(|line| line.contains("--auth-token")));
        assert!(coverage_report.iter().any(|line| line.contains("Pages: 0")));
        assert!(!coverage_report.iter().any(|line| line.contains("Forms:")));
        assert!(!coverage_report.iter().any(|line| line.contains("APIs:")));
        coverage.endpoints_auth_required = 2;
        coverage.endpoints_timed_out = 20;
        let coverage_report = render_for_with_coverage(&[], &coverage, true);
        assert!(coverage_report
            .iter()
            .any(|line| line.contains("Some pages require a login and were skipped.")));
        assert!(coverage_report
            .iter()
            .any(|line| line.contains("20 URLs timed out")));

        let high = ProofGate::admit(Evidence::AuthBypass {
            endpoint: "https://example.test/login".into(),
            method: "POST".into(),
        })
        .expect("auth bypass evidence admitted");
        let high_report = render_for(&[high.clone()]);
        assert!(high_report.iter().any(
            |line| line.contains("[!] YOUR SITE HAS 1 PROBLEM THAT NEEDS FIXING (1 findings).")
        ));
        assert!(high_report
            .iter()
            .any(|line| line.contains("[!!] FIX THESE FIRST (1 issues, 1 findings)")));
        assert!(high_report
            .iter()
            .any(|line| line.contains("Scan status: FINDINGS")));

        let second_high = ProofGate::admit(Evidence::AuthBypass {
            endpoint: "https://example.test/admin".into(),
            method: "POST".into(),
        })
        .expect("second auth bypass evidence admitted");
        let plural_report = render_for(&[high.clone(), second_high]);
        assert!(plural_report.iter().any(|line| {
            line.contains("[!] YOUR SITE HAS 1 PROBLEM THAT NEEDS FIXING (2 findings).")
        }));
        assert!(plural_report
            .iter()
            .any(|line| line.contains("[!!] FIX THESE FIRST (1 issues, 2 findings)")));

        let clean_report = render_for(&[]);
        assert!(clean_report
            .iter()
            .any(|line| line.contains("YOUR SITE LOOKS CLEAN - no issues found.")));
        assert!(clean_report
            .iter()
            .any(|line| line.contains("Scan status: NO FINDINGS")));
        assert!(!clean_report.iter().any(|line| line.contains(
            "Some pages were blocked by the site's firewall, required a login, or timed out and could not be tested."
        )));

        let findings_partial = render_for_with_verdict(
            &[ProofGate::admit(Evidence::AuthBypass {
                endpoint: "https://example.test/login".into(),
                method: "POST".into(),
            })
            .expect("auth bypass evidence admitted")],
            &ScanCoverage::default(),
            true,
            true,
        );
        assert!(findings_partial
            .iter()
            .any(|line| { line.contains("Scan status: FINDINGS (partial coverage)") }));
        assert!(findings_partial.iter().any(|line| line.contains(
            "Some pages were blocked by the site's firewall, required a login, or timed out and could not be tested."
        )));

        let clean_partial = render_for_with_verdict(&[], &ScanCoverage::default(), true, false);
        assert!(clean_partial
            .iter()
            .any(|line| { line.contains("Scan status: NO FINDINGS (partial coverage)") }));
        assert!(clean_partial.iter().any(|line| line.contains(
            "Some pages were blocked by the site's firewall, required a login, or timed out and could not be tested."
        )));

        let ascii_report = clean_report.join("\n");
        assert!(
            ascii_report.is_ascii(),
            "report contains non-ASCII text: {ascii_report}"
        );
        assert!(ascii_report.contains("Pages: 0"));
        assert!(!ascii_report.contains("Forms:"));
        assert!(!ascii_report.contains("APIs:"));
    }

    #[test]
    fn problem_counts_distinguish_groups_from_findings() {
        let findings: Vec<_> = (0..3)
            .map(|index| {
                ProofGate::admit(Evidence::AuthBypass {
                    endpoint: format!("https://example.test/login/{index}"),
                    method: "POST".into(),
                })
                .expect("auth bypass evidence admitted")
            })
            .collect();
        let report = render_for(&findings).join("\n");

        assert!(report.contains("[!] YOUR SITE HAS 1 PROBLEM THAT NEEDS FIXING (3 findings)."));
        assert!(report.contains("[!!] FIX THESE FIRST (1 issues, 3 findings)"));
        assert!(report.contains("-- PROBLEM 1 of 1 --"));
        assert!(!report.contains("3 PROBLEMS"));
    }

    #[test]
    fn passive_sensitive_data_is_labeled_high_and_needs_verification() {
        let finding = ProofGate::admit(Evidence::SensitiveDataExposure {
            url: "https://example.test/config".into(),
            data_type: "api key".into(),
        })
        .expect("passive evidence admitted");
        assert_eq!(finding.confidence(), Confidence::Potential);
        let report = render_for(std::slice::from_ref(&finding)).join("\n");
        assert!(report.contains("[HIGH] Files are reachable without a login (needs verification)"));
        assert!(report.contains(
            "Some findings are based on passive observation and may need manual verification."
        ));
        assert!(!report.contains("[CRITICAL]"));
        assert_eq!(severity_of(finding.evidence()), Severity::Critical);
    }

    #[test]
    fn report_titles_use_cautious_access_labels() {
        assert_eq!(
            plain_title("SourceDisclosure"),
            "Files are reachable without a login"
        );
        assert_eq!(
            plain_title("SensitivePathDisclosed"),
            "Files are reachable without a login"
        );
        assert_eq!(
            plain_title("UnauthenticatedRead"),
            "Data can be read without a login"
        );
        assert_eq!(
            plain_title("SensitiveDataExposure"),
            "Files are reachable without a login"
        );
        assert_eq!(plain_title("UnknownEvidence"), "Configuration improvements");
    }

    #[test]
    fn grouped_finding_text_has_plain_meaning_impact_and_action() {
        for variant in ["SqliError", "XssReflection", "SsrF", "CsrfMissingToken"] {
            let (meaning, impact, action) = plain_details(variant);
            assert!(!meaning.is_empty());
            assert!(!impact.is_empty());
            assert!(action.starts_with("Ask your "), "{action}");
            assert!(!plain_title(variant).is_empty());
        }
        assert_eq!(plain_title("SqliError"), plain_title("SqlInjection"));
        assert_eq!(
            follow_up_effect("SecurityMisconfiguration"),
            "Some browser protections may be missing or weak."
        );
        assert_eq!(
            follow_up_title(
                &Evidence::SecurityMisconfiguration {
                    url: "https://example.test/".into(),
                    issue: "missing_csp".into(),
                    severity: "Low".into(),
                },
                "SecurityMisconfiguration",
            ),
            "Missing security headers"
        );
        assert_eq!(
            follow_up_title(
                &Evidence::SecurityMisconfiguration {
                    url: "https://example.test/".into(),
                    issue: "cors_wildcard".into(),
                    severity: "Low".into(),
                },
                "SecurityMisconfiguration",
            ),
            "CORS allows too many origins"
        );
        assert_eq!(
            follow_up_title(
                &Evidence::SourceDisclosure {
                    url: "https://example.test/app.js.map".into(),
                    kind: SourceKind::SourceMap,
                },
                "SourceDisclosure",
            ),
            "Source code artifacts are public"
        );
        assert_eq!(
            follow_up_title(
                &Evidence::DnsMisconfiguration {
                    domain: "example.test".into(),
                    issue: "sitemap_routes".into(),
                },
                "DnsMisconfiguration",
            ),
            "Server details are publicly visible"
        );
    }

    #[test]
    fn full_url_keeps_absolute_and_joins_relative_references() {
        assert_eq!(
            full_url(
                "https://vulnerable-website.com/",
                "https://vulnerable-website.com/about"
            ),
            "https://vulnerable-website.com/about"
        );
        assert_eq!(
            full_url("https://vulnerable-website.com/", "/login?next=%2F"),
            "https://vulnerable-website.com/login?next=%2F"
        );
        assert_eq!(
            full_url("not a url", "/login"),
            "/login",
            "unparseable target keeps the reference as-is"
        );
    }

    #[test]
    fn groups_are_stable_and_word_wrap_does_not_split_tokens() {
        assert_eq!(
            wrap_words("Header issues (2): missing CSP, missing HSTS", 28),
            vec!["Header issues (2): missing", "CSP, missing HSTS"]
        );
        assert_eq!(plain_title("SqliError"), "Unsafe database queries");
    }
}
