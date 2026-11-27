//! Plain-text engine outcomes and final aggregation from real scan results.

use crate::ui::theme::{aggregation, muted, term_width, unicode_ok};
use riftlock_core::{
    severity_of, AccountingValidation, CrawlMetrics, DiscoveredEndpoint, EndpointOutcome,
    EndpointRecord, Finding, ScanVerdict, Severity,
};
use std::collections::HashSet;

/// Split findings the same way the finding list renders them: only
/// `Confidence::Confirmed` counts as confirmed; every other tier — including
/// verifier-supported `High` — is potential.
#[allow(dead_code)] // Retained for its classification tests and potential callers.
#[must_use]
pub fn finding_totals(findings: &[Finding]) -> (usize, usize) {
    findings.iter().fold((0, 0), |(confirmed, potential), f| {
        if f.confidence() == riftlock_core::Confidence::Confirmed {
            (confirmed + 1, potential)
        } else {
            (confirmed, potential + 1)
        }
    })
}
use std::time::Duration;

/// Task-owned counters for one engine. Derived from the engine's own fork,
/// never from differencing the run-wide ledger that concurrent engines share.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineStats {
    pub checks_completed: u64,
    pub checks_attempted: u64,
    pub endpoints_tested: u64,
    pub endpoints_planned: u64,
}

/// How one engine actually ended, as observed by the caller.
#[derive(Debug, Clone)]
pub enum EngineOutcome {
    /// The scanner completed with its measured duration and finding count.
    Done {
        elapsed: Duration,
        findings: usize,
        stats: EngineStats,
    },
    /// The scanner task panicked; its panic was caught and isolated.
    Panicked,
    /// The scanner did not complete, with its real reason.
    Skipped(String),
    /// The scanner failed without panicking, with its real error text.
    Failed(String),
}

/// The line printed when an engine is actually spawned. No target URLs here.
#[must_use]
pub fn started_line(id: &str, budget: Duration, endpoints_planned: usize) -> String {
    format!(
        "[>] {id} started (budget {}s, {endpoints_planned} endpoints planned)",
        budget.as_secs()
    )
}

/// One plain-text line for a completed engine, without terminal animation.
#[must_use]
pub fn outcome_line(id: &str, outcome: &EngineOutcome) -> String {
    match outcome {
        EngineOutcome::Done {
            elapsed,
            findings,
            stats,
            ..
        } => {
            let heading = aggregation(&format!("[+] {id} finished"));
            format!(
                "{heading} ({:.1}s) — findings: {findings}, checks: {}/{}, coverage: {}/{}",
                elapsed.as_secs_f64(),
                stats.checks_completed,
                stats.checks_attempted,
                stats.endpoints_tested,
                stats.endpoints_planned
            )
        }
        EngineOutcome::Panicked => format!("[x] {id} panicked — skipped"),
        EngineOutcome::Skipped(reason) => format!("[-] {id} skipped: {reason}"),
        EngineOutcome::Failed(reason) => format!("[x] {id} failed: {reason}"),
    }
}

/// Final status and the exact coverage snapshot used to derive it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunState {
    pub status: RunStatus,
    /// Findings and coverage reconciled into one honest, shared label.
    pub verdict: ScanVerdict,
    pub coverage: riftlock_report::ScanCoverage,
    /// Scan-boundary validation of the authoritative ledger.
    pub accounting: AccountingValidation,
    /// Executions that produced findings without registering ledger checks.
    pub unaccounted_executions: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Clean,
    Incomplete,
    Findings,
}

impl RunStatus {
    // Kept for callers that still want the coarse tier; the combined verdict
    // label is the one reports and summaries use.
    #[allow(dead_code)]
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Clean => "CLEAN",
            Self::Incomplete => "INCOMPLETE",
            Self::Findings => "FINDINGS",
        }
    }
}

/// Check failures tolerated before coverage is called incomplete. Four failed
/// checks out of 649 is a 99% pass rate, not a blocked scan.
pub(crate) const CHECK_FAILURE_TOLERANCE_PERCENT: u64 = 15;
/// Untested endpoints (auth walls, WAF blocks, failures, timeouts and
/// circuit-open probes) tolerated before coverage is called incomplete, as a
/// percentage of assessed endpoints (tested plus those untested outcomes).
/// Confirmed-absent skips never enter either side of this ratio. A handful of
/// dead endpoints in a large scan is normal; a cluster above this share is a
/// blocked run.
pub(crate) const ENDPOINT_FAILURE_TOLERANCE_PERCENT: u64 = 15;

impl RunState {
    #[allow(dead_code)] // kept as the simple constructor for tests and library use
    #[must_use]
    /// `failures` counts failed scan stages: engine failures plus a failed
    /// discovery, whose missing inventory leaves coverage unknown.
    pub fn new(findings: usize, failures: usize, coverage: riftlock_report::ScanCoverage) -> Self {
        Self::with_accounting(
            findings,
            failures,
            coverage,
            AccountingValidation {
                registered: coverage.vulnerability_checks_attempted,
                terminal: coverage.vulnerability_checks_attempted,
                in_flight: 0,
                duplicates_rejected: 0,
            },
            0,
        )
    }

    /// Construct with the real scan-boundary validation result.
    #[must_use]
    pub fn with_accounting(
        findings: usize,
        failures: usize,
        coverage: riftlock_report::ScanCoverage,
        accounting: AccountingValidation,
        unaccounted_executions: u64,
    ) -> Self {
        // A few blocked or failed endpoints do not invalidate the rest of the
        // run: coverage is incomplete only when nothing was tested, more than
        // 15% of the assessed endpoints were untested, or endpoints the
        // scanner never classified remain. Check failures are tolerated up to
        // 15% — four failed checks out of 649 is a 99% pass rate, not an
        // incomplete scan.
        // Engine failures, discovery/crawl failures and unbalanced accounting
        // remain independent incomplete causes below.
        //
        // 404/410 probes are confirmed absences (checked negatives), not
        // untested surface: skipped endpoints are excluded from both the
        // untested numerator and its denominator. WAF blocks, transport
        // failures, timeouts and circuit-open probes count as untested. Auth
        // walls are classified, but excluded from the failure ratio.
        let untested = coverage.endpoints_timed_out
            + coverage.endpoints_failed
            + coverage.endpoints_waf_blocked
            + coverage.endpoints_circuit_open;
        let nothing_assessed = coverage.endpoints_discovered == 0
            && coverage.vulnerability_checks_attempted == 0
            && coverage.vulnerability_checks_completed == 0;
        let tested_denominator = coverage
            .endpoints_tested_successfully
            .saturating_add(untested);
        let untested_share_exceeded = untested.saturating_mul(100)
            > tested_denominator.saturating_mul(ENDPOINT_FAILURE_TOLERANCE_PERCENT);
        // Auth-required, skipped and all untested outcomes are classified.
        let classified = tested_denominator
            .saturating_add(coverage.endpoints_skipped)
            .saturating_add(coverage.endpoints_auth_required);
        let endpoint_coverage_incomplete = nothing_assessed
            || (coverage.endpoints_discovered > 0
                && (coverage.endpoints_tested_successfully == 0
                    || untested_share_exceeded
                    || classified < coverage.endpoints_discovered));
        let non_completed_checks = coverage
            .vulnerability_checks_attempted
            .saturating_sub(coverage.vulnerability_checks_completed);
        let check_coverage_incomplete = coverage.vulnerability_checks_attempted > 0
            && non_completed_checks.saturating_mul(100)
                > coverage
                    .vulnerability_checks_attempted
                    .saturating_mul(CHECK_FAILURE_TOLERANCE_PERCENT);
        let uncertain_coverage = failures > 0
            || !accounting.reconciles()
            || unaccounted_executions > 0
            || endpoint_coverage_incomplete
            || check_coverage_incomplete
            // Passive observations are never completed active checks. A run
            // whose only evidence is passive has not actively assessed the
            // target, so its coverage cannot be called complete.
            || (coverage.passive_observations > 0
                && coverage.vulnerability_checks_attempted == 0);
        let verdict = ScanVerdict {
            findings: findings as u64,
            passive_observations: coverage.passive_observations,
            completed_checks: coverage.vulnerability_checks_completed,
            inconclusive_checks: coverage.vulnerability_checks_inconclusive,
            failed_checks: coverage.checks_failed,
            skipped_checks: coverage.checks_skipped,
            coverage_complete: !uncertain_coverage,
        };
        // `status` is kept for compatibility; the combined label lives on
        // `verdict` so findings and incomplete coverage are both visible.
        let status = if verdict.findings > 0 {
            RunStatus::Findings
        } else if !verdict.coverage_complete {
            RunStatus::Incomplete
        } else {
            RunStatus::Clean
        };
        Self {
            status,
            verdict,
            coverage,
            accounting,
            unaccounted_executions,
        }
    }

    /// The single status string shared by the terminal and every report.
    #[must_use]
    pub fn status_label(&self) -> &'static str {
        self.verdict.label()
    }
}

/// The real totals of a finished scan run, supplied after aggregation.
#[allow(dead_code)] // Retained for legacy report-rendering tests.
#[derive(Debug, Clone)]
pub struct AggregationReport {
    /// Scanners spawned in this run.
    pub engines_executed: usize,
    /// Scanners that panicked or failed.
    pub engines_failed: usize,
    /// Engines that completed with zero findings.
    pub engines_clean: usize,
    /// Discovery stage outcome (`complete`, `partial — <error>`,
    /// `failed — target root only`, `skipped (passive)`).
    pub discovery: String,
    /// Discovered endpoint inventory size.
    pub endpoints_discovered: usize,
    /// Generic scanner's planned endpoint denominator, before exclusions.
    pub generic_planned_endpoints: usize,
    /// Findings with hard evidence or verifier support.
    pub confirmed_findings: usize,
    /// Plausible findings without independent verification.
    pub potential_findings: usize,
    /// Attack chains the aggregation step built.
    pub chains: usize,
    /// Human-readable critical/high endpoint groups derived from findings.
    pub vulnerable_pages: Vec<String>,
    /// One outcome derived from the same coverage shown below.
    pub state: RunState,
    /// Total wall-clock time of the run.
    pub elapsed: Duration,
}

/// Format the final analysis using only the caller's measured counts.
#[allow(dead_code)] // Retained for legacy report-rendering tests.
#[must_use]
pub fn render_final(report: &AggregationReport) -> Vec<String> {
    let mut out = report.vulnerable_pages.clone();
    out.extend([aggregation("FINAL ANALYSIS"), green_separator()]);
    if report.state.coverage.endpoints_auth_required > 0 {
        out.push(format!(
            "{} endpoints required authentication — rerun with --auth-token <token> for full coverage",
            report.state.coverage.endpoints_auth_required
        ));
    }
    let rows = [
        ("status", report.state.status_label().to_owned()),
        ("engines executed", report.engines_executed.to_string()),
        ("engines failed", report.engines_failed.to_string()),
        (
            "engines completed cleanly",
            report.engines_clean.to_string(),
        ),
        ("discovery", report.discovery.clone()),
        (
            "discovered inventory endpoints",
            report.endpoints_discovered.to_string(),
        ),
        (
            "Generic planned endpoints",
            report.generic_planned_endpoints.to_string(),
        ),
        ("confirmed findings:", report.confirmed_findings.to_string()),
        ("potential findings:", report.potential_findings.to_string()),
        ("attack chains", report.chains.to_string()),
        {
            let c = &report.state.coverage;
            // Every engine records into the same counters, while the Generic
            // plan covers only Generic's endpoints. Pair the tested count with
            // the population it actually came from, so the ratio can never
            // show more tested endpoints than the denominator.
            let classified = c.endpoints_tested_successfully
                + c.endpoints_skipped
                + c.endpoints_circuit_open
                + c.endpoints_auth_required
                + c.endpoints_waf_blocked
                + c.endpoints_failed
                + c.endpoints_timed_out;
            (
                "endpoints tested (of classified)",
                format!("{}/{}", c.endpoints_tested_successfully, classified),
            )
        },
        {
            let c = &report.state.coverage;
            (
                "endpoints untested (skipped/auth/blocked/failed/timed out/circuit-open)",
                format!(
                    "{}/{}/{}/{}/{}/{}",
                    c.endpoints_skipped,
                    c.endpoints_auth_required,
                    c.endpoints_waf_blocked,
                    c.endpoints_failed,
                    c.endpoints_timed_out,
                    c.endpoints_circuit_open
                ),
            )
        },
        {
            let c = &report.state.coverage;
            (
                "checks attempted (completed/inconclusive/failed/timed out/cancelled)",
                format!(
                    "{} ({} completed, {} inconclusive, {} failed, {} timed out, {} cancelled)",
                    c.vulnerability_checks_attempted,
                    c.vulnerability_checks_completed,
                    c.vulnerability_checks_inconclusive,
                    c.checks_failed,
                    c.checks_timed_out,
                    c.checks_cancelled
                ),
            )
        },
        (
            "passive observations (not checks)",
            report.state.verdict.passive_observations.to_string(),
        ),
        (
            "check accounting reconciles",
            if report.state.coverage.check_accounting_invariant()
                && report.state.accounting.reconciles()
            {
                "yes"
            } else {
                "NO"
            }
            .to_owned(),
        ),
        (
            "ledger registered/terminal/in-flight",
            format!(
                "{}/{}/{}",
                report.state.accounting.registered,
                report.state.accounting.terminal,
                report.state.accounting.in_flight
            ),
        ),
        (
            "unaccounted executions",
            report.state.unaccounted_executions.to_string(),
        ),
        (
            "failed checks / checks skipped",
            format!(
                "{}/{}",
                report.state.verdict.failed_checks, report.state.verdict.skipped_checks
            ),
        ),
        (
            "coverage",
            if report.state.verdict.coverage_complete {
                "complete"
            } else {
                "INCOMPLETE"
            }
            .to_owned(),
        ),
        (
            "total elapsed",
            format!("{:.1}s", report.elapsed.as_secs_f64()),
        ),
    ];
    for (label, value) in rows {
        out.push(format!("  {}  {}", muted(&format!("{label:<26}")), value));
    }
    out
}

#[allow(dead_code)] // Used by the retained legacy final renderer.
fn green_separator() -> String {
    let w = term_width().min(72);
    let line = if unicode_ok() {
        "─".repeat(w)
    } else {
        "-".repeat(w)
    };
    aggregation(&line)
}

/// Print the in-memory discovery inventory without issuing any requests.
#[must_use]
pub fn print_attack_surface(
    mode: &str,
    endpoints: &[String],
    _methods: &[DiscoveredEndpoint],
    discovered_urls: &[String],
    _actions: &[String],
    _rpc: &[String],
    crawl: &CrawlMetrics,
) -> Vec<String> {
    let mut lines = vec!["ATTACK SURFACE".to_owned()];
    lines.push(format!("  mode: {mode}"));
    lines.push(format!(
        "  probe classes: {}",
        match mode {
            "Godmode" => "reflection, error-based SQLi, boolean/time SQLi, LFI/SSTI/command injection, parameter mining, BOLA mutation, broad JSON fuzz, login bypass, form POST",
            "Read" => "reflection and error-based SQLi",
            "Normal" => "passive reconnaissance only",
            _ => "passive reconnaissance only",
        }
    ));
    lines.push(format!("  endpoints: {}", endpoints.len()));
    lines.push(format!("  discovered URLs: {}", discovered_urls.len()));
    lines.push(format!(
        "  crawl: {} pages, {} in-scope URLs, {} blocked, {} failed, {} timed out ({})",
        crawl.tested,
        crawl.unique_in_scope,
        crawl.blocked,
        crawl.failed,
        crawl.timed_out,
        if crawl.termination_reason.is_empty() {
            "not reported"
        } else {
            crawl.termination_reason.as_str()
        }
    ));
    lines
}

/// Print Critical and High vulnerable endpoints, grouped by authoritative
/// evidence severity. Endpoint strings are extracted from serialized evidence
/// so this renderer does not maintain a second evidence-variant classifier.
#[must_use]
pub fn print_vulnerable_pages(findings: &[Finding]) -> Vec<String> {
    let mut groups: [Vec<String>; 2] = [Vec::new(), Vec::new()];
    let mut seen: [HashSet<String>; 2] = [HashSet::new(), HashSet::new()];
    for finding in findings {
        let severity = severity_of(finding.evidence());
        let (group, seen) = match severity {
            Severity::Critical => (&mut groups[0], &mut seen[0]),
            Severity::High => (&mut groups[1], &mut seen[1]),
            _ => continue,
        };
        let Ok(value) = serde_json::to_value(finding.evidence()) else {
            continue;
        };
        let endpoint = ["endpoint", "url", "path", "location"]
            .iter()
            .find_map(|key| value.get(key).and_then(serde_json::Value::as_str));
        if let Some(endpoint) = endpoint {
            // A set for dedupe: a linear scan here is quadratic in findings.
            let endpoint = endpoint.to_owned();
            if seen.insert(endpoint.clone()) {
                group.push(endpoint);
            }
        }
    }
    let mut lines = Vec::new();
    for (label, endpoints) in [("CRITICAL", &groups[0]), ("HIGH", &groups[1])] {
        if endpoints.is_empty() {
            continue;
        }
        lines.push(format!("VULNERABLE PAGES — {label}"));
        lines.extend(endpoints.iter().map(|endpoint| format!("  - {endpoint}")));
    }
    lines
}

/// Endpoints shown per outcome group before the remainder is summarized.
#[allow(dead_code)] // Used by the retained legacy untested-surface renderer.
const UNTESTED_SAMPLE: usize = 3;

/// Render `UNTESTED SURFACE`: every classified endpoint the scan could not
/// verify and every planned endpoint the engine never reached, grouped by
/// outcome and reduced to its path. Returns no lines when both lists are
/// empty, so a complete scan is never padded.
#[allow(dead_code)] // Retained for legacy renderer tests.
#[must_use]
pub fn render_untested_surface(records: &[EndpointRecord], unreached: &[String]) -> Vec<String> {
    const GROUPS: &[(&str, &[EndpointOutcome])] = &[
        ("AUTH REQUIRED", &[EndpointOutcome::AuthRequired]),
        ("WAF BLOCKED", &[EndpointOutcome::WafBlocked]),
        ("TIMED OUT", &[EndpointOutcome::TimedOut]),
        ("CONNECTION FAILED", &[EndpointOutcome::Failed]),
        ("CIRCUIT BREAKER", &[EndpointOutcome::CircuitOpen]),
        ("SKIPPED / NOT APPLICABLE", &[EndpointOutcome::Skipped]),
    ];
    let mut body = Vec::new();
    // Planned endpoints with no ledger record were never probed: the engine
    // stopped first. A URL the ledger already classified is reported through
    // its outcome group instead of twice.
    let classified: HashSet<&str> = records.iter().map(|record| record.url.as_str()).collect();
    let unreached: Vec<&str> = unreached
        .iter()
        .map(String::as_str)
        .filter(|url| !classified.contains(*url))
        .collect();
    if !unreached.is_empty() {
        body.push(format!(
            "  [PLANNED BUT NOT REACHED] ({count} endpoint{})",
            if unreached.len() == 1 { "" } else { "s" },
            count = unreached.len()
        ));
        let shown = unreached.len().min(UNTESTED_SAMPLE);
        for (index, url) in unreached.iter().take(shown).enumerate() {
            let suffix = if index + 1 == shown && unreached.len() > shown {
                format!(" (+{} more)", unreached.len() - shown)
            } else {
                String::new()
            };
            body.push(format!("    - {}{suffix}", endpoint_path(url)));
        }
    }
    for (label, outcomes) in GROUPS {
        let group: Vec<&EndpointRecord> = records
            .iter()
            .filter(|record| outcomes.contains(&record.outcome))
            .collect();
        if group.is_empty() {
            continue;
        }
        body.push(format!(
            "  [{label}] ({count} endpoint{})",
            if group.len() == 1 { "" } else { "s" },
            count = group.len()
        ));
        let shown = group.len().min(UNTESTED_SAMPLE);
        for (index, record) in group.iter().take(shown).enumerate() {
            let suffix = if index + 1 == shown && group.len() > shown {
                format!(" (+{} more)", group.len() - shown)
            } else {
                String::new()
            };
            body.push(format!("    - {}{suffix}", endpoint_path(&record.url)));
        }
    }
    if body.is_empty() {
        return Vec::new();
    }
    let mut lines = vec!["UNTESTED SURFACE (What Riftlock couldn't verify):".to_owned()];
    lines.extend(body);
    lines
}

/// The path (and query) of an endpoint URL; the origin is already on the
/// scan's status line. A malformed URL is shown as recorded.
#[allow(dead_code)] // Used by the retained legacy untested-surface renderer.
fn endpoint_path(url: &str) -> String {
    url::Url::parse(url).map_or_else(
        |_| url.to_owned(),
        |parsed| {
            let mut path = parsed.path().to_owned();
            if let Some(query) = parsed.query() {
                path.push('?');
                path.push_str(query);
            }
            path
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for e in chars.by_ref() {
                    if e.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn attack_surface_reports_mode_and_probe_classes() {
        let lines =
            print_attack_surface("Godmode", &[], &[], &[], &[], &[], &CrawlMetrics::default());
        assert!(lines.iter().any(|line| line == "  mode: Godmode"));
        assert!(lines.iter().any(|line| line.contains("boolean/time SQLi")));
        assert!(lines.iter().any(|line| line.contains("parameter mining")));
        assert!(lines.iter().any(|line| line.contains("broad JSON fuzz")));
    }

    #[test]
    fn outcomes_are_plain_text_with_real_counts_and_reasons() {
        assert_eq!(
            plain(&outcome_line(
                "SPA",
                &EngineOutcome::Done {
                    elapsed: Duration::from_millis(2500),
                    findings: 3,
                    stats: EngineStats {
                        checks_completed: 2,
                        checks_attempted: 2,
                        endpoints_tested: 4,
                        endpoints_planned: 5,
                    },
                }
            )),
            "[+] SPA finished (2.5s) — findings: 3, checks: 2/2, coverage: 4/5"
        );
        assert_eq!(
            started_line("GraphQL", Duration::from_secs(30), 3),
            "[>] GraphQL started (budget 30s, 3 endpoints planned)"
        );
        assert_eq!(
            outcome_line("Auth", &EngineOutcome::Skipped("connection refused".into())),
            "[-] Auth skipped: connection refused"
        );
        assert_eq!(
            outcome_line(
                "Supabase",
                &EngineOutcome::Skipped("not applicable: target is not a Supabase app".into())
            ),
            "[-] Supabase skipped: not applicable: target is not a Supabase app"
        );
        assert_eq!(
            outcome_line("Source", &EngineOutcome::Panicked),
            "[x] Source panicked — skipped"
        );
        assert_eq!(
            outcome_line("GraphQL", &EngineOutcome::Failed("invalid url".into())),
            "[x] GraphQL failed: invalid url"
        );
    }

    #[test]
    fn any_failed_stage_makes_a_findingless_run_incomplete() {
        let covered = riftlock_report::ScanCoverage {
            endpoints_discovered: 1,
            endpoints_tested_successfully: 1,
            vulnerability_checks_attempted: 1,
            vulnerability_checks_completed: 1,
            ..riftlock_report::ScanCoverage::default()
        };
        assert_eq!(RunState::new(0, 0, covered).status, RunStatus::Clean);
        // A failed discovery contributes one failed stage even when every
        // engine that ran covered its endpoint.
        assert_eq!(RunState::new(0, 1, covered).status, RunStatus::Incomplete);
    }

    #[test]
    fn auth_required_endpoints_are_classified_without_counting_as_failures() {
        let auth_only = riftlock_report::ScanCoverage {
            endpoints_discovered: 10,
            endpoints_tested_successfully: 1,
            endpoints_auth_required: 9,
            ..riftlock_report::ScanCoverage::default()
        };
        assert_eq!(RunState::new(0, 0, auth_only).status, RunStatus::Clean);

        let high_failure = riftlock_report::ScanCoverage {
            endpoints_discovered: 10,
            endpoints_tested_successfully: 6,
            endpoints_auth_required: 2,
            endpoints_failed: 2,
            ..riftlock_report::ScanCoverage::default()
        };
        assert_eq!(
            RunState::new(0, 0, high_failure).status,
            RunStatus::Incomplete
        );
    }

    #[test]
    fn confirmed_absence_is_excluded_but_circuit_open_is_untested() {
        let confirmed_absence = riftlock_report::ScanCoverage {
            endpoints_discovered: 6,
            endpoints_tested_successfully: 5,
            endpoints_skipped: 1,
            ..riftlock_report::ScanCoverage::default()
        };
        assert_eq!(
            RunState::new(0, 0, confirmed_absence).status,
            RunStatus::Clean
        );

        let circuit_open = riftlock_report::ScanCoverage {
            endpoints_discovered: 6,
            endpoints_tested_successfully: 5,
            endpoints_circuit_open: 1,
            ..riftlock_report::ScanCoverage::default()
        };
        assert_eq!(
            RunState::new(0, 0, circuit_open).status,
            RunStatus::Incomplete
        );
    }

    #[test]
    fn final_block_carries_exactly_the_supplied_counts() {
        let coverage = riftlock_report::ScanCoverage {
            endpoints_discovered: 42,
            endpoints_tested_successfully: 30,
            endpoints_circuit_open: 2,
            endpoints_timed_out: 2,
            endpoints_failed: 1,
            endpoints_auth_required: 4,
            endpoints_waf_blocked: 3,
            endpoints_skipped: 2,
            vulnerability_checks_attempted: 143,
            vulnerability_checks_completed: 138,
            vulnerability_checks_inconclusive: 4,
            checks_timed_out: 0,
            checks_cancelled: 0,
            passive_observations: 0,
            checks_failed: 1,
            checks_skipped: 0,
        };
        let report = AggregationReport {
            engines_executed: 14,
            engines_failed: 2,
            engines_clean: 10,
            discovery: "complete".into(),
            endpoints_discovered: 42,
            generic_planned_endpoints: 40,
            confirmed_findings: 8,
            potential_findings: 4,
            chains: 3,
            vulnerable_pages: Vec::new(),
            state: RunState::new(12, 2, coverage),
            elapsed: Duration::from_millis(8300),
        };
        let lines = render_final(&report);
        let visible: Vec<String> = lines.iter().map(|l| plain(l).trim().to_string()).collect();
        let summary = visible.join("\n");
        assert!(summary.contains("confirmed findings:"));
        assert!(summary.contains("potential findings:"));
        assert!(!summary.contains("evidence-verified"));
        assert_eq!(visible[0], "FINAL ANALYSIS");
        assert!(summary.contains("4 endpoints required authentication — rerun with --auth-token <token> for full coverage"));
        let rows = &visible[3..];
        assert_eq!(rows.len(), 20);
        for (row, label, value) in [
            (0, "status", "FINDINGS + INCOMPLETE COVERAGE"),
            (1, "engines executed", "14"),
            (2, "engines failed", "2"),
            (3, "engines completed cleanly", "10"),
            (4, "discovery", "complete"),
            (5, "discovered inventory endpoints", "42"),
            (6, "Generic planned endpoints", "40"),
            (7, "confirmed findings:", "8"),
            (8, "potential findings:", "4"),
            (9, "attack chains", "3"),
            (10, "endpoints tested (of classified)", "30/44"),
            (
                11,
                "endpoints untested (skipped/auth/blocked/failed/timed out/circuit-open)",
                "2/4/3/1/2/2",
            ),
            (
                12,
                "checks attempted (completed/inconclusive/failed/timed out/cancelled)",
                "143 (138 completed, 4 inconclusive, 1 failed, 0 timed out, 0 cancelled)",
            ),
            (13, "passive observations (not checks)", "0"),
            (14, "check accounting reconciles", "yes"),
            (15, "ledger registered/terminal/in-flight", "143/143/0"),
            (16, "unaccounted executions", "0"),
            (17, "failed checks / checks skipped", "1/0"),
            (18, "coverage", "INCOMPLETE"),
            (19, "total elapsed", "8.3s"),
        ] {
            assert!(
                rows[row].starts_with(label),
                "missing label {label}: {}",
                rows[row]
            );
            assert!(
                rows[row].ends_with(value),
                "missing value {value}: {}",
                rows[row]
            );
        }
        let digits: Vec<String> = visible
            .join(" ")
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        assert_eq!(
            digits,
            vec![
                "4", "14", "2", "10", "42", "40", "8", "4", "3", "30", "44", "2", "4", "3", "1",
                "2", "2", "143", "138", "4", "1", "0", "0", "0", "143", "143", "0", "0", "1", "0",
                "8", "3"
            ]
        );
    }

    #[test]
    fn tested_endpoints_never_exceed_the_paired_denominator() {
        // Other engines record into the same counters, so the aggregate tested
        // count can exceed Generic's plan: 46 tested against a 45-endpoint
        // plan. The row must pair the tested count with the population it
        // came from instead of showing an impossible ratio.
        let coverage = riftlock_report::ScanCoverage {
            endpoints_discovered: 45,
            endpoints_tested_successfully: 46,
            endpoints_skipped: 2,
            ..riftlock_report::ScanCoverage::default()
        };
        let report = AggregationReport {
            engines_executed: 3,
            engines_failed: 0,
            engines_clean: 3,
            discovery: "complete".into(),
            endpoints_discovered: 45,
            generic_planned_endpoints: 45,
            confirmed_findings: 0,
            potential_findings: 0,
            chains: 0,
            vulnerable_pages: Vec::new(),
            state: RunState::new(0, 0, coverage),
            elapsed: Duration::ZERO,
        };
        let rows: Vec<String> = render_final(&report)
            .iter()
            .map(|line| plain(line).trim().to_string())
            .collect();
        let row = rows
            .iter()
            .find(|line| line.starts_with("endpoints tested"))
            .expect("tested row");
        assert!(row.ends_with("46/48"), "{row}");
    }

    #[test]
    fn forced_tty_colors_headings_but_not_process_lines() {
        let _g = crate::ui::theme::global_lock();
        crate::ui::theme::set_color_override(true);
        let heading = outcome_line(
            "SPA",
            &EngineOutcome::Done {
                elapsed: Duration::from_secs(1),
                findings: 1,
                stats: EngineStats::default(),
            },
        );
        assert!(heading.contains("\u{1b}[38;2;57;255;20m[+] SPA finished\u{1b}[0m"));
        assert!(heading.ends_with("findings: 1, checks: 0/0, coverage: 0/0"));
        let process = outcome_line("Auth", &EngineOutcome::Skipped("connection refused".into()));
        assert!(!process.contains('\u{1b}'));
        let positive = crate::ui::theme::blush_pink("[!] Xss");
        assert!(positive.contains("\u{1b}[38;2;255;105;180m[!] Xss\u{1b}[0m"));
        assert!(!process.contains("\u{1b}[38;2;255;105;180m"));
        crate::ui::theme::unset_color_override();
    }

    #[test]
    fn no_color_environment_emits_no_ansi() {
        let _g = crate::ui::theme::global_lock();
        crate::ui::theme::set_color_override(true);
        std::env::set_var("NO_COLOR", "1");
        let lines = render_final(&AggregationReport {
            engines_executed: 0,
            engines_failed: 0,
            engines_clean: 0,
            discovery: "skipped (passive)".into(),
            endpoints_discovered: 0,
            generic_planned_endpoints: 0,
            confirmed_findings: 0,
            potential_findings: 0,
            chains: 0,
            vulnerable_pages: Vec::new(),
            state: RunState::new(0, 0, riftlock_report::ScanCoverage::default()),
            elapsed: Duration::ZERO,
        });
        assert!(lines.iter().all(|line| !line.contains('\u{1b}')));
        std::env::remove_var("NO_COLOR");
        crate::ui::theme::unset_color_override();
    }

    #[test]
    fn non_tty_emits_no_ansi() {
        let _g = crate::ui::theme::global_lock();
        crate::ui::theme::set_color_override(false);
        let lines = render_final(&AggregationReport {
            engines_executed: 0,
            engines_failed: 0,
            engines_clean: 0,
            discovery: "skipped (passive)".into(),
            endpoints_discovered: 0,
            generic_planned_endpoints: 0,
            confirmed_findings: 0,
            potential_findings: 0,
            chains: 0,
            vulnerable_pages: Vec::new(),
            state: RunState::new(0, 0, riftlock_report::ScanCoverage::default()),
            elapsed: Duration::ZERO,
        });
        assert!(lines.iter().all(|line| !line.contains('\u{1b}')));
        crate::ui::theme::unset_color_override();
    }

    fn cov(
        discovered: u64,
        tested: u64,
        attempted: u64,
        completed: u64,
        inconclusive: u64,
        passive: u64,
    ) -> riftlock_report::ScanCoverage {
        riftlock_report::ScanCoverage {
            endpoints_discovered: discovered,
            endpoints_tested_successfully: tested,
            vulnerability_checks_attempted: attempted,
            vulnerability_checks_completed: completed,
            vulnerability_checks_inconclusive: inconclusive,
            passive_observations: passive,
            ..Default::default()
        }
    }

    /// Ten deterministic accounting scenarios. Every case asserts that the
    /// combined label names both findings and coverage, that terminal and
    /// report use the same label, and that passive/failed/skipped work is
    /// never converted into a completed clean check.
    #[test]
    fn coverage_and_status_reconcile_across_all_scenarios() {
        let cases: Vec<(&str, usize, usize, riftlock_report::ScanCoverage, &str)> = vec![
            // name, findings, failures, coverage, expected label
            (
                "discovery failure, no findings",
                0,
                1,
                cov(0, 0, 0, 0, 0, 0),
                "INCOMPLETE",
            ),
            (
                "discovery failure, passive findings",
                2,
                1,
                cov(0, 0, 0, 0, 0, 2),
                "FINDINGS + INCOMPLETE COVERAGE",
            ),
            (
                "discovery failure, independent verified finding",
                1,
                1,
                cov(1, 1, 1, 1, 0, 0),
                "FINDINGS + INCOMPLETE COVERAGE",
            ),
            (
                "zero completed checks, passive observations",
                5,
                0,
                cov(1, 1, 0, 0, 0, 5),
                "FINDINGS + INCOMPLETE COVERAGE",
            ),
            (
                "scanner transport failure",
                0,
                1,
                cov(1, 1, 0, 0, 0, 0),
                "INCOMPLETE",
            ),
            (
                "two failed scanners, others succeeded",
                1,
                2,
                cov(3, 2, 2, 2, 0, 0),
                "FINDINGS + INCOMPLETE COVERAGE",
            ),
            (
                "shared host-wide transport failure",
                0,
                27,
                cov(0, 0, 0, 0, 0, 0),
                "INCOMPLETE",
            ),
            (
                "partial discovery, tested endpoints",
                0,
                0,
                cov(5, 3, 3, 3, 0, 0),
                "INCOMPLETE",
            ),
            (
                "all scanners skipped",
                0,
                0,
                cov(0, 0, 0, 0, 0, 0),
                "INCOMPLETE",
            ),
            (
                "complete scan, zero findings",
                0,
                0,
                cov(1, 1, 4, 4, 0, 0),
                "CLEAN",
            ),
        ];
        for (name, findings, failures, coverage, expected) in cases {
            let state = RunState::new(findings, failures, coverage);
            assert_eq!(state.status_label(), expected, "{name}");
            assert_eq!(state.verdict.label(), expected, "{name}");
            assert_eq!(state.verdict.findings, findings as u64, "{name}");
            assert!(
                state
                    .verdict
                    .reconciles(coverage.vulnerability_checks_attempted),
                "{name}"
            );
            assert!(
                state.verdict.completed_checks <= coverage.vulnerability_checks_attempted,
                "{name}: completed checks may not exceed attempted"
            );
            assert!(
                state.verdict.passive_observations <= state.verdict.findings,
                "{name}: passive observations are findings, not checks"
            );
            if name == "zero completed checks, passive observations" {
                assert_eq!(state.verdict.completed_checks, 0, "{name}");
                assert_eq!(state.verdict.passive_observations, 5, "{name}");
            }
            if name == "shared host-wide transport failure" {
                assert_eq!(
                    state.verdict.failed_checks, 0,
                    "engine failures are not check failures"
                );
                assert!(!state.verdict.is_complete(), "{name}");
            }
        }
    }

    #[test]
    fn accounting_failure_forces_incomplete_verdict() {
        let bad = AccountingValidation {
            registered: 10,
            terminal: 8,
            in_flight: 2,
            duplicates_rejected: 1,
        };
        let state =
            RunState::with_accounting(3, 0, riftlock_report::ScanCoverage::default(), bad, 0);
        assert_eq!(state.status_label(), "FINDINGS + INCOMPLETE COVERAGE");
        assert!(!state.verdict.coverage_complete);
        assert!(!state.accounting.reconciles());

        let unaccounted = RunState::with_accounting(
            1,
            0,
            riftlock_report::ScanCoverage::default(),
            AccountingValidation {
                registered: 0,
                terminal: 0,
                in_flight: 0,
                duplicates_rejected: 0,
            },
            1,
        );
        assert_eq!(unaccounted.status_label(), "FINDINGS + INCOMPLETE COVERAGE");
        assert_eq!(unaccounted.unaccounted_executions, 1);
    }

    #[test]
    fn final_block_is_green_in_its_heading_and_separator() {
        let _g = crate::ui::theme::global_lock();
        crate::ui::theme::set_color_override(true);
        let coverage = riftlock_report::ScanCoverage::default();
        let lines = render_final(&AggregationReport {
            engines_executed: 1,
            engines_failed: 0,
            engines_clean: 1,
            discovery: "complete".into(),
            endpoints_discovered: 0,
            generic_planned_endpoints: 0,
            confirmed_findings: 0,
            potential_findings: 0,
            chains: 0,
            vulnerable_pages: Vec::new(),
            state: RunState::new(0, 0, coverage),
            elapsed: Duration::from_millis(1),
        });
        assert!(lines[0].contains("\u{1b}[38;2;57;255;20m"));
        assert!(lines[1].contains("\u{1b}[38;2;57;255;20m"));
        assert!(!lines[0].contains("\u{1b}[38;2;57;255;20mFINDINGS\u{1b}[0m"));
        crate::ui::theme::unset_color_override();
    }

    #[test]
    fn high_confidence_is_potential_not_confirmed() {
        use riftlock_core::{Confidence, Evidence, ProofGate, Verifier};
        use std::future::Future;
        use std::pin::Pin;

        struct Always;
        impl Verifier for Always {
            fn verify<'a>(
                &'a self,
                _claim: &'a str,
                _evidence: &'a Evidence,
            ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
                Box::pin(async { true })
            }
        }

        let confirmed = ProofGate::admit(Evidence::AuthBypass {
            endpoint: "https://x/auth".into(),
            method: "POST".into(),
        })
        .expect("admitted");
        assert_eq!(confirmed.confidence(), Confidence::Confirmed);
        let high = ProofGate::admit_with_verifier(
            Evidence::Differential {
                without_key: 200,
                with_key: 200,
                inverted: false,
                cross_tenant: false,
                note: None,
            },
            &Always,
            "status=206",
        )
        .expect("verifier-approved");
        assert_eq!(high.confidence(), Confidence::High);
        assert_eq!(finding_totals(&[confirmed, high]), (1, 1));
    }

    fn record(url: &str, outcome: EndpointOutcome) -> EndpointRecord {
        EndpointRecord {
            url: url.to_owned(),
            outcome,
        }
    }

    #[test]
    fn untested_surface_groups_by_outcome_and_shortens_paths() {
        let records = vec![
            record("https://t.test/admin", EndpointOutcome::AuthRequired),
            record("https://t.test/dashboard", EndpointOutcome::AuthRequired),
            record("https://t.test/api/v1/users", EndpointOutcome::AuthRequired),
            record("https://t.test/api/v1/audit", EndpointOutcome::AuthRequired),
            record("https://t.test/contact", EndpointOutcome::WafBlocked),
            record("https://t.test/app.js", EndpointOutcome::Failed),
            record("https://t.test/slow", EndpointOutcome::TimedOut),
            record("https://t.test/reset", EndpointOutcome::Failed),
            record("https://t.test/breaker", EndpointOutcome::CircuitOpen),
            record("https://t.test/gone", EndpointOutcome::Skipped),
            // Tested endpoints never appear in the untested surface.
            record("https://t.test/", EndpointOutcome::Tested),
        ];
        let lines = render_untested_surface(&records, &[]);
        assert_eq!(
            lines[0],
            "UNTESTED SURFACE (What Riftlock couldn't verify):"
        );
        assert!(lines.contains(&"  [AUTH REQUIRED] (4 endpoints)".to_owned()));
        assert!(lines.contains(&"    - /admin".to_owned()));
        assert!(lines.contains(&"    - /api/v1/users (+1 more)".to_owned()));
        assert!(lines.contains(&"  [WAF BLOCKED] (1 endpoint)".to_owned()));
        assert!(lines.contains(&"  [TIMED OUT] (1 endpoint)".to_owned()));
        assert!(lines.contains(&"  [CONNECTION FAILED] (2 endpoints)".to_owned()));
        assert!(lines.contains(&"  [CIRCUIT BREAKER] (1 endpoint)".to_owned()));
        assert!(lines.contains(&"    - /slow".to_owned()));
        assert!(lines.contains(&"  [SKIPPED / NOT APPLICABLE] (1 endpoint)".to_owned()));
        assert!(!lines.iter().any(|line| line.contains("t.test")));
    }

    #[test]
    fn untested_surface_is_empty_when_everything_was_tested() {
        let records = vec![record("https://t.test/", EndpointOutcome::Tested)];
        assert!(render_untested_surface(&records, &[]).is_empty());
        assert!(render_untested_surface(&[], &[]).is_empty());
    }

    #[test]
    fn untested_surface_lists_planned_endpoints_never_reached() {
        let records = vec![
            record("https://t.test/", EndpointOutcome::Tested),
            record("https://t.test/gone", EndpointOutcome::Skipped),
        ];
        let unreached = vec![
            "https://t.test/api/users".to_owned(),
            "https://t.test/api/audit".to_owned(),
            // The ledger already classified this one; it must not repeat here.
            "https://t.test/gone".to_owned(),
        ];
        let lines = render_untested_surface(&records, &unreached);
        assert_eq!(
            lines[0],
            "UNTESTED SURFACE (What Riftlock couldn't verify):"
        );
        assert!(lines.contains(&"  [PLANNED BUT NOT REACHED] (2 endpoints)".to_owned()));
        assert!(lines.contains(&"    - /api/users".to_owned()));
        assert!(lines.contains(&"    - /api/audit".to_owned()));
        assert_eq!(
            lines.iter().filter(|line| line.contains("/gone")).count(),
            1,
            "a classified URL must appear only in its outcome group: {lines:?}"
        );
    }
}
