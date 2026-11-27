//! Terminal rendering of findings, attack chains and the final summary
//! box. Pure presentation on stdout: every severity, count and status is
//! derived from the real evidence passed in — nothing here invents data.
//! The palette comes exclusively from [`crate::ui::theme`].

use crate::ui::theme::{info, muted, scanning, separator, severity_tag, unicode_ok, Severity};
use riftlock_core::{Evidence, Finding};
use std::time::Duration;

/// Sort findings in requested Critical → High → Medium → Low order, with
/// informational and unknown evidence after the known severity tiers.
#[must_use]
pub fn severity_rank(evidence: &Evidence) -> u8 {
    match riftlock_core::severity_of(evidence) {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

/// One finding as a colored severity tag plus its one-line description.
/// Variants without a dedicated sentence fall back to their JSON form.
pub fn print_finding(finding: &Finding) {
    let evidence = finding.evidence();
    let calibration = match finding.confidence() {
        riftlock_core::Confidence::Potential => " [potential; static/passive evidence]",
        riftlock_core::Confidence::High => " [high confidence]",
        riftlock_core::Confidence::Inconclusive => " [inconclusive]",
        riftlock_core::Confidence::NotVulnerable => " [not vulnerable]",
        riftlock_core::Confidence::Confirmed => "",
        _ => " [confidence: other]",
    };
    match describe(evidence) {
        Some((sev, msg)) => println!("  {} {}{}", severity_tag(sev), msg, calibration),
        // Evidence is non_exhaustive: future variants print raw JSON.
        None => println!(
            "  {}{}",
            serde_json::to_string(evidence).unwrap_or_default(),
            calibration
        ),
    }
}

/// The authoritative tier, then the renderer's one-line message. Variants
/// without a dedicated sentence fall back to raw JSON in `print_finding`.
fn describe(evidence: &Evidence) -> Option<(Severity, String)> {
    let message = describe_message(evidence)?;
    Some((riftlock_core::severity_of(evidence), message))
}

/// Message only; severity lives solely in `riftlock_core::severity_of`.
fn describe_message(evidence: &Evidence) -> Option<String> {
    match evidence {
        Evidence::LeakedSecret { key_type, location, .. } => Some(format!("Leaked Secret ({key_type:?}) found in {location}")),
        Evidence::UnauthenticatedRead {
            endpoint,
            row_sample,
        } => Some(format!("Unauthenticated Read on {endpoint} (Row: {row_sample})")),
        Evidence::BrokenAccessControl {
            url,
            dashboard_marker,
        } => Some(format!("Anonymous access to {url} served signed-in UI ({dashboard_marker})")),
        Evidence::SensitivePathDisclosed { url, status } => Some(format!(
            "Sensitive path {url} disclosed via HTTP {status} (exists, denied anonymously)"
        )),
        Evidence::HttpSmuggling { endpoint, .. } => Some(format!("HTTP Smuggling vulnerability at {endpoint}")),
        Evidence::WriteProof {
            table,
            marker_id,
            cleaned_up,
        } => Some(format!("Unauthorized write on {table} (marker {marker_id}, cleaned up: {cleaned_up})")),
        Evidence::IdorProof {
            table, other_row, ..
        } => Some(format!("IDOR on {table}: foreign row {other_row} accessible")),
        Evidence::PrivilegeEscalation {
            from_role,
            to_role,
            method,
        } => Some(format!("Privilege escalation {from_role} -> {to_role} via {method}")),
        Evidence::Chain { steps, verdict } => Some(format!("Attack chain ({verdict}): {} linked steps", steps.len())),
        Evidence::Differential {
            without_key,
            with_key,
            inverted,
            cross_tenant,
            ..
        } => Some(format!(
                "Differential access proven (no key: {without_key}, high-priv: {with_key}{}, {})",
                if *inverted { ", RLS inverted" } else { "" },
                if *cross_tenant {
                    "cross-tenant"
                } else {
                    "same tenant"
                }
            )),
        Evidence::AuthBypass { endpoint, method } => Some(format!("Auth bypass at {endpoint} ({method})")),
        Evidence::BusinessLogicBypass { endpoint, kind } => Some(format!("Business-logic bypass ({kind}) at {endpoint}")),
        Evidence::SourceDisclosure { url, kind } => Some(format!("Source artifact disclosed ({kind:?}): {url}")),
        Evidence::StorageLeak {
            bucket,
            object_sample,
        } => Some(format!("Storage bucket readable: {bucket} (object: {object_sample})")),
        Evidence::FunctionExposed {
            endpoint,
            response_shape,
        } => Some(format!("RPC function exposed: {endpoint} ({response_shape})")),
        Evidence::CacheDeception { endpoint } => Some(format!("Cache deception bypass at {endpoint}")),
        Evidence::PathNormalizationBypass { path } => Some(format!("Path-normalization bypass via {path}")),
        Evidence::GraphQLBatching { endpoint } => Some(format!("GraphQL batching accepted at {endpoint}")),
        Evidence::SsrF { endpoint, payload } => Some(format!("SSRF at {endpoint} (fetched {payload})")),
        Evidence::SignedUrlBypass {
            endpoint,
            object_id,
        } => Some(format!("Signed-URL bypass at {endpoint} (foreign object {object_id})")),
        Evidence::PrototypePollution { endpoint, payload } => Some(format!("Prototype pollution at {endpoint} (payload {payload})")),
        Evidence::WebSocketDesync { endpoint } => Some(format!("WebSocket auth desync at {endpoint}")),
        Evidence::OAuthMisconfig { endpoint, flaw } => Some(format!("OAuth misconfig ({flaw}) at {endpoint}")),
        Evidence::SseDesync { endpoint } => Some(format!("SSE stream served unauthenticated at {endpoint}")),
        Evidence::RaceCondition {
            endpoint,
            successful_requests,
        } => Some(format!(
                "Race condition at {endpoint}: {successful_requests} concurrent writes succeeded"
            )),
        Evidence::SupplyChainVulnerability {
            manifest,
            package,
            version,
        } => Some(format!("Vulnerable dependency {package}@{version} exposed in {manifest}")),
        Evidence::PromptInjection { endpoint, .. } => Some(format!("Prompt injection accepted at {endpoint}")),
        Evidence::WebSocketCswh { endpoint } => Some(format!("Cross-site WebSocket hijacking accepted at {endpoint}")),
        Evidence::GrpcExposed { endpoint, .. } => Some(format!("gRPC server reflection exposed at {endpoint}")),
        // The matching source line is minified JS — useless in a terminal.
        Evidence::ClientSideFlaw {
            endpoint,
            flaw_type,
            ..
        } => Some(format!("Client-side flaw ({flaw_type}) found in {endpoint}")),
        Evidence::XssReflection {
            url,
            param,
            context,
        } => Some(format!("XSS reflection ({context}) at {url} (param {param})")),
        Evidence::SqliError { url, param, .. } => Some(format!("SQL error signature at {url} (param {param})")),
        Evidence::SqliTimeDelay {
            url,
            param,
            delay_ms,
        } => Some(format!("Time-based blind SQLi at {url} (param {param}, +{delay_ms}ms)")),
        Evidence::SstiReflection { url, param, .. } => Some(format!("Server-side template injection at {url} (param {param})")),
        Evidence::LfiRead {
            url,
            param,
            file_read,
        } => Some(format!("File read at {url} (param {param}, marker {file_read})")),
        Evidence::CommandInjection {
            url,
            param,
            payload,
        } => Some(format!("Command injection at {url} (param {param}, payload {payload})")),
        Evidence::DomXssTaint { url, source, sink } => Some(format!("DOM XSS taint at {url} ({source} -> {sink})")),
        Evidence::SqlInjection {
            url,
            param,
            payload,
        } => Some(format!("SQL injection auth bypass at {url} (param {param}, payload {payload})")),
        Evidence::ReflectedXss {
            url,
            param,
            payload,
        } => Some(format!("Reflected XSS at {url} (param {param}, payload {payload})")),
        Evidence::Idor {
            url,
            original_id,
            accessed_id,
        } => Some(format!(
                "IDOR object access at {url} (original id {original_id}, accessed id {accessed_id})"
            )),
        Evidence::NoSqlInjection {
            url,
            param,
            payload,
        } => Some(format!("NoSQL injection auth bypass at {url} (param {param}, payload {payload})")),
        Evidence::MassAssignment {
            url,
            param,
            payload,
        } => Some(format!("Mass assignment at {url} (field {param} set to {payload})")),
        Evidence::JwtVulnerability { endpoint, issue } => Some(format!("JWT vulnerability ({issue}) at {endpoint}")),
        Evidence::SensitiveDataExposure { url, data_type } => Some(format!("Sensitive data exposure ({data_type}) at {url}")),
        Evidence::GraphQLIntrospection { endpoint } => Some(format!("GraphQL introspection enabled at {endpoint}")),
        Evidence::OpenRedirect { url, param } => Some(format!("Open redirect at {url} (param {param})")),
        Evidence::MixedContent {
            page_url,
            resource_url,
        } => Some(format!("Mixed content on {page_url} (resource {resource_url})")),
        Evidence::CloudExposure { url, provider } => Some(format!("Cloud/infra API exposed ({provider}) at {url}")),
        Evidence::TechFingerprint {
            technology,
            version,
            confidence,
        } => Some(format!(
                "Technology fingerprint: {}{} ({confidence}% confidence)",
                technology,
                version
                    .as_ref()
                    .map_or_else(String::new, |v| format!(" {v}"))
            )),
        Evidence::DnsMisconfiguration { domain, issue } => Some(format!("DNS/info disclosure ({issue}) on {domain}")),
        Evidence::XxeExtraction { url, file_read } => Some(format!("XXE file extraction at {url} (read {file_read})")),
        // Absence of a hidden token is a posture observation, not proof of
        // exploitable CSRF: SameSite/Origin checks or a double-submit token
        // may still block cross-site requests. No cross-site probe is sent.
        Evidence::CsrfMissingToken { url, form_action } => Some(format!("CSRF token absent on form at {url} (action {form_action}; posture only, cross-site acceptance untested)")),
        Evidence::SpaEndpoint { url, .. } => {
            Some(format!("Discovered API Endpoint: {url}"))
        }
        Evidence::SecurityMisconfiguration { url, issue, .. } => {
            Some(format!("Misconfiguration: {issue} on {url}"))
        }
        // Evidence is non_exhaustive: future variants print raw JSON.
        _ => None,
    }
}

/// Map a misconfiguration severity string onto the tier system: "High",
/// "Medium" and "Low" name their tiers, anything else rides Info.
/// One attack chain: a cyan verdict header, then the real linked steps,
/// numbered, indented under it.
pub fn print_chain(steps: &[String], verdict: &str) {
    println!(
        "{}",
        info(&format!(
            "--- chain verdict={verdict} steps={}",
            steps.len()
        ))
    );
    for (i, s) in steps.iter().enumerate() {
        println!("  {}: {s}", muted(&format!("step {}", i + 1)));
    }
}

/// The severity tier counts over findings + chains. Returns (critical,
/// high, medium, warnings) — derived from the same `describe` tiering the
/// finding lines use, so a printed tag always matches the summary count.
#[allow(dead_code)] // Used by the retained summary renderer and its tests.
fn severity_counts(findings: &[Finding], chains: &[Finding]) -> (usize, usize, usize, usize) {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut warnings = 0usize;
    for f in findings.iter().chain(chains.iter()) {
        match riftlock_core::severity_of(f.evidence()) {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            // Low and Info ride the warning tier in the terminal summary.
            Severity::Low | Severity::Info => warnings += 1,
        }
    }
    (critical, high, medium, warnings)
}

/// Terminal summary: real severity counts over findings + chains, printed
/// even when the scan is clean, always on stdout.
#[allow(dead_code)] // Retained for its summary-rendering unit tests and potential callers.
pub fn print_summary(
    url: &str,
    mode: &str,
    elapsed: Duration,
    findings: &[Finding],
    chains: &[Finding],
    state: crate::ui::lifecycle::RunState,
) {
    let (critical, high, medium, warnings) = severity_counts(findings, chains);
    let total = findings.len() + chains.len();
    let dot = if unicode_ok() { "·" } else { "-" };
    let emdash = if unicode_ok() { "—" } else { "-" };
    println!("{}", separator());
    println!(
        "{}",
        scanning(&format!(
            "SCAN COMPLETE {emdash} riftlock v{}",
            env!("CARGO_PKG_VERSION")
        ))
    );
    println!(
        "{}",
        muted(&format!(
            "target {url} {dot} {:.1}s {dot} mode {mode}",
            elapsed.as_secs_f64()
        ))
    );
    println!("{}", separator());
    println!("{}", summary_row("status", &scanning(state.status_label())));
    println!("{}", summary_row("critical", &critical.to_string()));
    println!("{}", summary_row("high", &high.to_string()));
    println!("{}", summary_row("medium", &medium.to_string()));
    println!("{}", summary_row("warnings", &warnings.to_string()));
    println!("{}", summary_row("total", &total.to_string()));
    println!("{}", separator());
}

/// One aligned summary row: a muted label padded to a fixed column, two
/// spaces, then the value. Padding comes from the label's *visible* width,
/// never the ANSI-painted string, so the column stays aligned with color on.
fn summary_row(label: &str, painted: &str) -> String {
    let width = 10usize.saturating_sub(label.chars().count());
    format!("  {}{}  {painted}", muted(label), " ".repeat(width))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admitted(evidence: Evidence) -> Finding {
        match riftlock_core::ProofGate::admit(evidence.clone()) {
            Ok(f) => f,
            Err(riftlock_core::ProofError::NoLab) => riftlock_core::ProofGate::admit_lab(
                evidence,
                &riftlock_core::LabGuard::new_unsafe(),
            )
            .expect("lab admitted"),
            Err(e) => panic!("unexpected rejection: {e}"),
        }
    }

    #[test]
    fn severity_tiers_follow_the_house_rules() {
        let critical = describe(&Evidence::LeakedSecret {
            key_type: riftlock_core::KeyType::SupabaseSecret,
            location: "app.js".into(),
            masked: "sb_secret_********".into(),
            full: Default::default(),
        })
        .map(|(s, _)| s);
        assert_eq!(critical, Some(Severity::Critical));

        let high = describe(&Evidence::AuthBypass {
            endpoint: "https://x/auth".into(),
            method: "POST".into(),
        })
        .map(|(s, _)| s);
        assert_eq!(high, Some(Severity::High));

        let informational = describe(&Evidence::SpaEndpoint {
            url: "https://x/api".into(),
            source: "xhr".into(),
        })
        .map(|(s, _)| s);
        assert_eq!(informational, Some(Severity::Info));

        // A missing CSRF token is an unverified posture observation, not a
        // confirmed Medium vulnerability (no cross-site acceptance probe).
        let csrf = describe(&Evidence::CsrfMissingToken {
            url: "https://x/login".into(),
            form_action: "/login".into(),
        })
        .map(|(s, _)| s);
        assert_eq!(csrf, Some(Severity::Info));
    }

    #[test]
    fn severity_rank_orders_terminal_findings() {
        let ranks = [
            Evidence::SecurityMisconfiguration {
                url: "https://x".into(),
                issue: "low".into(),
                severity: "Low".into(),
            },
            Evidence::AuthBypass {
                endpoint: "https://x".into(),
                method: "POST".into(),
            },
            Evidence::LeakedSecret {
                key_type: riftlock_core::KeyType::SupabaseSecret,
                location: "app.js".into(),
                masked: "sb_secret_********".into(),
                full: Default::default(),
            },
        ]
        .map(|evidence| severity_rank(&evidence));
        assert_eq!(ranks, [3, 1, 0]);
    }

    /// The known disagreements from the audit, plus one Low case so the
    /// reportable tiers are exercised. Terminal, report totals and SARIF
    /// must all derive from the same `severity_of` result.
    #[test]
    fn all_renderers_agree_on_severity() {
        let cases: Vec<(Evidence, Severity)> = vec![
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
                Evidence::CsrfMissingToken {
                    url: "https://x/login".into(),
                    form_action: "/login".into(),
                },
                Severity::Info,
            ),
            (
                Evidence::XssReflection {
                    url: "https://x/s".into(),
                    param: "q".into(),
                    context: "html".into(),
                },
                Severity::Low,
            ),
        ];
        for (evidence, expected) in cases {
            let tier = riftlock_core::severity_of(&evidence);
            assert_eq!(tier, expected, "{evidence:?}");
            assert_eq!(describe(&evidence).map(|(s, _)| s), Some(tier));

            let finding = admitted(evidence);
            assert_eq!(
                riftlock_report::severity(&finding),
                tier.as_str(),
                "report totals disagree: {tier:?}"
            );
            let sarif = riftlock_report::to_sarif(std::slice::from_ref(&finding));
            let doc: serde_json::Value = serde_json::from_str(&sarif).expect("sarif json");
            assert_eq!(
                doc["runs"][0]["results"][0]["level"],
                tier.sarif_level(),
                "SARIF disagrees: {tier:?}"
            );
        }
    }

    #[test]
    fn misconfig_severity_names_tiers_and_falls_back_to_info() {
        let misconfig = |severity: &str| Evidence::SecurityMisconfiguration {
            url: "https://x/".into(),
            issue: "missing_csp".into(),
            severity: severity.into(),
        };
        assert_eq!(
            riftlock_core::severity_of(&misconfig("High")),
            Severity::High
        );
        assert_eq!(
            riftlock_core::severity_of(&misconfig("Medium")),
            Severity::Medium
        );
        assert_eq!(riftlock_core::severity_of(&misconfig("Low")), Severity::Low);
        assert_eq!(
            riftlock_core::severity_of(&misconfig("nonsense")),
            Severity::Info
        );
    }

    /// Strip ANSI escape sequences so assertions see the visible text only
    /// (a concurrent test may hold a color override on the process global).
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
    fn summary_rows_pad_the_label_column_by_visible_width() {
        let _g = crate::ui::theme::global_lock();
        crate::ui::theme::set_color_override(true);
        // ANSI paint must not shift the value column: the pad depends on
        // the label's visible width only.
        let row = summary_row("status", &scanning("FINDINGS"));
        assert!(row.contains(&scanning("FINDINGS")));
        assert_eq!(
            plain(&row).chars().count(),
            2 + 6 + 4 + 2 + "FINDINGS".chars().count()
        );
        let short = summary_row("hi", "1");
        assert_eq!(plain(&short).chars().count(), 2 + 2 + 8 + 2 + 1);
        crate::ui::theme::unset_color_override();
    }

    #[test]
    fn counts_split_by_tier_exactly_like_the_cli_rules() {
        let findings = vec![
            admitted(Evidence::AuthBypass {
                endpoint: "https://x/auth".into(),
                method: "POST".into(),
            }),
            admitted(Evidence::SecurityMisconfiguration {
                url: "https://x".into(),
                issue: "open cors".into(),
                severity: "Medium".into(),
            }),
            admitted(Evidence::SecurityMisconfiguration {
                url: "https://x".into(),
                issue: "odd header".into(),
                severity: "Low".into(),
            }),
        ];
        let chains = vec![admitted(Evidence::Chain {
            steps: vec!["a".into(), "b".into()],
            verdict: "critical_full_compromise".into(),
        })];
        let (critical, high, medium, warnings) = severity_counts(&findings, &chains);
        assert_eq!((critical, high, medium, warnings), (1, 1, 1, 1));
    }
}
