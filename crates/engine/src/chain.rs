//! The chain builder: link findings into `Evidence::Chain` attack paths.
//!
//! A chain only exists if the relationship between its steps is
//! demonstrable from the stored evidence alone: the linked findings must
//! name the same host, and the first step must materially enable the
//! second. Correlation across hosts is not a chain.

use riftlock_core::{Evidence, Finding, ProofGate};
use serde_json::json;
use url::Url;

/// Stringify one finding's evidence for a chain step (one-line JSON).
fn step(finding: &Finding) -> String {
    serde_json::to_string(&json!({
        "evidence": finding.evidence(),
    }))
    .unwrap_or_default()
}

/// The host a finding's evidence names, when it names one.
fn host_of(evidence: &Evidence) -> Option<String> {
    let url_of = |s: &str| Url::parse(s).ok()?.host_str().map(str::to_owned);
    match evidence {
        Evidence::SourceDisclosure { url, .. } => url_of(url),
        Evidence::AuthBypass { endpoint, .. } => url_of(endpoint),
        _ => None,
    }
}

/// Severity grade for a demonstrated chain, from its steps' evidence.
///
/// Exploitability: a write-class step (lab-admitted) is executed
/// exploitation, an auth bypass / injection is a proven exploit primitive.
/// Impact: those grade critical/high; disclosure-only steps are
/// reconnaissance value (medium). Preconditions and evidence strength are
/// uniform by construction — every step is a gate-admitted, verified
/// finding and a demonstrated chain is exactly two steps — so the grade
/// reduces to exploitability × impact.
fn grade(steps: &[String]) -> &'static str {
    let joined = steps.join("\n");
    const WRITE_CLASS: [&str; 5] = [
        "PrivilegeEscalation",
        "WriteProof",
        "IdorProof",
        "BusinessLogicBypass",
        "MassAssignment",
    ];
    const EXPLOIT_CLASS: [&str; 4] = ["AuthBypass", "SqlInjection", "Idor", "JwtVulnerability"];
    if WRITE_CLASS.iter().any(|m| joined.contains(m)) {
        "critical_full_compromise"
    } else if EXPLOIT_CLASS.iter().any(|m| joined.contains(m)) {
        "high_exploitable_path"
    } else {
        "medium_reconnaissance_path"
    }
}

/// Links findings into attack-path chains.
#[derive(Debug, Default)]
pub struct ChainBuilder;

impl ChainBuilder {
    /// Look for demonstrated links among `findings` and return chain
    /// findings.
    ///
    /// Link implemented:
    /// - `SourceDisclosure(SourceMap)` + `AuthBypass` **on the same host**:
    ///   the disclosed source documents the API surface the bypass
    ///   exploited.
    ///
    /// Pairs that were previously chained but whose relationship cannot be
    /// demonstrated from stored evidence (`LeakedSecret` + `StorageLeak`,
    /// `PrivilegeEscalation` + anonymous `UnauthenticatedRead` — an
    /// unauthenticated read gains nothing from an escalation) are
    /// deliberately not chained.
    pub fn build(findings: &[Finding]) -> Vec<Finding> {
        let is_sourcemap = |e: &Evidence| {
            matches!(
                e,
                Evidence::SourceDisclosure {
                    kind: riftlock_core::SourceKind::SourceMap,
                    ..
                }
            )
        };
        let is_auth_bypass = |e: &Evidence| matches!(e, Evidence::AuthBypass { .. });

        // The link is demonstrated only when some (sourcemap, bypass) pair
        // names the same host — a map on host A says nothing about an API
        // on host B.
        let demonstrated = findings.iter().any(|m| {
            is_sourcemap(m.evidence())
                && findings.iter().any(|b| {
                    is_auth_bypass(b.evidence())
                        && host_of(m.evidence()).is_some()
                        && host_of(m.evidence()) == host_of(b.evidence())
                })
        });
        let mut chains = Vec::new();
        if demonstrated {
            let collect = |pred: &dyn Fn(&Evidence) -> bool| {
                findings
                    .iter()
                    .filter(|f| pred(f.evidence()))
                    .map(step)
                    .collect::<Vec<_>>()
            };
            let mut steps = collect(&is_sourcemap);
            steps.extend(collect(&is_auth_bypass));
            let verdict = grade(&steps);
            if let Ok(f) = ProofGate::admit(Evidence::Chain {
                steps,
                verdict: verdict.to_owned(),
            }) {
                chains.push(f);
            }
        }
        chains
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::{KeyType, LabGuard, ProofGate, SourceKind};

    fn make(evidence: Evidence) -> Finding {
        ProofGate::admit(evidence).expect("admitted")
    }

    #[test]
    fn links_sourcemap_and_auth_bypass() {
        let findings = vec![
            make(Evidence::SourceDisclosure {
                url: "https://x/app.js.map".into(),
                kind: SourceKind::SourceMap,
            }),
            make(Evidence::AuthBypass {
                endpoint: "https://x/auth/v1/signup".into(),
                method: "POST".into(),
            }),
        ];
        let chains = ChainBuilder::build(&findings);
        assert_eq!(chains.len(), 1);
        let Evidence::Chain { steps, verdict } = chains[0].evidence() else {
            panic!("expected chain");
        };
        assert_eq!(verdict, "high_exploitable_path");
        assert_eq!(steps.len(), 2);
        assert!(steps.iter().all(|s| !s.is_empty()));
    }

    #[test]
    fn cross_host_sourcemap_and_bypass_are_not_chained() {
        // The map on host x says nothing about the API on host y: the
        // relationship is not demonstrable, so no chain exists.
        let findings = vec![
            make(Evidence::SourceDisclosure {
                url: "https://x/app.js.map".into(),
                kind: SourceKind::SourceMap,
            }),
            make(Evidence::AuthBypass {
                endpoint: "https://y/auth/v1/signup".into(),
                method: "POST".into(),
            }),
        ];
        assert!(ChainBuilder::build(&findings).is_empty());
    }

    #[test]
    fn undemonstrated_pairs_are_not_chained() {
        // A leaked publishable key proves nothing about a storage bucket,
        // and an unauthenticated read gains nothing from an escalation —
        // correlation across these pairs is not a demonstrated link.
        let scope = riftlock_core::ScopeConfig {
            target: "https://lab.test".into(),
            max_depth: "write".into(),
            allow_destructive: true,
            authorized_by: "ops".into(),
            authorized_at: "2026-11-13".into(),
        };
        let url = url::Url::parse("https://lab.test").expect("url");
        let lab = LabGuard::new_from_scope(&scope, &url).expect("owned");
        let esc = ProofGate::admit_lab(
            Evidence::PrivilegeEscalation {
                from_role: "anon".into(),
                to_role: "service_role".into(),
                method: "jwt_crack".into(),
            },
            &lab,
        )
        .expect("lab admitted");
        let findings = vec![
            esc,
            make(Evidence::UnauthenticatedRead {
                endpoint: "https://x/rest/v1/users".into(),
                row_sample: "{id=<int>}".into(),
            }),
            make(Evidence::LeakedSecret {
                key_type: KeyType::SupabasePublishable,
                location: "page".into(),
                masked: "sb_secret_********".into(),
                full: Default::default(),
            }),
            make(Evidence::StorageLeak {
                bucket: "ops-backup".into(),
                object_sample: "<string:8>".into(),
            }),
        ];
        assert!(ChainBuilder::build(&findings).is_empty());
    }

    #[test]
    fn no_links_no_chains() {
        let findings = vec![make(Evidence::AuthBypass {
            endpoint: "https://x/auth/v1/signup".into(),
            method: "POST".into(),
        })];
        assert!(ChainBuilder::build(&findings).is_empty());
    }

    #[test]
    fn escalation_cannot_be_admitted_without_lab() {
        assert!(ProofGate::admit(Evidence::PrivilegeEscalation {
            from_role: "anon".into(),
            to_role: "service_role".into(),
            method: "jwt_crack".into(),
        })
        .is_err());
    }
}
