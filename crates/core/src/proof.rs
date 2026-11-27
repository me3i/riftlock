//! The proof gate: the only path from [`Evidence`] to a [`Finding`].

use crate::types::Evidence;
use serde::Serialize;
use url::Url;

/// How strongly a finding is proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Confidence {
    /// Hard evidence: the gate admitted it without verifier help.
    Confirmed,
    /// The claim was judged supported by the LLM verifier.
    High,
    /// Plausible but unproven signal — triage only.
    Potential,
    /// The check could not reach a verdict (WAF block, timeout): surfaced
    /// in coverage, never fabricated into a finding.
    Inconclusive,
    /// The check ran and definitively found nothing (checked negative).
    NotVulnerable,
}

/// A confirmed finding. Private constructor; only [`ProofGate::admit`] can
/// build one, and only from valid [`Evidence`].
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    evidence: Evidence,
    confidence: Confidence,
}

impl Finding {
    /// The stored evidence for this finding.
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// How strongly this finding is proven.
    #[must_use]
    pub fn confidence(&self) -> Confidence {
        self.confidence
    }
}

/// Rejection reason for the proof gate.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofError {
    /// Heuristic material cannot become a finding.
    #[error("proof rejected: heuristic material cannot become a finding")]
    Heuristic,
    /// Lab-only evidence was offered without a lab guard.
    #[error("proof rejected: write/logic evidence requires an owned lab (LabGuard)")]
    NoLab,
}

/// Guard proving the target is a lab environment owned by the operator.
/// Write and business-logic evidence can only be admitted through
/// [`ProofGate::admit_lab`], which requires this guard.
#[derive(Debug, Clone)]
pub struct LabGuard {
    _private: (),
}

impl LabGuard {
    /// Create a lab guard from a scope file. Only succeeds when the scope
    /// authorizes destructive probes for `url`'s host.
    ///
    /// # Errors
    /// [`ProofError::NoLab`] when the scope does not authorize `url`.
    pub fn new_from_scope(
        scope: &crate::scope_file::ScopeConfig,
        url: &Url,
    ) -> Result<Self, ProofError> {
        if scope.is_destructive_allowed(url) {
            Ok(Self { _private: () })
        } else {
            Err(ProofError::NoLab)
        }
    }

    /// Lab guard authorized directly by the operator — used only when the
    /// operator typed the interactive confirmation. Skips the scope-file
    /// check by design; no CLI flag reaches this constructor.
    #[must_use]
    pub fn new_unsafe() -> Self {
        Self { _private: () }
    }
}

/// Gate that admits findings only from one of the three evidence variants.
#[derive(Debug, Default)]
pub struct ProofGate;

impl ProofGate {
    /// Admit `evidence` as a finding. Anything that is not valid evidence is
    /// rejected.
    ///
    /// Passive observations and fingerprints are admitted as
    /// [`Confidence::Potential`]: they stay reportable without being promoted
    /// to a confirmed vulnerability. Probe-derived and actively verified
    /// evidence is [`Confidence::Confirmed`].
    ///
    /// # Errors
    /// [`ProofError::Heuristic`] for an empty chain or static client-side signal;
    /// [`ProofError::NoLab`] for lab-only variants (use [`Self::admit_lab`]).
    pub fn admit(evidence: Evidence) -> Result<Finding, ProofError> {
        match &evidence {
            Evidence::Chain { steps, .. } if steps.iter().all(|s| !s.is_empty()) => Ok(Finding {
                evidence,
                confidence: Confidence::Confirmed,
            }),
            // Static client-side matches are signals, not executable proof.
            Evidence::ClientSideFlaw { .. } => Err(ProofError::Heuristic),
            // Lab-only variants require admit_lab.
            Evidence::WriteProof { .. }
            | Evidence::IdorProof { .. }
            | Evidence::BusinessLogicBypass { .. }
            | Evidence::PrivilegeEscalation { .. }
            | Evidence::MassAssignment { .. } => Err(ProofError::NoLab),
            // Empty or otherwise invalid chain.
            Evidence::Chain { .. } => Err(ProofError::Heuristic),
            _ => Ok(Finding {
                confidence: match evidence.provenance() {
                    crate::types::ProvenanceKind::PassiveObservation
                    | crate::types::ProvenanceKind::Fingerprint => Confidence::Potential,
                    crate::types::ProvenanceKind::ProbeDerived
                    | crate::types::ProvenanceKind::ActivelyVerified => Confidence::Confirmed,
                },
                evidence,
            }),
        }
    }

    /// Admit lab-only evidence (write/IDOR/business-logic) and privilege
    /// escalation. Requires a [`LabGuard`] proving the target is an owned
    /// lab.
    pub fn admit_lab(evidence: Evidence, _lab: &LabGuard) -> Result<Finding, ProofError> {
        match &evidence {
            Evidence::WriteProof { .. }
            | Evidence::IdorProof { .. }
            | Evidence::BusinessLogicBypass { .. }
            | Evidence::PrivilegeEscalation { .. }
            | Evidence::MassAssignment { .. } => Ok(Finding {
                evidence,
                confidence: Confidence::Confirmed,
            }),
            _ => Err(ProofError::Heuristic),
        }
    }

    /// Admit evidence, with LLM verification required for uncertain claims.
    ///
    /// A claim is uncertain when it describes a `206`/`300` status or a
    /// `200` with an HTML body on a `Differential` or `UnauthenticatedRead`
    /// (see [`crate::verify::claim_is_uncertain`]). Uncertain evidence is
    /// admitted only when `verifier` judges the claim supported; anything
    /// else follows the ordinary [`ProofGate::admit`] rules.
    pub fn admit_with_verifier(
        evidence: Evidence,
        verifier: &dyn crate::verify::Verifier,
        claim: &str,
    ) -> Result<Finding, ProofError> {
        let uncertain = matches!(
            &evidence,
            Evidence::Differential { .. } | Evidence::UnauthenticatedRead { .. }
        ) && crate::verify::claim_is_uncertain(claim);
        if uncertain {
            return if crate::verify::wait_for(verifier.verify(claim, &evidence)) {
                // Verifier-approved: supported, but not hard evidence.
                Ok(Finding {
                    evidence,
                    confidence: Confidence::High,
                })
            } else {
                Err(ProofError::Heuristic)
            };
        }
        Self::admit(evidence)
    }
}

/// Report-tier confidence states: the gate produces only Confirmed and
/// High findings — inconclusive checks surface through
/// [`crate::coverage::Coverage`] counters instead of fabricated findings,
/// and `NotVulnerable` marks a completed negative check.
impl Confidence {
    /// True for findings that carry proof or verifier support.
    #[must_use]
    pub fn is_actionable(self) -> bool {
        matches!(self, Self::Confirmed | Self::High)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::Verifier;
    use std::future::Future;
    use std::pin::Pin;

    struct Yes;
    struct No;

    fn fixed(v: bool) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        Box::pin(async move { v })
    }

    impl Verifier for Yes {
        fn verify<'a>(
            &'a self,
            _: &'a str,
            _: &'a Evidence,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            fixed(true)
        }
    }

    impl Verifier for No {
        fn verify<'a>(
            &'a self,
            _: &'a str,
            _: &'a Evidence,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            fixed(false)
        }
    }

    #[test]
    fn uncertain_claim_requires_verifier_yes() {
        let e = Evidence::UnauthenticatedRead {
            endpoint: "https://x/.json".into(),
            row_sample: "<html>".into(),
        };
        let claim = "status=200 body=html";
        assert!(ProofGate::admit_with_verifier(e.clone(), &Yes, claim).is_ok());
        assert!(ProofGate::admit_with_verifier(e, &No, claim).is_err());
    }

    #[test]
    fn non_uncertain_evidence_follows_normal_rules() {
        let e = Evidence::UnauthenticatedRead {
            endpoint: "https://x/rest/v1/users".into(),
            row_sample: "{id=<int>}".into(),
        };
        assert!(ProofGate::admit_with_verifier(e, &No, "status=200").is_ok());
    }

    #[test]
    fn uncertain_status_codes() {
        let e = Evidence::Differential {
            without_key: 206,
            with_key: 200,
            inverted: false,
            cross_tenant: false,
            note: None,
        };
        assert!(ProofGate::admit_with_verifier(e.clone(), &Yes, "status=206").is_ok());
        assert!(ProofGate::admit_with_verifier(e, &Yes, "status=300").is_ok());
    }

    #[test]
    fn web_and_spa_evidence_is_admitted() {
        let samples = [
            Evidence::XssReflection {
                url: "https://x/s".into(),
                param: "q".into(),
                context: "html".into(),
            },
            Evidence::SqliError {
                url: "https://x/s".into(),
                param: "q".into(),
                error_signature: "SQL syntax".into(),
            },
            Evidence::SqliTimeDelay {
                url: "https://x/s".into(),
                param: "q".into(),
                delay_ms: 5_000,
            },
            Evidence::CsrfMissingToken {
                url: "https://x/f".into(),
                form_action: "/login".into(),
            },
            Evidence::SpaEndpoint {
                url: "https://x/api/v1/users".into(),
                source: "xhr".into(),
            },
        ];
        for e in samples {
            assert!(ProofGate::admit(e).is_ok());
        }
    }

    #[test]
    fn static_client_side_signals_are_rejected_as_findings() {
        for evidence in [
            Evidence::ClientSideFlaw {
                endpoint: "https://x/app.js".into(),
                flaw_type: "dom_xss".into(),
                snippet: "el.innerHTML = input".into(),
            },
            Evidence::ClientSideFlaw {
                endpoint: "https://x/app.js".into(),
                flaw_type: "postmessage".into(),
                snippet: "handle(event.data)".into(),
            },
            Evidence::ClientSideFlaw {
                endpoint: "https://x/app.js".into(),
                flaw_type: "insecure_storage".into(),
                snippet: "localStorage.setItem(\"authToken\", token)".into(),
            },
        ] {
            assert!(matches!(
                ProofGate::admit(evidence),
                Err(ProofError::Heuristic)
            ));
        }
    }

    #[test]
    fn passive_observations_are_reportable_but_not_confirmed() {
        let cases = [
            Evidence::CsrfMissingToken {
                url: "https://x/f".into(),
                form_action: "/login".into(),
            },
            Evidence::SecurityMisconfiguration {
                url: "https://x/".into(),
                issue: "missing_csp".into(),
                severity: "Medium".into(),
            },
            Evidence::SensitiveDataExposure {
                url: "https://x/page".into(),
                data_type: "ssn".into(),
            },
            Evidence::XssReflection {
                url: "https://x/s".into(),
                param: "q".into(),
                context: "json".into(),
            },
            Evidence::LeakedSecret {
                key_type: crate::types::KeyType::SupabaseSecret,
                location: "https://x/app.js".into(),
                masked: "sb_secret_****".into(),
                full: Default::default(),
            },
        ];
        for evidence in cases {
            assert!(evidence.is_passive_observation(), "{evidence:?}");
            let finding = ProofGate::admit(evidence).expect("valid passive evidence");
            assert_eq!(finding.confidence(), Confidence::Potential);
            assert_eq!(
                finding.evidence().provenance(),
                crate::types::ProvenanceKind::PassiveObservation
            );
        }
    }

    #[test]
    fn fingerprints_are_not_confirmed_vulnerabilities() {
        for evidence in [
            Evidence::TechFingerprint {
                technology: "Next.js".into(),
                version: None,
                confidence: 90,
            },
            Evidence::SpaEndpoint {
                url: "https://x/api/v1/users".into(),
                source: "static".into(),
            },
        ] {
            let finding = ProofGate::admit(evidence).expect("fingerprint");
            assert_eq!(finding.confidence(), Confidence::Potential);
            assert_eq!(
                finding.evidence().provenance(),
                crate::types::ProvenanceKind::Fingerprint
            );
        }
    }

    #[test]
    fn probe_and_verified_evidence_stay_confirmed() {
        let probe = ProofGate::admit(Evidence::SqliError {
            url: "https://x/s".into(),
            param: "q".into(),
            error_signature: "SQL syntax".into(),
        })
        .expect("probe");
        assert_eq!(probe.confidence(), Confidence::Confirmed);
        assert_eq!(
            probe.evidence().provenance(),
            crate::types::ProvenanceKind::ProbeDerived
        );

        let verified = ProofGate::admit(Evidence::JwtVulnerability {
            endpoint: "https://x/admin".into(),
            issue: "alg_none".into(),
        })
        .expect("verified");
        assert_eq!(verified.confidence(), Confidence::Confirmed);
        assert_eq!(
            verified.evidence().provenance(),
            crate::types::ProvenanceKind::ActivelyVerified
        );
    }

    #[test]
    fn lab_variants_still_rejected_here() {
        let e = Evidence::WriteProof {
            table: "t".into(),
            marker_id: "m".into(),
            cleaned_up: true,
        };
        assert!(ProofGate::admit_with_verifier(e, &Yes, "status=200").is_err());
    }
}
