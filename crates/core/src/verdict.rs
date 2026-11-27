//! One reconciliation of findings and coverage into a reportable verdict.

/// The outcome of a scan, separating "what was found" from "how much was
/// actually assessed". Both facts must reach the user: a scan can find real
/// evidence while still having incomplete coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanVerdict {
    /// Findings supported by evidence.
    pub findings: u64,
    /// Findings that are passive observations or static indicators, not
    /// completed active probes.
    pub passive_observations: u64,
    /// Active checks that executed and reached a verdict.
    pub completed_checks: u64,
    /// Active checks that were attempted but stayed inconclusive.
    pub inconclusive_checks: u64,
    /// Checks that failed to execute.
    pub failed_checks: u64,
    /// Checks deliberately not executed.
    pub skipped_checks: u64,
    /// Whether discovery and every engine completed.
    pub coverage_complete: bool,
}

impl ScanVerdict {
    /// Single stable status string used by the terminal and every report.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match (self.findings > 0, self.coverage_complete) {
            (true, true) => "FINDINGS",
            (true, false) => "FINDINGS + INCOMPLETE COVERAGE",
            (false, true) => "CLEAN",
            (false, false) => "INCOMPLETE",
        }
    }

    /// True when real evidence was found, independent of coverage.
    #[must_use]
    pub fn has_findings(self) -> bool {
        self.findings > 0
    }

    /// True when discovery and all engines completed.
    #[must_use]
    pub fn is_complete(self) -> bool {
        self.coverage_complete
    }

    /// Completed active checks plus inconclusive ones must equal attempted
    /// checks; failed and skipped checks are never clean negatives.
    #[must_use]
    pub fn reconciles(self, attempted: u64) -> bool {
        self.completed_checks + self.inconclusive_checks <= attempted
            && self.passive_observations <= self.findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(findings: u64, complete: bool) -> ScanVerdict {
        ScanVerdict {
            findings,
            passive_observations: 0,
            completed_checks: 0,
            inconclusive_checks: 0,
            failed_checks: 0,
            skipped_checks: 0,
            coverage_complete: complete,
        }
    }

    #[test]
    fn status_communicates_findings_and_coverage_separately() {
        assert_eq!(verdict(0, true).label(), "CLEAN");
        assert_eq!(verdict(0, false).label(), "INCOMPLETE");
        assert_eq!(verdict(50, true).label(), "FINDINGS");
        assert_eq!(verdict(50, false).label(), "FINDINGS + INCOMPLETE COVERAGE");
    }

    #[test]
    fn failed_and_skipped_checks_are_never_completed_or_clean() {
        let mut v = verdict(2, false);
        v.failed_checks = 2;
        v.skipped_checks = 3;
        v.passive_observations = 2;
        assert!(v.has_findings());
        assert!(!v.is_complete());
        assert!(v.reconciles(0), "passive findings are not active checks");
        assert_eq!(v.completed_checks, 0);
    }
}
