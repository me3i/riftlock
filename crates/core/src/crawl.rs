//! Structured crawl accounting: every URL candidate's disposition, with the
//! exact pipeline stage that classified it. Counters are maintained at the
//! transitions in [`riftlock_discovery::crawler`], never inferred afterwards.

use serde::Serialize;

/// Crawl-stage counters. The equations in [`Self::reconciles`] are the
/// contract: a crawl that cannot balance its own counts is reported as
/// incomplete rather than rounded into a clean inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CrawlMetrics {
    /// Raw `href`/`src`/`action` values extracted from fetched pages.
    pub raw_extracted: u64,
    /// Raw values canonicalization rejected (empty, malformed, non-HTTP).
    pub malformed_rejected: u64,
    /// Raw values canonicalization accepted (before scope/dedup).
    pub normalization_accepted: u64,
    /// First-seen, in-scope URLs recorded in the inventory.
    pub unique_in_scope: u64,
    /// Canonical URLs rejected by `ScopeGuard` (external/private).
    pub external_excluded: u64,
    /// Canonical URLs already recorded (first-seen wins).
    pub duplicates_removed: u64,
    /// Canonical URLs deliberately not fetched (logout/session-killing,
    /// unsupported scheme).
    pub policy_excluded: u64,
    /// URLs enqueued for crawling (start page, seeds, links, bundles).
    pub scheduled: u64,
    /// Scheduled URLs fetched successfully.
    pub tested: u64,
    /// Scheduled URLs deliberately not fetched (depth/page cap, 404/410).
    pub skipped: u64,
    /// Scheduled URLs answered by a WAF/auth wall (401/403/406/429/503).
    pub blocked: u64,
    /// Scheduled URLs whose transport failed without timing out.
    pub failed: u64,
    /// Scheduled URLs whose request or body read timed out.
    pub timed_out: u64,
    /// Scheduled URLs still queued when the crawl stopped.
    pub remaining: u64,
    /// Configured page budget for this crawl.
    pub budget_configured: u64,
    /// Pages actually fetched (the page budget counter).
    pub budget_consumed: u64,
    /// Why the crawl ended: `queue_exhausted`, `deadline`, or `page_budget`.
    pub termination_reason: String,
}

impl CrawlMetrics {
    /// `raw = malformed + accepted`.
    #[must_use]
    pub fn normalization_reconciles(&self) -> bool {
        self.raw_extracted == self.malformed_rejected + self.normalization_accepted
    }

    /// `accepted = unique + external + duplicates + policy-excluded`.
    #[must_use]
    pub fn disposition_reconciles(&self) -> bool {
        self.normalization_accepted
            == self.unique_in_scope
                + self.external_excluded
                + self.duplicates_removed
                + self.policy_excluded
    }

    /// `scheduled = tested + skipped + blocked + failed + timed_out + remaining`.
    #[must_use]
    pub fn schedule_reconciles(&self) -> bool {
        self.scheduled
            == self.tested
                + self.skipped
                + self.blocked
                + self.failed
                + self.timed_out
                + self.remaining
    }

    /// Every equation holds.
    #[must_use]
    pub fn reconciles(&self) -> bool {
        self.normalization_reconciles()
            && self.disposition_reconciles()
            && self.schedule_reconciles()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equations_hold_for_a_balanced_crawl() {
        let m = CrawlMetrics {
            raw_extracted: 10,
            malformed_rejected: 2,
            normalization_accepted: 8,
            unique_in_scope: 3,
            external_excluded: 3,
            duplicates_removed: 1,
            policy_excluded: 1,
            scheduled: 9,
            tested: 5,
            skipped: 1,
            blocked: 1,
            failed: 1,
            timed_out: 0,
            remaining: 1,
            budget_configured: 50,
            budget_consumed: 5,
            termination_reason: "queue_exhausted".into(),
        };
        assert!(m.reconciles());
    }

    #[test]
    fn a_dropped_candidate_breaks_reconciliation() {
        let mut m = CrawlMetrics {
            raw_extracted: 2,
            malformed_rejected: 1,
            normalization_accepted: 1,
            unique_in_scope: 1,
            ..Default::default()
        };
        assert!(m.reconciles());
        m.raw_extracted += 1;
        assert!(!m.reconciles());
        m.malformed_rejected += 1;
        assert!(m.reconciles());
        m.external_excluded += 1;
        assert!(!m.disposition_reconciles());
    }
}
