//! Structured scan metadata shared by machine-readable reports.

use riftlock_core::{
    AccountingValidation, CoverageSnapshot, CrawlMetrics, EndpointOutcome, EndpointRecord,
};
/// Version of the machine-readable report schema.
pub const REPORT_SCHEMA_VERSION: u8 = 1;

/// Assessment metadata carried alongside findings in JSON/NDJSON.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanMetadata {
    pub schema_version: u8,
    pub scan_id: String,
    pub target: String,
    pub scope: Vec<String>,
    /// Shared verdict label, identical to the terminal and SARIF label.
    pub verdict: String,
    pub discovery_status: String,
    pub coverage: CoverageSnapshot,
    /// Endpoint-level negative space, including classified and unreached URLs.
    pub untested_surface: Vec<EndpointRecord>,
    /// Planned endpoints that no engine reached and therefore has no outcome for.
    pub unreached_endpoints: Vec<String>,
    /// Stage-by-stage crawl accounting; empty when discovery was skipped.
    pub crawl: CrawlMetrics,
    pub accounting: AccountingValidation,
    pub unaccounted_executions: u64,
    pub engines_executed: usize,
    pub engines_failed: usize,
    /// Number of endpoints in the discovery inventory, independent of scanner plans.
    pub discovered_inventory_endpoints: usize,
    /// Generic scanner's endpoint denominator, distinct from discovered inventory.
    pub generic_planned_endpoints: usize,
    pub passive_observations: u64,
    pub findings: usize,
    /// Engine-level failures with their real error text.
    pub scanner_failures: Vec<String>,
    pub termination_reason: String,
}

impl ScanMetadata {
    #[must_use]
    pub fn new(scan_id: String, target: String, verdict: String, discovery_status: String) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            scan_id,
            target,
            scope: Vec::new(),
            verdict,
            discovery_status,
            coverage: CoverageSnapshot::default(),
            untested_surface: Vec::new(),
            unreached_endpoints: Vec::new(),
            crawl: CrawlMetrics::default(),
            accounting: AccountingValidation {
                registered: 0,
                terminal: 0,
                in_flight: 0,
                duplicates_rejected: 0,
            },
            unaccounted_executions: 0,
            engines_executed: 0,
            engines_failed: 0,
            discovered_inventory_endpoints: 0,
            generic_planned_endpoints: 0,
            passive_observations: 0,
            findings: 0,
            scanner_failures: Vec::new(),
            termination_reason: String::new(),
        }
    }

    /// Convert to a JSON value without requiring a serde dependency here.
    #[must_use]
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "target": self.target,
            "scope": self.scope,
            "verdict": self.verdict,
            "discovery_status": self.discovery_status,
            "coverage": self.coverage,
            "untested_surface": self.untested_surface.iter().map(|record| {
                let outcome = match record.outcome {
                    EndpointOutcome::Tested => "tested",
                    EndpointOutcome::TimedOut => "timed_out",
                    EndpointOutcome::Failed => "failed",
                    EndpointOutcome::AuthRequired => "auth_required",
                    EndpointOutcome::WafBlocked => "waf_blocked",
                    EndpointOutcome::Skipped => "skipped",
                    EndpointOutcome::CircuitOpen => "circuit_open",
                    _ => "unknown",
                };
                serde_json::json!({"url": record.url, "outcome": outcome})
            }).collect::<Vec<_>>(),
            "unreached_endpoints": self.unreached_endpoints,
            "crawl": self.crawl,
            "accounting": {
                "registered": self.accounting.registered,
                "terminal": self.accounting.terminal,
                "in_flight": self.accounting.in_flight,
                "duplicates_rejected": self.accounting.duplicates_rejected,
            },
            "unaccounted_executions": self.unaccounted_executions,
            "engines_executed": self.engines_executed,
            "engines_failed": self.engines_failed,
            "discovered_inventory_endpoints": self.discovered_inventory_endpoints,
            "generic_planned_endpoints": self.generic_planned_endpoints,
            "passive_observations": self.passive_observations,
            "findings": self.findings,
            "scanner_failures": self.scanner_failures,
            "termination_reason": self.termination_reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_serializes_with_schema_version() {
        let meta = ScanMetadata::new(
            "s1".into(),
            "https://x".into(),
            "CLEAN".into(),
            "complete".into(),
        );
        let json = meta.to_value().to_string();
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"verdict\":\"CLEAN\""));
    }
}
