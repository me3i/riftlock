//! Crash-recovery checkpoints for scan runs. A scan checkpoints its
//! discovery results and every engine outcome as they land, so an
//! interrupted run resumes with `--resume <scan_id>` without re-firing
//! engines that already completed — completed engines keep their findings,
//! and destructive probes are never re-sent because of a resume.
//!
//! Secret-safety invariant: a checkpoint stores scope, config, discovered
//! endpoints and redacted-by-construction evidence (masked keys, typed row
//! samples) only. Credentials, cookies and session tokens live in env vars
//! and are re-read on resume — never persisted here.

use riftlock_core::{Evidence, Finding};
use riftlock_discovery::DiscoveredEndpoint;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

/// Bumped when the checkpoint layout changes; a loader refuses files from
/// another version instead of misreading them.
const CHECKPOINT_VERSION: u32 = 1;

/// The scan settings a resume restores (the resolved `ScanOptions`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointConfig {
    pub provider: String,
    pub passive_only: bool,
    /// The resolved depth label (`Normal`, `Read`, or `Godmode`).
    pub depth: String,
    pub allow_private: bool,
    pub unsafe_bypass: bool,
    pub scope_file: Option<String>,
    pub wordlist: Option<String>,
    pub godmode: bool,
}

/// One scan run's crash-recovery state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub checkpoint_version: u32,
    pub scan_id: String,
    pub target: String,
    /// The scope origins the run was authorized for.
    pub scope: Vec<String>,
    pub config: CheckpointConfig,
    /// Backward-compatible path-only endpoint inventory used by existing scanners.
    pub discovered_endpoints: Vec<String>,
    /// Method-aware discovery inventory. Missing in older checkpoints; paths
    /// remain available through `discovered_endpoints`.
    #[serde(default)]
    pub discovered_endpoint_methods: Vec<DiscoveredEndpoint>,
    /// Whether discovery ran to a completed result. An empty inventory is a
    /// real result only when this is true; a failed or timed-out discovery
    /// leaves it false and is retried on resume. Legacy checkpoints default
    /// to false, so they re-run discovery instead of trusting an empty list.
    #[serde(default)]
    pub discovery_complete: bool,
    /// Why the last discovery attempt failed or was partial, when it did.
    #[serde(default)]
    pub discovery_error: Option<String>,
    /// RPC function names and Next.js action ids discovery found.
    pub rpc_functions: Vec<String>,
    pub action_ids: Vec<String>,
    /// Engines that ran to completion this scan (skip on resume).
    pub completed_tasks: Vec<String>,
    /// Engines that failed or panicked, with the reason.
    pub failed_tasks: Vec<String>,
    /// Evidence the completed engines produced — already gate-admitted,
    /// redacted by construction; re-admitted through the gate on resume.
    pub findings: Vec<Evidence>,
    /// Serialized keys of `findings`, rebuilt on load. An in-memory index so
    /// recording a streamed finding is a set lookup, never a scan.
    #[serde(skip)]
    finding_keys: HashSet<String>,
}

/// Two checkpoints are equal when their persisted state is: the finding index
/// is derived from `findings` and never compared.
impl PartialEq for Checkpoint {
    fn eq(&self, other: &Self) -> bool {
        self.checkpoint_version == other.checkpoint_version
            && self.scan_id == other.scan_id
            && self.target == other.target
            && self.scope == other.scope
            && self.config == other.config
            && self.discovered_endpoints == other.discovered_endpoints
            && self.discovered_endpoint_methods == other.discovered_endpoint_methods
            && self.discovery_complete == other.discovery_complete
            && self.discovery_error == other.discovery_error
            && self.rpc_functions == other.rpc_functions
            && self.action_ids == other.action_ids
            && self.completed_tasks == other.completed_tasks
            && self.failed_tasks == other.failed_tasks
            && self.findings == other.findings
    }
}

impl Checkpoint {
    /// The checkpoint file for a scan id, in the working directory.
    fn path(scan_id: &str) -> PathBuf {
        PathBuf::from(format!("riftlock-checkpoint-{scan_id}.json"))
    }

    /// Append-only NDJSON sidecar for streamed findings: one line per finding
    /// so persisting one never rewrites the whole checkpoint.
    fn findings_path(scan_id: &str) -> PathBuf {
        PathBuf::from(format!("riftlock-checkpoint-{scan_id}.findings.ndjson"))
    }

    /// A fresh checkpoint for a starting scan.
    pub fn new(scan_id: &str, target: &str, scope: Vec<String>, config: CheckpointConfig) -> Self {
        Checkpoint {
            checkpoint_version: CHECKPOINT_VERSION,
            scan_id: scan_id.to_owned(),
            target: target.to_owned(),
            scope,
            config,
            discovered_endpoints: Vec::new(),
            discovered_endpoint_methods: Vec::new(),
            discovery_complete: false,
            discovery_error: None,
            rpc_functions: Vec::new(),
            action_ids: Vec::new(),
            completed_tasks: Vec::new(),
            failed_tasks: Vec::new(),
            findings: Vec::new(),
            finding_keys: HashSet::new(),
        }
    }

    /// Write the checkpoint atomically (tmp file + rename): a kill mid-save
    /// never truncates the previous good state. Best-effort — a failed
    /// checkpoint write warns but never aborts the scan it protects.
    pub fn save(&self) {
        let path = Self::path(&self.scan_id);
        let tmp = path.with_extension("json.tmp");
        let json = match serde_json::to_string_pretty(self) {
            Ok(j) => j,
            Err(e) => {
                riftlock_core::logger::line(&format!("warning: checkpoint serialize failed: {e}"));
                return;
            }
        };
        if let Err(e) = std::fs::write(&tmp, json) {
            riftlock_core::logger::line(&format!(
                "warning: cannot write checkpoint {}: {e}",
                tmp.display()
            ));
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            riftlock_core::logger::line(&format!(
                "warning: cannot persist checkpoint {}: {e}",
                path.display()
            ));
        }
    }

    /// Load a checkpoint for `--resume <scan_id>`.
    ///
    /// # Errors
    /// The file is missing, unreadable, unparseable, or from an
    /// incompatible checkpoint version.
    pub fn load(scan_id: &str) -> Result<Self, String> {
        let path = Self::path(scan_id);
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read checkpoint {}: {e}", path.display()))?;
        let mut ck: Checkpoint = serde_json::from_str(&raw)
            .map_err(|e| format!("cannot parse checkpoint {}: {e}", path.display()))?;
        if ck.checkpoint_version != CHECKPOINT_VERSION {
            return Err(format!(
                "checkpoint version {} is not supported (expected {CHECKPOINT_VERSION})",
                ck.checkpoint_version
            ));
        }
        ck.finding_keys = ck.findings.iter().map(finding_key).collect();
        // Merge findings streamed after the last full save; duplicates (the
        // first streamed finding also lands in the main document) collapse.
        let sidecar = Self::findings_path(scan_id);
        if let Ok(raw) = std::fs::read_to_string(&sidecar) {
            for line in raw.lines().filter(|line| !line.trim().is_empty()) {
                match serde_json::from_str::<Evidence>(line) {
                    Ok(evidence) => {
                        ck.insert_finding(evidence);
                    }
                    Err(e) => riftlock_core::logger::line(&format!(
                        "warning: skipping unreadable streamed finding in {}: {e}",
                        sidecar.display()
                    )),
                }
            }
        }
        Ok(ck)
    }

    /// Delete the checkpoint files: called when the scan completed, so only
    /// interrupted scans leave a resumable file behind. Best-effort.
    pub fn remove(&self) {
        let _ = std::fs::remove_file(Self::path(&self.scan_id));
        let _ = std::fs::remove_file(Self::findings_path(&self.scan_id));
    }

    /// Add `evidence` unless already recorded.
    fn insert_finding(&mut self, evidence: Evidence) {
        if self.finding_keys.insert(finding_key(&evidence)) {
            self.findings.push(evidence);
        }
    }

    /// Record an engine that ran to completion and checkpoint its findings.
    pub fn record_completed(&mut self, engine: &str, findings: &[Finding]) {
        self.completed_tasks.push(engine.to_owned());
        for evidence in findings.iter().map(Finding::evidence) {
            self.insert_finding(evidence.clone());
        }
        self.save();
    }

    /// Persist a proof-gated event before its engine can time out or be cancelled.
    pub fn record_streamed_finding(&mut self, evidence: &Evidence) {
        let key = finding_key(evidence);
        if !self.finding_keys.insert(key.clone()) {
            return;
        }
        self.findings.push(evidence.clone());
        // One appended line per finding; the full document is written only to
        // create it, so streaming is O(1) instead of a rewrite per finding.
        let sidecar = Self::findings_path(&self.scan_id);
        let line = format!("{key}\n");
        let appended = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&sidecar)
            .and_then(|mut file| std::io::Write::write_all(&mut file, line.as_bytes()));
        if let Err(e) = appended {
            riftlock_core::logger::line(&format!(
                "warning: cannot append streamed finding {}: {e}",
                sidecar.display()
            ));
        }
        if !Self::path(&self.scan_id).exists() {
            self.save();
        }
    }

    /// Record an engine that failed or panicked, with its real reason.
    pub fn record_failed(&mut self, engine: &str, reason: &str) {
        self.failed_tasks.push(format!("{engine}: {reason}"));
        self.save();
    }
}

/// A stable content key for a finding, identical to its sidecar line.
fn finding_key(evidence: &Evidence) -> String {
    serde_json::to_string(evidence).unwrap_or_else(|_| format!("{evidence:?}"))
}

/// A scan id for a fresh run: wall-clock seconds plus a hash of the target
/// and process id, so concurrent scans never share a checkpoint file.
pub fn new_scan_id(target: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    target.hash(&mut h);
    std::process::id().hash(&mut h);
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    format!("scan-{secs:x}-{:08x}", h.finish() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::ProofGate;

    fn sample() -> Checkpoint {
        Checkpoint::new(
            "scan-test-0",
            "https://t",
            vec!["https://t".into()],
            CheckpointConfig {
                provider: "auto".into(),
                passive_only: false,
                depth: "Read".into(),
                allow_private: true,
                unsafe_bypass: false,
                scope_file: None,
                wordlist: None,
                godmode: false,
            },
        )
    }

    #[test]
    fn roundtrips_through_json_and_records_outcomes() {
        let mut ck = sample();
        let f = ProofGate::admit(Evidence::AuthBypass {
            endpoint: "https://t/auth".into(),
            method: "POST".into(),
        })
        .expect("admitted");
        ck.record_completed("Generic", std::slice::from_ref(&f));
        ck.record_failed("Auth", "panicked");
        assert_eq!(ck.completed_tasks, vec!["Generic"]);
        assert_eq!(ck.failed_tasks, vec!["Auth: panicked"]);
        assert_eq!(ck.findings, vec![f.evidence().clone()]);

        let json = serde_json::to_string_pretty(&ck).expect("json");
        let back: Checkpoint = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(back, ck);
        assert_eq!(back.checkpoint_version, CHECKPOINT_VERSION);
        // The persisted form carries evidence, not credentials.
        assert!(!json.to_lowercase().contains("cookie"));
        assert!(!json.to_lowercase().contains("authorization"));
    }

    #[test]
    fn streamed_findings_are_persisted_before_engine_completion() {
        let mut ck = sample();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        ck.scan_id = format!("scan-streamed-{}-{nonce}", std::process::id());
        let evidence = Evidence::LeakedSecret {
            key_type: riftlock_core::KeyType::SupabaseSecret,
            location: "https://t/app.js".into(),
            masked: "sb_secret_****".into(),
            full: riftlock_core::SecretValue("sb_secret_streamedFullValue".into()),
        };

        ck.record_streamed_finding(&evidence);
        ck.record_streamed_finding(&evidence);

        let raw = std::fs::read_to_string(Checkpoint::path(&ck.scan_id)).expect("saved checkpoint");
        assert!(!raw.contains("sb_secret_streamedFullValue"));
        let loaded = Checkpoint::load(&ck.scan_id).expect("load checkpoint");
        assert!(loaded.completed_tasks.is_empty());
        assert_eq!(loaded.findings.len(), 1);
        match &loaded.findings[0] {
            Evidence::LeakedSecret { masked, full, .. } => {
                assert_eq!(masked, "sb_secret_****");
                assert!(full.0.is_empty());
            }
            other => panic!("unexpected evidence: {other:?}"),
        }
        loaded.remove();
    }

    #[test]
    fn checkpoint_never_persists_full_credential_value() {
        let mut ck = sample();
        let f = ProofGate::admit(Evidence::LeakedSecret {
            key_type: riftlock_core::KeyType::SupabaseSecret,
            location: "https://t/app.js".into(),
            masked: "sb_secret_****".into(),
            full: riftlock_core::SecretValue("sb_secret_AbC123xYz".into()),
        })
        .expect("admitted");
        ck.record_completed("Supabase", std::slice::from_ref(&f));
        let json = serde_json::to_string_pretty(&ck).expect("json");
        assert!(
            !json.contains("sb_secret_AbC123xYz"),
            "full secret in checkpoint"
        );
        assert!(
            json.contains("sb_secret_****"),
            "masked value should persist"
        );
        let back: Checkpoint = serde_json::from_str(&json).expect("roundtrip");
        // The skipped full field is rebuilt empty on load, never from disk.
        match &back.findings[0] {
            Evidence::LeakedSecret { full, .. } => assert!(full.0.is_empty()),
            other => panic!("unexpected evidence: {other:?}"),
        }
    }

    #[test]
    fn discovery_failure_is_distinct_from_completed_empty_discovery() {
        // Completed discovery with nothing found: skip the crawl on resume.
        let mut complete = sample();
        complete.discovery_complete = true;
        let json = serde_json::to_string(&complete).expect("json");
        let back: Checkpoint = serde_json::from_str(&json).expect("roundtrip");
        assert!(back.discovery_complete);
        assert!(back.discovered_endpoints.is_empty());
        assert!(back.discovery_error.is_none());

        // Failed discovery: same empty inventory, but resumable as unfinished.
        let mut failed = sample();
        failed.discovery_error = Some("http failure: connection refused".into());
        let json = serde_json::to_string(&failed).expect("json");
        let back: Checkpoint = serde_json::from_str(&json).expect("roundtrip");
        assert!(!back.discovery_complete);
        assert_eq!(
            back.discovery_error.as_deref(),
            Some("http failure: connection refused")
        );
        assert!(back.discovered_endpoints.is_empty());

        // A legacy checkpoint without the new fields is treated as unfinished,
        // never as a successful empty discovery.
        let legacy = serde_json::json!({
            "checkpoint_version": CHECKPOINT_VERSION,
            "scan_id": "scan-legacy",
            "target": "https://t",
            "scope": ["https://t"],
            "config": {
                "provider": "auto", "passive_only": false, "depth": "Read",
                "allow_private": true, "unsafe_bypass": false,
                "scope_file": null, "wordlist": null, "godmode": false
            },
            "discovered_endpoints": [],
            "rpc_functions": [],
            "action_ids": [],
            "completed_tasks": [],
            "failed_tasks": [],
            "findings": []
        });
        let back: Checkpoint = serde_json::from_value(legacy).expect("legacy");
        assert!(!back.discovery_complete);
        assert!(back.discovery_error.is_none());
    }

    #[test]
    fn method_aware_inventory_roundtrips_and_old_checkpoints_default_to_empty() {
        let mut ck = sample();
        ck.discovered_endpoints = vec!["/api/v1/users".into()];
        ck.discovered_endpoint_methods = vec![
            DiscoveredEndpoint {
                path: "/api/v1/users".into(),
                method: "GET".into(),
            },
            DiscoveredEndpoint {
                path: "/api/v1/users".into(),
                method: "POST".into(),
            },
        ];
        let back: Checkpoint =
            serde_json::from_str(&serde_json::to_string(&ck).expect("json")).expect("roundtrip");
        assert_eq!(
            back.discovered_endpoint_methods,
            ck.discovered_endpoint_methods
        );

        // The pre-method field layout still loads; callers fall back to the
        // path-only inventory instead of failing the resume.
        let legacy = serde_json::json!({
            "checkpoint_version": CHECKPOINT_VERSION,
            "scan_id": "scan-legacy-methods",
            "target": "https://t",
            "scope": ["https://t"],
            "config": {
                "provider": "auto", "passive_only": false, "depth": "Read",
                "allow_private": true, "unsafe_bypass": false,
                "scope_file": null, "wordlist": null, "godmode": false
            },
            "discovered_endpoints": ["/api/v1/users"],
            "rpc_functions": [],
            "action_ids": [],
            "completed_tasks": [],
            "failed_tasks": [],
            "findings": []
        });
        let back: Checkpoint = serde_json::from_value(legacy).expect("legacy");
        assert!(back.discovered_endpoint_methods.is_empty());
        assert_eq!(back.discovered_endpoints, vec!["/api/v1/users"]);
    }

    #[test]
    fn load_rejects_a_missing_file_and_another_version() {
        assert!(Checkpoint::load("scan-does-not-exist").is_err());

        let mut ck = sample();
        ck.scan_id = "scan-test-old".into();
        ck.checkpoint_version = 999;
        ck.save();
        assert!(Checkpoint::load("scan-test-old").is_err());
        ck.checkpoint_version = CHECKPOINT_VERSION;
        ck.save();
        assert!(Checkpoint::load("scan-test-old").is_ok());
        ck.remove();
        assert!(Checkpoint::load("scan-test-old").is_err());
    }
}
