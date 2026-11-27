//! The scope file: a verifiable authorization artifact replacing ad-hoc
//! `--lab-owned` flags.

use crate::scope::ScopeError;
use serde::{Deserialize, Serialize};
use url::Url;

/// A signed-by-hand authorization declaration for one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeConfig {
    /// The authorized target origin (e.g. `https://lab.example.com`).
    pub target: String,
    /// Maximum permitted scan depth (e.g. `read`, `auth`, `write`).
    pub max_depth: String,
    /// Whether destructive/write probes are authorized on the target.
    pub allow_destructive: bool,
    /// Who authorized this scope.
    pub authorized_by: String,
    /// When it was authorized (ISO-8601 string).
    pub authorized_at: String,
}

impl ScopeConfig {
    /// Load a scope file from `path`.
    ///
    /// # Errors
    /// I/O or YAML parse failures surface as [`ScopeError`].
    pub fn load(path: &str) -> Result<Self, ScopeError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ScopeError::ScopeFile(format!("{path}: {e}")))?;
        serde_yaml_ng::from_str(&text).map_err(|e| ScopeError::ScopeFile(format!("{path}: {e}")))
    }

    /// Whether destructive probes are allowed for `url`: the URL host must
    /// match the configured target's host AND `allow_destructive` must be
    /// true.
    pub fn is_destructive_allowed(&self, url: &Url) -> bool {
        if !self.allow_destructive {
            return false;
        }
        let target_host = Url::parse(&self.target)
            .ok()
            .and_then(|t| t.host_str().map(str::to_owned));
        let url_host = url.host_str();
        matches!((target_host, url_host), (Some(a), Some(b)) if a == b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(name: &str, content: &str) -> String {
        // Unique per test: these tests run concurrently in one process and
        // must not share a temp path.
        let path = std::env::temp_dir().join(format!("scope-{}-{name}.yaml", std::process::id()));
        std::fs::write(&path, content).expect("write tmp");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn loads_and_matches_target() {
        let path = write_tmp(
            "valid",
            "target: https://lab.example.com\nmax_depth: write\nallow_destructive: true\nauthorized_by: ops\nauthorized_at: \"2026-11-13T00:00:00Z\"\n",
        );
        let cfg = ScopeConfig::load(&path).expect("loaded");
        assert_eq!(cfg.max_depth, "write");
        let same = Url::parse("https://lab.example.com/rest/v1/users").expect("url");
        assert!(cfg.is_destructive_allowed(&same));
        let other = Url::parse("https://prod.example.com").expect("url");
        assert!(!cfg.is_destructive_allowed(&other));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn missing_or_invalid_file_errors() {
        assert!(ScopeConfig::load("/nonexistent/scope.yaml").is_err());
        let bad = write_tmp("invalid", "target: [unclosed\n");
        assert!(ScopeConfig::load(&bad).is_err());
        let _ = std::fs::remove_file(bad);
    }

    #[test]
    fn destructive_false_never_allowed() {
        let cfg = ScopeConfig {
            target: "https://lab.example.com".into(),
            max_depth: "write".into(),
            allow_destructive: false,
            authorized_by: "ops".into(),
            authorized_at: "2026-11-13".into(),
        };
        let url = Url::parse("https://lab.example.com").expect("url");
        assert!(!cfg.is_destructive_allowed(&url));
    }
}
