//! The `riftlock.toml` config file: scan defaults a user can check into a
//! repo instead of repeating them on the command line.

use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

/// Scan defaults parsed from a `riftlock.toml` file. Every field is
/// optional: absent fields fall through to the CLI's own defaults.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default)]
pub struct RiftlockConfig {
    /// Default scan target URL.
    pub target: Option<String>,
    /// Default scan depth.
    pub depth: Option<u32>,
    /// Default report format (e.g. `html`, `markdown`, `sarif`).
    pub format: Option<String>,
    /// Path to a wordlist file for discovery.
    pub wordlist: Option<String>,
    /// Discovery wall-clock budget in seconds. Overrides the 60 s default
    /// when the crawl of a slow target needs more time to finish.
    pub discovery_budget: Option<u64>,
}

/// Loading a `riftlock.toml` file failed at the I/O or parse stage.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    /// The file is not valid TOML.
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Load and parse a `riftlock.toml` config file from `path`.
///
/// # Errors
/// [`ConfigError::Io`] if the file cannot be read, [`ConfigError::Parse`]
/// if it is not valid TOML.
pub fn load(path: &Path) -> Result<RiftlockConfig, ConfigError> {
    let text = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&text)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        // Unique per test: these tests run concurrently in one process and
        // must not share a temp path.
        std::env::temp_dir().join(format!(
            "riftlock-config-{}-{name}.toml",
            std::process::id()
        ))
    }

    #[test]
    fn parses_all_fields() {
        let path = tmp("full");
        std::fs::write(
            &path,
            "target = \"https://lab.example.com\"\ndepth = 3\nformat = \"sarif\"\nwordlist = \"/usr/share/words.txt\"\ndiscovery_budget = 180\n",
        )
        .expect("write tmp");
        let cfg = load(&path).expect("parses");
        assert_eq!(
            cfg,
            RiftlockConfig {
                target: Some("https://lab.example.com".into()),
                depth: Some(3),
                format: Some("sarif".into()),
                wordlist: Some("/usr/share/words.txt".into()),
                discovery_budget: Some(180),
            }
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_fields_default_to_none() {
        let path = tmp("partial");
        std::fs::write(&path, "format = \"html\"\n").expect("write tmp");
        let cfg = load(&path).expect("parses");
        assert_eq!(cfg.format.as_deref(), Some("html"));
        assert_eq!(cfg.target, None);
        assert_eq!(cfg.depth, None);
        assert_eq!(cfg.wordlist, None);
        assert_eq!(cfg.discovery_budget, None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_file_is_a_clean_io_error() {
        let path = tmp("nope");
        match load(&path) {
            Err(ConfigError::Io(e)) => assert!(e.kind() == std::io::ErrorKind::NotFound),
            other => panic!("expected io error, got {other:?}"),
        }
    }

    #[test]
    fn malformed_toml_is_a_parse_error() {
        let path = tmp("bad");
        std::fs::write(&path, "target = [unterminated\n").expect("write tmp");
        assert!(matches!(load(&path), Err(ConfigError::Parse(_))));
        std::fs::remove_file(&path).ok();
    }
}
