//! Supply-chain scanner: probes the target root for publicly served
//! dependency manifests (`package.json`, `package-lock.json`,
//! `requirements.txt`, `composer.json`) and checks pinned versions against
//! a static list of known-vulnerable packages. A served manifest that pins
//! a vulnerable package is evidence of the exposure end to end.

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    text_limited_result, CheckState, Coverage, EndpointOutcome, Evidence, Finding, ProofGate,
    ScanError, Scanner, ScopeGuard,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use url::Url;

/// The supply-chain scanner.
#[derive(Debug, Default)]
pub struct SupplyChainScanner {
    /// Coverage for manifest probes, including unreadable bodies and transport failures.
    pub coverage: Coverage,
}

/// Manifest paths probed at the target root.
const MANIFEST_PATHS: [&str; 4] = [
    "/package.json",
    "/package-lock.json",
    "/requirements.txt",
    "/composer.json",
];

/// Known-vulnerable packages as `(package, first safe version)`: a pinned
/// version strictly below the safe one is the finding. The list covers the
/// historically hijacked/infected npm releases and one Python staple so
/// `requirements.txt` is meaningful too.
const VULNERABLE_PACKAGES: [(&str, &str); 5] = [
    ("event-stream", "4.0.2"),
    ("ua-parser-js", "1.0.33"),
    ("lodash", "4.17.21"),
    ("minimist", "1.2.6"),
    ("requests", "2.32.0"),
];

/// One pinned dependency extracted from a manifest.
#[derive(Debug, PartialEq, Eq)]
struct Pinned {
    package: String,
    version: String,
}

#[derive(Deserialize, Default)]
struct NpmManifest {
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(default)]
    dev_dependencies: HashMap<String, String>,
    #[serde(rename = "devDependencies", default)]
    dev_dependencies_camel: HashMap<String, String>,
}

/// Numeric prefix of one version segment (`"21"` → 21, `"0rc1"` → 0,
/// `"beta"` → 0).
fn segment(part: &str) -> u64 {
    let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().unwrap_or(0)
}

/// Version as comparable numeric vector: `"v4.17.20"` → [4, 17, 20].
/// Non-numeric junk degrades to 0 — a garbled version pin is treated as
/// the oldest possible release, which is the safe direction to err.
fn version_key(version: &str) -> Vec<u64> {
    version
        .trim()
        .trim_start_matches(['v', '^', '~', '=', ' '])
        .split('.')
        .map(segment)
        .collect()
}

/// Whether `version` is strictly below `first_safe`.
fn is_below(version: &str, first_safe: &str) -> bool {
    let v = version_key(version);
    let s = version_key(first_safe);
    for i in 0..s.len().max(v.len()) {
        let a = v.get(i).copied().unwrap_or(0);
        let b = s.get(i).copied().unwrap_or(0);
        if a != b {
            return a < b;
        }
    }
    false
}

fn parse_package_json(body: &str) -> Vec<Pinned> {
    let Ok(m) = serde_json::from_str::<NpmManifest>(body) else {
        return Vec::new();
    };
    m.dependencies
        .into_iter()
        .chain(m.dev_dependencies)
        .chain(m.dev_dependencies_camel)
        .map(|(package, version)| Pinned { package, version })
        .collect()
}

/// `package-lock.json` v2/v3 (`packages` map) with a v1 (`dependencies`
/// tree) fallback.
fn parse_package_lock(body: &str) -> Vec<Pinned> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(pkgs) = v.get("packages").and_then(Value::as_object) {
        for (key, val) in pkgs {
            let Some(name) = key.strip_prefix("node_modules/") else {
                continue;
            };
            if let Some(version) = val.get("version").and_then(Value::as_str) {
                out.push(Pinned {
                    package: name.to_owned(),
                    version: version.to_owned(),
                });
            }
        }
        return out;
    }
    if let Some(deps) = v.get("dependencies").and_then(Value::as_object) {
        for (name, val) in deps {
            if let Some(version) = val.get("version").and_then(Value::as_str) {
                out.push(Pinned {
                    package: name.clone(),
                    version: version.to_owned(),
                });
            }
        }
    }
    out
}

fn parse_requirements(body: &str) -> Vec<Pinned> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
        .filter_map(|line| line.split_once("=="))
        .map(|(name, version)| Pinned {
            package: name.trim().to_owned(),
            version: version
                .split([' ', '#', ';'])
                .next()
                .unwrap_or("")
                .to_owned(),
        })
        .filter(|p| !p.version.is_empty())
        .collect()
}

fn parse_composer(body: &str) -> Vec<Pinned> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    v.get("require")
        .and_then(Value::as_object)
        .map(|req| {
            req.iter()
                .filter_map(|(name, ver)| {
                    let version = ver.as_str()?;
                    Some(Pinned {
                        package: name.clone(),
                        version: version.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Dispatch on the manifest filename.
fn parse_manifest(path: &str, body: &str) -> Vec<Pinned> {
    if path.ends_with("package-lock.json") {
        parse_package_lock(body)
    } else if path.ends_with("package.json") {
        parse_package_json(body)
    } else if path.ends_with("requirements.txt") {
        parse_requirements(body)
    } else {
        parse_composer(body)
    }
}

impl Scanner for SupplyChainScanner {
    fn id(&self) -> &'static str {
        "supplychain"
    }

    fn matches(&self, _url: &Url) -> bool {
        true
    }

    async fn scan(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        if passive {
            return Ok(Vec::new());
        }
        guard.check_active(url)?;
        let mut findings = Vec::new();
        for path in MANIFEST_PATHS {
            let probe = url.join(path).map_err(|_| ScanError::InvalidUrl)?;
            if guard.check(&probe).is_err() {
                self.coverage
                    .endpoint_at(probe.as_str(), EndpointOutcome::Skipped);
                continue;
            }
            // A missing manifest (404) is a checked negative; a served one
            // is the supply chain laid bare.
            let check = self.coverage.begin_check();
            let resp = match client.get(probe.clone()).send().await {
                Ok(resp) => resp,
                Err(error) => {
                    let timed_out = error.is_timeout();
                    self.coverage.endpoint_at(
                        probe.as_str(),
                        if timed_out {
                            EndpointOutcome::TimedOut
                        } else {
                            EndpointOutcome::Failed
                        },
                    );
                    let _ = check.finish(if timed_out {
                        CheckState::TimedOut
                    } else {
                        CheckState::Failed
                    });
                    continue;
                }
            };
            if !resp.status().is_success() {
                let outcome = riftlock_core::classify(resp.status().as_u16());
                self.coverage.endpoint_at(probe.as_str(), outcome);
                let _ = check.finish(
                    if matches!(
                        outcome,
                        EndpointOutcome::AuthRequired | EndpointOutcome::WafBlocked
                    ) {
                        CheckState::Inconclusive
                    } else {
                        CheckState::Completed
                    },
                );
                continue;
            }
            let body = match text_limited_result(resp).await {
                Ok(body) => body,
                Err(_) => {
                    self.coverage
                        .endpoint_at(probe.as_str(), EndpointOutcome::Failed);
                    let _ = check.finish(CheckState::Inconclusive);
                    continue;
                }
            };
            self.coverage
                .endpoint_at(probe.as_str(), EndpointOutcome::Tested);
            let _ = check.finish(CheckState::Completed);
            for Pinned { package, version } in parse_manifest(path, &body) {
                for (vuln_pkg, first_safe) in VULNERABLE_PACKAGES {
                    if *vuln_pkg == package && is_below(&version, first_safe) {
                        findings.push(ProofGate::admit(Evidence::SupplyChainVulnerability {
                            manifest: probe.to_string(),
                            package: package.clone(),
                            version: version.clone(),
                        })?);
                    }
                }
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare_matches_semver_expectations() {
        assert!(is_below("4.17.20", "4.17.21"));
        assert!(!is_below("4.17.21", "4.17.21"));
        assert!(!is_below("4.18.0", "4.17.21"));
        assert!(is_below("1.0.32", "1.0.33"));
        assert!(is_below("v1.2.5", "1.2.6"));
        assert!(is_below("2.31.0", "2.32.0"));
        // Garbled pins degrade to 0.0.0: flagged as oldest release.
        assert!(is_below("not-a-version", "1.0.0"));
        assert!(is_below("beta", "0.0.1"));
    }

    #[test]
    fn parses_all_four_manifest_formats() {
        let npm = parse_package_json(
            r#"{"dependencies":{"lodash":"4.17.20"},"devDependencies":{"minimist":"1.2.5"}}"#,
        );
        assert_eq!(npm.len(), 2);
        assert!(npm.contains(&Pinned {
            package: "lodash".into(),
            version: "4.17.20".into()
        }));

        let lock = parse_package_lock(
            r#"{"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/ua-parser-js":{"version":"1.0.32"}}}"#,
        );
        assert_eq!(lock.len(), 2);
        assert!(lock.iter().any(|p| p.package == "ua-parser-js"));

        let reqs = parse_requirements("requests==2.31.0\n# comment\nflask==3.0.0\n");
        assert_eq!(
            reqs,
            vec![
                Pinned {
                    package: "requests".into(),
                    version: "2.31.0".into()
                },
                Pinned {
                    package: "flask".into(),
                    version: "3.0.0".into()
                }
            ]
        );

        let composer = parse_composer(r#"{"require":{"vendor/pkg":"^2.1.0","php":">=8.1"}}"#);
        assert_eq!(composer.len(), 2);
        assert!(composer.contains(&Pinned {
            package: "vendor/pkg".into(),
            version: "^2.1.0".into()
        }));
    }

    #[test]
    fn manifest_dispatch_selects_by_filename() {
        let body = r#"{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#;
        assert_eq!(parse_manifest("/package-lock.json", body).len(), 1);
        assert_eq!(parse_manifest("/package.json", body).len(), 0);
    }

    #[tokio::test]
    async fn scan_flags_served_manifest_and_skips_missing() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/package.json"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(r#"{"dependencies":{"lodash":"4.17.20","axios":"1.6.0"}}"#),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/package-lock.json"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let scanner = SupplyChainScanner::default();
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1, "{findings:?}");
        let Evidence::SupplyChainVulnerability {
            manifest,
            package,
            version,
        } = findings[0].evidence()
        else {
            panic!("wrong evidence variant");
        };
        assert_eq!(package, "lodash");
        assert_eq!(version, "4.17.20");
        assert!(manifest.ends_with("/package.json"), "{manifest}");
    }

    #[tokio::test]
    async fn corrupt_gzip_manifest_is_failed_and_inconclusive() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/package.json"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(b"not a gzip stream".to_vec()),
            )
            .mount(&server)
            .await;
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let scanner = SupplyChainScanner::default();

        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, false)
            .await
            .expect("unreadable manifest body is inconclusive, not a scan error");
        assert!(findings.is_empty());
        let snap = scanner.coverage.snapshot(0);
        assert_eq!(snap.endpoints_failed, 1);
        assert_eq!(snap.vulnerability_checks_inconclusive, 1);
        assert!(snap.check_accounting_invariant());
        assert!(scanner.coverage.finalize().reconciles());
    }

    #[tokio::test]
    async fn passive_scan_sends_nothing() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[base.as_str()]).expect("guard");
        let scanner = SupplyChainScanner::default();
        let findings = scanner
            .scan(&base, &Client::new_lab(), &guard, true)
            .await
            .expect("scan");
        assert!(findings.is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }
}
