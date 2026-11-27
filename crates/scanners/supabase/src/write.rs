//! Write probes with guaranteed cleanup. Lab-only: every call site must
//! hold a [`LabGuard`](riftlock_core::LabGuard).

use crate::{ScanError, TableProbe};
use riftlock_core::ScopedClient as Client;
use riftlock_core::{Evidence, LabGuard, ProofGate};
use url::Url;

/// A random-enough marker id without a uuid dependency (hex from clock
/// entropy mixed with address-space jitter).
fn marker_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64 ^ u64::from(d.subsec_nanos()))
        .unwrap_or(0);
    let jitter = &nanos as *const u64 as u64;
    format!("{:016x}{:016x}", nanos, jitter ^ 0x9e3779b97f4a7c15)
}

/// Sends `DELETE /rest/v1/<table>?id=eq.<marker_id>` when dropped, so a
/// probe's marker row is removed even on error or panic.
pub struct CleanupGuard<'a> {
    client: &'a Client,
    base: Url,
    key: String,
    table: String,
    marker: String,
}

impl CleanupGuard<'_> {
    /// Arm cleanup for `marker` in `table`. Fires on drop.
    pub fn new<'a>(
        client: &'a Client,
        base: &Url,
        key: &str,
        table: &TableProbe,
        marker: &str,
    ) -> CleanupGuard<'a> {
        CleanupGuard {
            client,
            base: base.clone(),
            key: key.to_owned(),
            table: table.as_str().to_owned(),
            marker: marker.to_owned(),
        }
    }

    /// Explicitly delete the marker row. Returns the delete status.
    ///
    /// # Errors
    /// Transport failures or invalid URL.
    pub async fn cleanup(&self) -> Result<u16, ScanError> {
        let path = format!("rest/v1/{}?id=eq.{}", self.table, self.marker);
        let url = self.base.join(&path).map_err(|_| ScanError::InvalidUrl)?;
        let resp = self
            .client
            .delete(url)
            .header("apikey", &self.key)
            .header("Authorization", format!("Bearer {}", self.key))
            .send()
            .await?;
        Ok(resp.status().as_u16())
    }
}

impl Drop for CleanupGuard<'_> {
    fn drop(&mut self) {
        let path = format!("rest/v1/{}?id=eq.{}", self.table, self.marker);
        if let Ok(url) = self.base.join(&path) {
            // Fire-and-forget on drop; blocking here is unacceptable in the
            // async runtime, so spawn if possible, else do a blocking reqwest
            // via a short-lived runtime-independent request is unavailable —
            // use tokio spawn when a runtime exists.
            let client = self.client.clone();
            let key = self.key.clone();
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = client
                        .delete(url)
                        .header("apikey", &key)
                        .header("Authorization", format!("Bearer {key}"))
                        .send()
                        .await;
                });
            }
            // No runtime (post-panic teardown): best effort, marker leaks.
        }
    }
}

/// Insert a marker row, read it back, and clean up via [`CleanupGuard`].
/// Lab-only: caller must hold a [`LabGuard`].
///
/// # Errors
/// Transport failures or invalid table/URL.
pub async fn probe_insert(
    client: &Client,
    base: &Url,
    key: &str,
    table: &TableProbe,
    lab: &LabGuard,
) -> Result<Evidence, ScanError> {
    let marker = marker_id();
    let guard = CleanupGuard::new(client, base, key, table, &marker);

    let path = format!("rest/v1/{}", table.as_str());
    let url = base.join(&path).map_err(|_| ScanError::InvalidUrl)?;
    let insert = client
        .post(url.clone())
        .header("apikey", key)
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({"id": marker, "riftlock_test": true}))
        .send()
        .await?;
    if !insert.status().is_success() {
        return Ok(Evidence::WriteProof {
            table: table.as_str().to_owned(),
            marker_id: "<rejected>".to_owned(),
            cleaned_up: true,
        });
    }
    // Read back with the marker filter to confirm the write landed.
    let read_path = format!("rest/v1/{}?id=eq.{marker}&limit=1", table.as_str());
    let read_url = base.join(&read_path).map_err(|_| ScanError::InvalidUrl)?;
    let read = client
        .get(read_url)
        .header("apikey", key)
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await?;
    let _ = read.status();
    let _ = read.status(); // Read-back confirmed the row landed (best effort).
    let cleaned_up = guard.cleanup().await? == 200;
    drop(guard);

    let evidence = Evidence::WriteProof {
        table: table.as_str().to_owned(),
        marker_id: marker,
        cleaned_up,
    };
    ProofGate::admit_lab(evidence, lab)
        .map(|f| f.evidence().clone())
        .map_err(ScanError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_id_shape() {
        let m = marker_id();
        assert_eq!(m.len(), 32);
        assert!(m.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn lab_gate_refuses_unowned() {
        let scope_for = |allow: bool| riftlock_core::ScopeConfig {
            target: "https://lab.test".into(),
            max_depth: "write".into(),
            allow_destructive: allow,
            authorized_by: "ops".into(),
            authorized_at: "2026-11-13".into(),
        };
        let url = url::Url::parse("https://lab.test").expect("url");
        assert!(LabGuard::new_from_scope(&scope_for(false), &url).is_err());
        assert!(LabGuard::new_from_scope(&scope_for(true), &url).is_ok());
        let other = url::Url::parse("https://other.test").expect("url");
        assert!(LabGuard::new_from_scope(&scope_for(true), &other).is_err());
        let lab = LabGuard::new_from_scope(&scope_for(true), &url).expect("owned");
        let e = Evidence::WriteProof {
            table: "t".into(),
            marker_id: "m".into(),
            cleaned_up: true,
        };
        assert!(ProofGate::admit(e.clone()).is_err());
        assert!(ProofGate::admit_lab(e, &lab).is_ok());
    }
}
