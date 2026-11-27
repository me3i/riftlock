//! Verifier implementation: deterministic WAF-aware classification.

use riftlock_core::Verifier;
use std::future::Future;
use std::pin::Pin;

/// Deterministic verifier: claims that look like WAF interstitials
/// (challenge pages, captcha walls) are rejected — those are not proofs.
/// Replaces the previous local-LLM judge; no model weights required.
#[derive(Debug, Default)]
pub struct StaticVerifier;

/// Substrings in a claim that mark it as a WAF/challenge page, not a proof.
const WAF_MARKERS: [&str; 6] = [
    "cloudflare",
    "captcha",
    "access denied",
    "waf",
    "blocked",
    "challenge",
];

impl Verifier for StaticVerifier {
    fn verify<'a>(
        &'a self,
        claim: &'a str,
        _evidence: &'a riftlock_core::Evidence,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let claim = claim.to_ascii_lowercase();
            !WAF_MARKERS.iter().any(|m| claim.contains(m))
        })
    }
}

/// The verifier to use.
#[must_use]
pub fn default_verifier() -> std::sync::Arc<dyn Verifier> {
    std::sync::Arc::new(StaticVerifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use riftlock_core::Evidence;

    #[test]
    fn static_verifier_rejects_waf_claims_only() {
        let e = Evidence::UnauthenticatedRead {
            endpoint: "https://x/.json".into(),
            row_sample: "{k: <redacted>}".into(),
        };
        let v = default_verifier();
        assert!(riftlock_core::verify::wait_for(v.verify("status=206", &e)));
        for waf in [
            "Cloudflare challenge page",
            "Please complete the CAPTCHA",
            "Access Denied",
        ] {
            assert!(
                !riftlock_core::verify::wait_for(v.verify(waf, &e)),
                "{waf} must be rejected"
            );
        }
    }
}
