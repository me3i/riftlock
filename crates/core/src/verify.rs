//! The verifier contract: an LLM-backed (or mock) judge for uncertain
//! evidence. Lives in core because [`ProofGate::admit_with_verifier`] takes
//! a `&dyn Verifier` and core cannot depend on engine.

use crate::types::Evidence;
use std::future::Future;
use std::pin::Pin;

/// Judges whether a claim is actually supported by evidence.
///
/// Object-safe by design: `async fn` in traits is not dyn-compatible, so the
/// future is boxed explicitly.
pub trait Verifier: Send + Sync {
    /// Whether the evidence supports the claim.
    fn verify<'a>(
        &'a self,
        claim: &'a str,
        evidence: &'a Evidence,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// Whether a claim describes uncertain material (a `206`/`300` status, or a
/// `200` whose body was HTML rather than JSON) that requires LLM judgement
/// before admission. Claim contract: the caller embeds the status as
/// `status=<code>` and, for HTML bodies, the marker `body=html`.
#[must_use]
pub fn claim_is_uncertain(claim: &str) -> bool {
    claim.contains("status=206") || claim.contains("status=300") || claim.contains("body=html")
}

/// Drive a boxed verifier future to completion on the current thread.
///
/// Verifier futures are effectively blocking (local model inference), so the
/// proof gate can poll them synchronously with a no-op waker. Never call this
/// on a future that awaits real async I/O from inside a non-blocking context.
pub fn wait_for(mut fut: Pin<Box<dyn Future<Output = bool> + Send + '_>>) -> bool {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    loop {
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => return v,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}
