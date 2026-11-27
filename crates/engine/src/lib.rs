//! Chain assembly and the intelligence layer: response routing,
//! deterministic verification, and finding chains.

pub mod chain;
pub mod router;
pub mod verifier;

pub use chain::ChainBuilder;
pub use riftlock_core::HostRateLimiter;
pub use router::{classify_response, Classification};
pub use verifier::{default_verifier, StaticVerifier};
