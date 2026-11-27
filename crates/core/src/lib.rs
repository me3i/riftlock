//! Shared types, proof gate, scope enforcement, and the scanner contract.

pub mod body;
pub mod config;
pub mod coverage;
pub mod crawl;
pub mod dns;
pub mod http;
pub mod limiter;
pub mod logger;
pub mod payloads;
pub mod proof;
pub mod scanner;
pub mod scope;
pub mod scope_file;
pub mod session;
pub mod severity;
pub mod transport;
pub mod types;
pub mod url;
pub mod verdict;
pub mod verify;

pub use crate::url::{canonical_url, UrlError};
pub use body::{looks_like_waf, text_limited, text_limited_result, MAX_BODY_BYTES};
pub use config::{load as load_config, ConfigError, RiftlockConfig};
pub use coverage::{
    classify, classify_baseline, error_outcome, is_auth_redirect, merge, scan_error_outcome,
    AccountingValidation, CheckError, CheckId, CheckState, Coverage, CoverageSnapshot,
    EndpointOutcome, EndpointRecord, PendingCheck,
};
pub use crawl::CrawlMetrics;
pub use dns::{is_safe_ip, SafeResolve};
pub use http::{configure_host_rate, ScopedClient, ScopedRequestBuilder, MAX_REDIRECT_HOPS};
pub use limiter::HostRateLimiter;
pub use payloads::{
    payloads_for, Context, Payload, Verification, VulnType, CMDI_OUTPUT_MARKERS, HEADER_NAMES,
};
pub use proof::{Confidence, Finding, LabGuard, ProofError, ProofGate};
pub use scanner::{
    paths_for_method, CircuitBreaker, DiscoveredEndpoint, DiscoveryContext, DynamicScanner,
    ScanError, Scanner,
};
pub use scope::{ScanPolicy, ScopeError, ScopeGuard};
pub use scope_file::ScopeConfig;
pub use session::SessionMatrix;
pub use severity::{severity_of, Severity};
pub use transport::TransportError;
pub use types::{Depth, Evidence, KeyType, ProbeStatus, ProvenanceKind, SecretValue, SourceKind};
pub use verdict::ScanVerdict;
pub use verify::{claim_is_uncertain, Verifier};
