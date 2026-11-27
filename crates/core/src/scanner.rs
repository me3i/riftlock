//! The scanner contract every provider implements.

use crate::proof::Finding;
use crate::scope::{ScopeError, ScopeGuard};
use crate::session::SessionMatrix;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use url::Url;

/// Errors surfaced by a scanner run.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScanError {
    /// This scanner does not apply to the target.
    #[error("not applicable: {0}")]
    NotApplicable(String),
    /// Scope enforcement rejected a request.
    #[error("scope violation")]
    Scope(#[from] ScopeError),
    /// Transport-level HTTP failure, including its reqwest cause.
    #[error("http failure: {0}")]
    Http(#[from] reqwest::Error),
    /// The server returned a status the operation could not use.
    #[error("unexpected HTTP status {0}")]
    HttpStatus(u16),
    /// Response body could not be read within the size limit or from the stream.
    #[error("response body failure: {0}")]
    Body(#[from] crate::body::BodyReadError),
    /// Raw-socket failure (non-HTTP probes, e.g. framing/protocol scans).
    #[error("io failure: {0}")]
    Io(#[from] std::io::Error),
    /// A target string could not be parsed as a URL.
    #[error("invalid url")]
    InvalidUrl,
    /// The proof gate rejected an admission attempt (unreachable from
    /// valid variants, but handled explicitly).
    #[error("proof gate rejected admission")]
    Proof(#[from] crate::proof::ProofError),
    /// A redirect pointed at a URL that had already been visited.
    #[error("redirect loop at {0}")]
    RedirectLoop(String),
    /// The redirect chain exceeded the configured hop limit.
    #[error("redirect chain exceeded {0} hops")]
    TooManyRedirects(usize),
    /// A redirect response carried no usable `Location` header.
    #[error("invalid redirect location")]
    InvalidRedirect,
    /// A redirect tried to change scheme or port, leaving the original scan boundary.
    #[error("redirect left the original scheme/port boundary: {0}")]
    RedirectBoundaryChange(String),
    /// A shared transport failure already blocked the target before this
    /// engine ran. No request was sent; the engine is failed, not a clean
    /// negative.
    #[error("shared transport failure: {0}")]
    SharedTransportFailure(String),
    /// The per-scan circuit breaker is open: consecutive transport failures
    /// made further requests to this target pointless, so none was sent.
    #[error("circuit breaker open: target stopped responding")]
    CircuitOpen,
    /// Three consecutive DNS or connection-refused failures across engines
    /// marked the host dead. No request was sent.
    #[error("host unreachable: {0}")]
    HostUnreachable(String),
}

impl ScanError {
    /// Whether this error is a request timeout, whether it surfaced as a
    /// transport error or a body-read failure.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        match self {
            Self::Http(error) => error.is_timeout(),
            Self::Body(crate::body::BodyReadError::Transport(error)) => error.is_timeout(),
            _ => false,
        }
    }

    /// The actionable transport category, when this error came from the
    /// network or a response-body read. Other errors return `None`.
    #[must_use]
    pub fn transport_category(&self) -> Option<crate::transport::TransportError> {
        match self {
            Self::Http(error) => Some(crate::transport::TransportError::from_reqwest(error)),
            Self::Body(crate::body::BodyReadError::Transport(error)) => {
                Some(crate::transport::TransportError::from_reqwest(error))
            }
            Self::Body(crate::body::BodyReadError::TooLarge) => {
                Some(crate::transport::TransportError::BodyRead)
            }
            Self::RedirectLoop(_)
            | Self::TooManyRedirects(_)
            | Self::InvalidRedirect
            | Self::RedirectBoundaryChange(_) => Some(crate::transport::TransportError::Redirect),
            _ => None,
        }
    }
}

/// Contract for provider scanners.
pub trait Scanner {
    /// Stable scanner identifier used in reports.
    fn id(&self) -> &'static str;

    /// Whether this scanner handles `url`.
    fn matches(&self, url: &Url) -> bool;

    /// Run the scan. In passive mode (`passive = true`) the scanner must not
    /// send probing requests — only observe fetchable material.
    ///
    /// # Errors
    /// Scope violations and transport failures.
    fn scan(
        &self,
        url: &Url,
        client: &crate::http::ScopedClient,
        guard: &ScopeGuard,
        passive: bool,
    ) -> impl std::future::Future<Output = Result<Vec<Finding>, ScanError>> + Send;

    /// Run the scan, stopping before `deadline` where the engine can. The
    /// CLI cancels an engine at its wall-clock budget, and a cancelled
    /// future takes every finding it already proved with it — so engines
    /// that accumulate findings should honour the wall clock and return
    /// their partial results instead. The default ignores the deadline.
    fn scan_until(
        &self,
        url: &Url,
        client: &crate::http::ScopedClient,
        guard: &ScopeGuard,
        passive: bool,
        _deadline: Option<std::time::Instant>,
    ) -> impl std::future::Future<Output = Result<Vec<Finding>, ScanError>> + Send {
        self.scan(url, client, guard, passive)
    }
}

/// One discovered HTTP endpoint and the method used to reach it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredEndpoint {
    /// Path or URL recorded by discovery.
    pub path: String,
    /// HTTP method (uppercased; discovery defaults to `GET` when not stated).
    pub method: String,
}

/// Discovered paths that `method` reaches.
///
/// `paths` is the legacy path-only inventory: when `methods` is empty — an
/// older checkpoint, or a caller that only knows paths — every path is
/// returned unchanged. A method-aware inventory narrows the list to paths
/// observed with `method`, deduplicated. Callers keep sending the verb they
/// already use; a recorded write method never becomes a request of its own.
pub fn paths_for_method(
    paths: &[String],
    methods: &[DiscoveredEndpoint],
    method: &str,
) -> Vec<String> {
    if methods.is_empty() {
        return paths.to_vec();
    }
    let mut seen = HashSet::new();
    methods
        .iter()
        .filter(|endpoint| endpoint.method.eq_ignore_ascii_case(method))
        .filter(|endpoint| seen.insert(endpoint.path.as_str()))
        .map(|endpoint| endpoint.path.clone())
        .collect()
}

/// Endpoints and parameters harvested by the discovery engine. Pure context:
/// discovery itself never emits findings, it only enriches what the
/// [`DynamicScanner`] implementations probe.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryContext {
    /// Discovered endpoint paths (e.g. `/api/v2/users`).
    pub endpoints: Vec<String>,
    /// Methods observed for discovered paths; empty preserves path-only callers.
    pub endpoint_methods: Vec<DiscoveredEndpoint>,
    /// Full URLs found by the authenticated crawler (links, script
    /// sources, form actions), first-seen order.
    pub discovered_urls: Vec<String>,
    /// Parameter names to fuzz each endpoint with.
    pub params: Vec<String>,
    /// Session tokens for multi-user differential probes.
    pub sessions: SessionMatrix,
}

/// Contract for scanners that probe dynamically discovered endpoints and
/// parameters. Implemented in addition to [`Scanner`]; the CLI invokes it
/// for scanners whose concrete type implements this trait.
pub trait DynamicScanner {
    /// Probe `ctx.endpoints` × `ctx.params` on `url` and emit findings for
    /// proven differentials.
    fn scan_dynamic(
        &self,
        url: &Url,
        client: &crate::http::ScopedClient,
        guard: &ScopeGuard,
        ctx: &DiscoveryContext,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Finding>, ScanError>> + Send + '_>>;
}

/// Circuit breaker for sequential probe loops: ten consecutive transport
/// failures trip it, and the loop aborts with a recorded `Io(TimedOut)`
/// failure instead of grinding through the remaining probes one request
/// timeout at a time (the 40 s engine budget never sees a fully blocked
/// target). Only transport errors count — a 4xx/5xx response is a healthy
/// answer and never feeds the breaker.
#[derive(Debug, Default)]
pub struct CircuitBreaker {
    consecutive: u32,
}

impl CircuitBreaker {
    /// Consecutive failures that trip the breaker.
    pub const TRIP_AT: u32 = 10;

    /// Record one failure (transport error only — never an HTTP status).
    /// Returns `true` once [`TRIP_AT`] consecutive failures are reached —
    /// the caller must abort its loop.
    pub fn failed(&mut self) -> bool {
        self.consecutive += 1;
        self.consecutive >= Self::TRIP_AT
    }

    /// Record any healthy response; the consecutive-failure count resets.
    pub fn healthy(&mut self) {
        self.consecutive = 0;
    }

    /// The error a tripped breaker aborts with: a real recorded failure,
    /// matching the engine-budget timeout shape.
    pub fn tripped_error() -> ScanError {
        ScanError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "circuit breaker: consecutive transport failures",
        ))
    }
}

#[cfg(test)]
mod breaker_tests {
    use super::*;

    fn endpoint(path: &str, method: &str) -> DiscoveredEndpoint {
        DiscoveredEndpoint {
            path: path.to_owned(),
            method: method.to_owned(),
        }
    }

    #[test]
    fn method_inventory_narrows_paths_and_keeps_path_only_callers() {
        let paths = vec!["/api/users".to_owned()];
        let methods = vec![
            endpoint("/api/users", "GET"),
            endpoint("/api/users", "POST"),
            endpoint("/api/users", "DELETE"),
        ];
        // No method-aware inventory: the legacy list passes through whole.
        assert_eq!(paths_for_method(&paths, &[], "GET"), paths);
        // Every method on the same path resolves to one deduplicated path.
        assert_eq!(paths_for_method(&paths, &methods, "GET"), paths);
        assert_eq!(paths_for_method(&paths, &methods, "POST"), paths);
        assert_eq!(paths_for_method(&paths, &methods, "delete"), paths);
        assert!(paths_for_method(&paths, &methods, "PUT").is_empty());
        assert_eq!(
            paths_for_method(
                &[],
                &[endpoint("/fetch", "GET"), endpoint("/write", "POST")],
                "POST"
            ),
            vec!["/write".to_owned()]
        );
    }

    #[test]
    fn breaker_trips_on_tenth_consecutive_failure_and_resets_on_health() {
        let mut b = CircuitBreaker::default();
        for _ in 0..CircuitBreaker::TRIP_AT - 1 {
            assert!(!b.failed());
        }
        assert!(b.failed());
        // Any healthy response rearms the breaker.
        b.healthy();
        for _ in 0..CircuitBreaker::TRIP_AT - 1 {
            assert!(!b.failed());
        }
        assert!(b.failed());
        assert!(matches!(CircuitBreaker::tripped_error(),
            ScanError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut));
    }
}
