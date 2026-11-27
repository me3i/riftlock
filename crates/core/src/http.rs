//! RIFTLOCK-owned HTTP client. Redirect policy is fixed here, not delegated to
//! a caller-supplied `reqwest::Client`.

use crate::scanner::ScanError;
use crate::scope::ScopeGuard;
use crate::SafeResolve;
use futures_util::{stream, Stream, StreamExt};
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, COOKIE, LOCATION, PROXY_AUTHORIZATION,
    RETRY_AFTER,
};
use reqwest::{
    Client, ClientBuilder, IntoUrl, Method, Request, Response, ResponseBuilderExt, StatusCode,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use url::Url;

static HOST_LIMITS: OnceLock<Mutex<Arc<crate::limiter::HostRateLimiter>>> = OnceLock::new();
const MAX_RETRIES: usize = 3;
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
/// Never wait less than one second, however fast the root page was.
const MIN_ADAPTIVE_TIMEOUT: Duration = Duration::from_secs(1);
/// A successful root sample is multiplied by this to size later requests,
/// giving a twenty-second root page a sixty-second budget.
const ADAPTIVE_TIMEOUT_FACTOR: u32 = 3;

/// Consecutive connection-refused or timeout failures per host before requests
/// are short-circuited across every engine in this process.
const DEFAULT_BREAKER_THRESHOLD: u32 = 20;
const BREAKER_WINDOW_SIZE: usize = 20;
/// Overrides [`DEFAULT_BREAKER_THRESHOLD`] for one process (parseable `u32`).
const BREAKER_THRESHOLD_ENV: &str = "RIFTLOCK_CIRCUIT_BREAKER_THRESHOLD";

/// Per-host transport health shared process-wide by every engine/client.
#[derive(Debug)]
struct HostState {
    threshold: u32,
    consecutive: AtomicU32,
    failure_window: Mutex<VecDeque<bool>>,
    open: AtomicBool,
}

impl HostState {
    fn from_env() -> Self {
        let threshold = std::env::var(BREAKER_THRESHOLD_ENV)
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value > 0)
            .map(|value| value.min(DEFAULT_BREAKER_THRESHOLD))
            .unwrap_or(DEFAULT_BREAKER_THRESHOLD);
        Self {
            threshold,
            consecutive: AtomicU32::new(0),
            failure_window: Mutex::new(VecDeque::with_capacity(BREAKER_WINDOW_SIZE)),
            open: AtomicBool::new(false),
        }
    }

    fn healthy(&self) {
        if self.open.swap(false, Ordering::Relaxed) {
            self.consecutive.store(0, Ordering::Relaxed);
            self.failure_window
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clear();
        }
        self.record(false);
    }

    fn failed(&self) {
        self.record(true);
    }

    fn record(&self, failed: bool) {
        let mut window = self
            .failure_window
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        window.push_back(failed);
        if window.len() > BREAKER_WINDOW_SIZE {
            window.pop_front();
        }
        let rate_trip = window.len() == BREAKER_WINDOW_SIZE
            && window.iter().filter(|failure| **failure).count() * 2 >= BREAKER_WINDOW_SIZE;
        let count = if failed {
            self.consecutive.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            self.consecutive.store(0, Ordering::Relaxed);
            0
        };
        let trip = failed && count >= self.threshold || rate_trip;
        if trip && !self.open.swap(true, Ordering::Relaxed) {
            crate::logln!(
                "[!] Host breaker tripped after {count} consecutive failures or at least 50% failures in the last {BREAKER_WINDOW_SIZE} requests — remaining requests will be skipped."
            );
        }
    }
}

/// Per-client skip ledger and per-host latency; breaker health lives in
/// `HOST_STATES`. Cloned clients share the latency map, so the scan's engines
/// all size timeouts from the same root sample.
#[derive(Debug, Default)]
struct TransportBreaker {
    skipped: Mutex<Vec<String>>,
    latencies: Mutex<HashMap<String, LatencyAverage>>,
    isolated_states: Option<Mutex<HashMap<String, Arc<HostState>>>>,
    /// Upper bound for adaptive timeouts, in milliseconds; 0 means uncapped.
    adaptive_cap_ms: std::sync::atomic::AtomicU64,
}

/// Integer moving average; no floating point in a request-path decision.
#[derive(Debug, Clone, Copy, Default)]
struct LatencyAverage {
    samples: u32,
    average: Duration,
}

impl LatencyAverage {
    fn record(&mut self, sample: Duration) {
        self.average = if self.samples == 0 {
            sample
        } else {
            self.average
                .saturating_mul(3)
                .saturating_add(sample)
                .checked_div(4)
                .unwrap_or(sample)
        };
        self.samples = self.samples.saturating_add(1);
    }
}

static HOST_STATES: OnceLock<Mutex<HashMap<String, Arc<HostState>>>> = OnceLock::new();

fn host_state(url: &Url) -> Arc<HostState> {
    let key = host_key(url);
    let mut states = HOST_STATES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    Arc::clone(
        states
            .entry(key)
            .or_insert_with(|| Arc::new(HostState::from_env())),
    )
}

impl TransportBreaker {
    fn isolated_state(&self, url: &Url) -> Option<Arc<HostState>> {
        self.isolated_states.as_ref().map(|states| {
            let mut states = states.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(
                states
                    .entry(host_key(url))
                    .or_insert_with(|| Arc::new(HostState::from_env())),
            )
        })
    }

    fn is_open(&self, url: &Url) -> bool {
        self.isolated_state(url)
            .unwrap_or_else(|| host_state(url))
            .open
            .load(Ordering::Relaxed)
    }

    /// Any response at all (2xx–5xx) means this host is alive.
    fn healthy(&self, url: &Url) {
        self.isolated_state(url)
            .unwrap_or_else(|| host_state(url))
            .healthy();
    }

    fn failed(&self, url: &Url) {
        self.isolated_state(url)
            .unwrap_or_else(|| host_state(url))
            .failed();
    }

    fn record_root_latency(&self, url: &Url, elapsed: Duration) {
        let mut latencies = self
            .latencies
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        latencies.entry(host_key(url)).or_default().record(elapsed);
    }

    fn observe_success(&self, url: &Url, elapsed: Duration) {
        self.record_root_latency(url, elapsed);
    }

    fn set_adaptive_timeout_cap(&self, cap: Duration) {
        let millis = u64::try_from(cap.as_millis()).unwrap_or(u64::MAX);
        self.adaptive_cap_ms.store(millis, Ordering::Relaxed);
    }

    fn adaptive_timeout(&self, url: &Url) -> Option<Duration> {
        let latencies = self
            .latencies
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        latencies.get(&host_key(url)).and_then(|latency| {
            (latency.samples > 0).then(|| {
                let timeout = latency
                    .average
                    .saturating_mul(ADAPTIVE_TIMEOUT_FACTOR)
                    .max(MIN_ADAPTIVE_TIMEOUT);
                let cap_ms = self.adaptive_cap_ms.load(Ordering::Relaxed);
                if cap_ms == 0 {
                    timeout
                } else {
                    timeout.min(Duration::from_millis(cap_ms))
                }
            })
        })
    }

    fn skip(&self, url: &Url) {
        let mut skipped = self.skipped.lock().unwrap_or_else(PoisonError::into_inner);
        if !skipped.iter().any(|seen| seen == url.as_str()) {
            skipped.push(url.as_str().to_owned());
        }
    }

    fn skipped_urls(&self) -> Vec<String> {
        self.skipped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Configure process-wide host pacing before requests are dispatched.
pub fn configure_host_rate(requests_per_second: u32) {
    let mut limits = HOST_LIMITS
        .get_or_init(|| Mutex::new(Arc::new(crate::limiter::HostRateLimiter::new())))
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    *limits = Arc::new(crate::limiter::HostRateLimiter::with_rate(
        requests_per_second,
    ));
}

fn host_limits() -> Arc<crate::limiter::HostRateLimiter> {
    let limits = HOST_LIMITS
        .get_or_init(|| Mutex::new(Arc::new(crate::limiter::HostRateLimiter::new())))
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    Arc::clone(&limits)
}

/// Maximum number of redirect hops RIFTLOCK will follow manually.
pub const MAX_REDIRECT_HOPS: usize = 10;

/// A reqwest client whose redirect policy RIFTLOCK controls. Constructing one
/// from a caller's builder forces `Policy::none()`, so reqwest can never follow
/// a redirect without a `ScopeGuard` decision. Scanners that need to follow an
/// in-scope redirect call [`ScopedClient::send_scoped`], which validates every
/// hop before sending it.
#[derive(Debug, Clone)]
pub struct ScopedClient {
    inner: Client,
    resolver: SafeResolve,
    breaker: Arc<TransportBreaker>,
}

impl ScopedClient {
    /// A client with reqwest defaults and redirects disabled, using production DNS policy.
    #[must_use]
    pub fn new() -> Self {
        Self::from_builder(Client::builder(), &ScopeGuard::default())
            .expect("build redirect-disabled client")
    }

    /// A client for an explicitly authorized local lab scope.
    #[must_use]
    pub fn new_lab() -> Self {
        let guard = ScopeGuard::new_lab(&[]).expect("empty lab scope is valid");
        Self::from_builder(Client::builder(), &guard).expect("build lab client")
    }

    /// Clone this client with an isolated per-host transport breaker.
    /// DNS policy and host pacing remain shared with the original client.
    #[must_use]
    pub fn isolated_breaker(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            resolver: self.resolver.clone(),
            breaker: Arc::new(TransportBreaker {
                isolated_states: Some(Mutex::new(HashMap::new())),
                ..TransportBreaker::default()
            }),
        }
    }

    /// Build from a caller's configuration, overriding only the redirect policy.
    /// Timeouts, TLS settings and proxy behavior are preserved.
    ///
    /// # Errors
    /// Propagates reqwest client construction failures.
    pub fn from_builder(
        builder: ClientBuilder,
        guard: &ScopeGuard,
    ) -> Result<Self, reqwest::Error> {
        Self::from_builder_with_resolver(builder, SafeResolve::system(guard))
    }

    /// Build with a custom resolver wrapped by the safe-address policy.
    ///
    /// # Errors
    /// Propagates reqwest client construction failures.
    pub fn from_builder_with_resolver(
        builder: ClientBuilder,
        resolver: SafeResolve,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            inner: builder
                .dns_resolver(Arc::new(resolver.clone()))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            resolver,
            breaker: Arc::new(TransportBreaker::default()),
        })
    }

    /// URLs whose requests the circuit breaker short-circuited, in first-seen
    /// order. Report each as untested coverage — a breaker skip is never a
    /// silent gap.
    #[must_use]
    pub fn circuit_skipped(&self) -> Vec<String> {
        self.breaker.skipped_urls()
    }

    /// Record how long the target's root page took. Later requests to the
    /// same origin use `max(1s, average * 3)`, overriding explicit request
    /// timeouts unless the caller explicitly bypasses adaptation. Successful
    /// responses on an origin seed or refine this automatically.
    pub fn record_root_latency(&self, url: &Url, elapsed: Duration) {
        self.breaker.record_root_latency(url, elapsed);
    }

    /// The adaptive timeout for `url`, when this scan has a root sample.
    #[must_use]
    pub fn adaptive_timeout(&self, url: &Url) -> Option<Duration> {
        self.breaker.adaptive_timeout(url)
    }

    /// Attach the adaptive timeout unless the request explicitly bypasses it.
    fn apply_adaptive_timeout(&self, request: &mut Request) {
        apply_adaptive_timeout(&self.breaker, request, false);
    }

    /// Clamp adaptive timeouts to `cap` for the lifetime of this client.
    /// The CLI uses this so its fallback request cap cannot be enlarged by
    /// observed slow-host latency.
    #[must_use]
    pub fn with_adaptive_timeout_cap(self, cap: Duration) -> Self {
        self.breaker.set_adaptive_timeout_cap(cap);
        self
    }

    /// Resolve a target hostname and port, validating every returned address.
    ///
    /// IP literals are validated directly without DNS lookup.
    ///
    /// # Errors
    /// Returns an error if resolution fails, produces no addresses, or includes
    /// any prohibited address.
    pub async fn lookup_host(
        &self,
        host: &str,
        port: u16,
    ) -> std::io::Result<Vec<std::net::SocketAddr>> {
        if let Ok(ip) = host
            .strip_prefix('[')
            .and_then(|bare| bare.strip_suffix(']'))
            .unwrap_or(host)
            .parse::<std::net::IpAddr>()
        {
            if !self.resolver.allows_address(host, ip) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "target address is prohibited",
                ));
            }
            return Ok(vec![std::net::SocketAddr::new(ip, port)]);
        }
        self.resolver.lookup_host(host, port).await
    }

    /// A GET request builder whose send path observes the host limiter.
    pub fn get<U: IntoUrl>(&self, url: U) -> ScopedRequestBuilder {
        ScopedRequestBuilder(
            self.inner.get(url),
            self.resolver.clone(),
            Arc::clone(&self.breaker),
            false,
        )
    }

    /// A POST request builder whose send path observes the host limiter.
    pub fn post<U: IntoUrl>(&self, url: U) -> ScopedRequestBuilder {
        ScopedRequestBuilder(
            self.inner.post(url),
            self.resolver.clone(),
            Arc::clone(&self.breaker),
            false,
        )
    }

    /// A PATCH request builder whose send path observes the host limiter.
    pub fn patch<U: IntoUrl>(&self, url: U) -> ScopedRequestBuilder {
        ScopedRequestBuilder(
            self.inner.patch(url),
            self.resolver.clone(),
            Arc::clone(&self.breaker),
            false,
        )
    }

    /// A DELETE request builder whose send path observes the host limiter.
    pub fn delete<U: IntoUrl>(&self, url: U) -> ScopedRequestBuilder {
        ScopedRequestBuilder(
            self.inner.delete(url),
            self.resolver.clone(),
            Arc::clone(&self.breaker),
            false,
        )
    }

    /// A PUT request builder whose send path observes the host limiter.
    pub fn put<U: IntoUrl>(&self, url: U) -> ScopedRequestBuilder {
        ScopedRequestBuilder(
            self.inner.put(url),
            self.resolver.clone(),
            Arc::clone(&self.breaker),
            false,
        )
    }

    /// A HEAD request builder whose send path observes the host limiter.
    pub fn head<U: IntoUrl>(&self, url: U) -> ScopedRequestBuilder {
        ScopedRequestBuilder(
            self.inner.head(url),
            self.resolver.clone(),
            Arc::clone(&self.breaker),
            false,
        )
    }

    /// Build an arbitrary method request whose send path observes the limiter.
    pub fn request<U: IntoUrl>(&self, method: Method, url: U) -> ScopedRequestBuilder {
        ScopedRequestBuilder(
            self.inner.request(method, url),
            self.resolver.clone(),
            Arc::clone(&self.breaker),
            false,
        )
    }

    /// Execute a built request after waiting for its host's rate-limit token.
    pub async fn execute(&self, request: Request) -> Result<Response, ScanError> {
        self.execute_timed(request)
            .await
            .map(|(response, _)| response)
    }

    /// Execute a built request after waiting for its host's rate-limit token,
    /// returning how long the request itself took. The limiter wait is excluded
    /// so pacing is never mistaken for server latency by a timing probe.
    pub async fn execute_timed(
        &self,
        mut request: Request,
    ) -> Result<(Response, Duration), ScanError> {
        let url = request.url().clone();
        if self.breaker.is_open(&url) {
            self.breaker.skip(&url);
            return Err(host_unreachable(&url));
        }
        self.apply_adaptive_timeout(&mut request);
        match execute_with_retries(&self.inner, &self.resolver, &self.breaker, request).await {
            Ok((response, elapsed)) => {
                self.breaker.observe_success(&url, elapsed);
                Ok((response, elapsed))
            }
            Err(error) => {
                let category = crate::transport::TransportError::from_reqwest(&error);
                if matches!(
                    category,
                    crate::transport::TransportError::ConnectionRefused
                        | crate::transport::TransportError::Timeout
                ) {
                    self.breaker.failed(&url);
                } else {
                    // Other transport failures break the consecutive timeout/refusal run.
                    self.breaker.healthy(&url);
                }
                Err(ScanError::Http(error))
            }
        }
    }

    /// Follow a redirect manually, checking each hop against `guard` first.
    /// Security-sensitive headers are dropped when the origin changes.
    ///
    /// # Errors
    /// Scope violations, invalid loops/chains, or transport failures.
    pub async fn send_scoped(
        &self,
        mut request: Request,
        guard: &ScopeGuard,
    ) -> Result<Response, ScanError> {
        let mut seen: HashSet<Url> = HashSet::new();
        // shortcut: scheme/port changes are refused on every hop rather than
        // tracked per scope origin. Upgrade by adding port/scheme sets to
        // ScopeGuard if a consumer needs cross-port in-scope redirects.
        let boundary_scheme = request.url().scheme().to_owned();
        let boundary_port = request.url().port_or_known_default();
        for _ in 0..=MAX_REDIRECT_HOPS {
            guard.check_request(request.url(), request.method())?;
            let current = request.url().clone();
            if !seen.insert(current.clone()) {
                return Err(ScanError::RedirectLoop(current.to_string()));
            }
            let method = request.method().clone();
            let headers = request.headers().clone();
            if self.breaker.is_open(request.url()) {
                self.breaker.skip(request.url());
                return Err(host_unreachable(request.url()));
            }
            let response = match self.execute(request).await {
                Ok(response) => response,
                Err(error) => return Err(error),
            };
            if !response.status().is_redirection() || response.status() == StatusCode::NOT_MODIFIED
            {
                return Ok(response);
            }
            let location = response
                .headers()
                .get(LOCATION)
                .ok_or(ScanError::InvalidRedirect)?
                .to_str()
                .map_err(|_| ScanError::InvalidRedirect)?;
            let next_url = current.join(location).map_err(|_| ScanError::InvalidUrl)?;
            if next_url.scheme() != boundary_scheme
                || next_url.port_or_known_default() != boundary_port
            {
                return Err(ScanError::RedirectBoundaryChange(next_url.to_string()));
            }
            let next_method = redirect_method(response.status(), &method);
            // Scope check happens before the next request is built or sent.
            guard.check_request(&next_url, &next_method)?;
            // shortcut: a 307/308 keeps its method but drops the body; the
            // body cannot be replayed from a stream. Upgrade by buffering the
            // body when a consumer needs exact 307/308 semantics.
            request = Request::new(next_method, next_url);
            *request.headers_mut() = strip_cross_origin_headers(&headers, &current, request.url());
        }
        Err(ScanError::TooManyRedirects(MAX_REDIRECT_HOPS))
    }

    /// Follow in-scope redirects one exchange per hop, without transport
    /// retries. Discovery uses this so an in-scope redirect chain costs exactly
    /// one request per hop and a 429/503 is observed immediately.
    ///
    /// # Errors
    /// Scope violations, invalid loops/chains, or transport failures.
    pub async fn send_scoped_once(
        &self,
        mut request: Request,
        guard: &ScopeGuard,
    ) -> Result<Response, ScanError> {
        let mut seen: HashSet<Url> = HashSet::new();
        let boundary_scheme = request.url().scheme().to_owned();
        let boundary_port = request.url().port_or_known_default();
        for _ in 0..=MAX_REDIRECT_HOPS {
            guard.check_request(request.url(), request.method())?;
            let current = request.url().clone();
            if !seen.insert(current.clone()) {
                return Err(ScanError::RedirectLoop(current.to_string()));
            }
            let method = request.method().clone();
            let headers = request.headers().clone();
            let (response, _) =
                execute_once(&self.inner, &self.resolver, &self.breaker, request, false).await?;
            if !response.status().is_redirection() || response.status() == StatusCode::NOT_MODIFIED
            {
                return Ok(response);
            }
            let location = response
                .headers()
                .get(LOCATION)
                .ok_or(ScanError::InvalidRedirect)?
                .to_str()
                .map_err(|_| ScanError::InvalidRedirect)?;
            let next_url = current.join(location).map_err(|_| ScanError::InvalidUrl)?;
            if next_url.scheme() != boundary_scheme
                || next_url.port_or_known_default() != boundary_port
            {
                return Err(ScanError::RedirectBoundaryChange(next_url.to_string()));
            }
            let next_method = redirect_method(response.status(), &method);
            guard.check_request(&next_url, &next_method)?;
            request = Request::new(next_method, next_url);
            *request.headers_mut() = strip_cross_origin_headers(&headers, &current, request.url());
        }
        Err(ScanError::TooManyRedirects(MAX_REDIRECT_HOPS))
    }
}

impl Default for ScopedClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Request builder that preserves reqwest's fluent configuration while
/// routing its send through RIFTLOCK's per-host limiter.
pub struct ScopedRequestBuilder(
    reqwest::RequestBuilder,
    SafeResolve,
    Arc<TransportBreaker>,
    bool,
);

async fn read_body_prefix(
    response: Response,
    limit: usize,
) -> (
    Vec<u8>,
    Pin<Box<dyn Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send>>,
    bool,
) {
    let mut stream: Pin<Box<dyn Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send>> =
        Box::pin(response.bytes_stream());
    let mut prefix = Vec::new();
    let mut remainder = limit;
    let mut truncated = false;
    while remainder > 0 {
        match stream.next().await {
            Some(Ok(chunk)) => {
                let take = chunk.len().min(remainder);
                prefix.extend_from_slice(&chunk[..take]);
                remainder -= take;
                if take < chunk.len() {
                    stream = Box::pin(
                        stream::iter(std::iter::once(Ok(chunk.slice(take..)))).chain(stream),
                    );
                    truncated = true;
                    break;
                }
                if remainder == 0 {
                    truncated = true;
                    break;
                }
            }
            Some(Err(error)) => {
                stream = Box::pin(stream::iter(std::iter::once(Err(error))).chain(stream));
                truncated = true;
                break;
            }
            None => break,
        }
    }
    (prefix, stream, truncated)
}

async fn inspect_rate_limit_response(
    response: Response,
    url: &Url,
) -> Result<(Response, bool, bool, Option<Duration>), reqwest::Error> {
    let status = response.status();
    let has_retry_after = response.headers().contains_key(RETRY_AFTER);
    let retry_after = retry_after(response.headers().get(RETRY_AFTER));
    let mut marked_block = false;
    if matches!(
        status,
        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
    ) {
        const BODY_MARKER_LIMIT: usize = 8192;
        let headers = response.headers().clone();
        let version = response.version();
        let (marker_bytes, remainder_stream, truncated) =
            read_body_prefix(response, BODY_MARKER_LIMIT).await;
        let body = marker_bytes.clone();
        let marker = String::from_utf8_lossy(&body).to_ascii_lowercase();
        marked_block = marker.contains("abuse") || marker.contains("blocked");
        let mut builder = http::Response::builder()
            .status(status)
            .version(version)
            .url(url.clone());
        *builder.headers_mut().expect("response builder headers") = headers.clone();
        let prefix = stream::iter(std::iter::once(Ok(bytes::Bytes::from(body))));
        let body_stream: Pin<Box<dyn Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send>> =
            if truncated {
                Box::pin(prefix.chain(remainder_stream))
            } else {
                Box::pin(prefix)
            };
        let rebuilt = builder
            .body(reqwest::Body::wrap_stream(body_stream))
            .expect("valid response parts");
        return Ok((
            Response::from(rebuilt),
            marked_block,
            has_retry_after,
            retry_after,
        ));
    }
    Ok((response, marked_block, has_retry_after, retry_after))
}

async fn execute_with_retries(
    client: &Client,
    resolver: &SafeResolve,
    breaker: &TransportBreaker,
    mut request: Request,
) -> Result<(Response, Duration), reqwest::Error> {
    let url = request.url().clone();
    let origin = origin_for(&url);
    let mut retries = 0usize;
    let mut elapsed = Duration::ZERO;
    loop {
        wait_for_request(&url).await;
        let started = std::time::Instant::now();
        reject_unsafe_literal(request.url(), resolver)?;
        let method = request.method().clone();
        let replay = request.try_clone();
        // A timed-out request should count immediately toward the global
        // breaker rather than being hidden behind a second long transport wait.
        let response = client.execute(request).await?;
        elapsed = elapsed.saturating_add(started.elapsed());
        let status = response.status();
        let retryable_status = matches!(
            status,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
        );
        let (response, marked_block, has_retry_after, retryable_after) =
            inspect_rate_limit_response(response, &url).await?;
        let response_was_rate_limited = matches!(
            status,
            StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
        ) && (marked_block || has_retry_after);
        breaker.healthy(&url);
        if response_was_rate_limited {
            let delay = retryable_after.unwrap_or(Duration::from_secs(30));
            host_limits().cooldown(&origin, Some(delay)).await;
            crate::logln!(
                "[!] Host {origin} rate-limited, retry after {} seconds.",
                delay.as_secs()
            );
        }
        if !retryable_status {
            host_limits().success(&origin).await;
            return Ok((response, elapsed));
        }
        if retryable_after.is_none() && marked_block {
            return Ok((response, elapsed));
        }
        // A present but unparseable Retry-After on a 429 still means the host
        // asked us to wait; use the 30s default instead of a short backoff.
        let delay = retryable_after
            .or_else(|| {
                (status == StatusCode::TOO_MANY_REQUESTS && has_retry_after)
                    .then_some(Duration::from_secs(30))
            })
            .unwrap_or_else(|| {
                retry_backoff(&origin, retries.saturating_add(1)).min(MAX_RETRY_DELAY)
            });
        host_limits().cooldown(&origin, Some(delay)).await;
        if retries >= MAX_RETRIES || !retryable_method(&method) {
            return Ok((response, elapsed));
        }
        let Some(replay) = replay else {
            return Ok((response, elapsed));
        };
        retries += 1;
        request = replay;
    }
}

impl ScopedRequestBuilder {
    /// Add a request header.
    pub fn header<K, V>(self, name: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        Self(self.0.header(name, value), self.1, self.2, self.3)
    }

    /// Merge request headers.
    pub fn headers(self, headers: HeaderMap) -> Self {
        Self(self.0.headers(headers), self.1, self.2, self.3)
    }

    /// Set the request body.
    pub fn body<T: Into<reqwest::Body>>(self, body: T) -> Self {
        Self(self.0.body(body), self.1, self.2, self.3)
    }

    /// Serialize a JSON request body.
    pub fn json<T: Serialize + ?Sized>(self, json: &T) -> Self {
        Self(self.0.json(json), self.1, self.2, self.3)
    }

    /// Serialize a form request body.
    pub fn form<T: Serialize + ?Sized>(self, form: &T) -> Self {
        Self(self.0.form(form), self.1, self.2, self.3)
    }

    /// Append query parameters.
    pub fn query<T: Serialize + ?Sized>(self, query: &T) -> Self {
        Self(self.0.query(query), self.1, self.2, self.3)
    }

    /// Set a per-request timeout, which adaptive host timing overrides by default.
    pub fn timeout(self, timeout: Duration) -> Self {
        Self(self.0.timeout(timeout), self.1, self.2, self.3)
    }

    /// Preserve the caller's timeout instead of applying the adaptive host timeout.
    #[must_use]
    pub fn bypass_adaptive_timeout(mut self) -> Self {
        self.3 = true;
        self
    }

    /// Set bearer authentication.
    pub fn bearer_auth<T: fmt::Display>(self, token: T) -> Self {
        Self(self.0.bearer_auth(token), self.1, self.2, self.3)
    }

    /// Set basic authentication.
    pub fn basic_auth<U: fmt::Display, P: fmt::Display>(
        self,
        username: U,
        password: Option<P>,
    ) -> Self {
        Self(
            self.0.basic_auth(username, password),
            self.1,
            self.2,
            self.3,
        )
    }

    /// Build the request without sending it.
    pub fn build(self) -> Result<Request, reqwest::Error> {
        self.0.build()
    }

    /// Send the request after acquiring its per-host token.
    ///
    /// # Errors
    /// [`ScanError::HostUnreachable`] without touching the network once the
    /// client's breaker has tripped; otherwise the transport failure.
    pub async fn send(self) -> Result<Response, ScanError> {
        self.send_timed().await.map(|(response, _)| response)
    }

    /// Send the request after acquiring its per-host token, returning how long
    /// the request itself took. The limiter wait is excluded so pacing is never
    /// mistaken for server latency by a timing probe.
    ///
    /// # Errors
    /// [`ScanError::HostUnreachable`] without touching the network once the
    /// client's breaker has tripped; otherwise the transport failure.
    pub async fn send_timed(self) -> Result<(Response, Duration), ScanError> {
        let Self(builder, resolver, breaker, bypass_adaptive) = self;
        let (client, request) = builder.build_split();
        let mut request = request?;
        let url = request.url().clone();
        if breaker.is_open(&url) {
            breaker.skip(&url);
            return Err(host_unreachable(&url));
        }
        apply_adaptive_timeout(&breaker, &mut request, bypass_adaptive);
        match execute_with_retries(&client, &resolver, &breaker, request).await {
            Ok((response, elapsed)) => {
                breaker.observe_success(&url, elapsed);
                Ok((response, elapsed))
            }
            Err(error) => {
                let category = crate::transport::TransportError::from_reqwest(&error);
                if matches!(
                    category,
                    crate::transport::TransportError::ConnectionRefused
                        | crate::transport::TransportError::Timeout
                ) {
                    breaker.failed(&url);
                } else {
                    breaker.healthy(&url);
                }
                Err(ScanError::Http(error))
            }
        }
    }

    /// Send exactly one HTTP exchange without status or timeout retries.
    /// Baseline classification uses this so two consecutive 429/503/challenge
    /// responses mean two requests, not hidden transport retries.
    ///
    /// # Errors
    /// [`ScanError::HostUnreachable`] once the client's breaker is open;
    /// otherwise the underlying transport failure.
    pub async fn send_once_timed(self) -> Result<(Response, Duration), ScanError> {
        let Self(builder, resolver, breaker, bypass_adaptive) = self;
        let (client, request) = builder.build_split();
        let request = request?;
        execute_once(&client, &resolver, &breaker, request, bypass_adaptive).await
    }
}

/// Perform exactly one HTTP exchange, honouring the breaker, adaptive timeout
/// and per-host limiter. Shared by [`ScopedRequestBuilder::send_once_timed`]
/// and [`ScopedClient::send_scoped_once`], so a redirect hop costs one request.
async fn execute_once(
    client: &Client,
    resolver: &SafeResolve,
    breaker: &TransportBreaker,
    mut request: Request,
    bypass_adaptive: bool,
) -> Result<(Response, Duration), ScanError> {
    let url = request.url().clone();
    if breaker.is_open(&url) {
        breaker.skip(&url);
        return Err(host_unreachable(&url));
    }
    apply_adaptive_timeout(breaker, &mut request, bypass_adaptive);
    wait_for_request(&url).await;
    reject_unsafe_literal(&url, resolver)?;
    let started = std::time::Instant::now();
    match client.execute(request).await {
        Ok(response) => {
            let elapsed = started.elapsed();
            let status = response.status();
            let (response, marked_block, has_retry_after, retry_after) =
                inspect_rate_limit_response(response, &url).await?;
            let rate_limited = matches!(
                status,
                StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
            ) && (marked_block || has_retry_after);
            if rate_limited {
                breaker.healthy(&url);
                let delay = retry_after.unwrap_or(Duration::from_secs(30));
                host_limits().cooldown(&origin_for(&url), Some(delay)).await;
                crate::logln!(
                    "[!] Host {} rate-limited, retry after {} seconds.",
                    origin_for(&url),
                    delay.as_secs()
                );
            } else {
                if !matches!(
                    status,
                    StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
                ) {
                    host_limits().success(&origin_for(&url)).await;
                }
                breaker.healthy(&url);
            }
            breaker.observe_success(&url, elapsed);
            Ok((response, elapsed))
        }
        Err(error) => {
            let category = crate::transport::TransportError::from_reqwest(&error);
            if matches!(
                category,
                crate::transport::TransportError::ConnectionRefused
                    | crate::transport::TransportError::Timeout
            ) {
                breaker.failed(&url);
            } else {
                breaker.healthy(&url);
            }
            Err(ScanError::Http(error))
        }
    }
}

fn apply_adaptive_timeout(
    breaker: &TransportBreaker,
    request: &mut Request,
    bypass_adaptive: bool,
) {
    if !bypass_adaptive {
        if let Some(timeout) = breaker.adaptive_timeout(request.url()) {
            *request.timeout_mut() = Some(timeout);
        }
    }
}

fn host_unreachable(url: &Url) -> ScanError {
    ScanError::HostUnreachable(origin_for(url))
}

fn retryable_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn retry_after(value: Option<&HeaderValue>) -> Option<Duration> {
    let value = value?.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(
        at.duration_since(std::time::SystemTime::now())
            .unwrap_or_default(),
    )
}

fn retry_backoff(origin: &str, attempt: usize) -> Duration {
    let exponential = Duration::from_millis(250u64.saturating_mul(1u64 << attempt.min(7)));
    let jitter = origin.bytes().fold(attempt as u64, |seed, byte| {
        seed.wrapping_mul(31).wrapping_add(u64::from(byte))
    }) % 251;
    exponential
        .saturating_add(Duration::from_millis(jitter))
        .min(MAX_RETRY_DELAY)
}

fn origin_for(url: &Url) -> String {
    format!(
        "{}://{}:{}",
        url.scheme(),
        url.host_str().unwrap_or_default().to_ascii_lowercase(),
        url.port_or_known_default().unwrap_or(0)
    )
}

/// Scheme-independent breaker identity: one host and port share health across engines.
fn host_key(url: &Url) -> String {
    format!(
        "{}:{}",
        url.host_str().unwrap_or_default().to_ascii_lowercase(),
        url.port_or_known_default().unwrap_or(0)
    )
}

fn reject_unsafe_literal(url: &Url, resolver: &SafeResolve) -> Result<(), reqwest::Error> {
    let Some(host) = url.host_str() else {
        return Ok(());
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return Ok(());
    };
    if resolver.allows_address(host, ip) {
        return Ok(());
    }

    // Reqwest exposes no error constructor; its URL parser can produce the
    // public error type locally, without opening a connection.
    Client::new()
        .get("http://[")
        .build()
        .map(|_| ())
        .map_err(|error| error.with_url(url.clone()))
}

async fn wait_for_request(url: &Url) {
    host_limits().until_ready(&origin_for(url)).await;
}

/// 303 always becomes GET; 301/302 downgrade non-idempotent methods; 307/308
/// keep the method because the client must not change the operation's meaning.
fn redirect_method(status: StatusCode, original: &Method) -> Method {
    if status == StatusCode::SEE_OTHER
        || ((status == StatusCode::MOVED_PERMANENTLY || status == StatusCode::FOUND)
            && original != Method::GET
            && original != Method::HEAD)
    {
        Method::GET
    } else {
        original.clone()
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn strip_cross_origin_headers(headers: &HeaderMap, from: &Url, to: &Url) -> HeaderMap {
    let mut out = headers.clone();
    if !same_origin(from, to) {
        // shortcut: only standard auth/cookie headers are stripped; custom
        // token headers (X-Api-Key etc.) are not inferred. Upgrade by adding a
        // configured sensitive-header deny-list when a consumer needs one.
        out.remove(AUTHORIZATION);
        out.remove(PROXY_AUTHORIZATION);
        out.remove(COOKIE);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScanPolicy;

    fn lab() -> ScopeGuard {
        ScopeGuard::new_lab(&["http://127.0.0.1"]).expect("lab guard")
    }

    #[test]
    fn breaker_trips_after_twenty_consecutive_failures_and_success_resets_host() {
        let url = Url::parse("http://breaker-reset.invalid:80/root").expect("URL");
        let other = Url::parse("http://other-breaker.invalid:80/root").expect("URL");
        let state = Arc::new(HostState {
            threshold: 20,
            consecutive: AtomicU32::new(0),
            failure_window: Mutex::new(VecDeque::new()),
            open: AtomicBool::new(false),
        });
        let breaker = TransportBreaker {
            isolated_states: Some(Mutex::new(HashMap::from([(
                host_key(&url),
                Arc::clone(&state),
            )]))),
            ..TransportBreaker::default()
        };
        for _ in 0..19 {
            state.failed();
        }
        assert!(!breaker.is_open(&url));
        state.failed();
        assert!(breaker.is_open(&url));
        assert!(!breaker.is_open(&other));
        breaker.healthy(&url);
        assert!(!breaker.is_open(&url));
        assert_eq!(state.consecutive.load(Ordering::Relaxed), 0);
        assert_eq!(state.failure_window.lock().unwrap().len(), 1);
    }

    fn rate_limited_response(
        status: StatusCode,
        headers: HeaderMap,
        body: &'static str,
    ) -> Response {
        let mut builder = http::Response::builder().status(status);
        *builder.headers_mut().expect("response headers") = headers;
        Response::from(builder.body(body.to_owned()).expect("response body"))
    }

    #[tokio::test]
    async fn blocked_403_uses_shared_default_cooldown_without_transport_failure() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(403).set_body_string("access blocked"))
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("server URL");
        let origin = origin_for(&url);
        let client = ScopedClient::new_lab().isolated_breaker();
        let response = client
            .get(url.clone())
            .send_once_timed()
            .await
            .expect("rate-limit response is returned")
            .0;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.text().await.expect("response body"),
            "access blocked"
        );

        let state = client.breaker.isolated_state(&url).expect("isolated state");
        assert_eq!(state.consecutive.load(Ordering::Relaxed), 0);
        assert_eq!(
            state
                .failure_window
                .lock()
                .unwrap()
                .iter()
                .filter(|failed| **failed)
                .count(),
            0
        );
        assert_eq!(origin_for(&url), origin);
    }

    #[tokio::test]
    async fn rate_limit_marker_without_header_is_detected_and_body_is_preserved() {
        let url = Url::parse("http://rate-limit.invalid/resource").expect("URL");
        let response =
            rate_limited_response(StatusCode::FORBIDDEN, HeaderMap::new(), "abuse blocked");
        let (response, marked, has_header, delay) = inspect_rate_limit_response(response, &url)
            .await
            .expect("inspect");
        assert!(marked);
        assert!(!has_header);
        assert_eq!(delay, None);
        assert_eq!(response.text().await.expect("body"), "abuse blocked");
    }

    #[tokio::test]
    async fn retry_after_header_is_detected_even_when_unparseable() {
        let url = Url::parse("http://rate-limit-header.invalid/resource").expect("URL");
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "not-a-date".parse().expect("header"));
        let response = rate_limited_response(StatusCode::TOO_MANY_REQUESTS, headers, "ignored");
        let (response, marked, has_header, delay) = inspect_rate_limit_response(response, &url)
            .await
            .expect("inspect");
        assert!(!marked);
        assert!(has_header);
        assert_eq!(delay, None);
        assert_eq!(response.text().await.expect("body"), "ignored");
    }

    #[tokio::test]
    async fn rate_limit_response_with_retry_after_is_exempt_from_breaker_failures() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "not-a-date")
                    .set_body_string("slow down"),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("server URL");
        let client = ScopedClient::new_lab().isolated_breaker();
        let response = client
            .get(url.clone())
            .send_once_timed()
            .await
            .expect("rate-limit response is returned")
            .0;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.text().await.expect("body"), "slow down");

        let state = client.breaker.isolated_state(&url).expect("isolated state");
        assert_eq!(state.consecutive.load(Ordering::Relaxed), 0);
        assert!(!state.open.load(Ordering::Relaxed));
        assert_eq!(
            state
                .failure_window
                .lock()
                .unwrap()
                .iter()
                .filter(|failed| **failed)
                .count(),
            0
        );
    }

    #[test]
    fn breaker_trips_at_half_failures_in_twenty_requests() {
        let url = Url::parse("http://breaker-rate.invalid:80/root").expect("URL");
        let state = Arc::new(HostState {
            threshold: 20,
            consecutive: AtomicU32::new(0),
            failure_window: Mutex::new(VecDeque::new()),
            open: AtomicBool::new(false),
        });
        let breaker = TransportBreaker {
            isolated_states: Some(Mutex::new(HashMap::from([(
                host_key(&url),
                Arc::clone(&state),
            )]))),
            ..TransportBreaker::default()
        };
        for _ in 0..10 {
            state.failed();
            state.healthy();
        }
        assert!(breaker.is_open(&url));
        assert_eq!(state.failure_window.lock().unwrap().len(), 20);
    }

    #[test]
    fn adaptive_timeout_scales_from_root_latency_with_a_one_second_floor() {
        let breaker = TransportBreaker::default();
        let fast = Url::parse("http://adaptive-fast.invalid:81/root").expect("fast URL");
        let slow = Url::parse("http://adaptive-slow.invalid:82/root").expect("slow URL");
        let unknown = Url::parse("http://adaptive-unknown.invalid:83/root").expect("unknown URL");
        breaker.record_root_latency(&fast, Duration::from_millis(50));
        breaker.record_root_latency(&slow, Duration::from_secs(20));
        assert_eq!(
            breaker.adaptive_timeout(&fast),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            breaker.adaptive_timeout(&slow),
            Some(Duration::from_secs(60))
        );
        assert_eq!(breaker.adaptive_timeout(&unknown), None);
    }

    #[test]
    fn adaptive_timeout_overrides_explicit_timeout_unless_bypassed() {
        let breaker = TransportBreaker::default();
        let url = Url::parse("http://adaptive-explicit.invalid:84/root").expect("URL");
        breaker.record_root_latency(&url, Duration::from_secs(20));
        let mut default = reqwest::Client::new()
            .get(url.clone())
            .timeout(Duration::from_secs(2))
            .build()
            .expect("adaptive request");
        apply_adaptive_timeout(&breaker, &mut default, false);
        assert_eq!(default.timeout(), Some(&Duration::from_secs(60)));

        let mut bypassed = reqwest::Client::new()
            .get(url)
            .timeout(Duration::from_secs(2))
            .build()
            .expect("bypassed request");
        apply_adaptive_timeout(&breaker, &mut bypassed, true);
        assert_eq!(bypassed.timeout(), Some(&Duration::from_secs(2)));
    }

    #[test]
    fn redirect_method_rules() {
        assert_eq!(
            redirect_method(StatusCode::SEE_OTHER, &Method::POST),
            Method::GET
        );
        assert_eq!(
            redirect_method(StatusCode::FOUND, &Method::POST),
            Method::GET
        );
        assert_eq!(
            redirect_method(StatusCode::FOUND, &Method::GET),
            Method::GET
        );
        assert_eq!(
            redirect_method(StatusCode::TEMPORARY_REDIRECT, &Method::POST),
            Method::POST
        );
    }

    #[test]
    fn cross_origin_strips_only_sensitive_headers() {
        let a = Url::parse("http://127.0.0.1:1/a").unwrap();
        let b = Url::parse("http://127.0.0.1:2/b").unwrap();
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, "bearer x".parse().unwrap());
        h.insert(COOKIE, "sid=x".parse().unwrap());
        h.insert("x-trace", "keep".parse().unwrap());
        let out = strip_cross_origin_headers(&h, &a, &b);
        assert!(!out.contains_key(AUTHORIZATION));
        assert!(!out.contains_key(COOKIE));
        assert_eq!(out.get("x-trace").unwrap(), "keep");
        let same = strip_cross_origin_headers(&h, &a, &a);
        assert!(same.contains_key(AUTHORIZATION));
    }

    #[test]
    fn read_only_guard_rejects_write_redirect_target() {
        let guard = lab().with_policy(ScanPolicy::ReadOnly);
        let url = Url::parse("http://127.0.0.1/write").unwrap();
        assert!(guard.check_request(&url, &Method::POST).is_err());
    }

    /// Serve exactly three HTTP/1.1 requests, closing each connection, then
    /// drop the listener so every later connect is actively refused.
    async fn serve_three_requests_then_close(listener: tokio::net::TcpListener) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut head = Vec::new();
            let mut buffer = [0u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.expect("read request");
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buffer[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .expect("write response");
            stream.shutdown().await.expect("close connection");
        }
    }

    #[tokio::test]
    async fn dead_host_breaker_fails_twenty_requests_within_fifty_milliseconds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind reset server");
        let addr = listener.local_addr().expect("local address");
        let server = tokio::spawn(serve_three_requests_then_close(listener));
        let client = ScopedClient::new_lab();
        let url = format!("http://{addr}/reset");
        for _ in 0..3 {
            client
                .get(&url)
                .send()
                .await
                .expect("warm request succeeds");
        }
        server.await.expect("server task");

        // Exercise the configured trip threshold directly; live requests below
        // verify that an open breaker skips the network.
        let state = host_state(&Url::parse(&url).expect("URL"));
        state.healthy();
        for _ in 0..20 {
            state.failed();
        }
        assert!(client.breaker.is_open(&Url::parse(&url).expect("URL")));
        let started = std::time::Instant::now();
        for _ in 0..20 {
            assert!(
                matches!(
                    client.get(&url).send().await,
                    Err(ScanError::HostUnreachable(_))
                ),
                "breaker must short-circuit dead-host requests"
            );
        }
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "twenty short-circuited requests took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn open_breaker_short_circuits_without_network_attempt() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind dead server");
        let addr = listener.local_addr().expect("local address");
        drop(listener);
        let client = ScopedClient::new_lab();
        let url = format!("http://{addr}/dead");
        let parsed = Url::parse(&url).expect("URL");
        let state = host_state(&parsed);
        state.healthy();
        for _ in 0..20 {
            state.failed();
        }
        assert!(matches!(
            client.get(&url).send().await,
            Err(ScanError::HostUnreachable(_))
        ));
        assert_eq!(client.circuit_skipped(), vec![url]);
    }

    #[tokio::test]
    async fn retries_retry_after_response_for_idempotent_request() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(|_: &wiremock::Request| {
                ResponseTemplate::new(503).insert_header("Retry-After", "0")
            })
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let response = ScopedClient::new_lab()
            .get(server.uri())
            .send()
            .await
            .expect("request succeeds after retry");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(server.received_requests().await.expect("requests").len(), 2);
    }

    #[tokio::test]
    async fn does_not_retry_non_idempotent_post_requests() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .mount(&server)
            .await;

        let response = ScopedClient::new_lab()
            .post(server.uri())
            .body("one-shot payload")
            .send()
            .await
            .expect("rate-limit response is returned");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(server.received_requests().await.expect("requests").len(), 1);
    }

    #[tokio::test]
    async fn retries_stop_after_three_retries_and_return_last_response() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .mount(&server)
            .await;

        let response = ScopedClient::new_lab()
            .get(server.uri())
            .send()
            .await
            .expect("rate-limit response is returned");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(server.received_requests().await.expect("requests").len(), 4);
    }

    #[tokio::test]
    async fn ordinary_requests_through_clones_are_paced_per_host() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("server URL");
        let client = ScopedClient::new_lab();
        let started = std::time::Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let client = client.clone();
            let url = url.clone();
            tasks.spawn(async move {
                client.get(url).send().await.expect("request succeeds");
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.expect("request task succeeds");
        }
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(450),
            "twenty requests to one host should exceed the initial ten-token burst"
        );
    }
}
