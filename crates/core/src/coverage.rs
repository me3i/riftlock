//! Scan coverage counters: what the engines actually probed, what stayed
//! untested, and why. Negative space is first-class — a WAF-blocked or
//! timed-out endpoint is a reported outcome, never a silent gap, and a
//! blocked or timed-out *check* is Inconclusive, never a fabricated finding.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Why an endpoint ended up outside the successfully-tested set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndpointOutcome {
    /// Answered a real request and was fuzzed.
    Tested,
    /// Requests stalled past the client timeout.
    TimedOut,
    /// Transport failed without timing out (refused, reset, DNS).
    Failed,
    /// The endpoint requires authentication (401).
    AuthRequired,
    /// A WAF/proxy answered for the origin (403/406).
    WafBlocked,
    /// Confirmed dead or not applicable (404/410, scope-rejected) — a
    /// checked negative, not a silent gap.
    Skipped,
    /// Not attempted: the per-scan circuit breaker was open. Counted as
    /// untested coverage, separately from a confirmed-absent skip.
    CircuitOpen,
}

/// Strength rank used by [`merge`]: a tested endpoint stays tested even
/// when a later pass failed; a blocked endpoint outranks a dead one.
fn rank(outcome: EndpointOutcome) -> u8 {
    match outcome {
        EndpointOutcome::Tested => 5,
        EndpointOutcome::WafBlocked | EndpointOutcome::AuthRequired => 4,
        EndpointOutcome::CircuitOpen => 3,
        EndpointOutcome::TimedOut | EndpointOutcome::Failed => 2,
        EndpointOutcome::Skipped => 1,
    }
}

/// Keep the stronger of two outcomes for the same endpoint.
#[must_use]
pub fn merge(best: EndpointOutcome, new: EndpointOutcome) -> EndpointOutcome {
    if rank(new) > rank(best) {
        new
    } else {
        best
    }
}

/// Path segments that identify a login wall. Compared as whole segments, so
/// `/authors` and `/authentication-guide` never match `/auth`.
const AUTH_PATH_SEGMENTS: &[&str] = &[
    "login",
    "log-in",
    "signin",
    "sign-in",
    "signon",
    "sign-on",
    "auth",
    "authenticate",
    "authentication",
    "sso",
    "oauth",
    "saml",
    "session",
];

/// Whether a redirect target is a known authentication wall. The location may
/// be relative; only its path is consulted, and only whole segments match.
#[must_use]
pub fn is_auth_redirect(location: &str) -> bool {
    let path = location.split(['?', '#']).next().unwrap_or(location).trim();
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .any(|segment| {
            AUTH_PATH_SEGMENTS
                .iter()
                .any(|auth| segment.eq_ignore_ascii_case(auth))
        })
}

/// Classify an endpoint's *baseline* response before any payload is sent.
///
/// This differs deliberately from [`classify`]: at baseline a 401/403 means
/// the route requires authentication, a 404 means the route is absent, and
/// both are terminal — no payload may follow. A redirect to a login wall is
/// also authentication-required. Probe-response classification is unchanged.
#[must_use]
pub fn classify_baseline(status: u16, location: Option<&str>) -> EndpointOutcome {
    match status {
        401 | 403 => EndpointOutcome::AuthRequired,
        300..=399 => match location {
            Some(location) if is_auth_redirect(location) => EndpointOutcome::AuthRequired,
            _ => EndpointOutcome::Tested,
        },
        404 | 410 => EndpointOutcome::Skipped,
        406 | 429 | 503 => EndpointOutcome::WafBlocked,
        // Any other complete HTTP response means the endpoint exists and the
        // check ran: a 4xx/5xx is a negative result, not a connection failure.
        100..=599 => EndpointOutcome::Tested,
        _ => EndpointOutcome::Failed,
    }
}

/// Outcomes that make further payloads against the same endpoint pointless.
fn blocks_endpoint(outcome: EndpointOutcome) -> bool {
    matches!(
        outcome,
        EndpointOutcome::AuthRequired | EndpointOutcome::WafBlocked | EndpointOutcome::Failed
    )
}

/// Classify a status code into an endpoint outcome.
#[must_use]
pub fn classify(status: u16) -> EndpointOutcome {
    match status {
        401 => EndpointOutcome::AuthRequired,
        403 | 406 | 429 | 503 => EndpointOutcome::WafBlocked,
        404 | 410 => EndpointOutcome::Skipped,
        // Any other complete HTTP response (2xx, 4xx, 5xx) means the check
        // ran; only a transport failure is a failed check.
        100..=599 => EndpointOutcome::Tested,
        _ => EndpointOutcome::Failed,
    }
}

/// Classify a transport failure (the request never produced a status).
#[must_use]
pub fn error_outcome(err: &reqwest::Error) -> EndpointOutcome {
    if err.is_timeout() {
        EndpointOutcome::TimedOut
    } else {
        EndpointOutcome::Failed
    }
}

/// Classify a scanner error. A breaker skip is `CircuitOpen`, a timeout is
/// `TimedOut`, and every other transport failure is `Failed`; non-transport
/// errors also fall back to `Failed` for callers that record them as misses.
#[must_use]
pub fn scan_error_outcome(err: &crate::scanner::ScanError) -> EndpointOutcome {
    match err {
        crate::scanner::ScanError::CircuitOpen | crate::scanner::ScanError::HostUnreachable(_) => {
            EndpointOutcome::CircuitOpen
        }
        crate::scanner::ScanError::Http(error) => error_outcome(error),
        crate::scanner::ScanError::Body(crate::body::BodyReadError::Transport(error)) => {
            error_outcome(error)
        }
        _ => EndpointOutcome::Failed,
    }
}

/// Shared coverage counters for one scan run. Clones share the same
/// counters: hand a clone to each engine task and snapshot at the end.
/// [`Coverage::fork`] additionally keeps a task-owned copy of every record,
/// so one engine's counts can be reported without differencing the shared
/// counters that other engines mutate concurrently.
#[derive(Debug, Clone, Default)]
pub struct Coverage {
    shared: Arc<Inner>,
    /// Engine-local counters, present only on a forked handle.
    local: Option<Arc<Inner>>,
}

/// One endpoint's merged disposition, keyed by URL. The run ledger keeps the
/// strongest outcome seen for a URL, so an endpoint tested by any engine is
/// never reported as untested by another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRecord {
    /// The absolute URL the outcome describes.
    pub url: String,
    /// The strongest outcome recorded for that URL.
    pub outcome: EndpointOutcome,
}

#[derive(Debug, Default)]
struct Inner {
    tested: AtomicU64,
    timed_out: AtomicU64,
    failed: AtomicU64,
    auth_required: AtomicU64,
    waf_blocked: AtomicU64,
    skipped: AtomicU64,
    circuit_open: AtomicU64,
    checks_attempted: AtomicU64,
    checks_completed: AtomicU64,
    checks_failed: AtomicU64,
    checks_inconclusive: AtomicU64,
    checks_timed_out: AtomicU64,
    checks_cancelled: AtomicU64,
    next_check_id: AtomicU64,
    duplicate_terminals: AtomicU64,
    terminal_checks: std::sync::Mutex<std::collections::HashSet<u64>>,
    /// URL-keyed dispositions for the untested-surface report. Merged with
    /// [`merge`], so a later success upgrades an earlier miss.
    endpoints: std::sync::Mutex<BTreeMap<String, EndpointOutcome>>,
    /// Endpoints whose baseline made payloads pointless. A hash set gives
    /// scanners an O(1) membership check per endpoint rather than rescanning
    /// the payload list (or the BTreeMap) for every probe.
    blocked: std::sync::Mutex<HashSet<String>>,
}

impl Inner {
    fn endpoint(&self, outcome: EndpointOutcome) {
        let cell = match outcome {
            EndpointOutcome::Tested => &self.tested,
            EndpointOutcome::TimedOut => &self.timed_out,
            EndpointOutcome::Failed => &self.failed,
            EndpointOutcome::AuthRequired => &self.auth_required,
            EndpointOutcome::WafBlocked => &self.waf_blocked,
            // A breaker skip is unattempted work, unlike a 404/410 skip,
            // which is a checked negative.
            EndpointOutcome::Skipped => &self.skipped,
            EndpointOutcome::CircuitOpen => &self.circuit_open,
        };
        cell.fetch_add(1, Ordering::Relaxed);
    }

    fn endpoint_at(&self, url: &str, outcome: EndpointOutcome) {
        self.endpoint(outcome);
        let mut endpoints = self
            .endpoints
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let merged = endpoints
            .entry(url.to_owned())
            .and_modify(|best| *best = merge(*best, outcome))
            .or_insert(outcome);
        let blocked = blocks_endpoint(*merged);
        drop(endpoints);
        let mut set = self
            .blocked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if blocked {
            set.insert(url.to_owned());
        } else {
            set.remove(url);
        }
    }

    fn mark_blocked(&self, url: &str) {
        self.blocked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(url.to_owned());
    }

    fn is_blocked(&self, url: &str) -> bool {
        self.blocked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(url)
    }

    fn attempt(&self) {
        self.checks_attempted.fetch_add(1, Ordering::Relaxed);
    }

    fn finish(&self, id: CheckId, state: CheckState) -> Result<(), CheckError> {
        let mut terminal = self
            .terminal_checks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !terminal.insert(id.0) {
            self.duplicate_terminals.fetch_add(1, Ordering::Relaxed);
            return Err(CheckError::DuplicateTerminal);
        }
        drop(terminal);
        let cell = match state {
            CheckState::Completed => &self.checks_completed,
            CheckState::Failed => &self.checks_failed,
            CheckState::Inconclusive => &self.checks_inconclusive,
            CheckState::TimedOut => &self.checks_timed_out,
            CheckState::Cancelled => &self.checks_cancelled,
        };
        cell.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// A started check's stable identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckId(u64);

/// A started check that guarantees exactly one terminal state. Dropping it
/// without an explicit verdict records `Inconclusive`, so early returns and
/// panics can never leave a check silently marked successful.
#[must_use = "a started check must reach a terminal state"]
pub struct PendingCheck<'a> {
    coverage: &'a Coverage,
    id: CheckId,
    finished: bool,
}

impl PendingCheck<'_> {
    /// Finish this check. Consumes the guard so it cannot be finished twice.
    ///
    /// # Errors
    /// [`CheckError::DuplicateTerminal`] if the id was already terminated.
    pub fn finish(mut self, state: CheckState) -> Result<(), CheckError> {
        self.finished = true;
        self.coverage.finish_check(self.id, state)
    }

    /// The stable id assigned at registration.
    #[must_use]
    pub fn id(&self) -> CheckId {
        self.id
    }
}

impl Drop for PendingCheck<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self
                .coverage
                .finish_check(self.id, CheckState::Inconclusive);
        }
    }
}

/// The single terminal state a check may reach, exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    /// The check executed and reached a definitive verdict.
    Completed,
    /// The check could not execute (transport error, crash).
    Failed,
    /// The check executed but the evidence was insufficient.
    Inconclusive,
    /// The check exceeded its deadline.
    TimedOut,
    /// The check was cancelled before it could finish.
    Cancelled,
}

/// A check tried to terminate twice, with an unknown id, or after snapshot.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CheckError {
    #[error("check already reached a terminal state")]
    DuplicateTerminal,
    #[error("unknown check id")]
    UnknownId,
}

impl Coverage {
    /// A handle whose records feed this ledger *and* their own counters.
    /// Use one per engine: concurrent engines share the run-wide ledger, so
    /// only task-owned counters can attribute a check to the engine that
    /// ran it.
    #[must_use]
    pub fn fork(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            local: Some(Arc::new(Inner::default())),
        }
    }

    /// The counters this handle reports: its own when forked, the run-wide
    /// ledger otherwise.
    fn counters(&self) -> &Inner {
        self.local.as_deref().unwrap_or(&self.shared)
    }

    fn record(&self, apply: impl Fn(&Inner)) {
        apply(&self.shared);
        if let Some(local) = &self.local {
            apply(local);
        }
    }

    /// Record one endpoint's outcome (each endpoint exactly once).
    pub fn endpoint(&self, outcome: EndpointOutcome) {
        self.record(|inner| inner.endpoint(outcome));
    }

    /// Record one endpoint's outcome keyed by URL. The run ledger keeps the
    /// strongest outcome seen for that URL; the aggregate counters record
    /// every classification event, as before.
    pub fn endpoint_at(&self, url: &str, outcome: EndpointOutcome) {
        self.record(|inner| inner.endpoint_at(url, outcome));
    }

    /// Record that an endpoint's baseline makes every later payload pointless
    /// (authentication wall, WAF cutoff, or a dead route). This updates the
    /// O(1) blocked set immediately, before the endpoint task finishes, so
    /// concurrent scanners can skip the endpoint without re-deriving why.
    pub fn mark_blocked(&self, url: &str) {
        self.record(|inner| inner.mark_blocked(url));
    }

    /// O(1) test used by scanners and proof admission: has this endpoint
    /// already been classified as one that must not receive payloads?
    #[must_use]
    pub fn is_blocked(&self, url: &str) -> bool {
        self.shared.is_blocked(url)
            || self
                .local
                .as_deref()
                .map(|local| local.is_blocked(url))
                .unwrap_or(false)
    }

    /// Record an endpoint probe whose response could not be read: the
    /// endpoint is `Failed` and the abandoned probe is `Inconclusive`.
    /// Unread data is never a tested endpoint or a completed check.
    pub fn unreadable_endpoint(&self) {
        self.endpoint(EndpointOutcome::Failed);
        let check = self.begin_check();
        let _ = check.finish(CheckState::Inconclusive);
    }

    /// URL-keyed [`Self::unreadable_endpoint`].
    pub fn unreadable_endpoint_at(&self, url: &str) {
        self.endpoint_at(url, EndpointOutcome::Failed);
        let check = self.begin_check();
        let _ = check.finish(CheckState::Inconclusive);
    }

    /// Record an endpoint rejected by scope before probing it. The skipped
    /// disposition is paired with a terminal inconclusive check so scope
    /// exclusions remain visible in both coverage ledgers.
    pub fn out_of_scope_endpoint(&self) {
        self.endpoint(EndpointOutcome::Skipped);
        self.scope_rejected_check();
    }

    /// URL-keyed [`Self::out_of_scope_endpoint`].
    pub fn out_of_scope_endpoint_at(&self, url: &str) {
        self.endpoint_at(url, EndpointOutcome::Skipped);
        self.scope_rejected_check();
    }

    /// Every URL the run ledger classified, with its merged outcome, sorted
    /// by URL. Read from the run-wide ledger (shared by forks), because the
    /// untested surface is a property of the whole scan.
    #[must_use]
    pub fn endpoint_records(&self) -> Vec<EndpointRecord> {
        self.shared
            .endpoints
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(url, outcome)| EndpointRecord {
                url: url.clone(),
                outcome: *outcome,
            })
            .collect()
    }

    /// Record a scope-rejected check without adding an endpoint disposition.
    /// Use when a caller will record the endpoint outcome separately.
    pub fn scope_rejected_check(&self) {
        let check = self.begin_check();
        let _ = check.finish(CheckState::Inconclusive);
    }

    /// One vulnerability check was dispatched (payload probe sent).
    pub fn check_attempted(&self) {
        self.record(Inner::attempt);
    }

    /// Start a check: assign a stable id and count it as attempted exactly once.
    #[must_use]
    pub fn start_check(&self) -> CheckId {
        self.record(Inner::attempt);
        // Ids come from the shared ledger so a forked check stays unique
        // run-wide and both ledgers can record its terminal state.
        CheckId(self.shared.next_check_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Start a check with a drop-safe guard.
    pub fn begin_check(&self) -> PendingCheck<'_> {
        PendingCheck {
            coverage: self,
            id: self.start_check(),
            finished: false,
        }
    }

    /// Terminate a started check. A second termination for the same id is
    /// rejected, so a retry needs its own `start_check` call.
    ///
    /// # Errors
    /// [`CheckError::DuplicateTerminal`] or [`CheckError::UnknownId`].
    pub fn finish_check(&self, id: CheckId, state: CheckState) -> Result<(), CheckError> {
        self.shared.finish(id, state)?;
        if let Some(local) = &self.local {
            // A duplicate here would mean the shared ledger already saw an
            // id this fork recorded twice; the shared error above covers it.
            let _ = local.finish(id, state);
        }
        Ok(())
    }

    /// One check reached a definitive verdict — proved *or* disproved.
    pub fn check_completed(&self) {
        self.record(|inner| {
            inner.checks_completed.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// One check could not reach a verdict: Inconclusive, never a finding.
    pub fn check_inconclusive(&self) {
        self.record(|inner| {
            inner.checks_inconclusive.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// One check failed to execute: Failed, never a clean negative.
    pub fn check_failed(&self) {
        self.record(|inner| {
            inner.checks_failed.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Validate the ledger at scan finalization. A run with checks still in
    /// flight or duplicate terminal transitions cannot claim complete
    /// accounting.
    #[must_use]
    pub fn finalize(&self) -> AccountingValidation {
        let counters = self.counters();
        let attempted = counters.checks_attempted.load(Ordering::Relaxed);
        let terminal = counters
            .terminal_checks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len() as u64;
        let in_flight = attempted.saturating_sub(terminal);
        let duplicates = counters.duplicate_terminals.load(Ordering::Relaxed);
        AccountingValidation {
            registered: attempted,
            terminal,
            in_flight,
            duplicates_rejected: duplicates,
        }
    }

    /// The run's snapshot. `endpoints_discovered` is supplied by the caller:
    /// discovery lives above the engines and is already counted there.
    #[must_use]
    pub fn snapshot(&self, endpoints_discovered: u64) -> CoverageSnapshot {
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let counters = self.counters();
        CoverageSnapshot {
            endpoints_discovered,
            endpoints_tested_successfully: load(&counters.tested),
            endpoints_timed_out: load(&counters.timed_out),
            endpoints_failed: load(&counters.failed),
            endpoints_auth_required: load(&counters.auth_required),
            endpoints_waf_blocked: load(&counters.waf_blocked),
            endpoints_skipped: load(&counters.skipped),
            endpoints_circuit_open: load(&counters.circuit_open),
            vulnerability_checks_attempted: load(&counters.checks_attempted),
            vulnerability_checks_completed: load(&counters.checks_completed),
            vulnerability_checks_inconclusive: load(&counters.checks_inconclusive),
            // Set by the caller, which owns findings and engine outcomes;
            // atomics here track only probe-level counters.
            passive_observations: 0,
            checks_failed: load(&counters.checks_failed),
            checks_timed_out: load(&counters.checks_timed_out),
            checks_cancelled: load(&counters.checks_cancelled),
            checks_skipped: 0,
        }
    }
}

/// Scan-boundary check of the authoritative ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountingValidation {
    /// Checks registered with a stable id.
    pub registered: u64,
    /// Checks that reached exactly one terminal state.
    pub terminal: u64,
    /// Checks still running at finalization — never a clean negative.
    pub in_flight: u64,
    /// Attempts to terminate a check twice that were rejected.
    pub duplicates_rejected: u64,
}

impl AccountingValidation {
    /// True only when every registered check terminated exactly once.
    #[must_use]
    pub fn reconciles(&self) -> bool {
        self.in_flight == 0 && self.duplicates_rejected == 0 && self.registered == self.terminal
    }
}

/// Plain-count snapshot of [`Coverage`] — the reportable scan coverage.
/// Re-exported as `riftlock_report::ScanCoverage`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct CoverageSnapshot {
    /// Endpoints discovery handed to the engines.
    pub endpoints_discovered: u64,
    /// Endpoints that answered a real request and were fuzzed.
    pub endpoints_tested_successfully: u64,
    /// Endpoints whose requests stalled past the client timeout.
    pub endpoints_timed_out: u64,
    /// Endpoints whose transport failed without timing out.
    pub endpoints_failed: u64,
    /// Endpoints answering 401.
    pub endpoints_auth_required: u64,
    /// Endpoints answered by a WAF/proxy (403/406).
    pub endpoints_waf_blocked: u64,
    /// Endpoints confirmed dead or scope-rejected — checked negatives.
    pub endpoints_skipped: u64,
    /// Endpoints not attempted because the per-scan circuit breaker was open.
    /// Kept separate from `endpoints_skipped` so completeness can distinguish
    /// a confirmed absence from an unattempted probe.
    pub endpoints_circuit_open: u64,
    /// Payload probes dispatched.
    pub vulnerability_checks_attempted: u64,
    /// Payload probes that reached a definitive verdict.
    pub vulnerability_checks_completed: u64,
    /// Payload probes blocked or timed out — Inconclusive, never findings.
    pub vulnerability_checks_inconclusive: u64,
    /// Findings that are passive observations or static indicators, never
    /// completed active checks.
    pub passive_observations: u64,
    /// Checks that failed to execute — never clean negatives.
    pub checks_failed: u64,
    /// Checks that exceeded their deadline.
    pub checks_timed_out: u64,
    /// Checks cancelled before completion.
    pub checks_cancelled: u64,
    /// Checks deliberately not executed — never clean negatives.
    pub checks_skipped: u64,
}

impl CoverageSnapshot {
    /// The authoritative probe-level invariant. Engine failures are a
    /// separate population and must never be added to this equation.
    #[must_use]
    pub fn check_accounting_invariant(&self) -> bool {
        self.vulnerability_checks_attempted
            == self.vulnerability_checks_completed
                + self.checks_failed
                + self.vulnerability_checks_inconclusive
                + self.checks_timed_out
                + self.checks_cancelled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_the_status_families() {
        assert_eq!(classify(200), EndpointOutcome::Tested);
        assert_eq!(classify(302), EndpointOutcome::Tested);
        assert_eq!(classify(401), EndpointOutcome::AuthRequired);
        assert_eq!(classify(403), EndpointOutcome::WafBlocked);
        assert_eq!(classify(406), EndpointOutcome::WafBlocked);
        assert_eq!(classify(404), EndpointOutcome::Skipped);
        assert_eq!(classify(410), EndpointOutcome::Skipped);
        assert_eq!(
            classify(500),
            EndpointOutcome::Tested,
            "a complete 5xx is a negative check, not a connection failure"
        );
        assert_eq!(classify(429), EndpointOutcome::WafBlocked);
    }

    #[test]
    fn baseline_classification_is_terminal_for_auth_and_missing_routes() {
        assert_eq!(classify_baseline(200, None), EndpointOutcome::Tested);
        assert_eq!(classify_baseline(401, None), EndpointOutcome::AuthRequired);
        assert_eq!(classify_baseline(403, None), EndpointOutcome::AuthRequired);
        assert_eq!(
            classify_baseline(302, Some("/login?return_to=%2Fadmin")),
            EndpointOutcome::AuthRequired
        );
        assert_eq!(
            classify_baseline(302, Some("https://example.test/auth/sign-in")),
            EndpointOutcome::AuthRequired
        );
        assert_eq!(
            classify_baseline(302, Some("/authors")),
            EndpointOutcome::Tested,
            "only whole auth segments match"
        );
        assert_eq!(
            classify_baseline(404, None),
            EndpointOutcome::Skipped,
            "a 404 is a negative result, not a failure"
        );
        assert_eq!(classify_baseline(410, None), EndpointOutcome::Skipped);
        assert_eq!(classify_baseline(405, None), EndpointOutcome::Tested);
        assert_eq!(classify_baseline(500, None), EndpointOutcome::Tested);
        assert_eq!(classify_baseline(503, None), EndpointOutcome::WafBlocked);
    }

    #[test]
    fn blocked_membership_is_o1_and_follows_the_strongest_outcome() {
        let coverage = Coverage::default();
        let url = "https://example.test/private";
        assert!(!coverage.is_blocked(url));
        coverage.endpoint_at(url, EndpointOutcome::AuthRequired);
        assert!(coverage.is_blocked(url));
        coverage.endpoint_at(url, EndpointOutcome::Tested);
        assert!(
            !coverage.is_blocked(url),
            "a later successful test clears the block"
        );
        coverage.mark_blocked(url);
        assert!(coverage.is_blocked(url));
        assert!(!coverage.is_blocked("https://example.test/other"));
    }

    #[test]
    fn merge_keeps_the_stronger_outcome() {
        // A tested endpoint is not downgraded by a later failed pass.
        assert_eq!(
            merge(EndpointOutcome::Tested, EndpointOutcome::TimedOut),
            EndpointOutcome::Tested
        );
        // A blocked endpoint outranks a dead one.
        assert_eq!(
            merge(EndpointOutcome::Skipped, EndpointOutcome::WafBlocked),
            EndpointOutcome::WafBlocked
        );
        // Success anywhere wins over any miss.
        assert_eq!(
            merge(EndpointOutcome::AuthRequired, EndpointOutcome::Tested),
            EndpointOutcome::Tested
        );
    }

    #[test]
    fn timeout_and_cancellation_are_distinct_terminal_states() {
        let cov = Coverage::default();
        let timed_out = cov.begin_check();
        let cancelled = cov.begin_check();
        assert_eq!(timed_out.finish(CheckState::TimedOut), Ok(()));
        assert_eq!(cancelled.finish(CheckState::Cancelled), Ok(()));
        let snap = cov.snapshot(0);
        assert_eq!(snap.checks_timed_out, 1);
        assert_eq!(snap.checks_cancelled, 1);
        assert!(snap.check_accounting_invariant());
        assert!(cov.finalize().reconciles());
    }

    #[test]
    fn finalize_detects_unfinished_and_duplicate_accounting() {
        let cov = Coverage::default();
        let unfinished = cov.start_check();
        let v = cov.finalize();
        assert_eq!(v.registered, 1);
        assert_eq!(v.terminal, 0);
        assert_eq!(v.in_flight, 1);
        assert!(!v.reconciles());

        assert_eq!(cov.finish_check(unfinished, CheckState::Completed), Ok(()));
        assert_eq!(
            cov.finish_check(unfinished, CheckState::Completed),
            Err(CheckError::DuplicateTerminal)
        );
        let v = cov.finalize();
        assert_eq!(v.duplicates_rejected, 1);
        assert!(!v.reconciles());
    }

    #[test]
    fn dropped_pending_check_falls_back_to_inconclusive() {
        let cov = Coverage::default();
        {
            let _check = cov.begin_check();
            // Dropped without an explicit verdict.
        }
        let snap = cov.snapshot(0);
        assert_eq!(snap.vulnerability_checks_attempted, 1);
        assert_eq!(snap.vulnerability_checks_inconclusive, 1);
        assert!(cov.finalize().reconciles());
    }

    #[test]
    fn check_ledger_rejects_duplicate_terminal_transitions() {
        let cov = Coverage::default();
        let id = cov.start_check();
        assert_eq!(cov.finish_check(id, CheckState::Completed), Ok(()));
        assert_eq!(
            cov.finish_check(id, CheckState::Completed),
            Err(CheckError::DuplicateTerminal)
        );
        let snap = cov.snapshot(0);
        assert_eq!(snap.vulnerability_checks_attempted, 1);
        assert_eq!(snap.vulnerability_checks_completed, 1);
        assert!(snap.check_accounting_invariant());
    }

    #[test]
    fn timeouts_cancellation_and_crashes_are_failed_not_successful() {
        let cov = Coverage::default();
        let timeout = cov.start_check();
        let cancelled = cov.start_check();
        let crashed = cov.start_check();
        let inconclusive = cov.start_check();
        assert_eq!(cov.finish_check(timeout, CheckState::Failed), Ok(()));
        assert_eq!(cov.finish_check(cancelled, CheckState::Failed), Ok(()));
        assert_eq!(cov.finish_check(crashed, CheckState::Failed), Ok(()));
        assert_eq!(
            cov.finish_check(inconclusive, CheckState::Inconclusive),
            Ok(())
        );
        let snap = cov.snapshot(0);
        assert_eq!(snap.vulnerability_checks_attempted, 4);
        assert_eq!(snap.checks_failed, 3);
        assert_eq!(snap.vulnerability_checks_inconclusive, 1);
        assert_eq!(snap.vulnerability_checks_completed, 0);
        assert!(snap.check_accounting_invariant());
    }

    #[test]
    fn retries_are_distinct_checks_with_distinct_ids() {
        let cov = Coverage::default();
        let first = cov.start_check();
        let second = cov.start_check();
        assert_ne!(first, second);
        assert_eq!(cov.finish_check(first, CheckState::Failed), Ok(()));
        assert_eq!(cov.finish_check(second, CheckState::Completed), Ok(()));
        assert!(cov.snapshot(0).check_accounting_invariant());
    }

    #[test]
    fn concurrent_checks_terminate_exactly_once() {
        use std::sync::Arc;
        let cov = Arc::new(Coverage::default());
        let mut handles = Vec::new();
        for i in 0..16 {
            let cov = Arc::clone(&cov);
            handles.push(std::thread::spawn(move || {
                let id = cov.start_check();
                let state = if i % 2 == 0 {
                    CheckState::Completed
                } else {
                    CheckState::Failed
                };
                cov.finish_check(id, state).expect("one terminal state");
            }));
        }
        for handle in handles {
            handle.join().expect("worker");
        }
        let snap = cov.snapshot(0);
        assert_eq!(snap.vulnerability_checks_attempted, 16);
        assert_eq!(snap.vulnerability_checks_completed, 8);
        assert_eq!(snap.checks_failed, 8);
        assert!(snap.check_accounting_invariant());
    }

    #[test]
    fn forks_report_their_own_counts_and_still_feed_the_run_ledger() {
        let run = Coverage::default();
        let engine = run.fork();
        engine.endpoint(EndpointOutcome::Tested);
        engine.endpoint(EndpointOutcome::Failed);
        let check = engine.begin_check();
        assert_eq!(check.finish(CheckState::Completed), Ok(()));

        let own = engine.snapshot(2);
        assert_eq!(own.endpoints_tested_successfully, 1);
        assert_eq!(own.endpoints_failed, 1);
        assert_eq!(own.vulnerability_checks_attempted, 1);
        assert_eq!(own.vulnerability_checks_completed, 1);
        assert!(engine.finalize().reconciles());

        // Another engine's work must not appear in the first fork.
        let other = run.fork();
        other.endpoint(EndpointOutcome::TimedOut);
        assert_eq!(engine.snapshot(2).endpoints_tested_successfully, 1);
        assert_eq!(engine.snapshot(2).endpoints_timed_out, 0);

        // The run-wide ledger is authoritative and sees every engine.
        let all = run.snapshot(2);
        assert_eq!(all.endpoints_tested_successfully, 1);
        assert_eq!(all.endpoints_failed, 1);
        assert_eq!(all.endpoints_timed_out, 1);
        assert_eq!(all.vulnerability_checks_attempted, 1);
        assert!(run.finalize().reconciles());
    }

    #[test]
    fn endpoint_records_keep_the_strongest_outcome_per_url() {
        let cov = Coverage::default();
        cov.endpoint_at("https://a.test/admin", EndpointOutcome::AuthRequired);
        cov.endpoint_at("https://a.test/admin", EndpointOutcome::Tested);
        cov.endpoint_at("https://a.test/contact", EndpointOutcome::WafBlocked);
        cov.endpoint_at("https://a.test/missing", EndpointOutcome::Skipped);

        let records = cov.endpoint_records();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records
                .iter()
                .find(|r| r.url.ends_with("/admin"))
                .map(|r| r.outcome),
            Some(EndpointOutcome::Tested)
        );
        // The aggregate counters still count every classification event.
        let snap = cov.snapshot(3);
        assert_eq!(snap.endpoints_auth_required, 1);
        assert_eq!(snap.endpoints_tested_successfully, 1);
        assert_eq!(snap.endpoints_waf_blocked, 1);
        assert_eq!(snap.endpoints_skipped, 1);
    }

    #[test]
    fn counters_add_up_to_the_snapshot() {
        let cov = Coverage::default();
        cov.endpoint(EndpointOutcome::Tested);
        cov.endpoint(EndpointOutcome::Skipped);
        cov.endpoint(EndpointOutcome::CircuitOpen);
        cov.check_attempted();
        cov.check_attempted();
        cov.check_completed();
        cov.check_inconclusive();
        let snap = cov.snapshot(7);
        assert_eq!(snap.endpoints_discovered, 7);
        assert_eq!(snap.endpoints_tested_successfully, 1);
        assert_eq!(snap.endpoints_skipped, 1);
        assert_eq!(snap.endpoints_circuit_open, 1);
        assert_eq!(snap.vulnerability_checks_attempted, 2);
        assert_eq!(snap.vulnerability_checks_completed, 1);
        assert_eq!(snap.vulnerability_checks_inconclusive, 1);
        // Clones share the same counters.
        cov.clone().endpoint(EndpointOutcome::Tested);
        assert_eq!(cov.snapshot(7).endpoints_tested_successfully, 2);
    }
}
