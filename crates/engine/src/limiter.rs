//! Per-host rate limiting: one token bucket per target host so a slow
//! host does not throttle scans of unrelated hosts (replacing the global
//! limiter the CLI used previously).

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, PoisonError};

/// Requests per second allowed to a single host, mirroring the CLI's
/// `SCAN_RATE`.
pub const HOST_RATE_PER_SECOND: NonZeroU32 = match NonZeroU32::new(5) {
    Some(n) => n,
    None => panic!("5 is nonzero"),
};

/// Rate limiter keyed by host. Keys are compared verbatim: callers pass
/// the `host:port` string from the URL's `host_str`/`port` (or just
/// `host_str` when there is no port), so `a.example:443` and `a.example`
/// are separate buckets. One decision, kept simple.
#[derive(Debug)]
pub struct HostRateLimiter {
    quota: Quota,
    limiters: Mutex<HashMap<String, Arc<DefaultDirectRateLimiter>>>,
}

impl Default for HostRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl HostRateLimiter {
    /// A limiter with the default 5 req/s per-host quota.
    pub fn new() -> Self {
        Self {
            quota: Quota::per_second(HOST_RATE_PER_SECOND),
            limiters: Mutex::new(HashMap::new()),
        }
    }

    /// Wait until one request to `host` is allowed by its per-host quota.
    ///
    /// Note: the wait uses governor's own monotonic clock and timer, not
    /// tokio's, so `tokio::time::pause` does not accelerate it.
    pub async fn until_ready(&self, host: &str) {
        self.limiter(host).until_ready().await;
    }

    /// Get or create the limiter for `host`. A poisoned map is recovered:
    /// limiter state is per-host and self-healing, so no request must fail
    /// over it.
    fn limiter(&self, host: &str) -> Arc<DefaultDirectRateLimiter> {
        let mut map = self.limiters.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            map.entry(host.to_owned())
                .or_insert_with(|| Arc::new(RateLimiter::direct(self.quota))),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test(start_paused = true)]
    async fn same_host_is_throttled() {
        let limiter = HostRateLimiter::new();
        // Burst of 5 goes through immediately; the 6th must wait, so it
        // does not resolve within an instant of (paused) time.
        for _ in 0..5 {
            limiter.until_ready("a.example:443").await;
        }
        assert!(
            timeout(Duration::ZERO, limiter.until_ready("a.example:443"))
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn different_hosts_are_independent() {
        let limiter = HostRateLimiter::new();
        for _ in 0..5 {
            limiter.until_ready("a.example:443").await;
        }
        // Host b has its own full burst even though a is exhausted.
        timeout(Duration::from_secs(1), async {
            for _ in 0..5 {
                limiter.until_ready("b.example:443").await;
            }
        })
        .await
        .expect("b.example must not be throttled by a.example");
    }

    #[test]
    fn limiter_is_reused_per_host() {
        let limiter = HostRateLimiter::new();
        let a1 = limiter.limiter("a.example:443");
        let a2 = limiter.limiter("a.example:443");
        let b = limiter.limiter("b.example:8080");
        assert!(Arc::ptr_eq(&a1, &a2), "same host must reuse its limiter");
        assert!(
            !Arc::ptr_eq(&a1, &b),
            "different hosts need separate entries"
        );
        assert_eq!(limiter.limiters.lock().unwrap().len(), 2);
    }
}
