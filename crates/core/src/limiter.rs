//! Per-host rate limiting shared by every scoped HTTP client.

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::time::Instant;

const MAX_ADAPTIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Default requests per second allowed to a single host.
pub const HOST_RATE_PER_SECOND: NonZeroU32 = match NonZeroU32::new(20) {
    Some(n) => n,
    None => panic!("20 is nonzero"),
};

/// Token buckets keyed by URL origin. Clones of this limiter are not needed:
/// the scoped HTTP layer shares one process-wide instance.
#[derive(Debug)]
pub struct HostRateLimiter {
    quota: Quota,
    base_interval: Duration,
    limiters: Mutex<HashMap<String, Arc<HostLimiter>>>,
}

#[derive(Debug)]
struct HostLimiter {
    governor: DefaultDirectRateLimiter,
    adaptive: tokio::sync::Mutex<AdaptiveState>,
}

#[derive(Debug)]
struct AdaptiveState {
    interval: Duration,
    next_slot: Instant,
    blocked_until: Instant,
    consecutive_successes: u8,
}

impl Default for HostRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl HostRateLimiter {
    /// Create a limiter with the default twenty-request-per-second host quota.
    #[must_use]
    pub fn new() -> Self {
        Self::with_rate(HOST_RATE_PER_SECOND.get())
    }

    /// Create a limiter with a request rate and an initial half-second burst.
    #[must_use]
    pub fn with_rate(requests_per_second: u32) -> Self {
        let rate = NonZeroU32::new(requests_per_second.max(1)).unwrap_or(HOST_RATE_PER_SECOND);
        let burst = NonZeroU32::new((rate.get() / 2).max(1)).unwrap_or(HOST_RATE_PER_SECOND);
        Self {
            quota: Quota::per_second(rate).allow_burst(burst),
            base_interval: Duration::from_secs(1) / rate.get(),
            limiters: Mutex::new(HashMap::new()),
        }
    }

    /// Wait for a token associated with the URL's normalized origin.
    pub async fn until_ready(&self, origin: &str) {
        let limiter = self.limiter(origin);
        limiter.governor.until_ready().await;
        loop {
            let slot = {
                let mut state = limiter.adaptive.lock().await;
                let now = Instant::now();
                let slot = state.next_slot.max(state.blocked_until).max(now);
                state.next_slot = slot + state.interval;
                slot
            };
            tokio::time::sleep_until(slot).await;
            if Instant::now() >= limiter.adaptive.lock().await.blocked_until {
                return;
            }
        }
    }

    /// Pause subsequent requests to a host for the supplied Retry-After delay.
    pub async fn cooldown(&self, origin: &str, retry_after: Option<Duration>) {
        let limiter = self.limiter(origin);
        let mut state = limiter.adaptive.lock().await;
        let now = Instant::now();
        state.consecutive_successes = 0;
        let delay = retry_after.unwrap_or(MAX_ADAPTIVE_INTERVAL);
        state.interval = state.interval.max(delay).min(MAX_ADAPTIVE_INTERVAL);
        state.blocked_until = now + delay;
        state.next_slot = state.next_slot.max(state.blocked_until);
    }

    /// Gradually restore the configured request interval after successful responses.
    pub async fn success(&self, origin: &str) {
        let limiter = self.limiter(origin);
        let mut state = limiter.adaptive.lock().await;
        state.consecutive_successes = state.consecutive_successes.saturating_add(1);
        if state.consecutive_successes >= 10 {
            state.interval = (state.interval / 2).max(Duration::ZERO);
            state.consecutive_successes = 0;
        }
    }

    fn limiter(&self, origin: &str) -> Arc<HostLimiter> {
        let mut map = self.limiters.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(map.entry(origin.to_owned()).or_insert_with(|| {
            Arc::new(HostLimiter {
                governor: RateLimiter::direct(self.quota),
                adaptive: tokio::sync::Mutex::new(AdaptiveState {
                    interval: self.base_interval,
                    next_slot: Instant::now(),
                    blocked_until: Instant::now(),
                    consecutive_successes: 0,
                }),
            })
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test(start_paused = true)]
    async fn configured_rate_uses_half_second_initial_burst() {
        let limiter = HostRateLimiter::with_rate(20);
        for _ in 0..10 {
            limiter.until_ready("http://a.example:443").await;
        }
        assert!(
            timeout(Duration::ZERO, limiter.until_ready("http://a.example:443"))
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn different_hosts_are_independent() {
        let limiter = HostRateLimiter::new();
        for _ in 0..10 {
            limiter.until_ready("http://a.example:443").await;
        }
        timeout(Duration::from_secs(1), async {
            for _ in 0..10 {
                limiter.until_ready("http://b.example:8080").await;
            }
        })
        .await
        .expect("b.example must not be throttled by a.example");
    }

    #[tokio::test(start_paused = true)]
    async fn throttling_increases_host_interval_and_success_recovers_it() {
        let limiter = HostRateLimiter::with_rate(20);
        let origin = "http://a.example:443";
        limiter.cooldown(origin, Some(Duration::from_secs(2))).await;
        let first = tokio::time::Instant::now();
        limiter.until_ready(origin).await;
        assert!(tokio::time::Instant::now() >= first + Duration::from_secs(2));

        for _ in 0..20 {
            limiter.success(origin).await;
        }
        let state = limiter.limiter(origin);
        assert!(state.adaptive.lock().await.interval < Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn retry_after_cooldown_is_not_clamped_and_default_is_thirty_seconds() {
        let limiter = HostRateLimiter::new();
        let long = "http://long-cooldown.example:80";
        let start = Instant::now();
        limiter.cooldown(long, Some(Duration::from_secs(45))).await;
        assert_eq!(
            limiter.limiter(long).adaptive.lock().await.blocked_until,
            start + Duration::from_secs(45)
        );

        let default = "http://default-cooldown.example:80";
        let start = Instant::now();
        limiter.cooldown(default, None).await;
        assert_eq!(
            limiter.limiter(default).adaptive.lock().await.blocked_until,
            start + Duration::from_secs(30)
        );
    }

    #[test]
    fn limiter_is_reused_per_host() {
        let limiter = HostRateLimiter::new();
        let a1 = limiter.limiter("http://a.example:443");
        let a2 = limiter.limiter("http://a.example:443");
        let b = limiter.limiter("http://b.example:8080");
        assert!(Arc::ptr_eq(&a1, &a2));
        assert!(!Arc::ptr_eq(&a1, &b));
        assert_eq!(limiter.limiters.lock().unwrap().len(), 2);
    }
}
