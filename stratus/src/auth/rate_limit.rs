//! Authentication brute-force protection via per-IP progressive lockout.
//!
//! Tracks failed authentication attempts per client IP address and imposes
//! escalating lockout durations after successive failures.
//!
//! Lockout schedule (configurable, these are defaults):
//! - 5 failures  → 30-second lockout
//! - 10 failures → 60-second lockout (30 × 2.0)
//! - 20 failures → 120-second lockout
//! - … up to a configurable maximum (default 30 minutes)

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::warn;

/// Per-IP failure tracking record
#[derive(Debug, Clone)]
struct FailureRecord {
    /// Total consecutive failures from this IP
    consecutive_failures: u32,
    /// When the current lockout ends (None = not currently locked out)
    locked_until: Option<Instant>,
}

/// Configuration for the auth rate limiter
#[derive(Debug, Clone)]
pub struct AuthRateLimitConfig {
    /// Failures before first lockout
    pub lockout_threshold: u32,
    /// Initial lockout duration
    pub initial_lockout: Duration,
    /// Multiplier applied per successive lockout (exponential backoff)
    pub backoff_multiplier: f64,
    /// Maximum lockout duration
    pub max_lockout: Duration,
}

impl Default for AuthRateLimitConfig {
    fn default() -> Self {
        Self {
            lockout_threshold: 5,
            initial_lockout: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            max_lockout: Duration::from_secs(1800),
        }
    }
}

/// Thread-safe per-IP authentication rate limiter
pub struct AuthRateLimiter {
    records: DashMap<IpAddr, FailureRecord>,
    config: AuthRateLimitConfig,
}

impl AuthRateLimiter {
    pub fn new(config: AuthRateLimitConfig) -> Self {
        Self {
            records: DashMap::new(),
            config,
        }
    }

    /// Check whether the given IP is currently locked out.
    ///
    /// Returns `Some(remaining)` with the remaining lockout duration if locked,
    /// or `None` if the IP may proceed.
    pub fn check_locked(&self, ip: IpAddr) -> Option<Duration> {
        let record = self.records.get(&ip)?;
        let locked_until = record.locked_until?;
        let now = Instant::now();
        if now < locked_until {
            Some(locked_until - now)
        } else {
            None
        }
    }

    /// Record a failed authentication attempt for the given IP.
    ///
    /// Increments the failure counter and applies a lockout if the threshold is crossed.
    pub fn record_failure(&self, ip: IpAddr) {
        let mut record = self.records.entry(ip).or_insert_with(|| FailureRecord {
            consecutive_failures: 0,
            locked_until: None,
        });

        record.consecutive_failures += 1;
        let failures = record.consecutive_failures;

        if failures >= self.config.lockout_threshold {
            // Compute how many lockout steps have been taken
            let lockout_step = (failures - self.config.lockout_threshold) / self.config.lockout_threshold;
            let multiplier = self.config.backoff_multiplier.powi(lockout_step as i32);
            let duration_secs =
                (self.config.initial_lockout.as_secs_f64() * multiplier) as u64;
            let lockout_duration = Duration::from_secs(duration_secs)
                .min(self.config.max_lockout);

            let locked_until = Instant::now() + lockout_duration;
            record.locked_until = Some(locked_until);

            warn!(
                ip = %ip,
                failures = failures,
                lockout_secs = lockout_duration.as_secs(),
                "Auth lockout applied"
            );
        }
    }

    /// Record a successful authentication, resetting the failure counter for the IP.
    pub fn record_success(&self, ip: IpAddr) {
        self.records.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    fn fast_config() -> AuthRateLimitConfig {
        AuthRateLimitConfig {
            lockout_threshold: 3,
            initial_lockout: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            max_lockout: Duration::from_secs(10),
        }
    }

    #[test]
    fn test_no_lockout_before_threshold() {
        let limiter = AuthRateLimiter::new(fast_config());
        let ip = test_ip();

        // Under threshold: no lockout
        limiter.record_failure(ip);
        limiter.record_failure(ip);
        assert!(limiter.check_locked(ip).is_none());
    }

    #[test]
    fn test_lockout_at_threshold() {
        let limiter = AuthRateLimiter::new(fast_config());
        let ip = test_ip();

        limiter.record_failure(ip);
        limiter.record_failure(ip);
        limiter.record_failure(ip); // 3rd failure = threshold
        assert!(limiter.check_locked(ip).is_some());
    }

    #[test]
    fn test_success_clears_record() {
        let limiter = AuthRateLimiter::new(fast_config());
        let ip = test_ip();

        limiter.record_failure(ip);
        limiter.record_failure(ip);
        limiter.record_failure(ip);
        assert!(limiter.check_locked(ip).is_some());

        limiter.record_success(ip);
        assert!(limiter.check_locked(ip).is_none());
    }

    #[tokio::test]
    async fn test_lockout_expires() {
        let limiter = AuthRateLimiter::new(fast_config());
        let ip = test_ip();

        limiter.record_failure(ip);
        limiter.record_failure(ip);
        limiter.record_failure(ip);
        assert!(limiter.check_locked(ip).is_some());

        // Wait for the 100ms lockout to expire
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(limiter.check_locked(ip).is_none());
    }

    #[test]
    fn test_no_lockout_for_unknown_ip() {
        let limiter = AuthRateLimiter::new(fast_config());
        let ip = test_ip();
        assert!(limiter.check_locked(ip).is_none());
    }
}
