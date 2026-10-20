//! Pre-auth rate limits (ARCHITECTURE.md §5 layer 10, SECURITY.md §9). Login: per client, per
//! client network, per client + email; refresh and step-up: per client.
//!
//! - "Client" = IPv4 address, or the IPv6 **/64** (one subscriber usually owns a whole /64, so per-
//!   /128 buckets would be free to rotate). "Network" = IPv4 /24 or IPv6 /48.
//! - No global login counter: one attacker could exhaust it and lock everybody out. Global CPU/RAM
//!   protection is the Argon2 semaphore (`LOGIN_HASH_CONCURRENCY`, 2 s wait, then 503 `auth.busy`);
//!   the per-network budget bounds what one /24 or /48 can take from it.
//! - Client IP comes ONLY from the trusted-proxy layer (`middleware::client_ip`), so a spoofed
//!   `X-Forwarded-For` from an untrusted peer lands in the peer's own bucket.
//! - Bucket keys are HMAC-SHA256(per-process random key, rule, parts): the raw IP is never stored,
//!   and the email part is the blind index (never the raw email). Nothing here is logged by value.
//! - Store: bounded in-memory (moka, size cap + idle TTL) behind [`RateLimitStore`], so a shared
//!   Redis store can replace it (`RATE_LIMIT_STORE=redis`, later) without touching the handlers.
//! - Closes carry-forward 16: login DB/hash work per client+email is capped, and 429 does not depend
//!   on whether the account exists.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aws_lc_rs::hmac;
use common::AppErrorKind;

use crate::errors::ApiError;

/// A fixed-window rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Metric/key label (static, bounded set).
    pub name: &'static str,
    pub limit: u32,
    pub window: Duration,
}

impl Rule {
    #[must_use]
    pub const fn new(name: &'static str, limit: u32, window: Duration) -> Self {
        Self {
            name,
            limit,
            window,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Limited { retry_after: Duration },
}

/// Counter store. Implementations must be bounded and must never block for long.
#[async_trait::async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Count one hit for `key` under `rule`.
    async fn hit(&self, key: [u8; 32], rule: &Rule) -> Decision;
}

#[derive(Debug)]
struct Bucket {
    start: Instant,
    count: u32,
}

/// Bounded in-memory store (per instance). Over the size cap moka evicts; an evicted bucket starts
/// again from zero (bounded memory wins over exactness, documented).
pub struct MemoryStore {
    buckets: moka::sync::Cache<[u8; 32], Arc<Mutex<Bucket>>>,
}

/// Default bucket cap (~100 B each -> a few MB worst case).
pub const DEFAULT_MAX_BUCKETS: u64 = 50_000;

impl MemoryStore {
    /// `ttl` must be >= the longest rule window.
    #[must_use]
    pub fn new(max_buckets: u64, ttl: Duration) -> Self {
        Self {
            buckets: moka::sync::Cache::builder()
                .max_capacity(max_buckets.max(1))
                .time_to_idle(ttl)
                .build(),
        }
    }
}

#[async_trait::async_trait]
impl RateLimitStore for MemoryStore {
    async fn hit(&self, key: [u8; 32], rule: &Rule) -> Decision {
        let now = Instant::now();
        let b = self.buckets.get_with(key, || {
            Arc::new(Mutex::new(Bucket {
                start: now,
                count: 0,
            }))
        });
        let mut b = b.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if now.saturating_duration_since(b.start) >= rule.window {
            b.start = now;
            b.count = 0;
        }
        if b.count >= rule.limit {
            let left = rule
                .window
                .saturating_sub(now.saturating_duration_since(b.start));
            return Decision::Limited { retry_after: left };
        }
        b.count += 1;
        Decision::Allowed
    }
}

/// Rule set (defaults: SECURITY.md §9 proposal; tune after P0-17 load test).
#[derive(Clone, Copy, Debug)]
pub struct Rules {
    /// Per client (IPv4 address / IPv6 /64).
    pub login_ip: Rule,
    /// Per client network (IPv4 /24 / IPv6 /48): bounds one network's share of the hash pool.
    pub login_net: Rule,
    /// Per client + email blind index.
    pub login_ip_email: Rule,
    pub refresh_ip: Rule,
    pub step_up_ip: Rule,
}

impl Default for Rules {
    fn default() -> Self {
        let min = Duration::from_secs(60);
        Self {
            login_ip: Rule::new("login_ip", 30, min),
            login_net: Rule::new("login_net", 300, min),
            login_ip_email: Rule::new("login_ip_email", 5, min),
            refresh_ip: Rule::new("refresh_ip", 60, min),
            step_up_ip: Rule::new("step_up_ip", 10, min),
        }
    }
}

impl Rules {
    fn longest(&self) -> Duration {
        [
            self.login_ip,
            self.login_net,
            self.login_ip_email,
            self.refresh_ip,
            self.step_up_ip,
        ]
        .iter()
        .map(|r| r.window)
        .max()
        .unwrap_or(Duration::from_secs(60))
    }
}

/// Address bytes a "client" bucket is keyed on: IPv4 /32, IPv6 /64. `None` -> one shared bucket.
#[must_use]
pub fn client_prefix(ip: Option<IpAddr>) -> Vec<u8> {
    match ip.map(|a| a.to_canonical()) {
        Some(IpAddr::V4(a)) => [&[4u8][..], &a.octets()].concat(),
        Some(IpAddr::V6(a)) => [&[6u8][..], &a.octets()[..8]].concat(),
        None => b"unknown".to_vec(),
    }
}

/// Network bucket: IPv4 /24, IPv6 /48.
#[must_use]
pub fn network_prefix(ip: Option<IpAddr>) -> Vec<u8> {
    match ip.map(|a| a.to_canonical()) {
        Some(IpAddr::V4(a)) => [&[4u8][..], &a.octets()[..3]].concat(),
        Some(IpAddr::V6(a)) => [&[6u8][..], &a.octets()[..6]].concat(),
        None => b"unknown".to_vec(),
    }
}

pub struct PreAuthLimiter {
    store: Arc<dyn RateLimitStore>,
    rules: Rules,
    key: hmac::Key,
}

impl std::fmt::Debug for PreAuthLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreAuthLimiter")
            .field("rules", &self.rules)
            .finish_non_exhaustive()
    }
}

impl PreAuthLimiter {
    /// # Errors
    /// RNG failure (bucket key).
    pub fn new(store: Arc<dyn RateLimitStore>, rules: Rules) -> Result<Self, ApiError> {
        let mut k = zeroize::Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(&mut k[..])
            .map_err(|_| ApiError::misconfigured("rate limit key rng"))?;
        Ok(Self {
            store,
            rules,
            key: hmac::Key::new(hmac::HMAC_SHA256, &k[..]),
        })
    }

    /// In-memory store sized for `rules`.
    ///
    /// # Errors
    /// See [`PreAuthLimiter::new`].
    pub fn in_memory(rules: Rules) -> Result<Self, ApiError> {
        Self::new(
            Arc::new(MemoryStore::new(DEFAULT_MAX_BUCKETS, rules.longest())),
            rules,
        )
    }

    fn bucket(&self, rule: &Rule, scope: &[u8], extra: &[u8]) -> [u8; 32] {
        let mut ctx = hmac::Context::with_key(&self.key);
        ctx.update(rule.name.as_bytes());
        ctx.update(&[0]);
        ctx.update(scope);
        ctx.update(&[0]);
        ctx.update(extra);
        let mut out = [0u8; 32];
        out.copy_from_slice(ctx.sign().as_ref());
        out
    }

    async fn check(&self, rule: &Rule, key: [u8; 32]) -> Result<(), ApiError> {
        match self.store.hit(key, rule).await {
            Decision::Allowed => {
                telemetry::meters::record_rate_limit(
                    rule.name,
                    telemetry::RateLimitOutcome::Allowed,
                );
                Ok(())
            }
            Decision::Limited { retry_after } => {
                telemetry::meters::record_rate_limit(
                    rule.name,
                    telemetry::RateLimitOutcome::Limited,
                );
                let secs = u32::try_from(retry_after.as_secs().saturating_add(1)).unwrap_or(60);
                Err(ApiError::new(
                    AppErrorKind::RateLimited {
                        retry_after_s: secs,
                    },
                    "rate_limited",
                    "too many requests, retry later",
                ))
            }
        }
    }

    /// Login: per client, per network, then per client + email blind index (if the email parsed).
    ///
    /// # Errors
    /// 429 + `Retry-After`.
    pub async fn login(
        &self,
        ip: Option<IpAddr>,
        email_bidx: Option<&[u8; 32]>,
    ) -> Result<(), ApiError> {
        let client = client_prefix(ip);
        let r = self.rules.login_ip;
        self.check(&r, self.bucket(&r, &client, b"")).await?;
        let n = self.rules.login_net;
        self.check(&n, self.bucket(&n, &network_prefix(ip), b""))
            .await?;
        if let Some(b) = email_bidx {
            let e = self.rules.login_ip_email;
            self.check(&e, self.bucket(&e, &client, b)).await?;
        }
        Ok(())
    }

    /// # Errors
    /// 429 + `Retry-After`.
    pub async fn refresh(&self, ip: Option<IpAddr>) -> Result<(), ApiError> {
        let r = self.rules.refresh_ip;
        self.check(&r, self.bucket(&r, &client_prefix(ip), b""))
            .await
    }

    /// # Errors
    /// 429 + `Retry-After`.
    pub async fn step_up(&self, ip: Option<IpAddr>) -> Result<(), ApiError> {
        let r = self.rules.step_up_ip;
        self.check(&r, self.bucket(&r, &client_prefix(ip), b""))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        s.parse().ok()
    }

    fn rules(n: u32) -> Rules {
        let r = |name| Rule::new(name, n, Duration::from_secs(60));
        Rules {
            login_ip: r("login_ip"),
            login_net: Rule::new("login_net", 10_000, Duration::from_secs(60)),
            login_ip_email: r("login_ip_email"),
            refresh_ip: r("refresh_ip"),
            step_up_ip: r("step_up_ip"),
        }
    }

    #[tokio::test]
    async fn per_ip_limit_and_retry_after() {
        let l = PreAuthLimiter::in_memory(rules(2)).expect("l");
        let a = ip("198.51.100.1");
        assert!(l.refresh(a).await.is_ok());
        assert!(l.refresh(a).await.is_ok());
        let e = l.refresh(a).await.expect_err("limited");
        assert!(matches!(
            e.kind(),
            AppErrorKind::RateLimited { retry_after_s } if (1..=61).contains(&retry_after_s)
        ));
        // another IP has its own bucket
        assert!(l.refresh(ip("198.51.100.2")).await.is_ok());
    }

    #[tokio::test]
    async fn ipv6_clients_are_keyed_by_slash_64() {
        // Default rules: 30 logins per client per minute.
        let l = PreAuthLimiter::in_memory(Rules::default()).expect("l");
        for i in 1..=30u32 {
            let a = ip(&format!("2001:db8:1:2::{i:x}"));
            assert!(l.login(a, None).await.is_ok(), "attempt {i}");
        }
        // 31st login from a 31st address inside the same /64: limited.
        let e = l
            .login(ip("2001:db8:1:2:ffff::31"), None)
            .await
            .expect_err("same /64");
        assert!(matches!(e.kind(), AppErrorKind::RateLimited { .. }));
        // A flood from that /64 does not block another prefix (same /48, other /64) ...
        assert!(l.login(ip("2001:db8:1:3::1"), None).await.is_ok());
        // ... nor another network.
        assert!(l.login(ip("2001:db8:9:9::1"), None).await.is_ok());
        assert!(l.login(ip("203.0.113.9"), None).await.is_ok());
        // IPv4-mapped IPv6 is the IPv4 client.
        assert_eq!(
            client_prefix(ip("::ffff:203.0.113.9")),
            client_prefix(ip("203.0.113.9"))
        );
    }

    #[tokio::test]
    async fn network_budget_caps_one_slash_24() {
        let r = Rules {
            login_net: Rule::new("login_net", 3, Duration::from_secs(60)),
            ..Rules::default()
        };
        let l = PreAuthLimiter::in_memory(r).expect("l");
        for i in 1..=3 {
            assert!(l.login(ip(&format!("198.51.100.{i}")), None).await.is_ok());
        }
        assert!(
            l.login(ip("198.51.100.200"), None).await.is_err(),
            "same /24"
        );
        assert!(l.login(ip("198.51.101.1"), None).await.is_ok(), "other /24");
    }

    #[tokio::test]
    async fn ip_email_bucket_is_separate_per_email() {
        let mut r = rules(100);
        r.login_ip_email = Rule::new("login_ip_email", 1, Duration::from_secs(60));
        let l = PreAuthLimiter::in_memory(r).expect("l");
        let a = ip("198.51.100.1");
        assert!(l.login(a, Some(&[1; 32])).await.is_ok());
        assert!(l.login(a, Some(&[1; 32])).await.is_err());
        assert!(l.login(a, Some(&[2; 32])).await.is_ok());
    }

    #[tokio::test]
    async fn window_resets() {
        let s = MemoryStore::new(10, Duration::from_secs(1));
        let r = Rule::new("t", 1, Duration::from_millis(30));
        assert_eq!(s.hit([0; 32], &r).await, Decision::Allowed);
        assert!(matches!(s.hit([0; 32], &r).await, Decision::Limited { .. }));
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(s.hit([0; 32], &r).await, Decision::Allowed);
    }
}
