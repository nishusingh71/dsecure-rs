//! Auth tunables from `config` (PHASE0_SPEC §5).

use time::Duration;

/// `AUTHZ_EPOCH_POLL_MS` default (not yet a `config` key; P0-10 wires it).
pub const DEFAULT_EPOCH_POLL_MS: u64 = 2000;
/// Step-up proof lifetime (SECURITY.md §5: 5 min).
pub const STEP_UP_TTL: Duration = Duration::minutes(5);
/// Poller older than this = cache bypass (DATABASE.md §4.4: 10 s).
pub const EPOCH_STALE_AFTER: Duration = Duration::seconds(10);
/// Staff session absolute lifetime (RBAC.md §3.2: 8 h). Key `STAFF_SESSION_MAX_SECS` later (P0-10).
pub const STAFF_SESSION_MAX: Duration = Duration::hours(8);
/// Staff session idle timeout (RBAC.md §3.2: 30 min). Key `STAFF_SESSION_IDLE_SECS` later (P0-10).
pub const STAFF_SESSION_IDLE: Duration = Duration::minutes(30);
/// `sessions.last_seen_at` is written at most once per this window per session (write RU control).
pub const SESSION_TOUCH_THROTTLE: Duration = Duration::minutes(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthSettings {
    pub issuer: String,
    pub access_ttl: Duration,
    pub refresh_ttl_web: Duration,
    pub refresh_ttl_app: Duration,
    /// Staff console sessions: absolute 8 h (= `staff_session_max`).
    pub refresh_ttl_platform: Duration,
    pub staff_session_max: Duration,
    pub staff_session_idle: Duration,
    pub session_touch_throttle: Duration,
    pub step_up_ttl: Duration,
    pub authz_cache_entries: u64,
    /// Hard upper bound for any cached principal, on top of epoch invalidation.
    pub authz_cache_ttl: std::time::Duration,
    pub epoch_poll: std::time::Duration,
    pub epoch_stale_after: Duration,
}

impl AuthSettings {
    #[must_use]
    pub fn from_config(cfg: &config::AppConfig) -> Self {
        let web = Duration::days(i64::from(cfg.jwt.refresh_ttl_web_days));
        Self {
            issuer: cfg.jwt.issuer.clone(),
            access_ttl: Duration::seconds(i64::from(cfg.jwt.access_token_ttl_secs)),
            refresh_ttl_web: web,
            refresh_ttl_app: Duration::days(i64::from(cfg.jwt.refresh_ttl_app_days)),
            refresh_ttl_platform: STAFF_SESSION_MAX,
            staff_session_max: STAFF_SESSION_MAX,
            staff_session_idle: STAFF_SESSION_IDLE,
            session_touch_throttle: SESSION_TOUCH_THROTTLE,
            step_up_ttl: STEP_UP_TTL,
            authz_cache_entries: cfg.limits.authz_cache_entries.max(1),
            authz_cache_ttl: std::time::Duration::from_secs(60),
            epoch_poll: std::time::Duration::from_millis(DEFAULT_EPOCH_POLL_MS),
            epoch_stale_after: EPOCH_STALE_AFTER,
        }
    }

    /// PHASE0 defaults (tests / tools without config).
    #[must_use]
    pub fn defaults(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            access_ttl: Duration::seconds(900),
            refresh_ttl_web: Duration::days(30),
            refresh_ttl_app: Duration::days(90),
            refresh_ttl_platform: STAFF_SESSION_MAX,
            staff_session_max: STAFF_SESSION_MAX,
            staff_session_idle: STAFF_SESSION_IDLE,
            session_touch_throttle: SESSION_TOUCH_THROTTLE,
            step_up_ttl: STEP_UP_TTL,
            authz_cache_entries: 10_000,
            authz_cache_ttl: std::time::Duration::from_secs(60),
            epoch_poll: std::time::Duration::from_millis(DEFAULT_EPOCH_POLL_MS),
            epoch_stale_after: EPOCH_STALE_AFTER,
        }
    }
}
