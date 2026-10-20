//! Pool / session tunables, taken from `config::DbConfig` (PHASE0_SPEC §5 keys).
//! `Default` = the PHASE0 defaults (only for tools/tests without a config).

use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbOptions {
    pub max_connections: u32,
    pub acquire_timeout: Duration,
    /// Per-connection prepared statement cache (bounded; TiDB `max_prepared_stmt_count` friendly).
    pub statement_cache_capacity: usize,
    /// App-side deadline for one transaction (begin -> commit).
    pub tx_timeout: Duration,
    /// Session `max_execution_time` (ms; same variable name on MySQL and TiDB).
    pub max_execution_time_ms: u32,
    /// Session `innodb_lock_wait_timeout` (s; TiDB honours it in pessimistic mode).
    pub lock_wait_timeout_s: u32,
    /// Total attempts of `with_retry` (1 = no retry).
    pub retry_max: u32,
    /// Base of the jittered exponential retry backoff (cap = 10 x base).
    pub retry_base_delay: Duration,
}

impl Default for DbOptions {
    fn default() -> Self {
        Self {
            max_connections: 8,
            acquire_timeout: Duration::from_millis(2000),
            statement_cache_capacity: 64,
            tx_timeout: Duration::from_millis(5000),
            max_execution_time_ms: 5000,
            lock_wait_timeout_s: 5,
            retry_max: 3,
            retry_base_delay: Duration::from_millis(20),
        }
    }
}

impl DbOptions {
    /// Every value from config (validated there); only clamped to sane minimums here.
    #[must_use]
    pub fn from_config(cfg: &config::DbConfig) -> Self {
        Self {
            max_connections: cfg.max_connections.max(1),
            acquire_timeout: Duration::from_millis(cfg.acquire_timeout_ms.max(1)),
            statement_cache_capacity: cfg.statement_cache_capacity,
            tx_timeout: Duration::from_millis(cfg.tx_timeout_ms.max(1)),
            max_execution_time_ms: u32::try_from(cfg.max_execution_ms).unwrap_or(u32::MAX),
            lock_wait_timeout_s: cfg.lock_wait_timeout_s.max(1),
            retry_max: cfg.retry_max_attempts.max(1),
            retry_base_delay: Duration::from_millis(cfg.retry_base_delay_ms.max(1)),
        }
    }
}
