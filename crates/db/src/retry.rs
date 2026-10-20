//! `with_retry`: rerun an idempotent transaction closure on TiDB write conflicts / deadlocks / lock
//! wait timeouts / lost connections (before COMMIT). Bounded (`retry_max_attempts` from config),
//! jittered exponential backoff from `retry_base_delay_ms` (cap 10 x base). `CommitUnknown` and every non-transient error surface immediately.

use crate::error::DbError;
use crate::pool::Db;
use crate::tx::{IdentityTx, TenantTx};
use domain::rbac::TenantScope;
use futures_util::future::BoxFuture;
use std::time::Duration;

/// Jittered exponential backoff for attempt `n` (1-based), always within `base..=10*base`.
#[must_use]
pub fn backoff(n: u32, base: Duration) -> Duration {
    let base_ms = u64::try_from(base.as_millis()).unwrap_or(u64::MAX).max(1);
    let cap_ms = base_ms.saturating_mul(10);
    let exp = base_ms
        .saturating_mul(1u64 << n.saturating_sub(1).min(4))
        .min(cap_ms);
    // Jitter source: UUIDv7 random bits (no extra RNG dependency).
    let rnd = u64::from(uuid::Uuid::now_v7().as_bytes()[15]);
    let jitter = rnd % (exp / 2 + 1);
    Duration::from_millis((exp / 2 + jitter).clamp(base_ms, cap_ms))
}

fn should_retry(e: &DbError, attempt: u32, max: u32) -> bool {
    e.is_retryable() && attempt < max
}

impl Db {
    /// Run `f` in a fresh `TenantTx` and commit; retry on transient errors. `f` must be idempotent.
    ///
    /// # Errors
    /// The last error (transient after `retry_max` attempts, or the first non-transient one).
    pub async fn with_retry<T, F>(&self, scope: &TenantScope, mut f: F) -> Result<T, DbError>
    where
        F: for<'t> FnMut(&'t mut TenantTx) -> BoxFuture<'t, Result<T, DbError>>,
    {
        let max = self.options().retry_max.max(1);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let r = match self.tenant_tx(scope).await {
                Ok(mut tx) => match f(&mut tx).await {
                    Ok(v) => tx.commit().await.map(|()| v),
                    Err(e) => {
                        tx.rollback().await;
                        Err(e)
                    }
                },
                Err(e) => Err(e),
            };
            match r {
                Err(e) if should_retry(&e, attempt, max) => {
                    tracing::debug!(attempt, "db transaction retry");
                    tokio::time::sleep(backoff(attempt, self.options().retry_base_delay)).await;
                }
                other => return other,
            }
        }
    }

    /// Same as [`Db::with_retry`] for identity transactions.
    ///
    /// # Errors
    /// See [`Db::with_retry`].
    pub async fn with_identity_retry<T, F>(&self, mut f: F) -> Result<T, DbError>
    where
        F: for<'t> FnMut(&'t mut IdentityTx) -> BoxFuture<'t, Result<T, DbError>>,
    {
        let max = self.options().retry_max.max(1);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let r = match self.identity_tx().await {
                Ok(mut tx) => match f(&mut tx).await {
                    Ok(v) => tx.commit().await.map(|()| v),
                    Err(e) => {
                        tx.rollback().await;
                        Err(e)
                    }
                },
                Err(e) => Err(e),
            };
            match r {
                Err(e) if should_retry(&e, attempt, max) => {
                    tokio::time::sleep(backoff(attempt, self.options().retry_base_delay)).await;
                }
                other => return other,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_bounds() {
        for n in 0..10 {
            let d = backoff(n, Duration::from_millis(20)).as_millis();
            assert!((20..=200).contains(&d), "attempt {n}: {d}");
            let d = backoff(n, Duration::from_millis(50)).as_millis();
            assert!((50..=500).contains(&d), "attempt {n}: {d}");
        }
    }

    #[test]
    fn retry_policy() {
        let t = DbError::Transient { code: 1213 };
        assert!(should_retry(&t, 1, 3));
        assert!(should_retry(&t, 2, 3));
        assert!(!should_retry(&t, 3, 3));
        assert!(!should_retry(&DbError::CommitUnknown, 1, 3));
        assert!(!should_retry(&DbError::LastOwner, 1, 3));
    }
}
