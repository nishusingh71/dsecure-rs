//! `idempotency_sweep`: removes/expires old idempotency keys in bounded batches.
//! The db crate has no sweep API yet (and the app DB user has no DELETE), so the storage side is
//! the [`IdempotencyStore`] trait; see the report for the db API this needs.

use crate::registry::{JobContext, JobError, JobHandler};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Expire/remove up to `limit` keys with `expires_at < now`; returns how many.
    async fn sweep_expired(&self, now: OffsetDateTime, limit: u32) -> Result<u64, JobError>;
}

pub struct IdempotencySweepJob {
    store: Arc<dyn IdempotencyStore>,
    clock: Arc<dyn common::Clock>,
    batch: u32,
    max_rounds: u32,
}

impl IdempotencySweepJob {
    pub const KIND: &'static str = "idempotency_sweep";

    #[must_use]
    pub fn new(store: Arc<dyn IdempotencyStore>, clock: Arc<dyn common::Clock>) -> Self {
        Self {
            store,
            clock,
            batch: 500,
            max_rounds: 20,
        }
    }

    #[must_use]
    pub const fn with_limits(mut self, batch: u32, max_rounds: u32) -> Self {
        self.batch = batch;
        self.max_rounds = max_rounds;
        self
    }
}

#[async_trait]
impl JobHandler for IdempotencySweepJob {
    fn kind(&self) -> &'static str {
        Self::KIND
    }

    fn completes_in_tx(&self) -> bool {
        true
    }

    fn max_concurrency(&self) -> usize {
        1
    }

    fn schedule(&self) -> Option<Duration> {
        Some(Duration::from_secs(3600))
    }

    async fn handle(&self, ctx: &JobContext) -> Result<(), JobError> {
        self.sweep_once(&|| ctx.is_cancelled()).await?;
        ctx.complete_system().await
    }
}

impl IdempotencySweepJob {
    /// One sweep run (bounded: `max_rounds` batches).
    ///
    /// # Errors
    /// The store error.
    pub async fn sweep_once(&self, cancelled: &(dyn Fn() -> bool + Sync)) -> Result<(), JobError> {
        let mut total = 0_u64;
        for _ in 0..self.max_rounds {
            if cancelled() {
                break;
            }
            let n = self
                .store
                .sweep_expired(self.clock.now(), self.batch)
                .await?;
            total += n;
            if n < u64::from(self.batch) {
                break;
            }
        }
        tracing::info!(removed = total, "idempotency_sweep done");
        Ok(())
    }
}

/// Real store: `db::idempotency::expire_older_than` (tombstones, no DELETE).
pub struct DbIdempotencyStore {
    db: db::Db,
}

impl DbIdempotencyStore {
    #[must_use]
    pub const fn new(db: db::Db) -> Self {
        Self { db }
    }
}

#[async_trait]
impl IdempotencyStore for DbIdempotencyStore {
    async fn sweep_expired(&self, now: OffsetDateTime, limit: u32) -> Result<u64, JobError> {
        db::idempotency::expire_older_than(&self.db, now, limit)
            .await
            .map_err(|_| JobError::new("idempotency_sweep_failed"))
    }
}
