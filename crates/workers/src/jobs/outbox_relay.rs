//! `outbox_relay`: ordered, at-least-once delivery of `outbox_events` to an [`OutboxPublisher`].
//!
//! Per run: claim a batch (oldest first) -> publish each in order -> mark published. A publish or
//! mark failure releases that row and every later row of the batch and fails the job (retry with
//! backoff), so order is never skipped. A crash between publish and mark re-delivers the event
//! (at-least-once): publishers must dedupe by `OutboxMessage::id`.
//! The db crate has no outbox read/claim API yet, so storage is the [`OutboxStore`] trait.

use crate::registry::{JobContext, JobError, JobHandler};
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq)]
pub struct OutboxMessage {
    pub id: uuid::Uuid,
    pub tenant_id: Option<uuid::Uuid>,
    pub event_type: String,
    pub aggregate_type: String,
    pub aggregate_id: uuid::Uuid,
    pub payload: serde_json::Value,
    pub created_at: OffsetDateTime,
    pub attempts: u32,
}

#[async_trait]
pub trait OutboxPublisher: Send + Sync {
    /// Deliver one event. Must be idempotent per `msg.id`.
    async fn publish(&self, msg: &OutboxMessage) -> Result<(), JobError>;
}

#[async_trait]
pub trait OutboxStore: Send + Sync {
    /// Lease up to `limit` unpublished, not-leased rows, ordered by `(created_at, id)`.
    async fn claim_batch(
        &self,
        worker: &str,
        now: OffsetDateTime,
        lease: time::Duration,
        limit: u32,
    ) -> Result<Vec<OutboxMessage>, JobError>;
    async fn mark_published(&self, id: uuid::Uuid, now: OffsetDateTime) -> Result<(), JobError>;
    /// Give the lease back without publishing.
    async fn release(&self, id: uuid::Uuid) -> Result<(), JobError>;
}

/// Phase 0 publisher: logs ids only (no payload, no PII).
#[derive(Clone, Copy, Debug, Default)]
pub struct LoggingPublisher;

#[async_trait]
impl OutboxPublisher for LoggingPublisher {
    async fn publish(&self, msg: &OutboxMessage) -> Result<(), JobError> {
        tracing::info!(
            event_id = %msg.id,
            event_type = %msg.event_type,
            aggregate_id = %msg.aggregate_id,
            "outbox event published (log only)"
        );
        Ok(())
    }
}

pub struct OutboxRelayJob {
    store: Arc<dyn OutboxStore>,
    publisher: Arc<dyn OutboxPublisher>,
    clock: Arc<dyn common::Clock>,
    worker_id: String,
    batch: u32,
    max_rounds: u32,
    interval: Duration,
    publish_timeout: Duration,
    soft_deadline: Duration,
}

impl OutboxRelayJob {
    pub const KIND: &'static str = "outbox_relay";

    #[must_use]
    pub fn new(
        store: Arc<dyn OutboxStore>,
        publisher: Arc<dyn OutboxPublisher>,
        clock: Arc<dyn common::Clock>,
        worker_id: String,
    ) -> Self {
        Self {
            store,
            publisher,
            clock,
            worker_id,
            batch: 100,
            max_rounds: 10,
            interval: Duration::from_secs(60),
            publish_timeout: Duration::from_secs(30),
            soft_deadline: Duration::from_secs(90),
        }
    }

    #[must_use]
    pub const fn with_limits(mut self, batch: u32, max_rounds: u32) -> Self {
        self.batch = batch;
        self.max_rounds = max_rounds;
        self
    }

    /// Seconds between chained runs (default 60).
    #[must_use]
    pub const fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Per-publish timeout and the soft stop of one run. Both are kept below the job timeout so the
    /// relay always releases its own leases before the runner could drop it.
    #[must_use]
    pub const fn with_timeouts(mut self, publish: Duration, soft_deadline: Duration) -> Self {
        self.publish_timeout = publish;
        self.soft_deadline = soft_deadline;
        self
    }

    /// Outbox lease: job timeout + margin, so a lease never expires under a live run.
    fn lease(&self) -> time::Duration {
        time::Duration::try_from(self.timeout() + Duration::from_secs(60))
            .unwrap_or(time::Duration::seconds(180))
    }

    async fn release_all(&self, rest: &[OutboxMessage]) {
        for m in rest {
            if let Err(e) = self.store.release(m.id).await {
                tracing::warn!(event_id = %m.id, code = %e.code, "outbox release failed");
            }
        }
    }
}

#[async_trait]
impl JobHandler for OutboxRelayJob {
    fn kind(&self) -> &'static str {
        Self::KIND
    }

    fn completes_in_tx(&self) -> bool {
        true
    }

    fn max_concurrency(&self) -> usize {
        1
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(120)
    }

    fn schedule(&self) -> Option<Duration> {
        Some(self.interval)
    }

    fn singleton(&self) -> bool {
        true
    }

    fn max_attempts(&self) -> u32 {
        100 // a dead relay job would end the chain
    }

    async fn handle(&self, ctx: &JobContext) -> Result<(), JobError> {
        self.relay_once(&|| ctx.is_cancelled()).await?;
        // Complete and chain the successor in ONE tx: exactly one relay job exists at any time.
        let now = ctx.now();
        let mut tx = ctx
            .db
            .system_tx_for_job(&ctx.job, now)
            .await
            .map_err(crate::registry::map_job_tx_err)?;
        let next = db::NewJob {
            kind: Self::KIND,
            job_key: format!("{}:next:{}", Self::KIND, uuid::Uuid::now_v7()),
            payload: serde_json::json!({}),
            run_after: now + time::Duration::try_from(self.interval).unwrap_or_default(),
            max_attempts: self.max_attempts(),
            max_pending: None,
        };
        if db::jobs::enqueue_system(tx.tx(), &next, now).await.is_err() {
            tx.rollback().await;
            return Err(JobError::new("chain_enqueue_failed"));
        }
        tx.complete(now)
            .await
            .map_err(crate::registry::map_job_tx_err)
    }
}

impl OutboxRelayJob {
    /// One relay run (the body of the job; `cancelled` is polled between events).
    ///
    /// # Errors
    /// The first store/publisher error (rows from that event on are released, order is kept).
    pub async fn relay_once(&self, cancelled: &(dyn Fn() -> bool + Sync)) -> Result<(), JobError> {
        let started = std::time::Instant::now();
        for _ in 0..self.max_rounds {
            if cancelled() || started.elapsed() >= self.soft_deadline {
                break;
            }
            let batch = self
                .store
                .claim_batch(&self.worker_id, self.clock.now(), self.lease(), self.batch)
                .await?;
            let n = batch.len();
            let mut seen = HashSet::new();
            for (i, msg) in batch.iter().enumerate() {
                let rest = batch.get(i..).unwrap_or(&[]);
                if cancelled() {
                    self.release_all(rest).await;
                    return Err(JobError::new("cancelled"));
                }
                if !seen.insert(msg.id) {
                    continue; // duplicate id inside the batch: one side effect per event id
                }
                if started.elapsed() >= self.soft_deadline {
                    self.release_all(rest).await; // partial progress; the next run continues in order
                    return Ok(());
                }
                // Strict order: the first failure (or timeout) stops the batch, nothing is skipped.
                let sent = tokio::time::timeout(self.publish_timeout, self.publisher.publish(msg))
                    .await
                    .unwrap_or_else(|_| Err(JobError::new("publish_timeout")));
                if let Err(e) = sent {
                    self.release_all(rest).await;
                    return Err(e);
                }
                if let Err(e) = self.store.mark_published(msg.id, self.clock.now()).await {
                    self.release_all(rest).await;
                    return Err(e);
                }
            }
            if n < usize::try_from(self.batch).unwrap_or(usize::MAX) {
                break;
            }
        }
        Ok(())
    }
}

/// Real store over the db crate (`outbox_claim_batch` / `mark_published` / `release`).
/// Keeps the claimed events of the current batch (bounded by the batch size) to hand back to db.
pub struct DbOutboxStore {
    db: db::Db,
    held: std::sync::Mutex<std::collections::HashMap<uuid::Uuid, db::outbox::ClaimedOutboxEvent>>,
}

impl DbOutboxStore {
    #[must_use]
    pub fn new(db: db::Db) -> Self {
        Self {
            db,
            held: std::sync::Mutex::default(),
        }
    }

    fn take(&self, id: uuid::Uuid) -> Option<db::outbox::ClaimedOutboxEvent> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id)
    }
}

#[async_trait]
impl OutboxStore for DbOutboxStore {
    async fn claim_batch(
        &self,
        worker: &str,
        now: OffsetDateTime,
        lease: time::Duration,
        limit: u32,
    ) -> Result<Vec<OutboxMessage>, JobError> {
        let evs = self
            .db
            .outbox_claim_batch(worker, now, limit, lease)
            .await
            .map_err(|_| JobError::new("outbox_claim_failed"))?;
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = Vec::with_capacity(evs.len());
        for e in evs {
            out.push(OutboxMessage {
                id: e.id,
                tenant_id: e.tenant.map(|t| t.0),
                event_type: e.event_type.clone(),
                aggregate_type: e.aggregate_type.clone(),
                aggregate_id: e.aggregate_id,
                payload: e.payload.clone(),
                created_at: e.created_at,
                attempts: e.attempts,
            });
            held.insert(e.id, e);
        }
        Ok(out)
    }

    async fn mark_published(&self, id: uuid::Uuid, now: OffsetDateTime) -> Result<(), JobError> {
        let Some(ev) = self.take(id) else {
            return Err(JobError::new("outbox_unknown_event"));
        };
        match self.db.outbox_mark_published(&[ev], now).await {
            Ok(1) => Ok(()),
            Ok(_) => {
                tracing::warn!(event_id = %id, "outbox lease expired before mark; event will be redelivered");
                Err(JobError::new("outbox_lease_lost"))
            }
            Err(_) => Err(JobError::new("outbox_mark_failed")),
        }
    }

    async fn release(&self, id: uuid::Uuid) -> Result<(), JobError> {
        if let Some(ev) = self.take(id) {
            self.db
                .outbox_release(&[ev])
                .await
                .map_err(|_| JobError::new("outbox_release_failed"))?;
        }
        Ok(())
    }
}
