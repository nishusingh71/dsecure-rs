//! In-memory doubles for the outbox relay and the sweeper (tests and local dev).
//! The db crate has no outbox/idempotency worker API yet, so these are the only implementations.

use super::idempotency_sweep::IdempotencyStore;
use super::outbox_relay::{OutboxMessage, OutboxPublisher, OutboxStore};
use crate::registry::JobError;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use time::OffsetDateTime;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Entry {
    msg: OutboxMessage,
    published: bool,
    lease_until: Option<OffsetDateTime>,
}

/// In-memory outbox table with the same claim/lease semantics the relay needs.
#[derive(Default)]
pub struct InMemoryOutboxStore {
    rows: Mutex<Vec<Entry>>,
    /// Fault injection: the next N `mark_published` calls fail (after the publish happened).
    pub fail_mark: AtomicU32,
}

impl InMemoryOutboxStore {
    pub fn push(&self, msg: OutboxMessage) {
        lock(&self.rows).push(Entry {
            msg,
            published: false,
            lease_until: None,
        });
    }

    #[must_use]
    pub fn pending(&self) -> usize {
        lock(&self.rows).iter().filter(|e| !e.published).count()
    }
}

#[async_trait]
impl OutboxStore for InMemoryOutboxStore {
    async fn claim_batch(
        &self,
        _worker: &str,
        now: OffsetDateTime,
        lease: time::Duration,
        limit: u32,
    ) -> Result<Vec<OutboxMessage>, JobError> {
        let mut rows = lock(&self.rows);
        let mut out = Vec::new();
        for e in rows.iter_mut() {
            if out.len() >= usize::try_from(limit).unwrap_or(usize::MAX) {
                break;
            }
            if e.published || e.lease_until.is_some_and(|l| l > now) {
                continue;
            }
            e.lease_until = Some(now + lease);
            e.msg.attempts += 1;
            out.push(e.msg.clone());
        }
        Ok(out)
    }

    async fn mark_published(&self, id: uuid::Uuid, _now: OffsetDateTime) -> Result<(), JobError> {
        let injected = self
            .fail_mark
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if injected {
            return Err(JobError::new("store_unavailable"));
        }
        if let Some(e) = lock(&self.rows).iter_mut().find(|e| e.msg.id == id) {
            e.published = true;
            e.lease_until = None;
        }
        Ok(())
    }

    async fn release(&self, id: uuid::Uuid) -> Result<(), JobError> {
        if let Some(e) = lock(&self.rows).iter_mut().find(|e| e.msg.id == id) {
            e.lease_until = None;
        }
        Ok(())
    }
}

/// Records deliveries. Side effects are idempotent per event id (`effects` has unique ids only);
/// `calls` counts every delivery attempt including re-deliveries.
#[derive(Default)]
pub struct InMemoryPublisher {
    effects: Mutex<Vec<uuid::Uuid>>,
    seen: Mutex<HashSet<uuid::Uuid>>,
    pub calls: AtomicU64,
    /// Fault injection: the next N publishes fail.
    pub fail_publish: AtomicU32,
    /// Simulated slow downstream.
    pub delay: std::time::Duration,
}

impl InMemoryPublisher {
    /// Publisher whose every delivery takes `delay` (slow downstream).
    #[must_use]
    pub fn with_delay(delay: std::time::Duration) -> Self {
        Self {
            delay,
            ..Self::default()
        }
    }

    /// Event ids in first-delivery order.
    #[must_use]
    pub fn effects(&self) -> Vec<uuid::Uuid> {
        lock(&self.effects).clone()
    }
}

#[async_trait]
impl OutboxPublisher for InMemoryPublisher {
    async fn publish(&self, msg: &OutboxMessage) -> Result<(), JobError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let injected = self
            .fail_publish
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if injected {
            return Err(JobError::new("publish_failed"));
        }
        if lock(&self.seen).insert(msg.id) {
            lock(&self.effects).push(msg.id);
        }
        Ok(())
    }
}

/// In-memory idempotency keys: just expiry timestamps.
#[derive(Default)]
pub struct InMemoryIdempotencyStore {
    expiries: Mutex<Vec<OffsetDateTime>>,
}

impl InMemoryIdempotencyStore {
    pub fn add(&self, expires_at: OffsetDateTime) {
        lock(&self.expiries).push(expires_at);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.expiries).len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl IdempotencyStore for InMemoryIdempotencyStore {
    async fn sweep_expired(&self, now: OffsetDateTime, limit: u32) -> Result<u64, JobError> {
        let mut v = lock(&self.expiries);
        let mut removed = 0_u64;
        let mut i = 0;
        while i < v.len() && removed < u64::from(limit) {
            if v[i] < now {
                v.swap_remove(i);
                removed += 1;
            } else {
                i += 1;
            }
        }
        Ok(removed)
    }
}
