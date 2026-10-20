//! `AuditSink` over the database: same-transaction writes (`record_in_tx`) and a bounded-channel
//! background writer for out-of-transaction events (`record`).
//!
//! Overflow policy: the channel is bounded; when full, `audit_sink_overflow_total` is incremented and the
//! event is written synchronously (bounded by the db transaction timeout). The audit trail is never dropped
//! because of a full queue, and the queue never grows without bound.

use crate::chain::{compute_row_hash, trunc_micros};
use crate::event::{AuditError, AuditEvent};
use common::{Clock, GrantId, TenantId};
use db::repo::audit::{self as repo, AuditRowRecord};
use db::{Db, DbError, IdentityTx, PlatformTx, SystemTx, TenantTx};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Counter: events that did not fit the queue and were written synchronously.
pub const METRIC_OVERFLOW: &str = "audit_sink_overflow_total";
/// Counter: events that could not be written at all (db error after fallback).
pub const METRIC_WRITE_FAILED: &str = "audit_sink_write_failed_total";

/// A transaction an audit row can be written into (the business transaction).
#[async_trait::async_trait]
pub trait AuditTx: Send {
    /// Tenant the transaction is bound to (`TenantTx`); events must not name another tenant.
    fn pinned_tenant(&self) -> Option<TenantId> {
        None
    }

    /// Staff grant of the request, when the transaction carries one.
    fn staff_grant(&self) -> Option<GrantId> {
        None
    }

    async fn insert_audit_row(&mut self, r: &AuditRowRecord) -> Result<(), DbError>;
}

#[async_trait::async_trait]
impl AuditTx for TenantTx {
    fn pinned_tenant(&self) -> Option<TenantId> {
        Some(self.tenant())
    }

    fn staff_grant(&self) -> Option<GrantId> {
        TenantTx::staff_grant(self)
    }

    async fn insert_audit_row(&mut self, r: &AuditRowRecord) -> Result<(), DbError> {
        repo::insert_event_tenant(self, r).await
    }
}

#[async_trait::async_trait]
impl AuditTx for PlatformTx {
    async fn insert_audit_row(&mut self, r: &AuditRowRecord) -> Result<(), DbError> {
        repo::insert_event_platform(self, r).await
    }
}

#[async_trait::async_trait]
impl AuditTx for SystemTx {
    async fn insert_audit_row(&mut self, r: &AuditRowRecord) -> Result<(), DbError> {
        repo::insert_event_system(self, r).await
    }
}

#[async_trait::async_trait]
impl AuditTx for IdentityTx {
    async fn insert_audit_row(&mut self, r: &AuditRowRecord) -> Result<(), DbError> {
        repo::insert_event_identity(self, r).await
    }
}

#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    /// Write the event in the SAME transaction as the business write (rollback = no audit row).
    ///
    /// # Errors
    /// `TenantMismatch`, `Invalid`, db errors (the caller must roll back: no change without its audit row).
    async fn record_in_tx(
        &self,
        tx: &mut (dyn AuditTx + Send),
        ev: AuditEvent,
    ) -> Result<(), AuditError>;

    /// Out-of-transaction event (auth failures, ...): queued, or written synchronously on overflow.
    ///
    /// # Errors
    /// `Invalid`; db errors only on the synchronous path.
    async fn record(&self, ev: AuditEvent) -> Result<(), AuditError>;
}

/// Build the row (id, time, hash) for an event.
fn build_record(
    ev: &AuditEvent,
    now: time::OffsetDateTime,
    pinned: Option<TenantId>,
    pinned_grant: Option<GrantId>,
) -> Result<AuditRowRecord, AuditError> {
    let tenant = match (pinned, ev.tenant) {
        (Some(p), None) => Some(p),
        (Some(p), Some(t)) if t != p => return Err(AuditError::TenantMismatch),
        (_, t) => t,
    };
    let grant = ev.staff_grant.or(pinned_grant);
    let mut r = AuditRowRecord {
        id: uuid::Uuid::now_v7(),
        occurred_at: trunc_micros(now),
        tenant_id: tenant.map(|t| t.0),
        actor_kind: ev.actor.kind().to_owned(),
        actor_id: ev.actor.id(),
        staff_grant_id: grant.map(|g| g.0),
        action: ev.action.as_str().to_owned(),
        outcome: ev.outcome.as_str().to_owned(),
        target_type: ev.target.map(|t| t.kind.as_str().to_owned()),
        target_id: ev.target.map(|t| t.id),
        request_id: Some(ev.request_id.0),
        ip_hmac: ev.ip_hmac.map(|h| h.to_vec()),
        metadata: ev.metadata.to_json()?,
        row_hash: Vec::new(),
    };
    r.row_hash = compute_row_hash(&r)?.to_vec();
    Ok(r)
}

enum Msg {
    Row(Box<AuditRowRecord>),
    Flush(oneshot::Sender<()>),
}

#[derive(Clone, Debug)]
pub struct SinkOptions {
    /// Bounded queue size.
    pub queue_capacity: usize,
    /// Max rows per background transaction.
    pub batch_max: usize,
    /// The writer waits this long before its first read (ops/test hook to simulate a slow writer).
    pub writer_start_delay: Duration,
}

impl Default for SinkOptions {
    fn default() -> Self {
        Self {
            queue_capacity: 1024,
            batch_max: 64,
            writer_start_delay: Duration::ZERO,
        }
    }
}

#[derive(Default)]
struct Counters {
    overflow: AtomicU64,
    written: AtomicU64,
    failed: AtomicU64,
}

pub struct DbAuditSink {
    db: Db,
    clock: Arc<dyn Clock>,
    tx: mpsc::Sender<Msg>,
    counters: Arc<Counters>,
    writer: JoinHandle<()>,
}

impl std::fmt::Debug for DbAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DbAuditSink")
    }
}

async fn write_one(db: &Db, r: &AuditRowRecord) -> Result<(), DbError> {
    let mut tx = db.system_tx().await?;
    match repo::insert_event_system(&mut tx, r).await {
        Ok(()) => tx.commit().await,
        Err(e) => {
            tx.rollback().await;
            Err(e)
        }
    }
}

async fn write_batch(db: &Db, rows: &[AuditRowRecord]) -> Result<(), DbError> {
    let mut tx = db.system_tx().await?;
    for r in rows {
        if let Err(e) = repo::insert_event_system(&mut tx, r).await {
            tx.rollback().await;
            return Err(e);
        }
    }
    tx.commit().await
}

async fn flush_rows(db: &Db, c: &Counters, rows: &mut Vec<AuditRowRecord>) {
    if rows.is_empty() {
        return;
    }
    if write_batch(db, rows).await.is_ok() {
        c.written.fetch_add(rows.len() as u64, Ordering::Relaxed);
    } else {
        // Whole batch failed (one bad row, or a transient error): row by row so good rows survive.
        for r in rows.iter() {
            match write_one(db, r).await {
                Ok(()) => {
                    c.written.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    c.failed.fetch_add(1, Ordering::Relaxed);
                    metrics::counter!(METRIC_WRITE_FAILED).increment(1);
                    tracing::error!(alert = "audit.write_failed", error = %e, "audit row lost");
                }
            }
        }
    }
    rows.clear();
}

async fn writer_loop(
    db: Db,
    mut rx: mpsc::Receiver<Msg>,
    counters: Arc<Counters>,
    opts: SinkOptions,
) {
    if !opts.writer_start_delay.is_zero() {
        tokio::time::sleep(opts.writer_start_delay).await;
    }
    let mut rows: Vec<AuditRowRecord> = Vec::new();
    let mut acks: Vec<oneshot::Sender<()>> = Vec::new();
    while let Some(first) = rx.recv().await {
        let mut next = Some(first);
        while let Some(m) = next.take() {
            match m {
                Msg::Row(r) => rows.push(*r),
                Msg::Flush(a) => acks.push(a),
            }
            if rows.len() < opts.batch_max.max(1) {
                next = rx.try_recv().ok();
            }
        }
        flush_rows(&db, &counters, &mut rows).await;
        for a in acks.drain(..) {
            let _ = a.send(());
        }
    }
}

impl DbAuditSink {
    /// Start the sink (needs a tokio runtime: it spawns the single bounded writer task).
    #[must_use]
    pub fn new(db: Db, clock: Arc<dyn Clock>, opts: SinkOptions) -> Self {
        let (tx, rx) = mpsc::channel(opts.queue_capacity.max(1));
        let counters = Arc::new(Counters::default());
        // One long-lived writer task per sink (bounded queue), not a per-request spawn.
        #[allow(clippy::disallowed_methods)]
        let writer = tokio::spawn(writer_loop(db.clone(), rx, Arc::clone(&counters), opts));
        Self {
            db,
            clock,
            tx,
            counters,
            writer,
        }
    }

    /// Events that overflowed the queue and took the synchronous path.
    #[must_use]
    pub fn overflow_count(&self) -> u64 {
        self.counters.overflow.load(Ordering::Relaxed)
    }

    /// Rows written by the background writer.
    #[must_use]
    pub fn written_count(&self) -> u64 {
        self.counters.written.load(Ordering::Relaxed)
    }

    /// Rows the background writer could not write (also logged + `audit_sink_write_failed_total`).
    #[must_use]
    pub fn failed_count(&self) -> u64 {
        self.counters.failed.load(Ordering::Relaxed)
    }

    /// Wait until everything queued before this call is written.
    pub async fn flush(&self) {
        let (a, b) = oneshot::channel();
        if self.tx.send(Msg::Flush(a)).await.is_ok() {
            let _ = b.await;
        }
    }

    /// Drain the queue and stop the writer.
    pub async fn shutdown(self) {
        let Self { tx, writer, .. } = self;
        drop(tx);
        let _ = writer.await;
    }
}

#[async_trait::async_trait]
impl AuditSink for DbAuditSink {
    async fn record_in_tx(
        &self,
        tx: &mut (dyn AuditTx + Send),
        ev: AuditEvent,
    ) -> Result<(), AuditError> {
        let rec = build_record(&ev, self.clock.now(), tx.pinned_tenant(), tx.staff_grant())?;
        tx.insert_audit_row(&rec).await?;
        Ok(())
    }

    async fn record(&self, ev: AuditEvent) -> Result<(), AuditError> {
        let rec = build_record(&ev, self.clock.now(), None, None)?;
        // `try_reserve` keeps the row in our hands when the queue is full (no clone needed).
        if let Ok(permit) = self.tx.try_reserve() {
            permit.send(Msg::Row(Box::new(rec)));
            return Ok(());
        }
        self.counters.overflow.fetch_add(1, Ordering::Relaxed);
        metrics::counter!(METRIC_OVERFLOW).increment(1);
        write_one(&self.db, &rec).await?;
        Ok(())
    }
}
