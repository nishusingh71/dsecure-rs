//! Transactional outbox insert (same tx as the business write; relay = Phase 0 P0-13 worker).

use crate::error::DbError;
use crate::queries::{
    OUTBOX_EVENTS_CLAIM_CANDIDATES, OUTBOX_EVENTS_CLAIM_CANDIDATES_TENANT, OUTBOX_EVENTS_CLAIM_ONE,
    OUTBOX_EVENTS_COUNT_PENDING_TENANT, OUTBOX_EVENTS_GET_CLAIMED, OUTBOX_EVENTS_INSERT,
    OUTBOX_EVENTS_MARK_PUBLISHED, OUTBOX_EVENTS_RELEASE,
};
use crate::sql;
use crate::tx::{Inner, SystemTx, TenantTx};
use crate::write_guard::WriteOutcome;
use common::TenantId;
use time::OffsetDateTime;

/// App cap on payload size (DATABASE.md §8: ids only, no PII, 4 KB).
pub const MAX_PAYLOAD_BYTES: usize = 4096;
/// Max unpublished events per tenant before inserts are refused (`QuotaExceeded("outbox.backlog")`).
pub const MAX_TENANT_BACKLOG: u32 = 1000;

#[derive(Clone, Debug)]
pub struct OutboxEvent {
    pub event_type: &'static str,
    pub aggregate_type: &'static str,
    pub aggregate_id: uuid::Uuid,
    pub payload: serde_json::Value,
}

async fn insert_inner(
    inner: &mut Inner,
    tenant: Option<TenantId>,
    ev: &OutboxEvent,
    now: OffsetDateTime,
) -> Result<uuid::Uuid, DbError> {
    let len = serde_json::to_vec(&ev.payload)
        .map_err(|_| DbError::Invalid("outbox payload not serialisable"))?
        .len();
    if len > MAX_PAYLOAD_BYTES {
        return Err(DbError::Invalid("outbox payload too large"));
    }
    // Per-tenant backlog cap (F12): a stuck relay or a noisy tenant cannot grow the table unbounded.
    // Bounded scan on ix_outbox_tenant_pending (at most the cap rows).
    if let Some(t) = tenant {
        let row = inner
            .fetch_optional(
                sql::q(OUTBOX_EVENTS_COUNT_PENDING_TENANT)
                    .bind(t.0)
                    .bind(MAX_TENANT_BACKLOG),
            )
            .await?
            .ok_or(DbError::Corrupt("count"))?;
        let n: i64 = sql::col(&row, "n")?;
        if n >= i64::from(MAX_TENANT_BACKLOG) {
            return Err(DbError::QuotaExceeded {
                quota: "outbox.backlog",
                limit: MAX_TENANT_BACKLOG,
                current: u32::try_from(n).unwrap_or(u32::MAX),
            });
        }
    }
    let id = uuid::Uuid::now_v7();
    inner
        .execute(
            sql::q(OUTBOX_EVENTS_INSERT)
                .bind(id)
                .bind(tenant.map(|t| t.0))
                .bind(ev.event_type)
                .bind(ev.aggregate_type)
                .bind(ev.aggregate_id)
                .bind(&ev.payload)
                .bind(now),
        )
        .await?
        .expect_one()?;
    Ok(id)
}

/// Outbox event of the tx tenant (tenant from the tx, never from the caller).
///
/// # Errors
/// `Invalid` (payload cap), server errors.
pub async fn outbox_insert(
    tx: &mut TenantTx,
    ev: &OutboxEvent,
    now: OffsetDateTime,
) -> Result<uuid::Uuid, DbError> {
    let tenant = tx.tenant();
    insert_inner(&mut tx.inner, Some(tenant), ev, now).await
}

/// Tenant-less system event.
///
/// # Errors
/// `Invalid` (payload cap), server errors.
pub async fn outbox_insert_system(
    tx: &mut SystemTx,
    ev: &OutboxEvent,
    now: OffsetDateTime,
) -> Result<uuid::Uuid, DbError> {
    insert_inner(&mut tx.inner, None, ev, now).await
}

/// One outbox event leased to a relay. Not constructible outside `db`; `claim_token` (fresh per
/// event and claim) is the lease token checked by `outbox_mark_published` / `outbox_release`.
#[derive(Clone, Debug)]
pub struct ClaimedOutboxEvent {
    pub id: uuid::Uuid,
    pub tenant: Option<TenantId>,
    pub event_type: String,
    pub aggregate_type: String,
    pub aggregate_id: uuid::Uuid,
    pub payload: serde_json::Value,
    pub created_at: OffsetDateTime,
    pub attempts: u32,
    pub lease_until: OffsetDateTime,
    claim_token: uuid::Uuid,
}

/// Max events per relay claim round.
pub const MAX_RELAY_BATCH: u32 = 200;

impl crate::pool::Db {
    /// Relay claim (at-least-once): oldest unpublished events by `(created_at, id)` whose lease is
    /// free or expired, each leased by a PK point update (rows_affected = 1 = owned, like jobs).
    /// Tenant comes from each row (the relay runs in system txs, never with a caller tenant).
    ///
    /// # Errors
    /// Server errors.
    pub async fn outbox_claim_batch(
        &self,
        worker: &str,
        now: OffsetDateTime,
        limit: u32,
        lease: time::Duration,
    ) -> Result<Vec<ClaimedOutboxEvent>, DbError> {
        self.outbox_claim_batch_for(worker, None, now, limit, lease)
            .await
    }

    /// Same, optionally limited to one tenant's events (per-tenant relay; tests on a shared DB).
    ///
    /// # Errors
    /// Server errors.
    pub async fn outbox_claim_batch_for(
        &self,
        worker: &str,
        tenant: Option<TenantId>,
        now: OffsetDateTime,
        limit: u32,
        lease: time::Duration,
    ) -> Result<Vec<ClaimedOutboxEvent>, DbError> {
        if worker.is_empty() || worker.len() > 64 {
            return Err(DbError::Invalid("worker id must be 1..=64 bytes"));
        }
        let limit = limit.clamp(1, MAX_RELAY_BATCH);
        let mut tx = self.system_tx().await?;
        let q = match tenant {
            None => sql::q(OUTBOX_EVENTS_CLAIM_CANDIDATES).bind(now).bind(limit),
            Some(t) => sql::q(OUTBOX_EVENTS_CLAIM_CANDIDATES_TENANT)
                .bind(t.0)
                .bind(now)
                .bind(limit),
        };
        let ids = tx
            .inner
            .fetch_all(q)
            .await?
            .iter()
            .map(|r| sql::uuid_col(r, "id"))
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit().await?;
        let lease_until = now + lease;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let token = uuid::Uuid::now_v7();
            let mut tx = self.system_tx().await?;
            let n = tx
                .inner
                .execute(
                    sql::q(OUTBOX_EVENTS_CLAIM_ONE)
                        .bind(worker)
                        .bind(token)
                        .bind(lease_until)
                        .bind(id)
                        .bind(now),
                )
                .await?;
            if n != 1 {
                tx.rollback().await;
                continue;
            }
            let row = tx
                .inner
                .fetch_optional(sql::q(OUTBOX_EVENTS_GET_CLAIMED).bind(id).bind(token))
                .await?
                .ok_or(DbError::NotPersisted {
                    expected: 1,
                    actual: 0,
                })?;
            tx.commit().await?;
            out.push(ClaimedOutboxEvent {
                id,
                tenant: sql::opt_uuid_col(&row, "tenant_id")?.map(TenantId),
                event_type: sql::col(&row, "event_type")?,
                aggregate_type: sql::col(&row, "aggregate_type")?,
                aggregate_id: sql::uuid_col(&row, "aggregate_id")?,
                payload: sql::col(&row, "payload")?,
                created_at: sql::col(&row, "created_at")?,
                attempts: u32::try_from(sql::col::<i32>(&row, "attempts")?)
                    .map_err(|_| DbError::Corrupt("outbox_events.attempts"))?,
                lease_until: sql::col(&row, "lease_until")?,
                claim_token: token,
            });
        }
        Ok(out)
    }

    /// Mark delivered events published: only with the event's own claim token and while the lease
    /// is still valid (`lease_until > now`). Returns how many were marked; the rest will be
    /// redelivered (at-least-once).
    ///
    /// # Errors
    /// Server errors.
    pub async fn outbox_mark_published(
        &self,
        events: &[ClaimedOutboxEvent],
        now: OffsetDateTime,
    ) -> Result<u64, DbError> {
        let mut tx = self.system_tx().await?;
        let mut n = 0;
        for e in events {
            n += tx
                .inner
                .execute(
                    sql::q(OUTBOX_EVENTS_MARK_PUBLISHED)
                        .bind(now)
                        .bind(e.id)
                        .bind(e.claim_token)
                        .bind(now),
                )
                .await?;
        }
        tx.commit().await?;
        Ok(n)
    }

    /// Give undelivered events back immediately (shutdown / downstream failure). Returns count.
    ///
    /// # Errors
    /// Server errors.
    pub async fn outbox_release(&self, events: &[ClaimedOutboxEvent]) -> Result<u64, DbError> {
        let mut tx = self.system_tx().await?;
        let mut n = 0;
        for e in events {
            n += tx
                .inner
                .execute(sql::q(OUTBOX_EVENTS_RELEASE).bind(e.id).bind(e.claim_token))
                .await?;
        }
        tx.commit().await?;
        Ok(n)
    }
}
