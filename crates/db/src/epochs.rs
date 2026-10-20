//! Authz epochs (DATABASE.md §4.4, LISTEN/NOTIFY replacement).
//!
//! Every authz-affecting write calls [`bump_epoch`] in the same `TenantTx`. Each instance polls
//! [`Db::poll_epochs`] (caller schedules it every `AUTHZ_EPOCH_POLL_MS`; db crate spawns nothing) and
//! keeps a bounded in-memory map; `auth` compares `epoch_seen` with [`EpochMap::current`].
//!
//! Poller correctness (review F3):
//! - compound keyset cursor `(updated_at, tenant_id)`, so any number of rows with the same
//!   `updated_at` is paged through (no stuck cursor, no skipped rows);
//! - every round re-reads an overlap window of `tx_timeout + 1 s` behind the high-water mark:
//!   `updated_at` is the app clock at statement time, and a tx can commit up to `tx_timeout` later,
//!   so a late commit with an older timestamp is still inside the window. Merge = max epoch;
//! - `last_ok` only advances when the round consumed every page (otherwise auth bypasses the cache).

use crate::error::DbError;
use crate::pool::Db;
use crate::queries::{
    AUTHZ_EPOCHS_BUMP, AUTHZ_EPOCHS_CHANGED_AFTER, AUTHZ_EPOCHS_CHANGED_TIES, AUTHZ_EPOCHS_GET,
};
use crate::sql;
use crate::tx::{SystemTx, TenantTx};
use crate::write_guard::WriteOutcome;
use common::TenantId;
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use time::{Duration, OffsetDateTime};

/// Hard bound on tracked tenants per instance (memory budget); beyond it callers bypass the cache.
pub const MAX_TRACKED_TENANTS: usize = 100_000;
/// Rows per page.
pub const POLL_BATCH: u32 = 500;
/// Pages per round (bounded work per poll; a backlog beyond this leaves `last_ok` unchanged).
pub const MAX_PAGES_PER_POLL: u32 = 50;

#[derive(Debug, Default)]
struct State {
    epochs: HashMap<TenantId, u64>,
    /// High-water mark of `updated_at` seen so far.
    high_water: Option<OffsetDateTime>,
    last_ok: Option<OffsetDateTime>,
}

/// Process-local view of tenant epochs.
#[derive(Debug, Default)]
pub struct EpochMap {
    state: Mutex<State>,
}

impl EpochMap {
    /// Last polled epoch of a tenant (`None` = unknown: caller must live-load).
    #[must_use]
    pub fn current(&self, tenant: TenantId) -> Option<u64> {
        self.lock().epochs.get(&tenant).copied()
    }

    /// When the last fully consumed poll finished (`auth` bypasses the cache when stale > 10 s).
    #[must_use]
    pub fn last_ok(&self) -> Option<OffsetDateTime> {
        self.lock().last_ok
    }

    /// Local write path: after committing a bump, the writer instance records it immediately.
    pub fn observe(&self, tenant: TenantId, epoch: u64) {
        apply(&mut self.lock(), tenant, epoch);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn merge(&self, rows: &[(TenantId, u64, OffsetDateTime)]) {
        let mut s = self.lock();
        for (t, e, at) in rows {
            apply(&mut s, *t, *e);
            if s.high_water.is_none_or(|x| *at > x) {
                s.high_water = Some(*at);
            }
        }
    }

    fn high_water(&self) -> Option<OffsetDateTime> {
        self.lock().high_water
    }

    fn mark_ok(&self, now: OffsetDateTime) {
        self.lock().last_ok = Some(now);
    }
}

fn apply(s: &mut State, tenant: TenantId, epoch: u64) {
    if s.epochs.len() >= MAX_TRACKED_TENANTS && !s.epochs.contains_key(&tenant) {
        return; // unknown => live load (never deny)
    }
    let e = s.epochs.entry(tenant).or_insert(0);
    if epoch > *e {
        *e = epoch;
    }
}

/// `+1` on the tx tenant's epoch (same tx as the authz change).
///
/// # Errors
/// `NotPersisted` if the tenant has no epoch row (broken bootstrap), server errors.
pub async fn bump_epoch(tx: &mut TenantTx, now: OffsetDateTime) -> Result<(), DbError> {
    let tid = tx.tid();
    tx.inner
        .execute(sql::q(AUTHZ_EPOCHS_BUMP).bind(now).bind(tid))
        .await?
        .expect_one()
}

/// Live epoch read of the tx tenant (high-risk actions, cache bypass).
///
/// # Errors
/// `NotFound`, server errors.
pub async fn current_epoch(tx: &mut TenantTx) -> Result<u64, DbError> {
    let tid = tx.tid();
    let row = tx
        .inner
        .fetch_optional(sql::q(AUTHZ_EPOCHS_GET).bind(tid))
        .await?
        .ok_or(DbError::NotFound("authz epoch"))?;
    tx.assert_row_tenant(TenantId(sql::uuid_col(&row, "tenant_id")?))?;
    sql::col::<u64>(&row, "epoch")
}

/// One page strictly after the compound cursor `(since, after_tenant)`.
///
/// # Errors
/// Server errors.
pub async fn changed_since(
    tx: &mut SystemTx,
    since: OffsetDateTime,
    after_tenant: TenantId,
    limit: u32,
) -> Result<Vec<(TenantId, u64, OffsetDateTime)>, DbError> {
    // Two index range scans instead of one OR predicate (TiDB planned the OR as a TableFullScan):
    // ties at exactly `since` after `after_tenant`, then strictly newer rows; together = rows after
    // the compound cursor, in (updated_at, tenant_id) order.
    let map = |r: &sqlx::mysql::MySqlRow| -> Result<(TenantId, u64, OffsetDateTime), DbError> {
        Ok((
            TenantId(sql::uuid_col(r, "tenant_id")?),
            sql::col::<u64>(r, "epoch")?,
            sql::col::<OffsetDateTime>(r, "updated_at")?,
        ))
    };
    let ties = tx
        .inner
        .fetch_all(
            sql::q(AUTHZ_EPOCHS_CHANGED_TIES)
                .bind(since)
                .bind(after_tenant.0)
                .bind(limit),
        )
        .await?;
    let mut out = ties.iter().map(map).collect::<Result<Vec<_>, _>>()?;
    let left = limit.saturating_sub(u32::try_from(out.len()).unwrap_or(u32::MAX));
    if left > 0 {
        let newer = tx
            .inner
            .fetch_all(sql::q(AUTHZ_EPOCHS_CHANGED_AFTER).bind(since).bind(left))
            .await?;
        for r in &newer {
            out.push(map(r)?);
        }
    }
    Ok(out)
}

impl Db {
    /// Re-read window behind the high-water mark (`tx_timeout + 1 s`).
    #[must_use]
    pub fn epoch_overlap(&self) -> Duration {
        Duration::try_from(self.options().tx_timeout).unwrap_or(Duration::seconds(5))
            + Duration::seconds(1)
    }

    /// One poll round: pages from `high_water - overlap` until a short page (fully consumed) or
    /// `MAX_PAGES_PER_POLL`. Returns rows read.
    ///
    /// # Errors
    /// Server errors (map keeps what was merged; `last_ok` not advanced -> auth bypasses cache).
    pub async fn poll_epochs(&self, now: OffsetDateTime) -> Result<usize, DbError> {
        let start = self
            .epochs()
            .high_water()
            .map_or(OffsetDateTime::UNIX_EPOCH, |h| h - self.epoch_overlap());
        // `(start - 1us, nil)` = every row with updated_at >= start (including the nil platform row).
        let mut since = start - Duration::microseconds(1);
        let mut after = TenantId(uuid::Uuid::nil());
        let mut total = 0usize;
        let mut consumed = false;
        let mut tx = self.system_tx().await?;
        for _ in 0..MAX_PAGES_PER_POLL {
            let rows = changed_since(&mut tx, since, after, POLL_BATCH).await?;
            total += rows.len();
            self.epochs().merge(&rows);
            let full = rows.len() >= usize::try_from(POLL_BATCH).unwrap_or(usize::MAX);
            match rows.last() {
                Some((t, _, at)) if full => {
                    since = *at;
                    after = *t;
                }
                _ => {
                    consumed = true;
                    break;
                }
            }
        }
        tx.commit().await?;
        if consumed {
            self.epochs().mark_ok(now);
        }
        Ok(total)
    }
}
