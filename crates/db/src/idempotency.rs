//! Idempotency keys (scope = tenant, principal = acting membership or device credential).
//! `reserve_committed` (own short tx, committed) -> business tx containing `complete` (stores the response to
//! replay) -> commit; on business failure / timeout `release`.

use crate::error::DbError;
use crate::pool::Db;
use crate::queries::{
    IDEMPOTENCY_KEYS_COMPLETE, IDEMPOTENCY_KEYS_EXPIRED_CANDIDATES,
    IDEMPOTENCY_KEYS_GET_FOR_UPDATE, IDEMPOTENCY_KEYS_INSERT, IDEMPOTENCY_KEYS_RELEASE,
    IDEMPOTENCY_KEYS_RESET_EXPIRED, IDEMPOTENCY_KEYS_RESET_TAKEOVER, IDEMPOTENCY_KEYS_TOMBSTONE,
};
use crate::sql;
use crate::tx::TenantTx;
use crate::write_guard::WriteOutcome;
use domain::rbac::TenantScope;
use time::{Duration, OffsetDateTime};

pub const MAX_KEY_LEN: usize = 128;
pub const MAX_RESPONSE_BYTES: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reservation {
    /// First time: proceed with the write.
    Fresh,
    /// Finished earlier with the same request: replay this response.
    Replay {
        status_code: u16,
        body: Option<Vec<u8>>,
        resource_id: Option<uuid::Uuid>,
    },
    /// Another request with this key is still running (409 / retry later).
    InProgress,
    /// Same key, different request body (422 per idempotency contract).
    Mismatch,
}

fn check_key(key: &str) -> Result<(), DbError> {
    if key.is_empty() || key.len() > MAX_KEY_LEN || !key.is_ascii() {
        return Err(DbError::Invalid(
            "idempotency key must be 1..=128 ASCII bytes",
        ));
    }
    Ok(())
}

enum Step {
    Done(Reservation),
    /// The INSERT hit a duplicate: someone else reserved concurrently.
    Raced,
}

async fn reserve_in(
    tx: &mut TenantTx,
    principal: uuid::Uuid,
    key: &str,
    request_hash: &[u8; 32],
    now: OffsetDateTime,
    ttl: Duration,
) -> Result<Step, DbError> {
    let tid = tx.tid();
    let existing = tx
        .inner
        .fetch_optional(
            sql::q(IDEMPOTENCY_KEYS_GET_FOR_UPDATE)
                .bind(tid)
                .bind(principal)
                .bind(key),
        )
        .await?;
    if let Some(row) = existing {
        let expires_at: OffsetDateTime = sql::col(&row, "expires_at")?;
        if expires_at > now {
            return classify(&row, request_hash).map(Step::Done);
        }
        // Existing (expired) row: a real row lock serialises concurrent resets on both engines.
        tx.inner
            .execute(
                sql::q(IDEMPOTENCY_KEYS_RESET_EXPIRED)
                    .bind(&request_hash[..])
                    .bind(now)
                    .bind(now + ttl)
                    .bind(tid)
                    .bind(principal)
                    .bind(key)
                    .bind(now),
            )
            .await?
            .expect_one()?;
        return Ok(Step::Done(Reservation::Fresh));
    }
    match tx
        .inner
        .execute(
            sql::q(IDEMPOTENCY_KEYS_INSERT)
                .bind(tid)
                .bind(principal)
                .bind(key)
                .bind(&request_hash[..])
                .bind(now)
                .bind(now + ttl),
        )
        .await
    {
        Ok(n) => {
            n.expect_one()?;
            Ok(Step::Done(Reservation::Fresh))
        }
        Err(DbError::Duplicate { .. }) => Ok(Step::Raced),
        Err(e) => Err(e),
    }
}

/// An uncompleted reservation older than this may be taken over by a new reserve of the same key
/// (its request died without `release`). 2 x the API request timeout.
pub const IN_PROGRESS_STALE: Duration = Duration::seconds(60);

/// Phase 2 of [`reserve_committed`]: the key exists (or existed). Lock it, then reuse it when expired
/// or stale in-progress, else classify. `None` = row vanished (winner rolled back): try again.
async fn claim_existing(
    db: &Db,
    scope: &TenantScope,
    principal: uuid::Uuid,
    key: &str,
    request_hash: &[u8; 32],
    now: OffsetDateTime,
    ttl: Duration,
) -> Result<Option<Reservation>, DbError> {
    let mut tx = db.tenant_tx(scope).await?;
    let tid = tx.tid();
    let r: Result<Option<Reservation>, DbError> = async {
        let Some(row) = tx
            .inner
            .fetch_optional(
                sql::q(IDEMPOTENCY_KEYS_GET_FOR_UPDATE)
                    .bind(tid)
                    .bind(principal)
                    .bind(key),
            )
            .await?
        else {
            return Ok(None);
        };
        let n = tx
            .inner
            .execute(
                sql::q(IDEMPOTENCY_KEYS_RESET_TAKEOVER)
                    .bind(&request_hash[..])
                    .bind(now)
                    .bind(now + ttl)
                    .bind(tid)
                    .bind(principal)
                    .bind(key)
                    .bind(now)
                    .bind(now - IN_PROGRESS_STALE),
            )
            .await?;
        if n == 1 {
            Ok(Some(Reservation::Fresh))
        } else {
            classify(&row, request_hash).map(Some)
        }
    }
    .await;
    match r {
        Ok(Some(Reservation::Fresh)) => {
            tx.commit().await?;
            Ok(Some(Reservation::Fresh))
        }
        other => {
            tx.rollback().await;
            other
        }
    }
}

/// Reserve `key` for `principal` in the scope's tenant in its OWN short transaction, committed before
/// the business work starts. Correct under MySQL gap locking and TiDB lazy unique checks:
/// 1. INSERT first (no `SELECT ... FOR UPDATE` on a missing row = no gap-lock deadlock) and commit;
///    a duplicate at INSERT or at COMMIT means the key exists.
/// 2. Then lock that row: reuse it when expired, or in progress for longer than
///    [`IN_PROGRESS_STALE`]; otherwise `InProgress` / `Replay` / `Mismatch`.
///
/// Flow: `Fresh` -> business tx with [`complete`] -> commit; on failure/timeout [`release`].
///
/// # Errors
/// `Invalid`, `ScopeMissing`, server errors (transient ones after 3 attempts).
pub async fn reserve_committed(
    db: &Db,
    scope: &TenantScope,
    principal: uuid::Uuid,
    key: &str,
    request_hash: &[u8; 32],
    now: OffsetDateTime,
    ttl: Duration,
) -> Result<Reservation, DbError> {
    check_key(key)?;
    let mut last = DbError::Transient { code: 0 };
    for attempt in 1..=3u32 {
        // Phase 1: insert + commit.
        let mut tx = db.tenant_tx(scope).await?;
        let tid = tx.tid();
        let ins = tx
            .inner
            .execute(
                sql::q(IDEMPOTENCY_KEYS_INSERT)
                    .bind(tid)
                    .bind(principal)
                    .bind(key)
                    .bind(&request_hash[..])
                    .bind(now)
                    .bind(now + ttl),
            )
            .await;
        let exists = match ins {
            Ok(n) => {
                n.expect_one()?;
                match tx.commit().await {
                    Ok(()) => return Ok(Reservation::Fresh),
                    Err(DbError::Duplicate { .. }) => true, // lazy unique check (TiDB)
                    Err(e) if e.is_retryable() => {
                        last = e;
                        false
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(DbError::Duplicate { .. }) => {
                tx.rollback().await;
                true
            }
            Err(e) if e.is_retryable() => {
                tx.rollback().await;
                last = e;
                false
            }
            Err(e) => {
                tx.rollback().await;
                return Err(e);
            }
        };
        if exists {
            match claim_existing(db, scope, principal, key, request_hash, now, ttl).await {
                Ok(Some(r)) => return Ok(r),
                Ok(None) => {} // winner rolled back: insert again
                Err(e) if e.is_retryable() => last = e,
                Err(e) => return Err(e),
            }
        }
        tokio::time::sleep(crate::retry::backoff(
            attempt,
            std::time::Duration::from_millis(20),
        ))
        .await;
    }
    Err(last)
}

/// LEGACY in-transaction reserve (kept so existing callers build). Correct on MySQL; on TiDB with lazy
/// unique checks two concurrent callers can both see `Fresh` until one fails at COMMIT. New code must
/// use [`reserve_committed`].
///
/// # Errors
/// `Invalid`, server errors.
pub async fn reserve(
    tx: &mut TenantTx,
    principal: uuid::Uuid,
    key: &str,
    request_hash: &[u8; 32],
    now: OffsetDateTime,
    ttl: Duration,
) -> Result<Reservation, DbError> {
    check_key(key)?;
    match reserve_in(tx, principal, key, request_hash, now, ttl).await? {
        Step::Done(r) => Ok(r),
        Step::Raced => {
            let tid = tx.tid();
            let row = tx
                .inner
                .fetch_optional(
                    sql::q(IDEMPOTENCY_KEYS_GET_FOR_UPDATE)
                        .bind(tid)
                        .bind(principal)
                        .bind(key),
                )
                .await?;
            match row {
                Some(r) => classify(&r, request_hash),
                None => Ok(Reservation::InProgress),
            }
        }
    }
}

/// The request that holds a `Fresh` reservation died, failed or timed out: turn its uncompleted
/// reservation (same principal, key and request hash) into expired, so the client's retry reserves
/// it again. UPDATE only, never DELETE. Returns whether a reservation was released (false =
/// already completed, taken over, or not ours).
///
/// # Errors
/// `Invalid`, server errors.
pub async fn release(
    db: &Db,
    scope: &TenantScope,
    principal: uuid::Uuid,
    key: &str,
    request_hash: &[u8; 32],
    now: OffsetDateTime,
) -> Result<bool, DbError> {
    check_key(key)?;
    let mut tx = db.tenant_tx(scope).await?;
    let tid = tx.tid();
    let r = tx
        .inner
        .execute(
            sql::q(IDEMPOTENCY_KEYS_RELEASE)
                .bind(now)
                .bind(tid)
                .bind(principal)
                .bind(key)
                .bind(&request_hash[..]),
        )
        .await;
    match r {
        Ok(n) => {
            tx.commit().await?;
            Ok(n == 1)
        }
        Err(e) => {
            tx.rollback().await;
            Err(e)
        }
    }
}

/// Existing, unexpired key: same hash -> InProgress/Replay, other hash -> Mismatch.
fn classify(row: &sqlx::mysql::MySqlRow, request_hash: &[u8; 32]) -> Result<Reservation, DbError> {
    let stored: Vec<u8> = sql::col(row, "request_hash")?;
    if stored.as_slice() != request_hash.as_slice() {
        return Ok(Reservation::Mismatch);
    }
    let status: Option<i16> = sql::col(row, "status_code")?;
    Ok(match status {
        None => Reservation::InProgress,
        Some(s) => Reservation::Replay {
            status_code: u16::try_from(s)
                .map_err(|_| DbError::Corrupt("idempotency_keys.status_code"))?,
            body: sql::col(row, "response_body")?,
            resource_id: sql::opt_uuid_col(row, "resource_id")?,
        },
    })
}

/// Store the response for replay (exactly once).
///
/// # Errors
/// `Invalid` (body cap), `NotPersisted` (not reserved / already completed), server errors.
pub async fn complete(
    tx: &mut TenantTx,
    principal: uuid::Uuid,
    key: &str,
    status_code: u16,
    body: Option<&[u8]>,
    resource_id: Option<uuid::Uuid>,
) -> Result<(), DbError> {
    check_key(key)?;
    if body.is_some_and(|b| b.len() > MAX_RESPONSE_BYTES) {
        return Err(DbError::Invalid("idempotent response too large"));
    }
    let code = i16::try_from(status_code).map_err(|_| DbError::Invalid("status code"))?;
    let tid = tx.tid();
    tx.inner
        .execute(
            sql::q(IDEMPOTENCY_KEYS_COMPLETE)
                .bind(code)
                .bind(body)
                .bind(resource_id)
                .bind(tid)
                .bind(principal)
                .bind(key),
        )
        .await?
        .expect_one()
}

/// Bounded sweep without DELETE: tombstone up to `batch` expired keys (stored response dropped; the
/// row stays until the TTL purge, D-56). Lookups already treat expired rows as absent (`reserve` resets
/// them to Fresh). Returns the number tombstoned.
///
/// # Errors
/// Server errors.
pub async fn expire_older_than(
    db: &crate::pool::Db,
    now: OffsetDateTime,
    batch: u32,
) -> Result<u64, DbError> {
    let batch = batch.clamp(1, 500);
    let mut tx = db.system_tx().await?;
    let rows = tx
        .inner
        .fetch_all(
            sql::q(IDEMPOTENCY_KEYS_EXPIRED_CANDIDATES)
                .bind(now)
                .bind(batch),
        )
        .await?;
    tx.commit().await?;
    let mut n = 0;
    for r in &rows {
        let scope = sql::uuid_col(r, "scope_key")?;
        let principal = sql::uuid_col(r, "principal_id")?;
        let key: String = sql::col(r, "idem_key")?;
        let mut tx = db.system_tx().await?;
        n += tx
            .inner
            .execute(
                sql::q(IDEMPOTENCY_KEYS_TOMBSTONE)
                    .bind(scope)
                    .bind(principal)
                    .bind(key.as_str())
                    .bind(now),
            )
            .await?;
        tx.commit().await?;
    }
    Ok(n)
}
