//! `audit_events` + `audit_chain_blocks` access for the `audit` crate (P0-12).
//!
//! The hash/merkle maths lives in the `audit` crate; this module only stores and reads rows. Writes are
//! INSERT-only (the app DB user must not hold UPDATE/DELETE on these tables, see `docs/ops/db_users.sql`).
//! Own query constants (not in `queries.rs`) so the audit work does not touch shared db files.

use crate::error::DbError;
use crate::sql;
use crate::tx::{IdentityTx, Inner, PlatformTx, SystemTx, TenantTx};
use crate::write_guard::WriteOutcome;
use sqlx::mysql::MySqlRow;
use time::OffsetDateTime;

const EVENTS_INSERT: &str = include_str!("../../queries/audit_events/insert.sql");
const EVENTS_LIST_RANGE: &str = include_str!("../../queries/audit_events/list_range.sql");
const EVENTS_EXISTS_BEFORE: &str = include_str!("../../queries/audit_events/exists_before.sql");
const EVENTS_MIN_TIME: &str = include_str!("../../queries/audit_events/min_time.sql");
const BLOCKS_INSERT: &str = include_str!("../../queries/audit_chain_blocks/insert.sql");
const BLOCKS_GET: &str = include_str!("../../queries/audit_chain_blocks/get.sql");
const BLOCKS_LAST: &str = include_str!("../../queries/audit_chain_blocks/last.sql");
const BLOCKS_BEFORE: &str = include_str!("../../queries/audit_chain_blocks/before.sql");
const BLOCKS_LIST_RANGE: &str = include_str!("../../queries/audit_chain_blocks/list_range.sql");

/// One `audit_events` row (all columns). `row_hash` is computed by the caller (`audit` crate).
#[derive(Clone, Debug, PartialEq)]
pub struct AuditRowRecord {
    pub id: uuid::Uuid,
    pub occurred_at: OffsetDateTime,
    pub tenant_id: Option<uuid::Uuid>,
    pub actor_kind: String,
    pub actor_id: Option<uuid::Uuid>,
    pub staff_grant_id: Option<uuid::Uuid>,
    pub action: String,
    pub outcome: String,
    pub target_type: Option<String>,
    pub target_id: Option<uuid::Uuid>,
    pub request_id: Option<uuid::Uuid>,
    pub ip_hmac: Option<Vec<u8>>,
    pub metadata: Option<serde_json::Value>,
    pub row_hash: Vec<u8>,
}

/// One `audit_chain_blocks` row.
#[derive(Clone, Debug, PartialEq)]
pub struct AuditBlockRecord {
    pub block_start: OffsetDateTime,
    pub block_end: OffsetDateTime,
    pub first_id: Option<uuid::Uuid>,
    pub last_id: Option<uuid::Uuid>,
    pub event_count: i64,
    pub merkle_root: Vec<u8>,
    pub prev_block_hash: Vec<u8>,
    pub block_hash: Vec<u8>,
    pub anchored_blob_key: Option<String>,
    pub anchored_blob_write_id: Option<uuid::Uuid>,
    pub anchored_blob_digest: Option<Vec<u8>>,
    pub sealed_at: OffsetDateTime,
}

async fn insert_event(inner: &mut Inner, r: &AuditRowRecord) -> Result<(), DbError> {
    inner
        .execute(
            sql::q(EVENTS_INSERT)
                .bind(r.id)
                .bind(r.occurred_at)
                .bind(r.tenant_id)
                .bind(r.actor_kind.as_str())
                .bind(r.actor_id)
                .bind(r.staff_grant_id)
                .bind(r.action.as_str())
                .bind(r.outcome.as_str())
                .bind(r.target_type.as_deref())
                .bind(r.target_id)
                .bind(r.request_id)
                .bind(r.ip_hmac.as_deref())
                .bind(r.metadata.as_ref())
                .bind(r.row_hash.as_slice()),
        )
        .await?
        .expect_one()
}

/// Audit row in the SAME transaction as a tenant write. The row's tenant must be the tx tenant.
///
/// # Errors
/// `TenantMismatch` (row of another tenant), server errors.
pub async fn insert_event_tenant(tx: &mut TenantTx, r: &AuditRowRecord) -> Result<(), DbError> {
    let row_tenant = r
        .tenant_id
        .map(common::TenantId)
        .ok_or(DbError::TenantMismatch)?;
    tx.assert_row_tenant(row_tenant)?;
    insert_event(&mut tx.inner, r).await
}

/// # Errors
/// Server errors.
pub async fn insert_event_platform(tx: &mut PlatformTx, r: &AuditRowRecord) -> Result<(), DbError> {
    insert_event(&mut tx.inner, r).await
}

/// # Errors
/// Server errors.
pub async fn insert_event_identity(tx: &mut IdentityTx, r: &AuditRowRecord) -> Result<(), DbError> {
    insert_event(&mut tx.inner, r).await
}

/// # Errors
/// Server errors.
pub async fn insert_event_system(tx: &mut SystemTx, r: &AuditRowRecord) -> Result<(), DbError> {
    insert_event(&mut tx.inner, r).await
}

fn event_of(row: &MySqlRow) -> Result<AuditRowRecord, DbError> {
    Ok(AuditRowRecord {
        id: sql::uuid_col(row, "id")?,
        occurred_at: sql::col(row, "occurred_at")?,
        tenant_id: sql::opt_uuid_col(row, "tenant_id")?,
        actor_kind: sql::col(row, "actor_kind")?,
        actor_id: sql::opt_uuid_col(row, "actor_id")?,
        staff_grant_id: sql::opt_uuid_col(row, "staff_grant_id")?,
        action: sql::col(row, "action")?,
        outcome: sql::col(row, "outcome")?,
        target_type: sql::col(row, "target_type")?,
        target_id: sql::opt_uuid_col(row, "target_id")?,
        request_id: sql::opt_uuid_col(row, "request_id")?,
        ip_hmac: sql::col(row, "ip_hmac")?,
        metadata: sql::col(row, "metadata")?,
        row_hash: sql::col(row, "row_hash")?,
    })
}

fn block_of(row: &MySqlRow) -> Result<AuditBlockRecord, DbError> {
    Ok(AuditBlockRecord {
        block_start: sql::col(row, "block_start")?,
        block_end: sql::col(row, "block_end")?,
        first_id: sql::opt_uuid_col(row, "first_id")?,
        last_id: sql::opt_uuid_col(row, "last_id")?,
        event_count: sql::col(row, "event_count")?,
        merkle_root: sql::col(row, "merkle_root")?,
        prev_block_hash: sql::col(row, "prev_block_hash")?,
        block_hash: sql::col(row, "block_hash")?,
        anchored_blob_key: sql::col(row, "anchored_blob_key")?,
        anchored_blob_write_id: sql::opt_uuid_col(row, "anchored_blob_write_id")?,
        anchored_blob_digest: sql::col(row, "anchored_blob_digest")?,
        sealed_at: sql::col(row, "sealed_at")?,
    })
}

/// One page of events with `range_start <= occurred_at < range_end`, in chain order `(occurred_at, id)`,
/// strictly after the `after` cursor (`None` = from the start).
///
/// # Errors
/// Server / decode errors.
pub async fn list_events_range(
    tx: &mut SystemTx,
    range_start: OffsetDateTime,
    range_end: OffsetDateTime,
    after: Option<(OffsetDateTime, uuid::Uuid)>,
    limit: u32,
) -> Result<Vec<AuditRowRecord>, DbError> {
    let (after_at, after_id) = after.unwrap_or((range_start, uuid::Uuid::nil()));
    let rows = tx
        .inner
        .fetch_all(
            sql::q(EVENTS_LIST_RANGE)
                .bind(range_start)
                .bind(range_end)
                .bind(after_at)
                .bind(after_id)
                .bind(i64::from(limit)),
        )
        .await?;
    rows.iter().map(event_of).collect()
}

/// Any event strictly before `before` (genesis check).
///
/// # Errors
/// Server errors.
pub async fn events_exist_before(
    tx: &mut SystemTx,
    before: OffsetDateTime,
) -> Result<bool, DbError> {
    tx.inner
        .exists(sql::q(EVENTS_EXISTS_BEFORE).bind(before))
        .await
}

/// Time of the oldest event (`None` = table empty).
///
/// # Errors
/// Server / decode errors.
pub async fn first_event_time(tx: &mut SystemTx) -> Result<Option<OffsetDateTime>, DbError> {
    let row = tx.inner.fetch_optional(sql::q(EVENTS_MIN_TIME)).await?;
    match row {
        Some(r) => sql::col(&r, "t"),
        None => Ok(None),
    }
}

/// # Errors
/// `Duplicate` (block already sealed by someone else), server errors.
pub async fn insert_block(tx: &mut SystemTx, b: &AuditBlockRecord) -> Result<(), DbError> {
    tx.inner
        .execute(
            sql::q(BLOCKS_INSERT)
                .bind(b.block_start)
                .bind(b.block_end)
                .bind(b.first_id)
                .bind(b.last_id)
                .bind(b.event_count)
                .bind(b.merkle_root.as_slice())
                .bind(b.prev_block_hash.as_slice())
                .bind(b.block_hash.as_slice())
                .bind(b.anchored_blob_key.as_deref())
                .bind(b.anchored_blob_write_id)
                .bind(b.anchored_blob_digest.as_deref())
                .bind(b.sealed_at),
        )
        .await?
        .expect_one()
}

/// # Errors
/// Server / decode errors.
pub async fn get_block(
    tx: &mut SystemTx,
    block_start: OffsetDateTime,
) -> Result<Option<AuditBlockRecord>, DbError> {
    let row = tx
        .inner
        .fetch_optional(sql::q(BLOCKS_GET).bind(block_start))
        .await?;
    row.as_ref().map(block_of).transpose()
}

/// Newest sealed block.
///
/// # Errors
/// Server / decode errors.
pub async fn last_block(tx: &mut SystemTx) -> Result<Option<AuditBlockRecord>, DbError> {
    let row = tx.inner.fetch_optional(sql::q(BLOCKS_LAST)).await?;
    row.as_ref().map(block_of).transpose()
}

/// Newest sealed block that starts before `block_start`.
///
/// # Errors
/// Server / decode errors.
pub async fn block_before(
    tx: &mut SystemTx,
    block_start: OffsetDateTime,
) -> Result<Option<AuditBlockRecord>, DbError> {
    let row = tx
        .inner
        .fetch_optional(sql::q(BLOCKS_BEFORE).bind(block_start))
        .await?;
    row.as_ref().map(block_of).transpose()
}

/// Blocks with `from <= block_start < to`, ascending, strictly after `after` (cursor).
///
/// # Errors
/// Server / decode errors.
pub async fn list_blocks_range(
    tx: &mut SystemTx,
    from: OffsetDateTime,
    to: OffsetDateTime,
    after: Option<OffsetDateTime>,
    limit: u32,
) -> Result<Vec<AuditBlockRecord>, DbError> {
    let rows = tx
        .inner
        .fetch_all(
            sql::q(BLOCKS_LIST_RANGE)
                .bind(from)
                .bind(to)
                .bind(after.unwrap_or(from - time::Duration::seconds(1)))
                .bind(i64::from(limit)),
        )
        .await?;
    rows.iter().map(block_of).collect()
}
