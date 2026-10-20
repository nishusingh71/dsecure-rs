//! `tenant_counters` (DATABASE.md §1.3 rule 4: O(1) dashboard counts, maintained in the same tx).

use crate::error::DbError;
use crate::queries::{
    TENANT_COUNTERS_ADD_DEPARTMENTS, TENANT_COUNTERS_ADD_GROUPS, TENANT_COUNTERS_ADD_MEMBERS,
    TENANT_COUNTERS_GET, TENANT_COUNTERS_LOCK_FOR_UPDATE,
};
use crate::sql;
use crate::tx::{Inner, TenantTx};
use crate::write_guard::WriteOutcome;
use common::TenantId;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TenantCounters {
    pub members_active: u32,
    pub groups_active: u32,
    pub departments_active: u32,
    pub devices_active: u32,
    pub licenses_active: u32,
    pub licenses_in_use: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Counter {
    Members,
    Groups,
    #[allow(dead_code)] // departments repo is Phase 1; query file + path already exist
    Departments,
}

fn non_neg(row: &sqlx::mysql::MySqlRow, name: &'static str) -> Result<u32, DbError> {
    u32::try_from(sql::col::<i32>(row, name)?).map_err(|_| DbError::Corrupt(name))
}

/// Counters of the tx tenant.
///
/// # Errors
/// `NotFound` (no counters row), `TenantMismatch`, server errors.
pub async fn get(tx: &mut TenantTx) -> Result<TenantCounters, DbError> {
    let tid = tx.tid();
    let row = tx
        .inner
        .fetch_optional(sql::q(TENANT_COUNTERS_GET).bind(tid))
        .await?
        .ok_or(DbError::NotFound("tenant counters"))?;
    tx.assert_row_tenant(TenantId(sql::uuid_col(&row, "tenant_id")?))?;
    Ok(TenantCounters {
        members_active: non_neg(&row, "members_active")?,
        groups_active: non_neg(&row, "groups_active")?,
        departments_active: non_neg(&row, "departments_active")?,
        devices_active: non_neg(&row, "devices_active")?,
        licenses_active: non_neg(&row, "licenses_active")?,
        licenses_in_use: non_neg(&row, "licenses_in_use")?,
    })
}

/// Lock the counters row (after the quota row) and return the current value of `c`.
pub(crate) async fn lock(inner: &mut Inner, tenant: TenantId, c: Counter) -> Result<u32, DbError> {
    let row = inner
        .fetch_optional(sql::q(TENANT_COUNTERS_LOCK_FOR_UPDATE).bind(tenant.0))
        .await?
        .ok_or(DbError::NotFound("tenant counters"))?;
    crate::tx::assert_row_tenant(tenant, TenantId(sql::uuid_col(&row, "tenant_id")?))?;
    non_neg(
        &row,
        match c {
            Counter::Members => "members_active",
            Counter::Groups => "groups_active",
            Counter::Departments => "departments_active",
        },
    )
}

pub(crate) async fn add(
    inner: &mut Inner,
    tenant: TenantId,
    c: Counter,
    delta: i32,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    let q = match c {
        Counter::Members => TENANT_COUNTERS_ADD_MEMBERS,
        Counter::Groups => TENANT_COUNTERS_ADD_GROUPS,
        Counter::Departments => TENANT_COUNTERS_ADD_DEPARTMENTS,
    };
    inner
        .execute(sql::q(q).bind(delta).bind(now).bind(tenant.0).bind(delta))
        .await?
        .expect_one()
}
