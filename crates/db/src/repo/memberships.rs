//! `memberships` + `membership_directory` (same tx) with app-level parent checks, quota mutex,
//! last-owner protection and authz epoch bumps (DATABASE.md §2.2, §4.3, §4.4).

use crate::epochs::bump_epoch;
use crate::error::DbError;
use crate::keyset;
use crate::queries::{
    DEPARTMENTS_EXISTS, MEMBER_COUNTERS_INSERT, MEMBERSHIP_DIRECTORY_INSERT,
    MEMBERSHIP_DIRECTORY_UPDATE, MEMBERSHIPS_ACTIVE_OWNERS_FOR_UPDATE, MEMBERSHIPS_EXISTS,
    MEMBERSHIPS_EXISTS_USER, MEMBERSHIPS_GET, MEMBERSHIPS_GET_FOR_UPDATE, MEMBERSHIPS_INSERT,
    MEMBERSHIPS_LIST_GROUPS, MEMBERSHIPS_LIST_SELF, MEMBERSHIPS_LIST_TENANT, MEMBERSHIPS_SET_ROLE,
    MEMBERSHIPS_SET_STATUS, MEMBERSHIPS_VISIBLE_IN_GROUPS, TENANT_QUOTAS_LOCK_FOR_UPDATE,
    USERS_EXISTS,
};
use crate::repo::counters::{self, Counter};
use crate::repo::tenants;
use crate::sql;
use crate::tx::{Inner, TenantTx};
use crate::write_guard::WriteOutcome;
use common::{MembershipId, Page, PageOut, TenantId, UserId};
use domain::rbac::{
    GroupIds, MemberState, MemberStatus, OwnerChange, QuotaKind, Quotas, TenantRole, Visibility,
    check_last_owner, check_quota,
};
use sqlx::mysql::MySqlRow;
use time::OffsetDateTime;

/// DB status values of `memberships.status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MembershipStatus {
    Invited,
    Active,
    Disabled,
    Deleted,
}

impl MembershipStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invited => "invited",
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Deleted => "deleted",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Invited, Self::Active, Self::Disabled, Self::Deleted]
            .into_iter()
            .find(|v| v.as_str() == s)
    }

    /// Domain view (invited = pending verification).
    #[must_use]
    pub const fn to_domain(self) -> MemberStatus {
        match self {
            Self::Invited => MemberStatus::PendingVerification,
            Self::Active => MemberStatus::Active,
            Self::Disabled => MemberStatus::Disabled,
            Self::Deleted => MemberStatus::Deleted,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipKind {
    Primary,
    Subuser,
}

impl MembershipKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Subuser => "subuser",
        }
    }
}

/// New membership. `id` is app-generated before insert (AAD binding of `display_name_enc`).
#[derive(Clone, Debug)]
pub struct NewMember {
    pub id: MembershipId,
    pub user_id: UserId,
    pub role: TenantRole,
    pub kind: MembershipKind,
    pub status: MembershipStatus,
    pub parent_membership_id: Option<MembershipId>,
    pub department_id: Option<uuid::Uuid>,
    pub display_name_enc: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRow {
    pub tenant: TenantId,
    pub id: MembershipId,
    pub user_id: UserId,
    pub role: TenantRole,
    pub kind: String,
    pub status: MembershipStatus,
    pub parent_membership_id: Option<MembershipId>,
    pub department_id: Option<uuid::Uuid>,
    pub authz_version: u64,
    pub version: u32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl MemberRow {
    fn as_state(&self) -> MemberState {
        MemberState {
            tenant: self.tenant,
            membership: self.id,
            role: self.role,
            status: self.status.to_domain(),
            groups: GroupIds::new(),
            ga_groups: GroupIds::new(),
        }
    }
}

/// Row mapper with the L6 row-tenant assert FIRST (no field is read before it passes).
pub(crate) fn map_row(tx: &TenantTx, row: &MySqlRow) -> Result<MemberRow, DbError> {
    let tenant = TenantId(sql::uuid_col(row, "tenant_id")?);
    tx.assert_row_tenant(tenant)?;
    let role: String = sql::col(row, "role")?;
    let status: String = sql::col(row, "status")?;
    Ok(MemberRow {
        tenant,
        id: MembershipId(sql::uuid_col(row, "id")?),
        user_id: UserId(sql::uuid_col(row, "user_id")?),
        role: TenantRole::parse(&role).ok_or(DbError::Corrupt("memberships.role"))?,
        kind: sql::col(row, "kind")?,
        status: MembershipStatus::parse(&status).ok_or(DbError::Corrupt("memberships.status"))?,
        parent_membership_id: sql::opt_uuid_col(row, "parent_membership_id")?.map(MembershipId),
        department_id: sql::opt_uuid_col(row, "department_id")?,
        authz_version: sql::col(row, "authz_version")?,
        version: sql::col(row, "version")?,
        created_at: sql::col(row, "created_at")?,
        updated_at: sql::col(row, "updated_at")?,
    })
}

/// Quotas row under `FOR UPDATE` (quota mutex).
async fn lock_quotas(inner: &mut Inner, tenant: TenantId) -> Result<Quotas, DbError> {
    let row = inner
        .fetch_optional(sql::q(TENANT_QUOTAS_LOCK_FOR_UPDATE).bind(tenant.0))
        .await?
        .ok_or(DbError::NotFound("tenant quotas"))?;
    crate::tx::assert_row_tenant(tenant, TenantId(sql::uuid_col(&row, "tenant_id")?))?;
    let get = |n: &'static str| -> Result<Option<u32>, DbError> {
        sql::col::<Option<i32>>(&row, n)?
            .map(|v| u32::try_from(v).map_err(|_| DbError::Corrupt(n)))
            .transpose()
    };
    Ok(Quotas {
        max_members: get("max_members")?,
        max_groups: get("max_groups")?,
        max_departments: get("max_departments")?,
        max_licenses: get("max_licenses")?,
    })
}

/// Counter check for one more active member. Caller already holds tenant + quota rows (and the
/// entity rows); counters are locked LAST (DATABASE.md §1.2: tenant -> quota -> entity -> counters).
async fn check_member_slot(
    inner: &mut Inner,
    tenant: TenantId,
    quotas: &Quotas,
) -> Result<(), DbError> {
    let current = counters::lock(inner, tenant, Counter::Members).await?;
    check_quota(quotas, QuotaKind::Members, current, 1).map_err(|q| DbError::QuotaExceeded {
        quota: q.quota,
        limit: q.limit,
        current: q.current,
    })
}

/// Insert without visibility/actor semantics. Used by [`insert`] and by `tenants::create` for the
/// owner of a tenant created in the same transaction. `tenant` is never a request value.
pub(crate) async fn insert_row(
    inner: &mut Inner,
    tenant: TenantId,
    created_by: Option<MembershipId>,
    m: &NewMember,
    now: OffsetDateTime,
) -> Result<MembershipId, DbError> {
    if !matches!(
        m.status,
        MembershipStatus::Invited | MembershipStatus::Active
    ) {
        return Err(DbError::Invalid("new membership must be invited or active"));
    }
    // Lock order (DATABASE.md §1.2): tenant -> quota -> entity (parents) -> counters.
    tenants::lock_inner(inner, tenant).await?;
    let quotas = if m.status == MembershipStatus::Active {
        Some(lock_quotas(inner, tenant).await?)
    } else {
        None
    };
    // App parent checks (locking reads): cross-tenant id = not found.
    if !inner.exists(sql::q(USERS_EXISTS).bind(m.user_id.0)).await? {
        return Err(DbError::NotFound("user"));
    }
    if let Some(p) = m.parent_membership_id
        && !inner
            .exists(sql::q(MEMBERSHIPS_EXISTS).bind(tenant.0).bind(p.0))
            .await?
    {
        return Err(DbError::NotFound("parent membership"));
    }
    if let Some(d) = m.department_id
        && !inner
            .exists(sql::q(DEPARTMENTS_EXISTS).bind(tenant.0).bind(d))
            .await?
    {
        return Err(DbError::NotFound("department"));
    }
    if let Some(q) = &quotas {
        check_member_slot(inner, tenant, q).await?;
    }
    let r = inner
        .execute(
            sql::q(MEMBERSHIPS_INSERT)
                .bind(tenant.0)
                .bind(m.id.0)
                .bind(m.user_id.0)
                .bind(m.role.as_str())
                .bind(m.role.rank())
                .bind(m.kind.as_str())
                .bind(m.status.as_str())
                .bind(m.parent_membership_id.map(|p| p.0))
                .bind(m.department_id)
                .bind(m.display_name_enc.as_deref())
                .bind(created_by.map(|c| c.0))
                .bind(now)
                .bind(now),
        )
        .await;
    match r {
        Ok(n) => n.expect_one()?,
        Err(e) if e.is_duplicate_of("ux_memberships_user") => {
            return Err(DbError::Conflict("members.already_member"));
        }
        Err(e) if e.is_duplicate_of("PRIMARY") => {
            return Err(DbError::Conflict("members.id_taken"));
        }
        // Unknown key name (engine message format): decide from the data, not the message.
        Err(DbError::Duplicate { .. }) => {
            let member = inner
                .exists(
                    sql::q(MEMBERSHIPS_EXISTS_USER)
                        .bind(tenant.0)
                        .bind(m.user_id.0),
                )
                .await?;
            return Err(DbError::Conflict(if member {
                "members.already_member"
            } else {
                "members.id_taken"
            }));
        }
        Err(e) => return Err(e),
    }
    inner
        .execute(
            sql::q(MEMBERSHIP_DIRECTORY_INSERT)
                .bind(m.user_id.0)
                .bind(tenant.0)
                .bind(m.id.0)
                .bind(m.status.as_str())
                .bind(m.role.as_str())
                .bind(now),
        )
        .await?
        .expect_one()?;
    inner
        .execute(sql::q(MEMBER_COUNTERS_INSERT).bind(tenant.0).bind(m.id.0))
        .await?
        .expect_one()?;
    if m.status == MembershipStatus::Active {
        counters::add(inner, tenant, Counter::Members, 1, now).await?;
    }
    Ok(m.id)
}

/// Add a member to the tx tenant (quota mutex, parent checks, directory in the same tx).
///
/// # Errors
/// `NotFound` (user/parent/department not in this tenant), `QuotaExceeded`,
/// `Conflict("members.already_member")`, server errors.
pub async fn insert(
    tx: &mut TenantTx,
    m: &NewMember,
    now: OffsetDateTime,
) -> Result<MembershipId, DbError> {
    let tenant = tx.tenant();
    let actor = tx.actor();
    insert_row(&mut tx.inner, tenant, actor, m, now).await
}

/// Is membership `id` inside the tx visibility?
async fn visible(tx: &mut TenantTx, id: MembershipId) -> Result<bool, DbError> {
    match tx.visibility().clone() {
        Visibility::Tenant => Ok(true),
        Visibility::SelfOnly => Ok(tx.actor() == Some(id)),
        Visibility::Groups(gs) => {
            if gs.is_empty() {
                return Ok(false); // fail closed
            }
            // > 200 groups: chunked (F13), visible if any chunk matches.
            for chunk in gs.chunks(sql::MAX_IDS) {
                let sql_text = sql::expand_ids(MEMBERSHIPS_VISIBLE_IN_GROUPS, chunk.len())?;
                let mut q = sql::dynamic(sql_text).bind(tx.tid()).bind(id.0);
                for g in chunk {
                    q = q.bind(g.0);
                }
                if tx.inner.exists(q).await? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// Get one membership of the tx tenant within the tx visibility (`None` = not found / not visible).
///
/// # Errors
/// `TenantMismatch`, `Corrupt`, server errors.
pub async fn get(tx: &mut TenantTx, id: MembershipId) -> Result<Option<MemberRow>, DbError> {
    let tid = tx.tid();
    let Some(row) = tx
        .inner
        .fetch_optional(sql::q(MEMBERSHIPS_GET).bind(tid).bind(id.0))
        .await?
    else {
        return Ok(None);
    };
    let m = map_row(tx, &row)?;
    if !visible(tx, id).await? {
        return Ok(None);
    }
    Ok(Some(m))
}

async fn get_for_update(tx: &mut TenantTx, id: MembershipId) -> Result<MemberRow, DbError> {
    let tid = tx.tid();
    let row = tx
        .inner
        .fetch_optional(sql::q(MEMBERSHIPS_GET_FOR_UPDATE).bind(tid).bind(id.0))
        .await?
        .ok_or(DbError::NotFound("membership"))?;
    let m = map_row(tx, &row)?;
    if !visible(tx, id).await? {
        return Err(DbError::NotFound("membership"));
    }
    Ok(m)
}

/// Keyset list (newest first) within the tx visibility.
///
/// # Errors
/// `TenantMismatch`, `Corrupt`, server errors.
pub async fn list(
    tx: &mut TenantTx,
    page: &Page,
    cursor_key: &[u8],
) -> Result<PageOut<MemberRow>, DbError> {
    let tid = tx.tid();
    let after = keyset::after_id(page);
    let limit = keyset::fetch_limit(page);
    let mapped = match tx.visibility().clone() {
        Visibility::Tenant => tx
            .inner
            .fetch_all(
                sql::q(MEMBERSHIPS_LIST_TENANT)
                    .bind(tid)
                    .bind(after)
                    .bind(limit),
            )
            .await?
            .iter()
            .map(|r| map_row(tx, r))
            .collect::<Result<Vec<_>, _>>()?,
        Visibility::SelfOnly => {
            let actor = tx.require_actor()?;
            tx.inner
                .fetch_all(
                    sql::q(MEMBERSHIPS_LIST_SELF)
                        .bind(tid)
                        .bind(actor.0)
                        .bind(after)
                        .bind(limit),
                )
                .await?
                .iter()
                .map(|r| map_row(tx, r))
                .collect::<Result<Vec<_>, _>>()?
        }
        Visibility::Groups(gs) => {
            // Empty list = nothing (fail closed). > 200 groups: one query per chunk, merged
            // newest-first, de-duplicated, cut to the overfetch size (F13).
            let mut all: Vec<MemberRow> = Vec::new();
            for chunk in gs.chunks(sql::MAX_IDS) {
                let sql_text = sql::expand_ids(MEMBERSHIPS_LIST_GROUPS, chunk.len())?;
                let mut q = sql::dynamic(sql_text).bind(tid).bind(after);
                for g in chunk {
                    q = q.bind(g.0);
                }
                let rows = tx.inner.fetch_all(q.bind(limit)).await?;
                for r in &rows {
                    all.push(map_row(tx, r)?);
                }
            }
            all.sort_by_key(|m| std::cmp::Reverse(m.id.0));
            all.dedup_by(|a, b| a.id == b.id);
            all.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            all
        }
    };
    keyset::finish(mapped, page, cursor_key, |m| (m.created_at, m.id.0))
}

/// Active owners under `FOR UPDATE` (caller already holds the tenant mutex).
async fn active_owner_count(tx: &mut TenantTx) -> Result<u32, DbError> {
    let tid = tx.tid();
    let rows = tx
        .inner
        .fetch_all(sql::q(MEMBERSHIPS_ACTIVE_OWNERS_FOR_UPDATE).bind(tid))
        .await?;
    u32::try_from(rows.len()).map_err(|_| DbError::Corrupt("owner count"))
}

async fn update_directory(
    tx: &mut TenantTx,
    m: &MemberRow,
    status: MembershipStatus,
    role: TenantRole,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    let tid = tx.tid();
    tx.inner
        .execute(
            sql::q(MEMBERSHIP_DIRECTORY_UPDATE)
                .bind(status.as_str())
                .bind(role.as_str())
                .bind(now)
                .bind(m.user_id.0)
                .bind(tid),
        )
        .await?
        .expect_one()
}

/// Change a member's role. Tenant row mutex -> target row -> active owners (all `FOR UPDATE`) ->
/// `domain::check_last_owner` -> update (+authz_version) -> directory -> epoch bump.
///
/// # Errors
/// `NotFound`, `LastOwner`, `NotPersisted`, server errors.
pub async fn set_role(
    tx: &mut TenantTx,
    id: MembershipId,
    role: TenantRole,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    tenants::lock_own(tx).await?;
    let target = get_for_update(tx, id).await?;
    if target.role == role {
        return Ok(());
    }
    let owners = active_owner_count(tx).await?;
    check_last_owner(&target.as_state(), OwnerChange::Demote { to: role }, owners)
        .map_err(|_| DbError::LastOwner)?;
    let tid = tx.tid();
    tx.inner
        .execute(
            sql::q(MEMBERSHIPS_SET_ROLE)
                .bind(role.as_str())
                .bind(role.rank())
                .bind(now)
                .bind(tid)
                .bind(id.0),
        )
        .await?
        .expect_one()?;
    update_directory(tx, &target, target.status, role, now).await?;
    bump_epoch(tx, now).await
}

/// Enable (`Active`) or disable (`Disabled`) a member. Disable runs the last-owner rule under the
/// tenant mutex; enable takes a quota slot. Counters and epoch in the same tx.
///
/// # Errors
/// `Invalid` (other target statuses: delete/invite flows are Phase 1), `NotFound`, `LastOwner`,
/// `QuotaExceeded`, `NotPersisted`, server errors.
pub async fn set_status(
    tx: &mut TenantTx,
    id: MembershipId,
    status: MembershipStatus,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    if !matches!(
        status,
        MembershipStatus::Active | MembershipStatus::Disabled
    ) {
        return Err(DbError::Invalid("set_status supports active/disabled only"));
    }
    // Lock order: tenant -> quota (only when enabling) -> entity -> counters.
    tenants::lock_own(tx).await?;
    let tenant = tx.tenant();
    let quotas = if status == MembershipStatus::Active {
        Some(lock_quotas(&mut tx.inner, tenant).await?)
    } else {
        None
    };
    let target = get_for_update(tx, id).await?;
    if target.status == status {
        return Ok(());
    }
    let was_active = target.status == MembershipStatus::Active;
    if status == MembershipStatus::Disabled {
        let owners = active_owner_count(tx).await?;
        check_last_owner(&target.as_state(), OwnerChange::Disable, owners)
            .map_err(|_| DbError::LastOwner)?;
    } else if let Some(q) = &quotas {
        check_member_slot(&mut tx.inner, tenant, q).await?;
    }
    let disabled_at = (status == MembershipStatus::Disabled).then_some(now);
    let tid = tx.tid();
    tx.inner
        .execute(
            sql::q(MEMBERSHIPS_SET_STATUS)
                .bind(status.as_str())
                .bind(disabled_at)
                .bind(now)
                .bind(tid)
                .bind(id.0),
        )
        .await?
        .expect_one()?;
    let delta = match (was_active, status == MembershipStatus::Active) {
        (true, false) => -1,
        (false, true) => 1,
        _ => 0,
    };
    if delta != 0 {
        counters::add(&mut tx.inner, tenant, Counter::Members, delta, now).await?;
    }
    update_directory(tx, &target, status, target.role, now).await?;
    bump_epoch(tx, now).await
}
