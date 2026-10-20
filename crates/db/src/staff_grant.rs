//! Staff access grants (DATABASE.md §4 `staff_access_grants`, RBAC.md platform staff).
//!
//! [`verify`] / `verify_inner` is the ONLY caller of
//! `domain::rbac::VerifiedStaffGrant::__from_verified_grant`. It checks, on the latest committed row
//! (non-locking, first read of the tx): grant exists, not closed, not expired, for `tenant`, owned by `staff_user`, the staff
//! membership is not revoked; and it carries the grant SCOPE (`read` / `support_write`). Every staff
//! transaction (`Db::tenant_tx_for_staff`, `Db::platform_tx`) re-runs it inside its own tx.
//!
//! The read is NON-locking: the app user has only SELECT on the staff tables (a `FOR UPDATE` there is
//! refused with 1142), and `FOR SHARE` is not used because TiDB treats shared locks as noop/error
//! (DATABASE.md §1.1). As the first statement of the tx it reads the latest committed row; a grant
//! closed after that is honoured from the next tx on (window <= `DB_TX_TIMEOUT_MS`).
//!
//! Creating staff and grants (review R1) is NOT possible with the app DB user (no INSERT on
//! `platform_staff` / `staff_access_grants`): it needs a [`crate::platform_admin::PlatformAdminTx`]
//! (platform-admin DB user, verified approver with the right platform permission, audit row in the
//! same transaction).

use crate::error::DbError;
use crate::platform_admin::PlatformAdminTx;
use crate::queries::{
    PLATFORM_STAFF_GET_FOR_UPDATE, PLATFORM_STAFF_INSERT, STAFF_ACCESS_GRANTS_CLOSE,
    STAFF_ACCESS_GRANTS_GET_CURRENT, STAFF_ACCESS_GRANTS_INSERT, TENANTS_EXISTS_ACTIVE,
};
use crate::sql;
use crate::tx::{Inner, SystemTx};
use crate::write_guard::WriteOutcome;
use common::{GrantId, TenantId, UserId};
use domain::rbac::{PlatformPerm, StaffRole, VerifiedStaffGrant};
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantScope {
    /// Read tenant data only: the staff tenant tx refuses every write.
    Read,
    /// Support writes allowed.
    SupportWrite,
}

impl GrantScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::SupportWrite => "support_write",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "support_write" => Some(Self::SupportWrite),
            _ => None,
        }
    }
}

/// A grant verified by the db layer. Not constructible outside `db`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedGrant {
    proof: VerifiedStaffGrant,
    staff_user: UserId,
    tenant: TenantId,
    grant: GrantId,
    role: StaffRole,
    scope: GrantScope,
    expires_at: OffsetDateTime,
}

impl VerifiedGrant {
    /// Domain proof (for `StaffScope::new`).
    #[must_use]
    pub const fn proof(&self) -> &VerifiedStaffGrant {
        &self.proof
    }
    #[must_use]
    pub const fn staff_user(&self) -> UserId {
        self.staff_user
    }
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn grant(&self) -> GrantId {
        self.grant
    }
    #[must_use]
    pub const fn role(&self) -> StaffRole {
        self.role
    }
    #[must_use]
    pub const fn scope(&self) -> GrantScope {
        self.scope
    }
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

pub(crate) async fn verify_inner(
    inner: &mut Inner,
    staff_user: UserId,
    grant: GrantId,
    tenant: TenantId,
    now: OffsetDateTime,
) -> Result<VerifiedGrant, DbError> {
    let row = inner
        .fetch_optional(sql::q(STAFF_ACCESS_GRANTS_GET_CURRENT).bind(grant.0))
        .await?
        .ok_or(DbError::Forbidden("staff grant not valid"))?;
    let row_staff = UserId(sql::uuid_col(&row, "staff_user_id")?);
    let row_tenant = TenantId(sql::uuid_col(&row, "tenant_id")?);
    let expires_at: OffsetDateTime = sql::col(&row, "expires_at")?;
    let closed_at: Option<OffsetDateTime> = sql::col(&row, "closed_at")?;
    let revoked_at: Option<OffsetDateTime> = sql::col(&row, "revoked_at")?;
    let role: String = sql::col(&row, "role")?;
    let scope: String = sql::col(&row, "scope")?;
    // Same NotFound for every failure: no oracle about which check failed.
    if row_tenant == crate::PLATFORM_TENANT_ID
        || row_staff != staff_user
        || row_tenant != tenant
        || closed_at.is_some()
        || revoked_at.is_some()
        || expires_at <= now
    {
        return Err(DbError::Forbidden("staff grant not valid"));
    }
    let role = StaffRole::parse(&role).ok_or(DbError::Corrupt("platform_staff.role"))?;
    // Unknown scope value = corrupt row, refused (never widened to write).
    let scope = GrantScope::parse(&scope).ok_or(DbError::Corrupt("staff_access_grants.scope"))?;
    Ok(VerifiedGrant {
        proof: VerifiedStaffGrant::__from_verified_grant(role, tenant, grant),
        staff_user,
        tenant,
        grant,
        role,
        scope,
        expires_at,
    })
}

/// Verify a staff access grant (see module docs).
///
/// # Errors
/// `Forbidden("staff grant not valid")` (403) for unknown/closed/expired/other-tenant/other-staff
/// grants (one answer for all: no oracle).
pub async fn verify(
    tx: &mut SystemTx,
    staff_user: UserId,
    grant: GrantId,
    tenant: TenantId,
    now: OffsetDateTime,
) -> Result<VerifiedGrant, DbError> {
    verify_inner(&mut tx.inner, staff_user, grant, tenant, now).await
}

/// Active (not revoked) staff role of `user`, locked for the rest of the tx.
pub(crate) async fn active_staff_role(
    inner: &mut Inner,
    user: UserId,
) -> Result<Option<StaffRole>, DbError> {
    let Some(row) = inner
        .fetch_optional(sql::q(PLATFORM_STAFF_GET_FOR_UPDATE).bind(user.0))
        .await?
    else {
        return Ok(None);
    };
    let revoked: Option<OffsetDateTime> = sql::col(&row, "revoked_at")?;
    if revoked.is_some() {
        return Ok(None);
    }
    let role: String = sql::col(&row, "role")?;
    Ok(Some(
        StaffRole::parse(&role).ok_or(DbError::Corrupt("platform_staff.role"))?,
    ))
}

/// Register a platform staff member. Approver must hold `platform.staff.manage`.
///
/// # Errors
/// `Forbidden`, `Conflict("staff.exists")`, server errors.
pub async fn insert_staff(
    tx: &mut PlatformAdminTx,
    user: UserId,
    role: StaffRole,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    tx.require(PlatformPerm::StaffManage)?;
    let approver = tx.approver().user();
    match tx
        .inner
        .execute(
            sql::q(PLATFORM_STAFF_INSERT)
                .bind(user.0)
                .bind(role.as_str())
                .bind(Some(approver.0))
                .bind(now),
        )
        .await
    {
        Ok(n) => n.expect_one(),
        Err(e) if e.is_duplicate_of("PRIMARY") => Err(DbError::Conflict("staff.exists")),
        Err(e) => Err(e),
    }
}

/// Open a time-boxed grant for `staff_user` on `tenant`. Approver must hold
/// `platform.staff_access.open` (ticket mandatory when the matrix says so); target must be active
/// staff; tenant must be an active real tenant.
///
/// # Errors
/// `Forbidden`, `Invalid`, `NotFound`, server errors.
#[allow(clippy::too_many_arguments)]
pub async fn open_grant(
    tx: &mut PlatformAdminTx,
    staff_user: UserId,
    tenant: TenantId,
    reason: &str,
    ticket_ref: Option<&str>,
    scope: GrantScope,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<GrantId, DbError> {
    let g = tx.require(PlatformPerm::StaffAccessOpen)?;
    if g.ticket_required && ticket_ref.is_none_or(|t| t.trim().is_empty()) {
        return Err(DbError::Invalid("ticket reference required"));
    }
    if reason.trim().is_empty() || reason.len() > 500 {
        return Err(DbError::Invalid("grant reason must be 1..=500 bytes"));
    }
    if expires_at <= now {
        return Err(DbError::Invalid("grant must expire in the future"));
    }
    if tenant == crate::PLATFORM_TENANT_ID
        || !tx
            .inner
            .exists(sql::q(TENANTS_EXISTS_ACTIVE).bind(tenant.0))
            .await?
    {
        return Err(DbError::NotFound("tenant"));
    }
    if active_staff_role(&mut tx.inner, staff_user)
        .await?
        .is_none()
    {
        return Err(DbError::NotFound("staff"));
    }
    let id = GrantId::new();
    tx.inner
        .execute(
            sql::q(STAFF_ACCESS_GRANTS_INSERT)
                .bind(id.0)
                .bind(staff_user.0)
                .bind(tenant.0)
                .bind(reason)
                .bind(ticket_ref)
                .bind(scope.as_str())
                .bind(now)
                .bind(expires_at),
        )
        .await?
        .expect_one()?;
    Ok(id)
}

/// Close a grant early (approver with `platform.staff_access.open`).
///
/// # Errors
/// `Forbidden`, `NotPersisted` (unknown/already closed), server errors.
pub async fn close_grant(
    tx: &mut PlatformAdminTx,
    grant: GrantId,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    tx.require(PlatformPerm::StaffAccessOpen)?;
    tx.inner
        .execute(sql::q(STAFF_ACCESS_GRANTS_CLOSE).bind(now).bind(grant.0))
        .await?
        .expect_one()
}
