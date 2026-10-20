//! Principal live state for the `auth` crate (PHASE0_SPEC §3.4 `PrincipalStateLoader`, RBAC.md §6.3).
//!
//! These reads run BEFORE an authz decision exists, so they cannot use `TenantTx` (which needs a
//! `TenantScope` built from a decision). Instead the tenant / membership / session ids come from a
//! **verified access token** (signature, audience, expiry checked by `auth`), and every tenant-class
//! table is still addressed by a tenant-leading key with `tenant_id = ?` bound from those claims.
//! Rule: only `auth::PrincipalStateLoader` / `auth::AuthService` call this module.
//!
//! Each loader is ONE statement (indexed point gets + small tenant-leading subqueries).

use crate::error::DbError;
use crate::sql;
use crate::tx::IdentityTx;
use common::{DeviceId, GroupId, MembershipId, SessionId, TenantId, UserId};
use domain::rbac::{GroupIds, TenantRole};
use sqlx::mysql::MySqlRow;
use time::OffsetDateTime;

use crate::repo::memberships::MembershipStatus;
use crate::repo::users::UserStatus;

const MEMBER_LIVE: &str = include_str!("../../queries/auth_state/member_live.sql");
const STAFF_LIVE: &str = include_str!("../../queries/auth_state/staff_live.sql");
const DEVICE_LIVE: &str = include_str!("../../queries/auth_state/device_live.sql");
const REVOKE_SESSION_REFRESH: &str =
    include_str!("../../queries/auth_state/revoke_session_refresh.sql");
const BUMP_EPOCH_OF_SESSION: &str =
    include_str!("../../queries/auth_state/bump_epoch_of_session.sql");
const TOUCH_SESSION: &str = include_str!("../../queries/auth_state/touch_session.sql");
const MARK_SESSION_MFA: &str = include_str!("../../queries/auth_state/mark_session_mfa.sql");

/// Upper bound of group ids per member carried in the principal (GROUP_CONCAT default max length is
/// 1024 bytes = 31 ids). A longer list is detected via the COUNT columns and fails closed.
pub const MAX_GROUPS_IN_PRINCIPAL: usize = 31;

/// `membership_capabilities` row (absent = role defaults, decided by `auth`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityRow {
    pub can_view_reports: bool,
    pub can_manage_machines: bool,
    pub can_assign_licenses: bool,
    pub max_machines: Option<i32>,
}

/// Session columns relevant for the live check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionLive {
    pub id: SessionId,
    pub principal_kind: String,
    pub client_kind: String,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub mfa_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
}

/// User columns relevant for the live check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserLive {
    pub status: UserStatus,
    pub email_verified_at: Option<OffsetDateTime>,
    pub authz_version: u64,
    pub tokens_valid_after: Option<OffsetDateTime>,
}

/// Live state of a member principal (one statement).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberLiveRow {
    pub session: SessionLive,
    pub user: UserLive,
    pub tenant: TenantId,
    pub membership: MembershipId,
    pub role: TenantRole,
    pub membership_status: MembershipStatus,
    pub membership_authz_version: u64,
    /// `tenants.status` raw value (`active|suspended|closed|erased`).
    pub tenant_status: String,
    /// `None` = epoch row missing (broken bootstrap): caller must never cache.
    pub epoch: Option<u64>,
    pub caps: Option<CapabilityRow>,
    pub groups: GroupIds,
    pub ga_groups: GroupIds,
    /// Enabled feature names (`tenant_features.feature` where enabled).
    pub features: Vec<String>,
}

/// Live state of a staff principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaffLiveRow {
    pub session: SessionLive,
    pub user: UserLive,
    /// `platform_staff.role` raw value.
    pub staff_role: String,
    pub staff_revoked_at: Option<OffsetDateTime>,
}

/// Live state of a device principal: credential + operator membership (one statement).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLiveRow {
    pub tenant: TenantId,
    pub credential_id: uuid::Uuid,
    pub device: DeviceId,
    pub operator: MembershipId,
    pub product_code: String,
    /// Space separated scope codes.
    pub scopes: String,
    pub credential_revoked_at: Option<OffsetDateTime>,
    pub tenant_status: String,
    pub epoch: Option<u64>,
    pub operator_role: TenantRole,
    pub operator_status: MembershipStatus,
    pub operator_authz_version: u64,
    pub operator_user_status: UserStatus,
    pub operator_email_verified_at: Option<OffsetDateTime>,
    pub caps: Option<CapabilityRow>,
    pub groups: GroupIds,
    pub ga_groups: GroupIds,
    pub features: Vec<String>,
}

fn opt_text(row: &MySqlRow, name: &'static str) -> Result<Option<String>, DbError> {
    let raw: Option<Vec<u8>> = sql::col(row, name)?;
    raw.map(|b| String::from_utf8(b).map_err(|_| DbError::Corrupt(name)))
        .transpose()
}

fn group_list(
    row: &MySqlRow,
    list: &'static str,
    count: &'static str,
) -> Result<GroupIds, DbError> {
    let n: i64 = sql::col(row, count)?;
    let text = opt_text(row, list)?.unwrap_or_default();
    let mut out = GroupIds::new();
    for part in text.split(',').filter(|p| !p.is_empty()) {
        let id = uuid::Uuid::try_parse(part).map_err(|_| DbError::Corrupt(list))?;
        out.push(GroupId(id));
    }
    // GROUP_CONCAT truncation (or a concurrent change between subqueries) = fail closed.
    if i64::try_from(out.len()).ok() != Some(n) || out.len() > MAX_GROUPS_IN_PRINCIPAL {
        return Err(DbError::Corrupt("principal group list incomplete"));
    }
    Ok(out)
}

fn features(row: &MySqlRow) -> Result<Vec<String>, DbError> {
    Ok(opt_text(row, "features")?
        .unwrap_or_default()
        .split(',')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect())
}

fn caps(row: &MySqlRow) -> Result<Option<CapabilityRow>, DbError> {
    let view: Option<bool> = sql::col(row, "can_view_reports")?;
    let Some(can_view_reports) = view else {
        return Ok(None);
    };
    Ok(Some(CapabilityRow {
        can_view_reports,
        can_manage_machines: sql::col::<Option<bool>>(row, "can_manage_machines")?.unwrap_or(false),
        can_assign_licenses: sql::col::<Option<bool>>(row, "can_assign_licenses")?.unwrap_or(false),
        max_machines: sql::col(row, "max_machines")?,
    }))
}

fn session_live(row: &MySqlRow) -> Result<SessionLive, DbError> {
    Ok(SessionLive {
        id: SessionId(sql::uuid_col(row, "session_id")?),
        principal_kind: sql::col(row, "principal_kind")?,
        client_kind: sql::col(row, "client_kind")?,
        expires_at: sql::col(row, "session_expires_at")?,
        revoked_at: sql::col(row, "session_revoked_at")?,
        mfa_at: sql::col(row, "mfa_at")?,
        created_at: sql::col(row, "session_created_at")?,
        last_seen_at: sql::col(row, "session_last_seen_at")?,
    })
}

fn user_status(row: &MySqlRow, name: &'static str) -> Result<UserStatus, DbError> {
    let s: String = sql::col(row, name)?;
    UserStatus::parse(&s).ok_or(DbError::Corrupt("users.status"))
}

fn user_live(row: &MySqlRow) -> Result<UserLive, DbError> {
    Ok(UserLive {
        status: user_status(row, "user_status")?,
        email_verified_at: sql::col(row, "email_verified_at")?,
        authz_version: sql::col(row, "user_authz_version")?,
        tokens_valid_after: sql::col(row, "tokens_valid_after")?,
    })
}

fn role(row: &MySqlRow) -> Result<TenantRole, DbError> {
    let r: String = sql::col(row, "role")?;
    TenantRole::parse(&r).ok_or(DbError::Corrupt("memberships.role"))
}

fn membership_status(row: &MySqlRow) -> Result<MembershipStatus, DbError> {
    let s: String = sql::col(row, "membership_status")?;
    MembershipStatus::parse(&s).ok_or(DbError::Corrupt("memberships.status"))
}

/// Member principal live state. `None` = no such session for this user/tenant/membership.
///
/// # Errors
/// `TenantMismatch` (row tenant differs from the claimed tenant), `Corrupt`, server errors.
pub async fn member_live(
    tx: &mut IdentityTx,
    session: SessionId,
    user: UserId,
    tenant: TenantId,
    membership: MembershipId,
) -> Result<Option<MemberLiveRow>, DbError> {
    let t = tenant.0;
    let Some(row) = tx
        .inner
        .fetch_optional(
            sql::q(MEMBER_LIVE)
                .bind(t)
                .bind(t)
                .bind(t)
                .bind(t)
                .bind(t)
                .bind(t)
                .bind(t)
                .bind(session.0)
                .bind(user.0)
                .bind(t)
                .bind(membership.0),
        )
        .await?
    else {
        return Ok(None);
    };
    let row_tenant = TenantId(sql::uuid_col(&row, "tenant_id")?);
    crate::tx::assert_row_tenant(tenant, row_tenant)?;
    let row_membership = MembershipId(sql::uuid_col(&row, "membership_id")?);
    if row_membership != membership {
        return Err(DbError::Corrupt("memberships.id"));
    }
    Ok(Some(MemberLiveRow {
        session: session_live(&row)?,
        user: user_live(&row)?,
        tenant: row_tenant,
        membership: row_membership,
        role: role(&row)?,
        membership_status: membership_status(&row)?,
        membership_authz_version: sql::col(&row, "membership_authz_version")?,
        tenant_status: sql::col(&row, "tenant_status")?,
        epoch: sql::col(&row, "epoch")?,
        caps: caps(&row)?,
        groups: group_list(&row, "group_ids", "group_count")?,
        ga_groups: group_list(&row, "ga_group_ids", "ga_group_count")?,
        features: features(&row)?,
    }))
}

/// Staff principal live state. `None` = no staff session for this user (or not staff at all).
///
/// # Errors
/// `Corrupt`, server errors.
pub async fn staff_live(
    tx: &mut IdentityTx,
    session: SessionId,
    user: UserId,
) -> Result<Option<StaffLiveRow>, DbError> {
    let Some(row) = tx
        .inner
        .fetch_optional(sql::q(STAFF_LIVE).bind(session.0).bind(user.0))
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(StaffLiveRow {
        session: session_live(&row)?,
        user: user_live(&row)?,
        staff_role: sql::col(&row, "staff_role")?,
        staff_revoked_at: sql::col(&row, "staff_revoked_at")?,
    }))
}

/// Device principal live state (credential of `device` in `tenant`).
///
/// # Errors
/// `TenantMismatch`, `Corrupt`, server errors.
pub async fn device_live(
    tx: &mut IdentityTx,
    tenant: TenantId,
    credential_id: uuid::Uuid,
    device: DeviceId,
) -> Result<Option<DeviceLiveRow>, DbError> {
    let t = tenant.0;
    let Some(row) = tx
        .inner
        .fetch_optional(
            sql::q(DEVICE_LIVE)
                .bind(t)
                .bind(t)
                .bind(t)
                .bind(t)
                .bind(t)
                .bind(t)
                .bind(t)
                .bind(t)
                .bind(credential_id)
                .bind(device.0),
        )
        .await?
    else {
        return Ok(None);
    };
    let row_tenant = TenantId(sql::uuid_col(&row, "tenant_id")?);
    crate::tx::assert_row_tenant(tenant, row_tenant)?;
    let row_device = DeviceId(sql::uuid_col(&row, "device_id")?);
    if row_device != device {
        return Err(DbError::Corrupt("device_credentials.device_id"));
    }
    Ok(Some(DeviceLiveRow {
        tenant: row_tenant,
        credential_id: sql::uuid_col(&row, "credential_id")?,
        device: row_device,
        operator: MembershipId(sql::uuid_col(&row, "operator_membership_id")?),
        product_code: sql::col(&row, "product_code")?,
        scopes: sql::col(&row, "scopes")?,
        credential_revoked_at: sql::col(&row, "credential_revoked_at")?,
        tenant_status: sql::col(&row, "tenant_status")?,
        epoch: sql::col(&row, "epoch")?,
        operator_role: role(&row)?,
        operator_status: membership_status(&row)?,
        operator_authz_version: sql::col(&row, "membership_authz_version")?,
        operator_user_status: user_status(&row, "user_status")?,
        operator_email_verified_at: sql::col(&row, "email_verified_at")?,
        caps: caps(&row)?,
        groups: group_list(&row, "group_ids", "group_count")?,
        ga_groups: group_list(&row, "ga_group_ids", "ga_group_count")?,
        features: features(&row)?,
    }))
}

/// Revoke a session, every live refresh token of it, and bump the epoch of its tenant (session revoke
/// is authz-affecting, DATABASE.md §4.4). Returns `false` if the session was already revoked/unknown
/// (refresh tokens and epoch are still handled: idempotent).
///
/// # Errors
/// Server errors.
pub async fn revoke_session(
    tx: &mut IdentityTx,
    session: SessionId,
    reason: &'static str,
    now: OffsetDateTime,
) -> Result<bool, DbError> {
    let revoked = crate::repo::sessions::revoke(tx, session, reason, now).await?;
    tx.inner
        .execute(sql::q(REVOKE_SESSION_REFRESH).bind(now).bind(session.0))
        .await?;
    tx.inner
        .execute(sql::q(BUMP_EPOCH_OF_SESSION).bind(now).bind(session.0))
        .await?;
    Ok(revoked)
}

/// Idle tracking: set `last_seen_at = now` if it is older than `now - throttle` (bounded writes).
/// Returns whether a row was written.
///
/// # Errors
/// Server errors.
pub async fn touch_session(
    tx: &mut IdentityTx,
    session: SessionId,
    now: OffsetDateTime,
    throttle: time::Duration,
) -> Result<bool, DbError> {
    let n = tx
        .inner
        .execute(
            sql::q(TOUCH_SESSION)
                .bind(now)
                .bind(session.0)
                .bind(now - throttle),
        )
        .await?;
    Ok(n == 1)
}

/// Record a completed second factor on a session (MFA flow, P0-11).
///
/// # Errors
/// `NotPersisted` (unknown or revoked session), server errors.
pub async fn mark_session_mfa(
    tx: &mut IdentityTx,
    session: SessionId,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    use crate::write_guard::WriteOutcome as _;
    tx.inner
        .execute(sql::q(MARK_SESSION_MFA).bind(now).bind(session.0))
        .await?
        .expect_one()
}

/// Test fixture: make `user` platform staff without the 4-eyes `PlatformAdminTx` path.
/// Only with the `test-fixtures` feature (never in production builds).
///
/// # Errors
/// Server errors.
#[cfg(any(test, feature = "test-fixtures"))]
pub async fn testing_insert_staff(
    tx: &mut crate::tx::SystemTx,
    user: UserId,
    role: domain::rbac::StaffRole,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    use crate::write_guard::WriteOutcome as _;
    tx.inner
        .execute(
            sql::q(crate::queries::PLATFORM_STAFF_INSERT)
                .bind(user.0)
                .bind(role.as_str())
                .bind(None::<uuid::Uuid>)
                .bind(now),
        )
        .await?
        .expect_one()
}
