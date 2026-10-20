//! Account state changes that the auth live checks depend on (RBAC.md §6.3, §6.4).
//!
//! Every function here is authz-affecting and bumps the affected tenant epochs in the same tx, so
//! cached principals on every instance are invalidated (DATABASE.md §4.4).
//!
//! Review note: `set_tenant_status` runs on `SystemTx` until `PlatformTx` takes a verified staff
//! grant (db staff-grant change); the platform endpoint must move it to `PlatformTx`.

use crate::error::DbError;
use crate::queries::AUTHZ_EPOCHS_BUMP;
use crate::sql;
use crate::tx::{IdentityTx, SystemTx};
use crate::write_guard::WriteOutcome;
use common::{TenantId, UserId};
use time::OffsetDateTime;

use crate::repo::users::UserStatus;

const MARK_EMAIL_VERIFIED: &str =
    include_str!("../../queries/auth_account/mark_email_verified.sql");
const SET_USER_STATUS: &str = include_str!("../../queries/auth_account/set_user_status.sql");
const BUMP_EPOCHS_OF_USER: &str =
    include_str!("../../queries/auth_account/bump_epochs_of_user.sql");
const REVOKE_USER_SESSIONS: &str =
    include_str!("../../queries/auth_account/revoke_user_sessions.sql");
const REVOKE_USER_REFRESH: &str =
    include_str!("../../queries/auth_account/revoke_user_refresh.sql");
const SET_TENANT_STATUS: &str = include_str!("../../queries/auth_account/set_tenant_status.sql");

/// Tenant status values (`tenants.status`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantStatus {
    Active,
    Suspended,
    Closed,
    Erased,
}

impl TenantStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Closed => "closed",
            Self::Erased => "erased",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Active, Self::Suspended, Self::Closed, Self::Erased]
            .into_iter()
            .find(|v| v.as_str() == s)
    }
}

/// Email verification (verify-link flow, legacy import, staff).
///
/// # Errors
/// `NotPersisted` (unknown/erased user), server errors.
pub async fn mark_email_verified(
    tx: &mut IdentityTx,
    user: UserId,
    source: &'static str,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    tx.inner
        .execute(
            sql::q(MARK_EMAIL_VERIFIED)
                .bind(now)
                .bind(source)
                .bind(now)
                .bind(user.0),
        )
        .await?
        .expect_one()?;
    tx.inner
        .execute(sql::q(BUMP_EPOCHS_OF_USER).bind(now).bind(user.0))
        .await?;
    Ok(())
}

/// Change a user's global status. Any non-active status also moves `tokens_valid_after` to `now`
/// and revokes every session and refresh token of the user in the SAME tx, so a later reactivation
/// never brings old tokens back. Epochs of all the user's tenants +1.
///
/// # Errors
/// `NotPersisted`, server errors.
pub async fn set_user_status(
    tx: &mut IdentityTx,
    user: UserId,
    status: UserStatus,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    let valid_after = (status != UserStatus::Active).then_some(now);
    tx.inner
        .execute(
            sql::q(SET_USER_STATUS)
                .bind(status.as_str())
                .bind(valid_after)
                .bind(now)
                .bind(user.0),
        )
        .await?
        .expect_one()?;
    if status != UserStatus::Active {
        tx.inner
            .execute(sql::q(REVOKE_USER_REFRESH).bind(now).bind(user.0))
            .await?;
        tx.inner
            .execute(
                sql::q(REVOKE_USER_SESSIONS)
                    .bind(now)
                    .bind("account_status")
                    .bind(user.0),
            )
            .await?;
    }
    tx.inner
        .execute(sql::q(BUMP_EPOCHS_OF_USER).bind(now).bind(user.0))
        .await?;
    Ok(())
}

/// Suspend / reactivate / close a tenant, + epoch bump (same tx).
///
/// # Errors
/// `NotPersisted` (unknown tenant or missing epoch row), server errors.
pub async fn set_tenant_status(
    tx: &mut SystemTx,
    tenant: TenantId,
    status: TenantStatus,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    tx.inner
        .execute(
            sql::q(SET_TENANT_STATUS)
                .bind(status.as_str())
                .bind(now)
                .bind(tenant.0),
        )
        .await?
        .expect_one()?;
    tx.inner
        .execute(sql::q(AUTHZ_EPOCHS_BUMP).bind(now).bind(tenant.0))
        .await?
        .expect_one()
}
