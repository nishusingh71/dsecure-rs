//! Identity-class repos: `users`, `user_credentials`, `membership_directory` (login: user -> tenants).

use crate::error::DbError;
use crate::queries::{
    MEMBERSHIP_DIRECTORY_BY_USER, USER_CREDENTIALS_GET, USER_CREDENTIALS_UPSERT,
    USERS_FIND_BY_EMAIL_BIDX, USERS_GET, USERS_INSERT,
};
use crate::repo::memberships::MembershipStatus;
use crate::sql;
use crate::tx::IdentityTx;
use crate::write_guard::WriteOutcome;
use common::{MembershipId, TenantId, UserId};
use domain::rbac::TenantRole;
use sqlx::mysql::MySqlRow;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserStatus {
    PendingVerification,
    Active,
    Suspended,
    Disabled,
    Erased,
}

impl UserStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingVerification => "pending_verification",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Disabled => "disabled",
            Self::Erased => "erased",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::PendingVerification,
            Self::Active,
            Self::Suspended,
            Self::Disabled,
            Self::Erased,
        ]
        .into_iter()
        .find(|v| v.as_str() == s)
    }
}

#[derive(Clone, Debug)]
pub struct NewUser {
    pub id: UserId,
    pub email_bidx: [u8; 32],
    pub email_enc: Vec<u8>,
    pub name_enc: Option<Vec<u8>>,
    pub status: UserStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRow {
    pub id: UserId,
    pub email_bidx: Vec<u8>,
    pub email_enc: Vec<u8>,
    pub name_enc: Option<Vec<u8>>,
    pub status: UserStatus,
    pub email_verified_at: Option<OffsetDateTime>,
    pub authz_version: u64,
    pub tokens_valid_after: Option<OffsetDateTime>,
    pub version: u32,
    pub created_at: OffsetDateTime,
}

fn map_user(row: &MySqlRow) -> Result<UserRow, DbError> {
    let status: String = sql::col(row, "status")?;
    Ok(UserRow {
        id: UserId(sql::uuid_col(row, "id")?),
        email_bidx: sql::col(row, "email_bidx")?,
        email_enc: sql::col(row, "email_enc")?,
        name_enc: sql::col(row, "name_enc")?,
        status: UserStatus::parse(&status).ok_or(DbError::Corrupt("users.status"))?,
        email_verified_at: sql::col(row, "email_verified_at")?,
        authz_version: sql::col(row, "authz_version")?,
        tokens_valid_after: sql::col(row, "tokens_valid_after")?,
        version: sql::col(row, "version")?,
        created_at: sql::col(row, "created_at")?,
    })
}

/// # Errors
/// `Conflict("users.email_taken")`, `Conflict("users.id_taken")`, server errors.
pub async fn insert(
    tx: &mut IdentityTx,
    u: &NewUser,
    now: OffsetDateTime,
) -> Result<UserId, DbError> {
    let r = tx
        .inner
        .execute(
            sql::q(USERS_INSERT)
                .bind(u.id.0)
                .bind(&u.email_bidx[..])
                .bind(u.email_enc.as_slice())
                .bind(u.name_enc.as_deref())
                .bind(u.status.as_str())
                .bind(now)
                .bind(now),
        )
        .await;
    match r {
        Ok(n) => n.expect_one()?,
        Err(e) if e.is_duplicate_of("ux_users_email_bidx") => {
            return Err(DbError::Conflict("users.email_taken"));
        }
        Err(e) if e.is_duplicate_of("PRIMARY") => return Err(DbError::Conflict("users.id_taken")),
        Err(e) => return Err(e),
    }
    Ok(u.id)
}

/// # Errors
/// Server / decode errors.
pub async fn get(tx: &mut IdentityTx, id: UserId) -> Result<Option<UserRow>, DbError> {
    tx.inner
        .fetch_optional(sql::q(USERS_GET).bind(id.0))
        .await?
        .as_ref()
        .map(map_user)
        .transpose()
}

/// # Errors
/// Server / decode errors.
pub async fn find_by_email_bidx(
    tx: &mut IdentityTx,
    email_bidx: &[u8; 32],
) -> Result<Option<UserRow>, DbError> {
    tx.inner
        .fetch_optional(sql::q(USERS_FIND_BY_EMAIL_BIDX).bind(&email_bidx[..]))
        .await?
        .as_ref()
        .map(map_user)
        .transpose()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashScheme {
    Argon2id,
    BcryptLegacy,
}

impl HashScheme {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Argon2id => "argon2id",
            Self::BcryptLegacy => "bcrypt_legacy",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRow {
    pub user_id: UserId,
    pub password_hash: String,
    pub hash_scheme: String,
    pub failed_attempts: i32,
    pub locked_until: Option<OffsetDateTime>,
    pub version: u32,
}

impl std::fmt::Debug for CredentialRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialRow")
            .field("user_id", &self.user_id)
            .field("hash_scheme", &self.hash_scheme)
            .finish_non_exhaustive()
    }
}

/// Insert or replace the password hash (PHC string) and reset lockout counters.
///
/// # Errors
/// `NotPersisted`, server errors (FK on MySQL CI if the user does not exist).
pub async fn set_password(
    tx: &mut IdentityTx,
    user: UserId,
    phc: &str,
    scheme: HashScheme,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    let n = tx
        .inner
        .execute(
            sql::q(USER_CREDENTIALS_UPSERT)
                .bind(user.0)
                .bind(phc)
                .bind(scheme.as_str())
                .bind(now),
        )
        .await?;
    // ON DUPLICATE KEY UPDATE: 1 = inserted, 2 = updated (CLIENT_FOUND_ROWS).
    if n == 1 || n == 2 {
        Ok(())
    } else {
        Err(DbError::NotPersisted {
            expected: 1,
            actual: n,
        })
    }
}

/// # Errors
/// Server / decode errors.
pub async fn credentials(
    tx: &mut IdentityTx,
    user: UserId,
) -> Result<Option<CredentialRow>, DbError> {
    let Some(row) = tx
        .inner
        .fetch_optional(sql::q(USER_CREDENTIALS_GET).bind(user.0))
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(CredentialRow {
        user_id: UserId(sql::uuid_col(&row, "user_id")?),
        password_hash: sql::col(&row, "password_hash")?,
        hash_scheme: sql::col(&row, "hash_scheme")?,
        failed_attempts: sql::col(&row, "failed_attempts")?,
        locked_until: sql::col(&row, "locked_until")?,
        version: sql::col(&row, "version")?,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub tenant: TenantId,
    pub membership: MembershipId,
    pub status: MembershipStatus,
    pub role: TenantRole,
}

/// Tenants of a user (login tenant picker). Bounded to 200.
///
/// # Errors
/// Server / decode errors.
pub async fn memberships_of(
    tx: &mut IdentityTx,
    user: UserId,
) -> Result<Vec<DirectoryEntry>, DbError> {
    let rows = tx
        .inner
        .fetch_all(sql::q(MEMBERSHIP_DIRECTORY_BY_USER).bind(user.0))
        .await?;
    rows.iter()
        .map(|r| {
            let status: String = sql::col(r, "status")?;
            let role: String = sql::col(r, "role")?;
            if UserId(sql::uuid_col(r, "user_id")?) != user {
                return Err(DbError::Corrupt("membership_directory.user_id"));
            }
            Ok(DirectoryEntry {
                tenant: TenantId(sql::uuid_col(r, "tenant_id")?),
                membership: MembershipId(sql::uuid_col(r, "membership_id")?),
                status: MembershipStatus::parse(&status)
                    .ok_or(DbError::Corrupt("membership_directory.status"))?,
                role: TenantRole::parse(&role)
                    .ok_or(DbError::Corrupt("membership_directory.role"))?,
            })
        })
        .collect()
}
