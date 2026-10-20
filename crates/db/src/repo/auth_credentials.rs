//! Login credential bookkeeping for `auth` (lockout counter, rehash). Identity class.

use crate::error::DbError;
use crate::sql;
use crate::tx::IdentityTx;
use crate::write_guard::WriteOutcome;
use common::UserId;
use time::OffsetDateTime;

use crate::repo::users::HashScheme;

const GET_FOR_UPDATE: &str = include_str!("../../queries/auth_credentials/get_for_update.sql");
const RECORD_FAILURE: &str = include_str!("../../queries/auth_credentials/record_failure.sql");
const RESET_FAILURES: &str = include_str!("../../queries/auth_credentials/reset_failures.sql");
const REHASH: &str = include_str!("../../queries/auth_credentials/rehash.sql");

/// Lockout columns + current hash of `user_credentials` (row locked by [`lockout_for_update`]).
/// `Debug` never prints the hash.
#[derive(Clone, PartialEq, Eq)]
pub struct LockoutRow {
    pub user_id: UserId,
    pub password_hash: String,
    pub failed_attempts: i32,
    pub last_failed_at: Option<OffsetDateTime>,
    pub locked_until: Option<OffsetDateTime>,
}

impl std::fmt::Debug for LockoutRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockoutRow")
            .field("user_id", &self.user_id)
            .field("failed_attempts", &self.failed_attempts)
            .finish_non_exhaustive()
    }
}

/// Lock the credential row and read its lockout counters (`SELECT ... FOR UPDATE`).
///
/// # Errors
/// Server / decode errors.
pub async fn lockout_for_update(
    tx: &mut IdentityTx,
    user: UserId,
) -> Result<Option<LockoutRow>, DbError> {
    let Some(row) = tx
        .inner
        .fetch_optional(sql::q(GET_FOR_UPDATE).bind(user.0))
        .await?
    else {
        return Ok(None);
    };
    let id = UserId(sql::uuid_col(&row, "user_id")?);
    if id != user {
        return Err(DbError::Corrupt("user_credentials.user_id"));
    }
    Ok(Some(LockoutRow {
        user_id: id,
        password_hash: sql::col(&row, "password_hash")?,
        failed_attempts: sql::col(&row, "failed_attempts")?,
        last_failed_at: sql::col(&row, "last_failed_at")?,
        locked_until: sql::col(&row, "locked_until")?,
    }))
}

/// Store a failed attempt (values computed by `auth::lockout` from the locked row).
///
/// # Errors
/// `NotPersisted`, server errors.
pub async fn record_failure(
    tx: &mut IdentityTx,
    user: UserId,
    failed_attempts: i32,
    last_failed_at: OffsetDateTime,
    locked_until: Option<OffsetDateTime>,
) -> Result<(), DbError> {
    tx.inner
        .execute(
            sql::q(RECORD_FAILURE)
                .bind(failed_attempts)
                .bind(last_failed_at)
                .bind(locked_until)
                .bind(user.0),
        )
        .await?
        .expect_one()
}

/// Successful login: counters back to zero.
///
/// # Errors
/// `NotPersisted`, server errors.
pub async fn reset_failures(tx: &mut IdentityTx, user: UserId) -> Result<(), DbError> {
    tx.inner
        .execute(sql::q(RESET_FAILURES).bind(user.0))
        .await?
        .expect_one()
}

/// Replace `old_hash` with `new_hash` (compare-and-swap). `false` = the stored hash changed meanwhile
/// (password change raced the login): nothing written.
///
/// # Errors
/// Server errors.
pub async fn rehash(
    tx: &mut IdentityTx,
    user: UserId,
    old_hash: &str,
    new_hash: &str,
    scheme: HashScheme,
) -> Result<bool, DbError> {
    let n = tx
        .inner
        .execute(
            sql::q(REHASH)
                .bind(new_hash)
                .bind(scheme.as_str())
                .bind(user.0)
                .bind(old_hash),
        )
        .await?;
    Ok(n == 1)
}
