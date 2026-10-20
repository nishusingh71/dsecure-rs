//! MFA factors and recovery codes for `auth` (identity class; tables from set `0100`, no schema change).
//!
//! Column semantics (documented here because no migration is added):
//! - A TOTP factor is PENDING while `last_used_at IS NULL`; the confirming code sets it, so
//!   confirmed = `last_used_at IS NOT NULL AND disabled_at IS NULL`.
//! - `last_used_at` holds the START of the last accepted 30 s time step (not the wall-clock use
//!   time). [`use_step`] accepts a code only for a strictly later step in one atomic UPDATE: replay
//!   protection without a read-modify-write race.
//! - Recovery codes: only an HMAC is stored; [`use_recovery`] is single use (atomic UPDATE).

use crate::error::DbError;
use crate::sql;
use crate::tx::IdentityTx;
use crate::write_guard::WriteOutcome;
use common::UserId;
use time::OffsetDateTime;

const INSERT_FACTOR: &str = include_str!("../../queries/auth_mfa/insert_factor.sql");
const GET_FACTOR: &str = include_str!("../../queries/auth_mfa/get_factor.sql");
const ACTIVE_FACTOR: &str = include_str!("../../queries/auth_mfa/active_factor.sql");
const USE_STEP: &str = include_str!("../../queries/auth_mfa/use_step.sql");
const DISABLE_OTHERS: &str = include_str!("../../queries/auth_mfa/disable_others.sql");
const BURN_RECOVERY: &str = include_str!("../../queries/auth_mfa/burn_recovery.sql");
const INSERT_RECOVERY: &str = include_str!("../../queries/auth_mfa/insert_recovery.sql");
const USE_RECOVERY: &str = include_str!("../../queries/auth_mfa/use_recovery.sql");

/// A TOTP factor row. `Debug` never shows the (encrypted) secret.
#[derive(Clone, PartialEq, Eq)]
pub struct FactorRow {
    pub user_id: UserId,
    pub id: uuid::Uuid,
    pub secret_enc: Vec<u8>,
    /// Start of the last accepted step; `None` = pending enrolment.
    pub last_step_at: Option<OffsetDateTime>,
    pub disabled_at: Option<OffsetDateTime>,
}

impl std::fmt::Debug for FactorRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactorRow")
            .field("user_id", &self.user_id)
            .field("id", &self.id)
            .field("confirmed", &self.last_step_at.is_some())
            .finish_non_exhaustive()
    }
}

fn map_factor(row: &sqlx::mysql::MySqlRow, user: UserId) -> Result<FactorRow, DbError> {
    let id = UserId(sql::uuid_col(row, "user_id")?);
    if id != user {
        return Err(DbError::Corrupt("mfa_factors.user_id"));
    }
    let secret: Option<Vec<u8>> = sql::col(row, "secret_enc")?;
    Ok(FactorRow {
        user_id: id,
        id: sql::uuid_col(row, "id")?,
        secret_enc: secret.ok_or(DbError::Corrupt("mfa_factors.secret_enc"))?,
        last_step_at: sql::col(row, "last_used_at")?,
        disabled_at: sql::col(row, "disabled_at")?,
    })
}

/// New pending TOTP factor (`secret_enc` = `FieldEncryptor` output, purpose Secrets, platform scope).
///
/// # Errors
/// `Invalid` (label too long), server errors.
pub async fn insert_factor(
    tx: &mut IdentityTx,
    user: UserId,
    id: uuid::Uuid,
    secret_enc: &[u8],
    label: Option<&str>,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    if label.is_some_and(|l| l.len() > 64) || secret_enc.len() > 256 {
        return Err(DbError::Invalid("mfa factor field too long"));
    }
    tx.inner
        .execute(
            sql::q(INSERT_FACTOR)
                .bind(user.0)
                .bind(id)
                .bind(secret_enc)
                .bind(label)
                .bind(now),
        )
        .await?
        .expect_one()
}

/// # Errors
/// Server / decode errors.
pub async fn get_factor(
    tx: &mut IdentityTx,
    user: UserId,
    id: uuid::Uuid,
) -> Result<Option<FactorRow>, DbError> {
    tx.inner
        .fetch_optional(sql::q(GET_FACTOR).bind(user.0).bind(id))
        .await?
        .as_ref()
        .map(|r| map_factor(r, user))
        .transpose()
}

/// The user's confirmed, enabled TOTP factor (latest).
///
/// # Errors
/// Server / decode errors.
pub async fn active_factor(
    tx: &mut IdentityTx,
    user: UserId,
) -> Result<Option<FactorRow>, DbError> {
    tx.inner
        .fetch_optional(sql::q(ACTIVE_FACTOR).bind(user.0))
        .await?
        .as_ref()
        .map(|r| map_factor(r, user))
        .transpose()
}

/// Record step `step_at` as used if it is strictly later than the stored one. `false` = replay (same
/// or older step) or disabled factor.
///
/// # Errors
/// Server errors.
pub async fn use_step(
    tx: &mut IdentityTx,
    user: UserId,
    id: uuid::Uuid,
    step_at: OffsetDateTime,
) -> Result<bool, DbError> {
    let n = tx
        .inner
        .execute(
            sql::q(USE_STEP)
                .bind(step_at)
                .bind(user.0)
                .bind(id)
                .bind(step_at),
        )
        .await?;
    Ok(n == 1)
}

/// Disable every other TOTP factor of the user (after confirming `keep`).
///
/// # Errors
/// Server errors.
pub async fn disable_others(
    tx: &mut IdentityTx,
    user: UserId,
    keep: uuid::Uuid,
    now: OffsetDateTime,
) -> Result<u64, DbError> {
    tx.inner
        .execute(sql::q(DISABLE_OTHERS).bind(now).bind(user.0).bind(keep))
        .await
}

/// Replace the user's recovery codes: old unused ones are burned, new HMACs inserted.
///
/// # Errors
/// `Invalid` (more than 16 codes), server errors.
pub async fn replace_recovery(
    tx: &mut IdentityTx,
    user: UserId,
    hmacs: &[[u8; 32]],
    now: OffsetDateTime,
) -> Result<(), DbError> {
    if hmacs.len() > 16 {
        return Err(DbError::Invalid("too many recovery codes"));
    }
    tx.inner
        .execute(sql::q(BURN_RECOVERY).bind(now).bind(user.0))
        .await?;
    for h in hmacs {
        tx.inner
            .execute(
                sql::q(INSERT_RECOVERY)
                    .bind(user.0)
                    .bind(uuid::Uuid::now_v7())
                    .bind(&h[..]),
            )
            .await?
            .expect_one()?;
    }
    Ok(())
}

/// Consume one recovery code (single use). `false` = unknown or already used.
///
/// # Errors
/// Server errors.
pub async fn use_recovery(
    tx: &mut IdentityTx,
    user: UserId,
    hmac: &[u8; 32],
    now: OffsetDateTime,
) -> Result<bool, DbError> {
    let n = tx
        .inner
        .execute(sql::q(USE_RECOVERY).bind(now).bind(user.0).bind(&hmac[..]))
        .await?;
    Ok(n == 1)
}
