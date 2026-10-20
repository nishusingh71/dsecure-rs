//! Step-up proofs (`step_up_tokens`, identity class; RBAC.md §6.6, SECURITY.md §5): 5 min, single
//! use, bound to session + action + target. Only an HMAC of the opaque token is stored.

use crate::error::DbError;
use crate::sql;
use crate::tx::IdentityTx;
use crate::write_guard::WriteOutcome;
use common::SessionId;
use time::OffsetDateTime;

const INSERT: &str = include_str!("../../queries/auth_step_up/insert.sql");
const CONSUME: &str = include_str!("../../queries/auth_step_up/consume.sql");

/// Max `action` length (`step_up_tokens.action VARCHAR(48)`).
pub const MAX_ACTION_LEN: usize = 48;

#[derive(Clone, Debug)]
pub struct NewStepUp<'a> {
    /// `jti` of the proof.
    pub id: uuid::Uuid,
    pub session: SessionId,
    pub action: &'a str,
    pub target: Option<uuid::Uuid>,
    pub token_hash: [u8; 32],
    pub expires_at: OffsetDateTime,
}

/// # Errors
/// `Invalid` (action too long / empty), server errors.
pub async fn insert(tx: &mut IdentityTx, s: &NewStepUp<'_>) -> Result<(), DbError> {
    if s.action.is_empty() || s.action.len() > MAX_ACTION_LEN {
        return Err(DbError::Invalid("step-up action length"));
    }
    tx.inner
        .execute(
            sql::q(INSERT)
                .bind(s.id)
                .bind(s.session.0)
                .bind(s.action)
                .bind(s.target)
                .bind(&s.token_hash[..])
                .bind(s.expires_at),
        )
        .await?
        .expect_one()
}

/// Atomically consume a proof for exactly (session, action, target). `false` = replay, wrong
/// session/action/target, or expired (one answer for all: no oracle).
///
/// # Errors
/// Server errors.
pub async fn consume(
    tx: &mut IdentityTx,
    token_hash: &[u8; 32],
    session: SessionId,
    action: &str,
    target: Option<uuid::Uuid>,
    now: OffsetDateTime,
) -> Result<bool, DbError> {
    let n = tx
        .inner
        .execute(
            sql::q(CONSUME)
                .bind(now)
                .bind(&token_hash[..])
                .bind(session.0)
                .bind(action)
                .bind(target)
                .bind(now),
        )
        .await?;
    Ok(n == 1)
}
