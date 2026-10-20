//! Device credentials (Device principal, DATABASE.md §5 `device_credentials`). Tenant class.

use crate::error::DbError;
use crate::queries::AUTHZ_EPOCHS_BUMP;
use crate::repo::memberships;
use crate::sql;
use crate::tx::TenantTx;
use crate::write_guard::WriteOutcome;
use common::{DeviceId, MembershipId};
use time::OffsetDateTime;

const INSERT: &str = include_str!("../../queries/auth_devices/insert.sql");
const REVOKE: &str = include_str!("../../queries/auth_devices/revoke.sql");

#[derive(Clone, Debug)]
pub struct NewDeviceCredential {
    pub id: uuid::Uuid,
    pub device: DeviceId,
    pub operator: MembershipId,
    pub product_code: String,
    /// Space separated scope codes (validated by `auth` / api against `domain::DeviceScope`).
    pub scopes: String,
    pub secret_hash: Option<[u8; 32]>,
}

/// Enrol a device credential. The operator membership must exist in the tx tenant (parent check).
///
/// # Errors
/// `NotFound("membership")`, `Invalid` (scopes too long), server errors.
pub async fn insert(
    tx: &mut TenantTx,
    c: &NewDeviceCredential,
    now: OffsetDateTime,
) -> Result<uuid::Uuid, DbError> {
    if c.scopes.len() > 255 || c.product_code.len() > 16 {
        return Err(DbError::Invalid("device credential field too long"));
    }
    if memberships::get(tx, c.operator).await?.is_none() {
        return Err(DbError::NotFound("membership"));
    }
    let tid = tx.tid();
    tx.inner
        .execute(
            sql::q(INSERT)
                .bind(tid)
                .bind(c.id)
                .bind(c.device.0)
                .bind(c.operator.0)
                .bind(c.product_code.as_str())
                .bind(c.scopes.as_str())
                .bind(c.secret_hash.as_ref().map(|h| &h[..]))
                .bind(now),
        )
        .await?
        .expect_one()?;
    Ok(c.id)
}

/// Revoke a credential (decommission). Authz-affecting: epoch +1 in the same tx.
///
/// # Errors
/// `NotPersisted` (unknown or already revoked), server errors.
pub async fn revoke(tx: &mut TenantTx, id: uuid::Uuid, now: OffsetDateTime) -> Result<(), DbError> {
    let tid = tx.tid();
    tx.inner
        .execute(sql::q(REVOKE).bind(now).bind(tid).bind(id))
        .await?
        .expect_one()?;
    tx.inner
        .execute(sql::q(AUTHZ_EPOCHS_BUMP).bind(now).bind(tid))
        .await?
        .expect_one()
}
