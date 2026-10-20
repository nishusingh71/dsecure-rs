//! Staff tenant-data grants.
//!
//! `domain::VerifiedStaffGrant` is built ONLY inside `db::staff_grant::verify` (locking read: grant
//! open, unexpired, for that tenant, owned by that staff user, staff not revoked). auth never calls
//! `__from_verified_grant`; [`DbStaffGrantVerifier`] is the single place auth reaches the db verifier
//! (carry-forward item 13: CI grep gate on other callers).
//!
//! Staff tenant data then goes through `Db::tenant_tx_for_staff(&VerifiedGrant, &AuditRowRecord,
//! now)` (db re-verifies and audits). A `Read` grant makes writes fail with `DbError::ReadOnly`;
//! [`staff_db_error`] maps that (and `Forbidden`) to `AuthError::Forbidden` = HTTP 403.
//! Staff login itself stays refused until MFA lands (P0-11, review F2).

use common::{GrantId, TenantId, UserId};
use db::{Db, DbError, VerifiedGrant};
use time::OffsetDateTime;

use crate::error::AuthError;

#[async_trait::async_trait]
pub trait StaffGrantVerifier: Send + Sync {
    /// Any failure = deny (the db fn answers one `NotFound` for every failed check: no oracle).
    async fn verify(
        &self,
        staff_user: UserId,
        grant: GrantId,
        tenant: TenantId,
        now: OffsetDateTime,
    ) -> Result<VerifiedGrant, AuthError>;
}

/// Production verifier over `db::staff_grant::verify` (own short `SystemTx`).
#[derive(Clone, Debug)]
pub struct DbStaffGrantVerifier {
    db: Db,
}

impl DbStaffGrantVerifier {
    #[must_use]
    pub const fn new(db: Db) -> Self {
        Self { db }
    }
}

/// Map db errors of staff paths: grant problems and read-only writes are 403, never 500.
#[must_use]
pub fn staff_db_error(e: &DbError) -> AuthError {
    match e {
        DbError::NotFound(_) => AuthError::Forbidden("staff_grant"),
        DbError::ReadOnly => AuthError::Forbidden("staff_grant_read_only"),
        DbError::Forbidden(_) => AuthError::Forbidden("staff_forbidden"),
        other => AuthError::from_db(other),
    }
}

#[async_trait::async_trait]
impl StaffGrantVerifier for DbStaffGrantVerifier {
    async fn verify(
        &self,
        staff_user: UserId,
        grant: GrantId,
        tenant: TenantId,
        now: OffsetDateTime,
    ) -> Result<VerifiedGrant, AuthError> {
        let mut tx = self.db.system_tx().await.map_err(|e| staff_db_error(&e))?;
        match db::staff_grant::verify(&mut tx, staff_user, grant, tenant, now).await {
            Ok(g) => {
                tx.commit().await.map_err(|e| staff_db_error(&e))?;
                Ok(g)
            }
            Err(e) => {
                tx.rollback().await;
                Err(staff_db_error(&e))
            }
        }
    }
}
