//! Platform-admin path (review R1/R5): the ONLY way to create staff, open/close access grants (and,
//! with its own `DbDekStore`, rotate DEKs). It runs on a separate pool connected as the
//! `dsecure_platform_admin` DB user, which holds INSERT on the staff tables and column-limited UPDATEs
//! (see `db::grants`); the app user cannot do any of this (no INSERT/UPDATE grants there).
//!
//! Every [`PlatformAdminTx`] starts by verifying the APPROVER inside the tx (active staff row, locked;
//! role holds the requested `PlatformPerm`; owner-approval cells refused) and inserting the caller's
//! audit row (built and hashed by the `audit` crate) in the same transaction.

use crate::error::DbError;
use crate::pool::Db;
use crate::queries::{PLATFORM_STAFF_COUNT_FOR_UPDATE, PLATFORM_STAFF_INSERT};
use crate::repo::audit::AuditRowRecord;
use crate::sql;
use crate::staff_grant::active_staff_role;
use crate::tx::{Inner, SystemTx};
use crate::write_guard::WriteOutcome;
use common::UserId;
use domain::rbac::{PlatformGrant, PlatformPerm, StaffRole, platform_grants};
use sqlx::Row as _;
use time::OffsetDateTime;

/// DB user name of the platform-admin pool (TiDB Serverless adds a `<prefix>.` in front).
pub const PLATFORM_ADMIN_DB_USER: &str = "dsecure_platform_admin";

/// Approver verified inside a [`PlatformAdminTx`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedApprover {
    user: UserId,
    role: StaffRole,
    perm: PlatformPerm,
    grant: PlatformGrant,
}

impl VerifiedApprover {
    #[must_use]
    pub const fn user(&self) -> UserId {
        self.user
    }
    #[must_use]
    pub const fn role(&self) -> StaffRole {
        self.role
    }
    #[must_use]
    pub const fn perm(&self) -> PlatformPerm {
        self.perm
    }
}

/// Pool on the platform-admin DB user.
#[derive(Clone, Debug)]
pub struct PlatformAdminDb {
    db: Db,
}

/// Transaction of a verified approver for exactly one platform permission.
pub struct PlatformAdminTx {
    pub(crate) inner: Inner,
    approver: VerifiedApprover,
}

impl std::fmt::Debug for PlatformAdminTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PlatformAdminTx")
    }
}

fn audit_matches(audit: &AuditRowRecord, actor: UserId) -> bool {
    audit.actor_id == Some(actor.0) && !audit.action.is_empty()
}

/// Insert an audit row through the audit repo (system variant) inside `inner`.
async fn insert_audit(inner: Inner, audit: &AuditRowRecord) -> (Inner, Result<(), DbError>) {
    let mut s = SystemTx { inner };
    let r = crate::repo::audit::insert_event_system(&mut s, audit).await;
    (s.inner, r)
}

impl PlatformAdminDb {
    /// Connect the platform-admin pool. Outside dev/test the server-side `CURRENT_USER()` must be the
    /// platform-admin user (so the narrow grants really apply).
    ///
    /// # Errors
    /// Connect refusals, `Config("not the platform-admin DB user")`.
    pub async fn connect(
        cfg: &config::DbConfig,
        env: config::Environment,
    ) -> Result<Self, DbError> {
        let db = Db::connect(cfg, env).await?;
        if !env.is_local() {
            let row = sql::q(crate::queries_internal::SELECT_CURRENT_USER)
                .fetch_one(db.pool())
                .await
                .map_err(sql::map_err)?;
            let u: String = row
                .try_get("u")
                .map_err(|_| DbError::Corrupt("CURRENT_USER()"))?;
            let name = u.split('@').next().unwrap_or("");
            let name = name.rsplit('.').next().unwrap_or(name);
            if name != PLATFORM_ADMIN_DB_USER {
                db.close().await;
                return Err(DbError::Config("not the platform-admin DB user"));
            }
        }
        Ok(Self { db })
    }

    /// Wrap an existing pool (tests: the scratch migrator; feature `test-fixtures`).
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub const fn for_tests(db: Db) -> Self {
        Self { db }
    }

    /// Open a tx for `approver` acting with `perm`; writes `audit` (actor must be the approver).
    ///
    /// # Errors
    /// `Invalid` (audit mismatch), `Forbidden` (not active staff / perm not granted / owner approval
    /// needed), server errors.
    pub async fn admin_tx(
        &self,
        approver: UserId,
        perm: PlatformPerm,
        audit: &AuditRowRecord,
        _now: OffsetDateTime,
    ) -> Result<PlatformAdminTx, DbError> {
        self.open(approver, perm, audit, false).await
    }

    async fn open(
        &self,
        approver: UserId,
        perm: PlatformPerm,
        audit: &AuditRowRecord,
        owner_approved: bool,
    ) -> Result<PlatformAdminTx, DbError> {
        if audit.actor_kind != "staff" || !audit_matches(audit, approver) {
            return Err(DbError::Invalid("audit row does not match the approver"));
        }
        let mut inner = Inner::begin(&self.db).await?;
        let checked = async {
            let role = active_staff_role(&mut inner, approver)
                .await?
                .ok_or(DbError::Forbidden("approver is not active staff"))?;
            let grant = platform_grants(role, perm)
                .ok_or(DbError::Forbidden("approver lacks the platform permission"))?;
            if grant.owner_approval && !owner_approved {
                return Err(DbError::Forbidden("owner approval required"));
            }
            Ok(VerifiedApprover {
                user: approver,
                role,
                perm,
                grant,
            })
        }
        .await;
        let approver = match checked {
            Ok(a) => a,
            Err(e) => {
                inner.rollback().await;
                return Err(e);
            }
        };
        let (inner, r) = insert_audit(inner, audit).await;
        if let Err(e) = r {
            inner.rollback().await;
            return Err(e);
        }
        Ok(PlatformAdminTx { inner, approver })
    }

    /// Same as [`PlatformAdminDb::admin_tx`] for permissions whose matrix cell needs OWNER approval
    /// (e.g. `platform.keys.rotate`). `owner_approval_ref` (ledger / ticket id of the owner's written
    /// approval) is mandatory and must be recorded in the audit row's `metadata.owner_approval_ref`.
    /// Phase 0 has no approvals table, so the reference itself is not verified here (open item).
    ///
    /// # Errors
    /// `Invalid` (missing/unrecorded reference, audit mismatch), `Forbidden`, server errors.
    pub async fn admin_tx_owner_approved(
        &self,
        approver: UserId,
        perm: PlatformPerm,
        owner_approval_ref: &str,
        audit: &AuditRowRecord,
        _now: OffsetDateTime,
    ) -> Result<PlatformAdminTx, DbError> {
        let r = owner_approval_ref.trim();
        if r.is_empty() || r.len() > 128 {
            return Err(DbError::Invalid("owner approval reference required"));
        }
        let recorded = audit
            .metadata
            .as_ref()
            .and_then(|m| m.get("owner_approval_ref"))
            .and_then(serde_json::Value::as_str)
            == Some(r);
        if !recorded {
            return Err(DbError::Invalid(
                "owner approval reference not in audit row",
            ));
        }
        self.open(approver, perm, audit, true).await
    }

    /// First-run bootstrap: create the first `platform_superadmin` ONLY while `platform_staff` is empty
    /// (locked count), with an audit row (`actor_kind` = `system`, actor = the new user).
    ///
    /// # Errors
    /// `Conflict("staff.bootstrap_done")`, `Invalid`, server errors.
    pub async fn bootstrap_first_superadmin(
        &self,
        user: UserId,
        audit: &AuditRowRecord,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        if audit.actor_kind != "system" || !audit_matches(audit, user) {
            return Err(DbError::Invalid("audit row does not match the bootstrap"));
        }
        let mut inner = Inner::begin(&self.db).await?;
        let r = async {
            let row = inner
                .fetch_optional(sql::q(PLATFORM_STAFF_COUNT_FOR_UPDATE))
                .await?
                .ok_or(DbError::Corrupt("count"))?;
            if sql::col::<i64>(&row, "n")? != 0 {
                return Err(DbError::Conflict("staff.bootstrap_done"));
            }
            inner
                .execute(
                    sql::q(PLATFORM_STAFF_INSERT)
                        .bind(user.0)
                        .bind(StaffRole::Superadmin.as_str())
                        .bind(None::<uuid::Uuid>)
                        .bind(now),
                )
                .await?
                .expect_one()
        }
        .await;
        if let Err(e) = r {
            inner.rollback().await;
            return Err(e);
        }
        let (inner, r) = insert_audit(inner, audit).await;
        match r {
            Ok(()) => SystemTx { inner }.commit().await,
            Err(e) => {
                inner.rollback().await;
                Err(e)
            }
        }
    }

    /// The underlying pool (e.g. a `DbDekStore` for DEK rotation on the admin user).
    #[must_use]
    pub const fn db(&self) -> &Db {
        &self.db
    }
}

impl PlatformAdminTx {
    #[must_use]
    pub const fn approver(&self) -> &VerifiedApprover {
        &self.approver
    }

    /// The tx was opened for `perm`?
    pub(crate) fn require(&self, perm: PlatformPerm) -> Result<PlatformGrant, DbError> {
        if self.approver.perm == perm {
            Ok(self.approver.grant)
        } else {
            Err(DbError::Forbidden(
                "transaction opened for another permission",
            ))
        }
    }

    /// Commit (audit row + changes together).
    ///
    /// # Errors
    /// Server error, `CommitUnknown`.
    pub async fn commit(self) -> Result<(), DbError> {
        SystemTx { inner: self.inner }.commit().await
    }

    pub async fn rollback(self) {
        self.inner.rollback().await;
    }
}
