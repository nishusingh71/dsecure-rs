//! Platform-admin path (review R1/R5): the ONLY way to create staff, open/close access grants (and,
//! with its own `DbDekStore`, rotate DEKs). It runs on a separate pool connected as the
//! `rs_padm` DB user ([`PLATFORM_ADMIN_DB_USER`]), which holds INSERT on the staff tables and column-limited UPDATEs
//! (see `db::grants`); the app user cannot do any of this (no INSERT/UPDATE grants there).
//!
//! Every [`PlatformAdminTx`] starts by verifying the APPROVER inside the tx (active staff row, locked;
//! role holds the requested `PlatformPerm`; owner-approval cells refused) and inserting the caller's
//! audit row (built and hashed by the `audit` crate) in the same transaction.

use crate::error::DbError;
use crate::pool::Db;
use crate::queries::{
    PLATFORM_BOOTSTRAP_GET, PLATFORM_BOOTSTRAP_INSERT, PLATFORM_STAFF_COUNT_FOR_UPDATE,
    PLATFORM_STAFF_INSERT,
};
use crate::repo::audit::AuditRowRecord;
use crate::repo::keys::{PlatformDekPlan, insert_platform_dek_inner, platform_active_inner};
use crate::sql;
use crate::staff_grant::active_staff_role;
use crate::tx::{Inner, SystemTx};
use crate::write_guard::WriteOutcome;
use common::UserId;
use domain::rbac::{PlatformGrant, PlatformPerm, StaffRole, platform_grants};
use sqlx::Row as _;
use time::OffsetDateTime;

/// DB user name of the platform-admin pool (TiDB Serverless adds a `<prefix>.` in front; B3: short
/// enough for the 32-character limit, see `grants::MAX_DB_USER_NAME_LEN`).
pub const PLATFORM_ADMIN_DB_USER: &str = crate::grants::DB_USER_PLATFORM_ADMIN;

/// `CURRENT_USER()` (`user@host`) names the platform-admin user: the user part is exactly
/// [`PLATFORM_ADMIN_DB_USER`] or `<prefix>.<that name>` with a non-empty prefix without dots (TiDB
/// Serverless). Any host. Everything else (other names, empty prefix, nested dots) is refused.
///
/// Review N5: this proves the user NAME only, not that the user really holds the narrow
/// `DbRole::PlatformAdmin` grants. On self-hosted MySQL/TiDB anyone who can create users can name one
/// `x.rs_padm`; the grants themselves come from `docs/ops/db_users.sql` (check with `SHOW GRANTS`).
#[must_use]
pub fn is_platform_admin_user(current_user: &str) -> bool {
    let user = current_user
        .rsplit_once('@')
        .map_or(current_user, |(u, _)| u);
    match user.split_once('.') {
        None => user == PLATFORM_ADMIN_DB_USER,
        Some((prefix, name)) => !prefix.is_empty() && name == PLATFORM_ADMIN_DB_USER,
    }
}

/// `metadata.actor` of audit rows written through [`PlatformAdminDb::ops_tx_owner_approved`].
pub const OPS_CLI_ACTOR: &str = "ops_cli";

/// Owner-approval reference: non-empty, <= 128 chars, and recorded in `metadata.owner_approval_ref`.
fn check_owner_ref(owner_approval_ref: &str, audit: &AuditRowRecord) -> Result<(), DbError> {
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
    if recorded {
        Ok(())
    } else {
        Err(DbError::Invalid(
            "owner approval reference not in audit row",
        ))
    }
}

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
            if !is_platform_admin_user(&u) {
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
        self.open_verified(approver, perm, audit, owner_approved, false)
            .await
    }

    /// Shared tail of every platform-admin tx: verify the approver INSIDE the tx (locked staff row,
    /// role grant, owner-approval cell; `superadmin_only` for the ops-CLI path), then insert `audit`.
    async fn open_verified(
        &self,
        approver: UserId,
        perm: PlatformPerm,
        audit: &AuditRowRecord,
        owner_approved: bool,
        superadmin_only: bool,
    ) -> Result<PlatformAdminTx, DbError> {
        let mut inner = Inner::begin(&self.db).await?;
        let checked = async {
            let role = active_staff_role(&mut inner, approver)
                .await?
                .ok_or(DbError::Forbidden("approver is not active staff"))?;
            if superadmin_only && role != StaffRole::Superadmin {
                return Err(DbError::Forbidden("approver is not a platform superadmin"));
            }
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
        check_owner_ref(owner_approval_ref, audit)?;
        self.open(approver, perm, audit, true).await
    }

    /// Ops-CLI variant of [`PlatformAdminDb::admin_tx_owner_approved`] (e.g. `xtask provision-keys
    /// seed-db`): the operator only has DB credentials, no staff session/MFA, so the approver is
    /// CLAIMED, not authenticated. The audit row therefore says so: `actor_kind` = `system`,
    /// `actor_id` NULL, `metadata.actor` = [`OPS_CLI_ACTOR`], `metadata.claimed_approver` = the
    /// approver UUID, plus `metadata.owner_approval_ref`. The claimed approver must still be an ACTIVE
    /// `platform_superadmin` whose role holds `perm` (checked inside the tx, row locked), and the
    /// owner-approval reference is mandatory. The API path (`admin_tx*`) keeps its own checks.
    ///
    /// # Errors
    /// `Invalid` (audit row not an ops-CLI row / reference missing), `Forbidden`, server errors.
    pub async fn ops_tx_owner_approved(
        &self,
        claimed_approver: UserId,
        perm: PlatformPerm,
        owner_approval_ref: &str,
        audit: &AuditRowRecord,
        _now: OffsetDateTime,
    ) -> Result<PlatformAdminTx, DbError> {
        check_owner_ref(owner_approval_ref, audit)?;
        let meta = |k: &str| {
            audit
                .metadata
                .as_ref()
                .and_then(|m| m.get(k))
                .and_then(serde_json::Value::as_str)
        };
        let claimed = claimed_approver.0.hyphenated().to_string();
        if audit.actor_kind != "system"
            || audit.actor_id.is_some()
            || audit.staff_grant_id.is_some()
            || audit.action.is_empty()
            || meta("actor") != Some(OPS_CLI_ACTOR)
            || meta("claimed_approver") != Some(claimed.as_str())
        {
            return Err(DbError::Invalid(
                "audit row is not an ops-cli row for this approver",
            ));
        }
        self.open_verified(claimed_approver, perm, audit, true, true)
            .await
    }

    /// First-run bootstrap without platform DEKs (tests / fixtures). See
    /// [`PlatformAdminDb::bootstrap_first_superadmin_with_deks`].
    ///
    /// # Errors
    /// `Conflict("staff.bootstrap_done")`, `Invalid`, server errors.
    pub async fn bootstrap_first_superadmin(
        &self,
        user: UserId,
        audit: &AuditRowRecord,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        self.bootstrap_first_superadmin_with_deks(user, &[], audit, now)
            .await
    }

    /// First-run bootstrap: create the first `platform_superadmin` exactly once, in ONE transaction:
    /// 1. singleton marker `platform_bootstrap(id = 1)` (review N2: a concurrent second bootstrap
    ///    fails on the PRIMARY KEY on MySQL and TiDB alike; the locked COUNT alone does not serialise
    ///    on TiDB, which has no gap locks),
    /// 2. locked count: `platform_staff` must be empty (staff created by other paths),
    /// 3. the planned platform DEKs (review N1, from `repo::keys::plan_platform_deks`): an existing
    ///    one must still be the active row with the same wrapped bytes; a new one must still be missing
    ///    and is inserted here, so DEKs never commit without the staff row (no mixed-KEK leftovers),
    /// 4. the staff row, 5. the audit row (`actor_kind` = `system`, actor = the new user).
    ///
    /// # Errors
    /// `Conflict("staff.bootstrap_done")`, `Conflict("data_keys.changed")`, `Invalid`, server errors.
    pub async fn bootstrap_first_superadmin_with_deks(
        &self,
        user: UserId,
        deks: &[PlatformDekPlan],
        audit: &AuditRowRecord,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        if audit.actor_kind != "system" || !audit_matches(audit, user) {
            return Err(DbError::Invalid("audit row does not match the bootstrap"));
        }
        let mut inner = Inner::begin(&self.db).await?;
        let r = async {
            match inner
                .execute(sql::q(PLATFORM_BOOTSTRAP_INSERT).bind(user.0).bind(now))
                .await
            {
                Ok(n) => n.expect_one()?,
                Err(DbError::Duplicate { .. }) => {
                    return Err(DbError::Conflict("staff.bootstrap_done"));
                }
                Err(e) => return Err(e),
            }
            let row = inner
                .fetch_optional(sql::q(PLATFORM_STAFF_COUNT_FOR_UPDATE))
                .await?
                .ok_or(DbError::Corrupt("count"))?;
            if sql::col::<i64>(&row, "n")? != 0 {
                return Err(DbError::Conflict("staff.bootstrap_done"));
            }
            for d in deks {
                let active = platform_active_inner(&mut inner, d.purpose).await?;
                match (d.existing, active) {
                    (true, Some((k, w))) if k == d.kid && w == d.wrapped => {}
                    (false, None) => {
                        insert_platform_dek_inner(&mut inner, &d.kid, d.purpose, &d.wrapped, now)
                            .await?;
                    }
                    _ => return Err(DbError::Conflict("data_keys.changed")),
                }
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
            // A duplicate that only surfaces at COMMIT (TiDB optimistic mode): another bootstrap won.
            Ok(()) => match (SystemTx { inner }).commit().await {
                Err(DbError::Duplicate { .. }) => Err(DbError::Conflict("staff.bootstrap_done")),
                other => other,
            },
            Err(e) => {
                inner.rollback().await;
                Err(e)
            }
        }
    }

    /// Did the first-run bootstrap of `user` commit? Reads the singleton marker (written in the SAME
    /// tx as the staff row and the DEKs) in a NEW short tx, e.g. after `CommitUnknown` (review M1).
    ///
    /// # Errors
    /// Server errors (outcome still unknown).
    pub async fn bootstrap_committed_for(&self, user: UserId) -> Result<bool, DbError> {
        let mut inner = Inner::begin(&self.db).await?;
        let r = inner.fetch_optional(sql::q(PLATFORM_BOOTSTRAP_GET)).await;
        inner.rollback().await;
        match r? {
            None => Ok(false),
            Some(row) => Ok(sql::uuid_col(&row, "user_id")? == user.0),
        }
    }

    /// Pre-check of the first-run bootstrap (ops tool): is there any `platform_staff` row at all
    /// (active or revoked)? Short tx, always rolled back. The authoritative check is the locked count
    /// inside [`PlatformAdminDb::bootstrap_first_superadmin_with_deks`].
    ///
    /// # Errors
    /// Server errors.
    pub async fn has_any_staff(&self) -> Result<bool, DbError> {
        let mut inner = Inner::begin(&self.db).await?;
        let r = inner
            .fetch_optional(sql::q(PLATFORM_STAFF_COUNT_FOR_UPDATE))
            .await;
        inner.rollback().await;
        let row = r?.ok_or(DbError::Corrupt("count"))?;
        Ok(sql::col::<i64>(&row, "n")? != 0)
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

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn current_user_check_accepts_exact_or_one_prefix() {
        for ok in [
            "rs_padm@%",
            "rs_padm@10.0.0.7",
            "rs_padm",
            "4Xyz1abcDEF23gh.rs_padm@%",
            "p.rs_padm@localhost",
        ] {
            assert!(is_platform_admin_user(ok), "{ok}");
        }
        for bad in [
            "",
            "@%",
            "rs_app@%",
            ".rs_padm@%",
            "a.b.rs_padm@%",
            "prefix.rs_padm2@%",
            "prefix.xrs_padm@%",
            "rs_padm.x@%",
            "dsecure_platform_admin@%",
            "prefix.dsecure_platform_admin@%",
            "RS_PADM@%",
        ] {
            assert!(!is_platform_admin_user(bad), "{bad}");
        }
    }
}
