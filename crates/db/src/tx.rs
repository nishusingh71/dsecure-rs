//! Transaction types (PHASE0_SPEC §3.5, DATABASE.md §2.2 L1/L6).
//!
//! - `TenantTx`: the ONLY way to touch tenant-class tables. Tenant comes from a verified
//!   `domain::rbac::TenantScope` (built by `auth` after `decide()`), or from a claimed job row
//!   (re-verified inside the tx). Repository fns never take a tenant id argument.
//! - `IdentityTx`: global identity tables (users, credentials, sessions, refresh tokens, directory).
//! - `PlatformTx`: staff/platform writes (quota changes), records the acting staff user.
//! - `SystemTx`: infra/bootstrap (tenant creation, system outbox/jobs).
//!
//! Every statement runs under the app-side deadline (`DB_TX_TIMEOUT_MS`); BEGIN runs on a connection
//! whose session is already REPEATABLE READ (+ pessimistic on TiDB, see `pool`).

use crate::error::DbError;
use crate::pool::Db;
use crate::sql::{self, Q};
use crate::staff_grant::VerifiedGrant;
use crate::write_guard::WriteOutcome as _;
use common::{GrantId, MembershipId, TenantId, UserId};
use domain::rbac::{TenantScope, Visibility};
use sqlx::Transaction;
use sqlx::mysql::{MySql, MySqlRow};
use time::OffsetDateTime;
use tokio::time::Instant;

/// Shared transaction core (crate-private).
pub(crate) struct Inner {
    tx: Transaction<'static, MySql>,
    deadline: Instant,
    /// Set for staff `read` grants (review R2): every write statement is refused in code.
    read_only: bool,
}

impl Inner {
    pub(crate) async fn begin(db: &Db) -> Result<Self, DbError> {
        let deadline = Instant::now() + db.shared.opts.tx_timeout;
        let tx = tokio::time::timeout_at(deadline, db.pool().begin())
            .await
            .map_err(|_| DbError::Timeout)?
            .map_err(sql::map_err)?;
        Ok(Self {
            tx,
            deadline,
            read_only: false,
        })
    }

    pub(crate) async fn execute(&mut self, q: Q<'_>) -> Result<u64, DbError> {
        if self.read_only {
            return Err(DbError::ReadOnly);
        }
        let r = tokio::time::timeout_at(self.deadline, q.execute(&mut *self.tx))
            .await
            .map_err(|_| DbError::Timeout)?
            .map_err(sql::map_err)?;
        Ok(r.rows_affected())
    }

    pub(crate) async fn fetch_optional(&mut self, q: Q<'_>) -> Result<Option<MySqlRow>, DbError> {
        tokio::time::timeout_at(self.deadline, q.fetch_optional(&mut *self.tx))
            .await
            .map_err(|_| DbError::Timeout)?
            .map_err(sql::map_err)
    }

    pub(crate) async fn fetch_all(&mut self, q: Q<'_>) -> Result<Vec<MySqlRow>, DbError> {
        tokio::time::timeout_at(self.deadline, q.fetch_all(&mut *self.tx))
            .await
            .map_err(|_| DbError::Timeout)?
            .map_err(sql::map_err)
    }

    pub(crate) async fn exists(&mut self, q: Q<'_>) -> Result<bool, DbError> {
        Ok(self.fetch_optional(q).await?.is_some())
    }

    async fn commit(self) -> Result<(), DbError> {
        match tokio::time::timeout_at(self.deadline, self.tx.commit()).await {
            Err(_) => Err(DbError::CommitUnknown),
            Ok(Ok(())) => Ok(()),
            // I/O failure during COMMIT: outcome unknown, never retried blindly (DATABASE.md §1.2).
            Ok(Err(sqlx::Error::Io(_))) => Err(DbError::CommitUnknown),
            Ok(Err(e)) => Err(sql::map_err(e)),
        }
    }

    pub(crate) async fn rollback(self) {
        // Rollback failure = connection already gone; server rolls back on disconnect anyway.
        let _ = self.tx.rollback().await;
    }
}

/// Where the tenant of a `TenantTx` came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxOrigin {
    /// Member/staff request: `TenantScope` from the authz decision.
    Request,
    /// Worker job: tenant read from the claimed job row (re-verified in this tx).
    Job { job_id: uuid::Uuid },
    /// Staff under a db-verified access grant.
    Staff,
}

/// Tenant-scoped transaction. No public constructor except via [`Db`].
pub struct TenantTx {
    pub(crate) inner: Inner,
    tenant: TenantId,
    actor: Option<MembershipId>,
    visibility: Visibility,
    staff_grant: Option<GrantId>,
    origin: TxOrigin,
}

impl std::fmt::Debug for TenantTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantTx")
            .field("tenant", &self.tenant)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl TenantTx {
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Acting membership (`None` for job/bootstrap transactions).
    #[must_use]
    pub const fn actor(&self) -> Option<MembershipId> {
        self.actor
    }

    #[must_use]
    pub const fn visibility(&self) -> &Visibility {
        &self.visibility
    }

    #[must_use]
    pub const fn staff_grant(&self) -> Option<GrantId> {
        self.staff_grant
    }

    #[must_use]
    pub const fn origin(&self) -> TxOrigin {
        self.origin
    }

    /// Tenant id as bind value (the only source of `tenant_id` binds).
    pub(crate) const fn tid(&self) -> uuid::Uuid {
        self.tenant.0
    }

    pub(crate) fn require_actor(&self) -> Result<MembershipId, DbError> {
        self.actor.ok_or(DbError::ScopeMissing(
            "operation needs an acting membership",
        ))
    }

    /// L6 row-tenant assert: every tenant row mapper calls this with the row's `tenant_id`.
    ///
    /// # Errors
    /// `TenantMismatch` (fail closed, no data returned) + `db.tenant_mismatch` alert event.
    pub fn assert_row_tenant(&self, row_tenant: TenantId) -> Result<(), DbError> {
        assert_row_tenant(self.tenant, row_tenant)
    }

    /// Commit.
    ///
    /// # Errors
    /// Server error, `CommitUnknown`.
    pub async fn commit(self) -> Result<(), DbError> {
        self.inner.commit().await
    }

    pub async fn rollback(self) {
        self.inner.rollback().await;
    }
}

/// Free-function form of the L6 check (PHASE0_SPEC §3.5).
///
/// # Errors
/// `TenantMismatch`.
pub fn assert_row_tenant(tx_tenant: TenantId, row_tenant: TenantId) -> Result<(), DbError> {
    if tx_tenant == row_tenant {
        Ok(())
    } else {
        // Alert hook (`db.tenant_mismatch`); ids are non-secret, but row data is never logged.
        tracing::error!(
            alert = "db.tenant_mismatch",
            "row tenant differs from tx tenant"
        );
        Err(DbError::TenantMismatch)
    }
}

macro_rules! simple_tx {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        pub struct $name {
            pub(crate) inner: Inner,
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        impl $name {
            /// Commit.
            ///
            /// # Errors
            /// Server error, `CommitUnknown`.
            pub async fn commit(self) -> Result<(), DbError> {
                self.inner.commit().await
            }

            pub async fn rollback(self) {
                self.inner.rollback().await;
            }
        }
    };
}

simple_tx!(
    IdentityTx,
    "Global identity tables (users, credentials, sessions, refresh tokens, membership directory)."
);
simple_tx!(
    SystemTx,
    "Infra/bootstrap: tenant creation, system outbox/jobs, epoch poller."
);

/// Staff/platform transaction, opened only with a db-verified staff grant; the grant is re-verified
/// and an audit row is written inside this same transaction (`Db::platform_tx`).
pub struct PlatformTx {
    pub(crate) inner: Inner,
    grant: VerifiedGrant,
}

impl std::fmt::Debug for PlatformTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PlatformTx")
    }
}

impl PlatformTx {
    #[must_use]
    pub const fn staff_user(&self) -> UserId {
        self.grant.staff_user()
    }

    /// The verified grant (tenant the staff member acts on).
    #[must_use]
    pub const fn grant(&self) -> &VerifiedGrant {
        &self.grant
    }

    /// Commit.
    ///
    /// # Errors
    /// Server error, `CommitUnknown`.
    pub async fn commit(self) -> Result<(), DbError> {
        self.inner.commit().await
    }

    pub async fn rollback(self) {
        self.inner.rollback().await;
    }
}

/// A claimed job's business transaction (tenant job). The lease row is locked (`FOR UPDATE`, lease
/// not expired) for the whole tx, so the reaper cannot requeue it meanwhile; [`JobTx::complete`] marks
/// the job succeeded in the SAME tx as the business write (no double apply).
#[derive(Debug)]
pub struct JobTx {
    tx: TenantTx,
    job_id: uuid::Uuid,
    claim_token: uuid::Uuid,
}

async fn complete_in(
    inner: &mut Inner,
    job_id: uuid::Uuid,
    claim_token: uuid::Uuid,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    inner
        .execute(
            sql::q(crate::queries::JOBS_COMPLETE)
                .bind(now)
                .bind(job_id)
                .bind(claim_token),
        )
        .await?
        .expect_one()
}

impl JobTx {
    /// The tenant transaction for the business write (tenant from the job row).
    pub fn tx(&mut self) -> &mut TenantTx {
        &mut self.tx
    }

    /// Mark succeeded and commit business write + job state atomically.
    ///
    /// # Errors
    /// `NotPersisted` (guard; cannot happen while the row lock is held), server errors,
    /// `CommitUnknown`.
    pub async fn complete(mut self, now: OffsetDateTime) -> Result<(), DbError> {
        match complete_in(&mut self.tx.inner, self.job_id, self.claim_token, now).await {
            Ok(()) => self.tx.commit().await,
            Err(e) => {
                self.tx.rollback().await;
                Err(e)
            }
        }
    }

    /// Abort the business write (job stays `running` until `fail_job` / lease expiry).
    pub async fn rollback(self) {
        self.tx.rollback().await;
    }
}

/// Same as [`JobTx`] for tenant-less system jobs.
#[derive(Debug)]
pub struct SystemJobTx {
    tx: SystemTx,
    job_id: uuid::Uuid,
    claim_token: uuid::Uuid,
}

impl SystemJobTx {
    pub fn tx(&mut self) -> &mut SystemTx {
        &mut self.tx
    }

    /// # Errors
    /// See [`JobTx::complete`].
    pub async fn complete(mut self, now: OffsetDateTime) -> Result<(), DbError> {
        match complete_in(&mut self.tx.inner, self.job_id, self.claim_token, now).await {
            Ok(()) => self.tx.commit().await,
            Err(e) => {
                self.tx.rollback().await;
                Err(e)
            }
        }
    }

    pub async fn rollback(self) {
        self.tx.rollback().await;
    }
}

/// Lock the job lease row (latest committed, `lease_until > now`) inside `inner`; returns its tenant.
async fn lock_lease(
    inner: &mut Inner,
    job: &crate::jobs::ClaimedJob,
    now: OffsetDateTime,
) -> Result<Option<TenantId>, DbError> {
    let row = inner
        .fetch_optional(
            sql::q(crate::queries::JOBS_LOCK_CLAIMED)
                .bind(job.id())
                .bind(job.claim_token())
                .bind(now),
        )
        .await?
        .ok_or(DbError::NotFound("job lease"))?;
    Ok(sql::opt_uuid_col(&row, "tenant_id")?.map(TenantId))
}

impl Db {
    /// Open a tenant transaction for an authorized member request.
    ///
    /// # Errors
    /// `ScopeMissing` for a nil tenant/actor, or for a scope carrying a staff grant (staff must use
    /// [`Db::tenant_tx_for_staff`] with a db-verified grant); pool/begin errors.
    pub async fn tenant_tx(&self, scope: &TenantScope) -> Result<TenantTx, DbError> {
        if scope.tenant().0.is_nil() {
            return Err(DbError::ScopeMissing("tenant id is nil"));
        }
        if scope.actor().0.is_nil() {
            return Err(DbError::ScopeMissing("actor membership is nil"));
        }
        if scope.tenant() == crate::PLATFORM_TENANT_ID {
            return Err(DbError::ScopeMissing(
                "platform pseudo-tenant has no tenant tx",
            ));
        }
        if scope.staff_grant().is_some() {
            return Err(DbError::ScopeMissing(
                "staff grant must be verified: use tenant_tx_for_staff",
            ));
        }
        Ok(TenantTx {
            inner: Inner::begin(self).await?,
            tenant: scope.tenant(),
            actor: Some(scope.actor()),
            visibility: scope.visibility().clone(),
            staff_grant: None,
            origin: TxOrigin::Request,
        })
    }

    /// Tenant tx for a staff member acting under a grant: the grant is re-verified (locked) inside
    /// this tx, the "staff access opened" `audit` row (built by the `audit` crate; must match the
    /// grant) is written in the same tx, and a `read` grant makes the tx read-only (every write repo
    /// fn returns `DbError::ReadOnly`). No acting membership, tenant-wide visibility.
    ///
    /// # Errors
    /// `Invalid` (audit mismatch), `Forbidden("staff grant not valid")`, pool/begin errors.
    pub async fn tenant_tx_for_staff(
        &self,
        grant: &VerifiedGrant,
        audit: &crate::repo::audit::AuditRowRecord,
        now: OffsetDateTime,
    ) -> Result<TenantTx, DbError> {
        if !audit_matches_grant(audit, grant) {
            return Err(DbError::Invalid("audit row does not match the staff grant"));
        }
        let mut inner = Inner::begin(self).await?;
        let verified = match crate::staff_grant::verify_inner(
            &mut inner,
            grant.staff_user(),
            grant.grant(),
            grant.tenant(),
            now,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                inner.rollback().await;
                return Err(e);
            }
        };
        let mut tx = TenantTx {
            inner,
            tenant: verified.tenant(),
            actor: None,
            visibility: Visibility::Tenant,
            staff_grant: Some(verified.grant()),
            origin: TxOrigin::Staff,
        };
        if let Err(e) = crate::repo::audit::insert_event_tenant(&mut tx, audit).await {
            tx.rollback().await;
            return Err(e);
        }
        // Scope from the freshly verified row, not from the caller's copy.
        tx.inner.read_only = verified.scope() == crate::staff_grant::GrantScope::Read;
        Ok(tx)
    }

    /// Business tx of a claimed TENANT job (lease locked, tenant from the job row).
    ///
    /// # Errors
    /// `ScopeMissing` (system job: use [`Db::system_tx_for_job`]), `NotFound("job lease")` (lost or
    /// expired lease), `TenantMismatch`.
    pub async fn tenant_tx_for_job(
        &self,
        job: &crate::jobs::ClaimedJob,
        now: OffsetDateTime,
    ) -> Result<JobTx, DbError> {
        let tenant = job
            .tenant()
            .ok_or(DbError::ScopeMissing("job has no tenant"))?;
        if tenant == crate::PLATFORM_TENANT_ID {
            return Err(DbError::ScopeMissing(
                "platform pseudo-tenant has no tenant tx",
            ));
        }
        let mut inner = Inner::begin(self).await?;
        let row_tenant = match lock_lease(&mut inner, job, now).await {
            Ok(t) => t,
            Err(e) => {
                inner.rollback().await;
                return Err(e);
            }
        };
        if row_tenant != Some(tenant) {
            inner.rollback().await;
            return Err(assert_row_tenant(
                tenant,
                row_tenant.unwrap_or(TenantId(uuid::Uuid::nil())),
            )
            .err()
            .unwrap_or(DbError::TenantMismatch));
        }
        Ok(JobTx {
            tx: TenantTx {
                inner,
                tenant,
                actor: None,
                visibility: Visibility::Tenant,
                staff_grant: None,
                origin: TxOrigin::Job { job_id: job.id() },
            },
            job_id: job.id(),
            claim_token: job.claim_token(),
        })
    }

    /// Business tx of a claimed SYSTEM (tenant-less) job.
    ///
    /// # Errors
    /// `ScopeMissing` (tenant job), `NotFound("job lease")`.
    pub async fn system_tx_for_job(
        &self,
        job: &crate::jobs::ClaimedJob,
        now: OffsetDateTime,
    ) -> Result<SystemJobTx, DbError> {
        if job.tenant().is_some() {
            return Err(DbError::ScopeMissing("tenant job: use tenant_tx_for_job"));
        }
        let mut inner = Inner::begin(self).await?;
        match lock_lease(&mut inner, job, now).await {
            Ok(None) => Ok(SystemJobTx {
                tx: SystemTx { inner },
                job_id: job.id(),
                claim_token: job.claim_token(),
            }),
            Ok(Some(_)) => {
                inner.rollback().await;
                Err(DbError::TenantMismatch)
            }
            Err(e) => {
                inner.rollback().await;
                Err(e)
            }
        }
    }

    /// # Errors
    /// Pool/begin errors.
    pub async fn identity_tx(&self) -> Result<IdentityTx, DbError> {
        Ok(IdentityTx {
            inner: Inner::begin(self).await?,
        })
    }

    /// Staff/platform tx: re-verifies `grant` inside the tx and inserts `audit` (built and hashed by
    /// the `audit` crate) through `repo::audit::insert_event_platform` in the same tx. The audit row
    /// must describe this grant: actor_kind `staff`, actor = staff user, tenant + staff_grant_id = grant.
    ///
    /// # Errors
    /// `Invalid` (audit row does not match the grant), `Forbidden("staff grant not valid")`, server errors.
    pub async fn platform_tx(
        &self,
        grant: &VerifiedGrant,
        audit: &crate::repo::audit::AuditRowRecord,
        now: OffsetDateTime,
    ) -> Result<PlatformTx, DbError> {
        if !audit_matches_grant(audit, grant) {
            return Err(DbError::Invalid("audit row does not match the staff grant"));
        }
        let mut inner = Inner::begin(self).await?;
        let verified = match crate::staff_grant::verify_inner(
            &mut inner,
            grant.staff_user(),
            grant.grant(),
            grant.tenant(),
            now,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                inner.rollback().await;
                return Err(e);
            }
        };
        if verified.scope() != crate::staff_grant::GrantScope::SupportWrite {
            inner.rollback().await;
            return Err(DbError::Forbidden(
                "read grant cannot open a platform write tx",
            ));
        }
        let mut tx = PlatformTx {
            inner,
            grant: verified,
        };
        if let Err(e) = crate::repo::audit::insert_event_platform(&mut tx, audit).await {
            tx.rollback().await;
            return Err(e);
        }
        Ok(tx)
    }

    /// # Errors
    /// Pool/begin errors.
    pub async fn system_tx(&self) -> Result<SystemTx, DbError> {
        Ok(SystemTx {
            inner: Inner::begin(self).await?,
        })
    }
}

fn audit_matches_grant(audit: &crate::repo::audit::AuditRowRecord, grant: &VerifiedGrant) -> bool {
    audit.actor_kind == "staff"
        && audit.actor_id == Some(grant.staff_user().0)
        && audit.tenant_id == Some(grant.tenant().0)
        && audit.staff_grant_id == Some(grant.grant().0)
}
