//! Job queue without `SKIP LOCKED` (DATABASE.md §8.4): snapshot candidates -> per-candidate
//! conditional `UPDATE ... WHERE status='queued'` (rows_affected = 1 = owned) -> heartbeat / complete /
//! fail with `claim_token` -> reaper requeues expired leases. Same behaviour on MySQL and TiDB.
//! Handlers must be idempotent (a lost lease can mean a second run).

use crate::error::DbError;
use crate::pool::Db;
use crate::queries::{
    JOBS_CANDIDATES, JOBS_CLAIM, JOBS_COMPLETE, JOBS_COUNT_PENDING_TENANT, JOBS_DEAD,
    JOBS_GET_CLAIMED, JOBS_GET_STATUS, JOBS_HEARTBEAT, JOBS_INSERT, JOBS_REAP_CANDIDATES,
    JOBS_REAP_CANDIDATES_KIND, JOBS_REAP_DEAD_ONE, JOBS_REAP_REQUEUE_ONE, JOBS_RELEASE, JOBS_RETRY,
};
use crate::sql;
use crate::tx::{Inner, SystemTx, TenantTx};
use crate::write_guard::WriteOutcome;
use common::TenantId;
use time::{Duration, OffsetDateTime};

/// App cap on job payload (4 KB, ids only).
pub const MAX_PAYLOAD_BYTES: usize = 4096;
/// Upper bound of candidates per claim round and rows per reaper statement.
pub const MAX_BATCH: u32 = 100;

#[derive(Clone, Debug)]
pub struct NewJob {
    pub kind: &'static str,
    /// Globally unique dedupe key (e.g. `"export:<tenant>:<request>"`).
    pub job_key: String,
    pub payload: serde_json::Value,
    pub run_after: OffsetDateTime,
    pub max_attempts: u32,
    /// Per-tenant cap of queued+running jobs of this kind (`None` = no cap).
    pub max_pending: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueued {
    New(uuid::Uuid),
    /// Same `job_key` already exists (idempotent enqueue).
    Duplicate,
}

/// A job owned by this worker. Not constructible outside `db` (tenant/lease come from the row).
#[derive(Clone, Debug)]
pub struct ClaimedJob {
    id: uuid::Uuid,
    kind: String,
    tenant: Option<TenantId>,
    payload: serde_json::Value,
    attempts: u32,
    max_attempts: u32,
    claim_token: uuid::Uuid,
    lease_until: OffsetDateTime,
}

impl ClaimedJob {
    #[must_use]
    pub const fn id(&self) -> uuid::Uuid {
        self.id
    }
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }
    #[must_use]
    pub const fn tenant(&self) -> Option<TenantId> {
        self.tenant
    }
    #[must_use]
    pub const fn payload(&self) -> &serde_json::Value {
        &self.payload
    }
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
    #[must_use]
    pub const fn lease_until(&self) -> OffsetDateTime {
        self.lease_until
    }
    pub(crate) const fn claim_token(&self) -> uuid::Uuid {
        self.claim_token
    }

    /// Test fixture (feature `test-fixtures`): a job value for unit tests of other crates. Using it
    /// against a real DB only works with the real `claim_token` (the lease is always re-checked).
    #[cfg(feature = "test-fixtures")]
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn for_tests(
        id: uuid::Uuid,
        kind: &str,
        tenant: Option<TenantId>,
        payload: serde_json::Value,
        attempts: u32,
        max_attempts: u32,
        claim_token: uuid::Uuid,
        lease_until: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            kind: kind.to_owned(),
            tenant,
            payload,
            attempts,
            max_attempts,
            claim_token,
            lease_until,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Reaped {
    pub requeued: u64,
    pub dead: u64,
}

fn payload_ok(p: &serde_json::Value) -> Result<(), DbError> {
    let n = serde_json::to_vec(p)
        .map_err(|_| DbError::Invalid("job payload not serialisable"))?
        .len();
    if n > MAX_PAYLOAD_BYTES {
        return Err(DbError::Invalid("job payload too large"));
    }
    Ok(())
}

async fn enqueue_inner(
    inner: &mut Inner,
    tenant: Option<TenantId>,
    j: &NewJob,
    now: OffsetDateTime,
) -> Result<Enqueued, DbError> {
    payload_ok(&j.payload)?;
    if j.job_key.is_empty() || j.job_key.len() > 160 {
        return Err(DbError::Invalid("job_key must be 1..=160 bytes"));
    }
    if let (Some(t), Some(max)) = (tenant, j.max_pending) {
        // Per-tenant mutex (tenant_counters row) so parallel enqueues cannot both pass the cap (F7).
        crate::repo::counters::lock(inner, t, crate::repo::counters::Counter::Members).await?;
        let row = inner
            .fetch_optional(sql::q(JOBS_COUNT_PENDING_TENANT).bind(t.0).bind(j.kind))
            .await?
            .ok_or(DbError::Corrupt("count"))?;
        let n: i64 = sql::col(&row, "n")?;
        if n >= i64::from(max) {
            return Err(DbError::QuotaExceeded {
                quota: "jobs.max_pending",
                limit: max,
                current: u32::try_from(n).unwrap_or(u32::MAX),
            });
        }
    }
    let id = uuid::Uuid::now_v7();
    match inner
        .execute(
            sql::q(JOBS_INSERT)
                .bind(id)
                .bind(j.kind)
                .bind(j.job_key.as_str())
                .bind(tenant.map(|t| t.0))
                .bind(&j.payload)
                .bind(j.run_after)
                .bind(j.max_attempts.max(1))
                .bind(now),
        )
        .await
    {
        Ok(n) => {
            n.expect_one()?;
            Ok(Enqueued::New(id))
        }
        Err(e) if e.is_duplicate_of("ux_jobs_key") => Ok(Enqueued::Duplicate),
        Err(e) => Err(e),
    }
}

/// Enqueue a job of the tx tenant (same tx as the business write).
///
/// # Errors
/// `Invalid`, `QuotaExceeded("jobs.max_pending")`, server errors.
pub async fn enqueue(
    tx: &mut TenantTx,
    j: &NewJob,
    now: OffsetDateTime,
) -> Result<Enqueued, DbError> {
    let t = tx.tenant();
    enqueue_inner(&mut tx.inner, Some(t), j, now).await
}

/// Enqueue a tenant-less system job.
///
/// # Errors
/// `Invalid`, server errors.
pub async fn enqueue_system(
    tx: &mut SystemTx,
    j: &NewJob,
    now: OffsetDateTime,
) -> Result<Enqueued, DbError> {
    enqueue_inner(&mut tx.inner, None, j, now).await
}

/// Cheap pseudo-random shuffle so concurrent workers do not all race for the same first row.
fn shuffle(ids: &mut [uuid::Uuid]) {
    for i in (1..ids.len()).rev() {
        let r = usize::from(uuid::Uuid::now_v7().as_bytes()[15]) % (i + 1);
        ids.swap(i, r);
    }
}

impl Db {
    /// Claim up to `max` due jobs of `kind` for `worker` with a lease of `lease`.
    ///
    /// # Errors
    /// Server errors (already-claimed rows are skipped, not errors).
    pub async fn claim_jobs(
        &self,
        worker: &str,
        kind: &str,
        now: OffsetDateTime,
        lease: Duration,
        max: u32,
    ) -> Result<Vec<ClaimedJob>, DbError> {
        if worker.is_empty() || worker.len() > 64 {
            return Err(DbError::Invalid("worker id must be 1..=64 bytes"));
        }
        let limit = max.clamp(1, MAX_BATCH);
        let mut tx = self.system_tx().await?;
        let rows = tx
            .inner
            .fetch_all(sql::q(JOBS_CANDIDATES).bind(kind).bind(now).bind(limit))
            .await?;
        tx.commit().await?;
        let mut ids = rows
            .iter()
            .map(|r| sql::uuid_col(r, "id"))
            .collect::<Result<Vec<_>, _>>()?;
        shuffle(&mut ids);

        let lease_until = now + lease;
        let mut out = Vec::new();
        for id in ids {
            let token = uuid::Uuid::now_v7();
            // Each claim is its own short autocommit-style tx: row lock only on that one job row.
            let mut tx = self.system_tx().await?;
            let n = tx
                .inner
                .execute(
                    sql::q(JOBS_CLAIM)
                        .bind(worker)
                        .bind(token)
                        .bind(lease_until)
                        .bind(id)
                        .bind(now),
                )
                .await?;
            if n != 1 {
                tx.rollback().await;
                continue; // another worker won
            }
            let row = tx
                .inner
                .fetch_optional(sql::q(JOBS_GET_CLAIMED).bind(id).bind(token))
                .await?
                .ok_or(DbError::NotPersisted {
                    expected: 1,
                    actual: 0,
                })?;
            tx.commit().await?;
            out.push(ClaimedJob {
                id,
                kind: sql::col(&row, "kind")?,
                tenant: sql::opt_uuid_col(&row, "tenant_id")?.map(TenantId),
                payload: sql::col(&row, "payload")?,
                attempts: u32::try_from(sql::col::<i32>(&row, "attempts")?)
                    .map_err(|_| DbError::Corrupt("jobs.attempts"))?,
                max_attempts: u32::try_from(sql::col::<i32>(&row, "max_attempts")?)
                    .map_err(|_| DbError::Corrupt("jobs.max_attempts"))?,
                claim_token: token,
                lease_until: sql::col(&row, "lease_until")?,
            });
            if out.len() >= usize::try_from(limit).unwrap_or(usize::MAX) {
                break;
            }
        }
        Ok(out)
    }

    async fn job_write(&self, q: crate::sql::Q<'_>) -> Result<(), DbError> {
        let mut tx = self.system_tx().await?;
        match tx.inner.execute(q).await.and_then(WriteOutcome::expect_one) {
            Ok(()) => tx.commit().await,
            Err(e) => {
                tx.rollback().await;
                Err(e)
            }
        }
    }

    /// Extend the lease. `NotPersisted` = lease lost (stop working on it).
    ///
    /// # Errors
    /// `NotPersisted`, server errors.
    pub async fn heartbeat_job(
        &self,
        job: &mut ClaimedJob,
        now: OffsetDateTime,
        lease: Duration,
    ) -> Result<(), DbError> {
        let until = now + lease;
        self.job_write(
            sql::q(JOBS_HEARTBEAT)
                .bind(until)
                .bind(job.id)
                .bind(job.claim_token),
        )
        .await?;
        job.lease_until = until;
        Ok(())
    }

    /// Mark succeeded in its own tx. ONLY for handlers without a DB business write; handlers that
    /// write must use `Db::tenant_tx_for_job` / `Db::system_tx_for_job` and `JobTx::complete`
    /// (same tx, no double apply). `NotPersisted` = lease lost meanwhile.
    ///
    /// # Errors
    /// `NotPersisted`, server errors.
    pub async fn complete_job(&self, job: &ClaimedJob, now: OffsetDateTime) -> Result<(), DbError> {
        self.job_write(
            sql::q(JOBS_COMPLETE)
                .bind(now)
                .bind(job.id)
                .bind(job.claim_token),
        )
        .await
    }

    /// Failure: requeue with exponential backoff (30 s * 2^attempts, max 1 h) or `dead` after
    /// `max_attempts`. `error_code` is a short code, never a message with data.
    ///
    /// # Errors
    /// `NotPersisted` (lease lost), `Invalid`, server errors.
    pub async fn fail_job(
        &self,
        job: &ClaimedJob,
        error_code: &str,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        if error_code.is_empty()
            || error_code.len() > 48
            || !error_code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        {
            return Err(DbError::Invalid(
                "error_code must be a short [a-z0-9_.] code",
            ));
        }
        if job.attempts >= job.max_attempts {
            return self
                .job_write(
                    sql::q(JOBS_DEAD)
                        .bind(now)
                        .bind(error_code)
                        .bind(job.id)
                        .bind(job.claim_token),
                )
                .await;
        }
        let secs = 30_i64
            .saturating_mul(1_i64 << job.attempts.min(7))
            .min(3600);
        self.job_write(
            sql::q(JOBS_RETRY)
                .bind(now + Duration::seconds(secs))
                .bind(error_code)
                .bind(job.id)
                .bind(job.claim_token),
        )
        .await
    }

    /// Reaper: expired leases -> `queued` (attempts left) or `dead`. Candidates come from a snapshot
    /// read; each job is then updated by PK with the lease condition re-checked, so no index range is
    /// locked (a bulk `UPDATE ... LIMIT` deadlocked against an open job tx on MySQL, 1213) and a job
    /// whose `JobTx` is still open is waited for and then left alone. `kind` limits the sweep.
    ///
    /// # Errors
    /// Server errors.
    pub async fn reap_jobs_kind(
        &self,
        now: OffsetDateTime,
        limit: u32,
        kind: Option<&str>,
    ) -> Result<Reaped, DbError> {
        let limit = limit.clamp(1, MAX_BATCH);
        let mut tx = self.system_tx().await?;
        let rows = match kind {
            None => {
                tx.inner
                    .fetch_all(sql::q(JOBS_REAP_CANDIDATES).bind(now).bind(limit))
                    .await?
            }
            Some(k) => {
                tx.inner
                    .fetch_all(
                        sql::q(JOBS_REAP_CANDIDATES_KIND)
                            .bind(now)
                            .bind(k)
                            .bind(limit),
                    )
                    .await?
            }
        };
        tx.commit().await?;
        let mut out = Reaped::default();
        for r in &rows {
            let id = sql::uuid_col(r, "id")?;
            // One short tx per job: only that row is locked.
            let mut tx = self.system_tx().await?;
            let requeued = tx
                .inner
                .execute(sql::q(JOBS_REAP_REQUEUE_ONE).bind(now).bind(id).bind(now))
                .await?;
            let dead = if requeued == 0 {
                tx.inner
                    .execute(sql::q(JOBS_REAP_DEAD_ONE).bind(now).bind(id).bind(now))
                    .await?
            } else {
                0
            };
            tx.commit().await?;
            out.requeued += requeued;
            out.dead += dead;
        }
        Ok(out)
    }

    /// All kinds (unchanged signature): `reap_jobs_kind(now, limit, None)`.
    ///
    /// # Errors
    /// Server errors.
    pub async fn reap_jobs(&self, now: OffsetDateTime, limit: u32) -> Result<Reaped, DbError> {
        self.reap_jobs_kind(now, limit, None).await
    }

    /// Graceful shutdown: give the job back (`queued`) WITHOUT consuming the attempt and without
    /// backoff. `NotPersisted` = lease already lost.
    ///
    /// # Errors
    /// `NotPersisted`, server errors.
    pub async fn release_job(&self, job: &ClaimedJob) -> Result<(), DbError> {
        self.job_write(sql::q(JOBS_RELEASE).bind(job.id).bind(job.claim_token))
            .await
    }

    /// Status + attempts of a job (ops/tests).
    ///
    /// # Errors
    /// `NotFound`, server errors.
    pub async fn job_status(&self, id: uuid::Uuid) -> Result<(String, u32), DbError> {
        let mut tx = self.system_tx().await?;
        let row = tx
            .inner
            .fetch_optional(sql::q(JOBS_GET_STATUS).bind(id))
            .await?
            .ok_or(DbError::NotFound("job"))?;
        tx.commit().await?;
        Ok((
            sql::col(&row, "status")?,
            u32::try_from(sql::col::<i32>(&row, "attempts")?)
                .map_err(|_| DbError::Corrupt("jobs.attempts"))?,
        ))
    }
}
