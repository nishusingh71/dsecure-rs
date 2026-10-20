//! Job registry: `JobHandler` per job kind.

use async_trait::async_trait;
use common::Clock;
use db::{ClaimedJob, Db, DbError};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Handler failure. `code` is a short `[a-z0-9_.]` code (stored in `jobs.last_error_code`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobError {
    pub code: String,
}

impl JobError {
    #[must_use]
    pub fn new(code: &str) -> Self {
        Self {
            code: sanitize_code(code),
        }
    }
}

/// Force a code into what `Db::fail_job` accepts (1..=48 of `[A-Za-z0-9_.]`).
#[must_use]
pub fn sanitize_code(code: &str) -> String {
    let s: String = code
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    if s.is_empty() {
        String::from("error")
    } else {
        s
    }
}

/// What a handler gets: the claimed job, the db, and a cancel signal (lease lost / hard stop).
pub struct JobContext {
    pub job: ClaimedJob,
    pub db: Db,
    clock: Arc<dyn Clock>,
    cancel: watch::Receiver<bool>,
}

impl JobContext {
    #[must_use]
    pub fn new(
        job: ClaimedJob,
        db: Db,
        clock: Arc<dyn Clock>,
        cancel: watch::Receiver<bool>,
    ) -> Self {
        Self {
            job,
            db,
            clock,
            cancel,
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.cancel.borrow()
    }

    #[must_use]
    pub fn now(&self) -> time::OffsetDateTime {
        self.clock.now()
    }

    /// For tenant-less jobs whose work already finished: open the job tx (re-checks and locks the
    /// lease) and complete it. `completes_in_tx` handlers end with this (or do their writes on
    /// `db.tenant_tx_for_job(..)` / `db.system_tx_for_job(..)` and call `.complete(now)` there).
    ///
    /// # Errors
    /// `lease_lost` (lease expired or taken over), `db_error`.
    pub async fn complete_system(&self) -> Result<(), JobError> {
        let now = self.now();
        let tx = self
            .db
            .system_tx_for_job(&self.job, now)
            .await
            .map_err(map_job_tx_err)?;
        tx.complete(now).await.map_err(map_job_tx_err)
    }
}

/// `NotFound("job lease")` / `NotPersisted` = the lease is gone.
#[must_use]
pub fn map_job_tx_err(e: DbError) -> JobError {
    match e {
        DbError::NotFound(_) | DbError::NotPersisted { .. } => JobError::new("lease_lost"),
        _ => JobError::new("db_error"),
    }
}

/// Handlers must be idempotent: a lost lease can mean a second run (at-least-once).
#[async_trait]
pub trait JobHandler: Send + Sync {
    fn kind(&self) -> &'static str;

    /// Per-job timeout (the runner drops the handler future after this).
    fn timeout(&self) -> Duration {
        Duration::from_secs(300)
    }

    /// Recurring job: the runner enqueues one job per interval (deduped by `job_key`).
    fn schedule(&self) -> Option<Duration> {
        None
    }

    /// Exactly one live job of this kind across all instances: the scheduler enqueues only the
    /// one-time `kind:seed` job and the handler chains its successor in its completion tx.
    fn singleton(&self) -> bool {
        false
    }

    /// Max jobs of this kind in flight at once (per-kind semaphore, ARCHITECTURE section 9).
    /// Default = no extra limit beyond `WORKER_CONCURRENCY`.
    fn max_concurrency(&self) -> usize {
        usize::MAX
    }

    /// Attempts before the job goes `dead`.
    fn max_attempts(&self) -> u32 {
        5
    }

    /// `true` = the handler completes the job itself inside its own db transaction (job-tx API),
    /// so the runner must not call `complete_job` after `Ok`.
    fn completes_in_tx(&self) -> bool {
        false
    }

    async fn handle(&self, ctx: &JobContext) -> Result<(), JobError>;
}

#[derive(Default, Clone)]
pub struct JobRegistry {
    handlers: HashMap<&'static str, Arc<dyn JobHandler>>,
}

impl JobRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Later registration of the same kind replaces the earlier one.
    pub fn register(&mut self, h: Arc<dyn JobHandler>) {
        self.handlers.insert(h.kind(), h);
    }

    #[must_use]
    pub fn get(&self, kind: &str) -> Option<&Arc<dyn JobHandler>> {
        self.handlers.get(kind)
    }

    /// Kinds in a stable order.
    #[must_use]
    pub fn kinds(&self) -> Vec<&'static str> {
        let mut k: Vec<&'static str> = self.handlers.keys().copied().collect();
        k.sort_unstable();
        k
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}
