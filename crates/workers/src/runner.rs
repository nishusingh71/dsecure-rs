//! Lease-based job runner (DATABASE.md 8.4).
//!
//! One claim loop per `Runner`. Memory/DB load stay bounded:
//! - a semaphore with `concurrency` permits; a job is claimed only when a permit is free
//!   (`claim_jobs(max = free permits)`), and every task is started via [`crate::task::bounded_spawn`];
//! - the poll interval backs off (jittered) while the queue is empty;
//! - heartbeat, per-job timeout and lease-loss detection run in the job's own task (no extra tasks);
//! - the reaper and the recurring-job scheduler run inside the claim loop.
//!
//! Shutdown: stop claiming -> wait for in-flight jobs up to `shutdown_deadline` -> hard stop
//! (handlers dropped, lease released with `fail_job("shutdown")`; db has no plain "release" API).

use crate::registry::{JobContext, JobError, JobHandler, JobRegistry, sanitize_code};
use crate::task::{bounded_spawn, try_permit};
use common::Clock;
use db::{ClaimedJob, Db, DbError, NewJob};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

#[derive(Clone, Debug)]
pub struct RunnerConfig {
    /// `claimed_by` value (1..=64 bytes). Must differ per runner.
    pub worker_id: String,
    /// Max jobs in flight (`WORKER_CONCURRENCY`).
    pub concurrency: usize,
    /// Lease length written on claim and on every heartbeat.
    pub lease: time::Duration,
    /// Heartbeat period (should be well below `lease`).
    pub heartbeat_every: Duration,
    /// Poll backoff bounds when the queue is empty.
    pub poll_min: Duration,
    pub poll_max: Duration,
    pub reaper_every: Duration,
    /// Max candidates claimed per kind per round.
    pub claim_batch: u32,
    /// In-flight jobs get this long after the shutdown signal.
    pub shutdown_deadline: Duration,
    /// After the hard stop, wait this long for tasks to release their leases.
    pub shutdown_grace: Duration,
}

impl RunnerConfig {
    #[must_use]
    pub fn new(worker_id: String, concurrency: usize) -> Self {
        Self {
            worker_id,
            concurrency: concurrency.max(1),
            lease: time::Duration::seconds(30),
            heartbeat_every: Duration::from_secs(10),
            poll_min: Duration::from_secs(1),
            poll_max: Duration::from_secs(30),
            reaper_every: Duration::from_secs(60),
            claim_batch: 10,
            shutdown_deadline: Duration::from_secs(25),
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// Counters (tests and ops). All monotonic except `in_flight`.
#[derive(Debug, Default)]
pub struct RunnerStats {
    pub in_flight: AtomicUsize,
    pub max_in_flight: AtomicUsize,
    pub claimed: AtomicU64,
    pub completed: AtomicU64,
    pub retried: AtomicU64,
    pub dead: AtomicU64,
    pub timeouts: AtomicU64,
    pub lost_leases: AtomicU64,
    pub interrupted: AtomicU64,
}

struct InFlightGuard<'a>(&'a RunnerStats);

impl<'a> InFlightGuard<'a> {
    fn enter(s: &'a RunnerStats) -> Self {
        let now = s.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        s.max_in_flight.fetch_max(now, Ordering::SeqCst);
        Self(s)
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Cloneable trigger for graceful shutdown.
#[derive(Clone)]
pub struct ShutdownHandle(Arc<watch::Sender<bool>>);

impl ShutdownHandle {
    pub fn trigger(&self) {
        let _ = self.0.send(true);
    }
}

struct Shared {
    db: Db,
    clock: Arc<dyn Clock>,
    cfg: RunnerConfig,
    stats: Arc<RunnerStats>,
}

pub struct Runner {
    shared: Arc<Shared>,
    registry: JobRegistry,
    shutdown: Arc<watch::Sender<bool>>,
}

/// Jitter into 50%..100% of `d` (uuid v7 low bytes are random).
fn jitter(d: Duration) -> Duration {
    let b = u32::from(uuid::Uuid::now_v7().as_bytes()[15]);
    d * (500 + b * 500 / 255) / 1000
}

enum Ended {
    Done(Result<(), JobError>),
    Timeout,
    LostLease,
    HardStop,
}

impl Runner {
    #[must_use]
    pub fn new(db: Db, registry: JobRegistry, clock: Arc<dyn Clock>, cfg: RunnerConfig) -> Self {
        let (tx, _rx) = watch::channel(false);
        Self {
            shared: Arc::new(Shared {
                db,
                clock,
                cfg,
                stats: Arc::new(RunnerStats::default()),
            }),
            registry,
            shutdown: Arc::new(tx),
        }
    }

    #[must_use]
    pub fn stats(&self) -> Arc<RunnerStats> {
        Arc::clone(&self.shared.stats)
    }

    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle(Arc::clone(&self.shutdown))
    }

    /// Run until [`ShutdownHandle::trigger`]; returns after the drain.
    pub async fn run(&self) {
        let sh = &self.shared;
        let sem = Arc::new(Semaphore::new(sh.cfg.concurrency));
        let mut set: JoinSet<()> = JoinSet::new();
        let mut shutdown_rx = self.shutdown.subscribe();
        let (hard_tx, hard_rx) = watch::channel(false);
        let kinds = self.registry.kinds();
        let kind_sems: HashMap<&'static str, Arc<Semaphore>> = kinds
            .iter()
            .filter_map(|k| {
                let h = self.registry.get(k)?;
                let n = h.max_concurrency().clamp(1, sh.cfg.concurrency);
                Some((*k, Arc::new(Semaphore::new(n))))
            })
            .collect();
        let mut backoff = sh.cfg.poll_min;
        let mut last_reap: Option<Instant> = None;
        let mut sched: HashMap<&'static str, i64> = HashMap::new();
        let mut rotate = 0_usize;

        while !*shutdown_rx.borrow() {
            while set.try_join_next().is_some() {}
            if last_reap.is_none_or(|t| t.elapsed() >= sh.cfg.reaper_every) {
                last_reap = Some(Instant::now());
                for kind in &kinds {
                    match sh
                        .db
                        .reap_jobs_kind(sh.clock.now(), db::jobs::MAX_BATCH, Some(*kind))
                        .await
                    {
                        Ok(r) if r.requeued + r.dead > 0 => {
                            tracing::info!(kind, requeued = r.requeued, dead = r.dead, "reaper");
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(kind, error = %e, "reaper failed"),
                    }
                }
            }
            self.schedule_due(&mut sched).await;

            let mut claimed_any = false;
            if sem.available_permits() > 0 && !kinds.is_empty() {
                rotate = rotate.wrapping_add(1);
                for i in 0..kinds.len() {
                    let kind = kinds[(rotate + i) % kinds.len()];
                    let free = sem.available_permits();
                    if free == 0 {
                        break;
                    }
                    let Some(handler) = self.registry.get(kind) else {
                        continue;
                    };
                    let Some(ksem) = kind_sems.get(kind) else {
                        continue;
                    };
                    let free = free.min(ksem.available_permits());
                    if free == 0 {
                        continue;
                    }
                    let want = u32::try_from(free)
                        .unwrap_or(u32::MAX)
                        .min(sh.cfg.claim_batch);
                    let jobs = match sh
                        .db
                        .claim_jobs(&sh.cfg.worker_id, kind, sh.clock.now(), sh.cfg.lease, want)
                        .await
                    {
                        Ok(j) => j,
                        Err(e) => {
                            tracing::warn!(kind, error = %e, "claim failed");
                            continue;
                        }
                    };
                    for job in jobs {
                        // Only this loop takes permits and we asked for <= free: never None.
                        let Some(permit) = try_permit(&sem) else {
                            tracing::error!(kind, "no permit for a claimed job; lease will expire");
                            continue;
                        };
                        let Some(kind_permit) = try_permit(ksem) else {
                            tracing::error!(
                                kind,
                                "no kind permit for a claimed job; lease will expire"
                            );
                            continue;
                        };
                        claimed_any = true;
                        sh.stats.claimed.fetch_add(1, Ordering::Relaxed);
                        let shared = Arc::clone(sh);
                        let handler = Arc::clone(handler);
                        let hard = hard_rx.clone();
                        bounded_spawn(&mut set, permit, async move {
                            let _kind_permit = kind_permit;
                            execute(&shared, handler, job, hard).await;
                        });
                    }
                }
            }

            let wait = if claimed_any {
                backoff = sh.cfg.poll_min;
                Duration::ZERO
            } else if sem.available_permits() == 0 {
                sh.cfg.poll_min
            } else {
                let w = jitter(backoff);
                backoff = (backoff * 2).min(sh.cfg.poll_max);
                w
            };
            if wait.is_zero() {
                tokio::task::yield_now().await;
            } else {
                tokio::select! {
                    _ = shutdown_rx.changed() => {}
                    () = tokio::time::sleep(wait) => {}
                }
            }
        }

        // Drain: finish in-flight work with a deadline, then hard stop (releases leases).
        let deadline = tokio::time::sleep(sh.cfg.shutdown_deadline);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                r = set.join_next() => {
                    if r.is_none() {
                        break;
                    }
                }
                () = &mut deadline => {
                    let _ = hard_tx.send(true);
                    break;
                }
            }
        }
        if !set.is_empty() {
            let grace = tokio::time::timeout(sh.cfg.shutdown_grace, async {
                while set.join_next().await.is_some() {}
            })
            .await;
            if grace.is_err() {
                tracing::warn!("shutdown grace exceeded; aborting tasks (leases expire)");
                set.abort_all();
                while set.join_next().await.is_some() {}
            }
        }
        tracing::info!(worker = %sh.cfg.worker_id, "runner stopped");
    }

    /// Enqueue recurring jobs once per interval bucket (deduped across instances by `job_key`).
    async fn schedule_due(&self, last_bucket: &mut HashMap<&'static str, i64>) {
        let sh = &self.shared;
        let now = sh.clock.now();
        for kind in self.registry.kinds() {
            let Some(h) = self.registry.get(kind) else {
                continue;
            };
            let Some(every) = h.schedule() else {
                continue;
            };
            let bucket = if h.singleton() {
                0 // one seed for the whole life of the system; the handler chains its successors
            } else {
                now.unix_timestamp() / i64::try_from(every.as_secs().max(1)).unwrap_or(1)
            };
            if last_bucket.get(kind) == Some(&bucket) {
                continue;
            }
            let job = NewJob {
                kind,
                job_key: if h.singleton() {
                    format!("{kind}:seed")
                } else {
                    format!("{kind}:{bucket}")
                },
                payload: serde_json::json!({}),
                run_after: now,
                max_attempts: h.max_attempts(),
                max_pending: None,
            };
            let res = async {
                let mut tx = sh.db.system_tx().await?;
                match db::jobs::enqueue_system(&mut tx, &job, now).await {
                    Ok(r) => tx.commit().await.map(|()| r),
                    Err(e) => {
                        tx.rollback().await;
                        Err(e)
                    }
                }
            }
            .await;
            match res {
                Ok(_) => {
                    last_bucket.insert(kind, bucket);
                }
                Err(e) => tracing::warn!(kind, error = %e, "schedule enqueue failed"),
            }
        }
    }
}

async fn execute(
    sh: &Shared,
    handler: Arc<dyn JobHandler>,
    mut job: ClaimedJob,
    mut hard: watch::Receiver<bool>,
) {
    let _in_flight = InFlightGuard::enter(&sh.stats);
    let kind = handler.kind();
    let started = Instant::now();
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let ctx = JobContext::new(job.clone(), sh.db.clone(), Arc::clone(&sh.clock), cancel_rx);
    let ended = {
        let fut = handler.handle(&ctx);
        tokio::pin!(fut);
        let timeout = tokio::time::sleep(handler.timeout());
        tokio::pin!(timeout);
        let mut hb = tokio::time::interval_at(
            tokio::time::Instant::now() + sh.cfg.heartbeat_every,
            sh.cfg.heartbeat_every,
        );
        hb.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                r = &mut fut => break Ended::Done(r),
                () = &mut timeout => break Ended::Timeout,
                _ = hard.changed() => break Ended::HardStop,
                _ = hb.tick() => {
                    match sh.db.heartbeat_job(&mut job, sh.clock.now(), sh.cfg.lease).await {
                        Ok(()) => {}
                        Err(DbError::NotPersisted { .. }) => break Ended::LostLease,
                        Err(e) => tracing::warn!(kind, error = %e, "heartbeat failed"),
                    }
                }
            }
        }
    };
    let _ = cancel_tx.send(true);
    let elapsed = started.elapsed();
    let st = &sh.stats;
    match ended {
        Ended::Done(Ok(())) if handler.completes_in_tx() => {
            st.completed.fetch_add(1, Ordering::SeqCst);
            telemetry::meters::record_job(kind, telemetry::JobOutcome::Ok, elapsed);
        }
        Ended::Done(Ok(())) => match sh.db.complete_job(&job, sh.clock.now()).await {
            Ok(()) => {
                st.completed.fetch_add(1, Ordering::SeqCst);
                telemetry::meters::record_job(kind, telemetry::JobOutcome::Ok, elapsed);
            }
            Err(DbError::NotPersisted { .. }) => {
                st.lost_leases.fetch_add(1, Ordering::SeqCst);
                tracing::warn!(
                    kind,
                    "lease lost before completion; another worker owns the job"
                );
            }
            Err(e) => tracing::warn!(kind, error = %e, "complete failed; lease will expire"),
        },
        Ended::Done(Err(e)) => fail(sh, &job, kind, &e.code, elapsed).await,
        Ended::Timeout => {
            st.timeouts.fetch_add(1, Ordering::SeqCst);
            fail(sh, &job, kind, "timeout", elapsed).await;
        }
        Ended::HardStop => {
            st.interrupted.fetch_add(1, Ordering::SeqCst);
            // Back to queued without consuming the attempt or adding backoff.
            match sh.db.release_job(&job).await {
                Ok(()) => {}
                Err(DbError::NotPersisted { .. }) => {
                    st.lost_leases.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => tracing::warn!(kind, error = %e, "release_job failed; lease will expire"),
            }
        }
        Ended::LostLease => {
            st.lost_leases.fetch_add(1, Ordering::SeqCst);
            tracing::warn!(kind, "heartbeat: lease lost, handler dropped");
        }
    }
}

async fn fail(sh: &Shared, job: &ClaimedJob, kind: &'static str, code: &str, elapsed: Duration) {
    let code = sanitize_code(code);
    match sh.db.fail_job(job, &code, sh.clock.now()).await {
        Ok(()) => {
            if job.attempts() >= job.max_attempts() {
                sh.stats.dead.fetch_add(1, Ordering::SeqCst);
                telemetry::meters::record_job(kind, telemetry::JobOutcome::Failed, elapsed);
            } else {
                sh.stats.retried.fetch_add(1, Ordering::SeqCst);
                telemetry::meters::record_job(kind, telemetry::JobOutcome::Retried, elapsed);
            }
        }
        Err(DbError::NotPersisted { .. }) => {
            sh.stats.lost_leases.fetch_add(1, Ordering::SeqCst);
        }
        Err(e) => tracing::warn!(kind, error = %e, "fail_job failed; lease will expire"),
    }
}
