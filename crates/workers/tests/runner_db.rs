//! Runner tests against the LOCAL MySQL 8.4 (127.0.0.1:3307, db `dsecure_test`) only.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // test helpers (clippy.toml only exempts #[test] fns)
//! Credentials come from `.dev/dev.env` and are never printed. Every test uses its own unique job
//! kind, so tests do not see each other's rows. Missing file/server = `SKIP` (test returns).

use async_trait::async_trait;
use common::{Clock, FixedClock};
use db::Db;
use db::jobs::{self, NewJob};
use futures_util::FutureExt as _;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::sync::Notify;
use workers::jobs::testing::InMemoryPublisher;
use workers::jobs::{DbOutboxStore, OutboxRelayJob};
use workers::registry::{JobContext, JobError, JobHandler, JobRegistry};
use workers::runner::{Runner, RunnerConfig, RunnerStats};

/// Own scratch database per test (dropped at the end, also after a panic). Without the local
/// dev env / server the test prints SKIP and returns.
async fn with_scratch<F, Fut>(test: &str, f: F)
where
    F: FnOnce(Db) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let env = match db::testing::load_env() {
        Ok(e) => e,
        Err(why) => {
            eprintln!("SKIP {test}: {why}");
            return;
        }
    };
    let scratch = match db::testing::ScratchDb::create(&env).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SKIP {test}: scratch db failed ({e})");
            return;
        }
    };
    let db = scratch.app().unwrap_or_else(|| scratch.migrator()).clone();
    let res = std::panic::AssertUnwindSafe(f(db)).catch_unwind().await;
    let _ = scratch.drop_db(&env).await;
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

fn kind_for(test: &str) -> &'static str {
    let id = uuid::Uuid::now_v7().simple().to_string();
    Box::leak(format!("t.{}.{}", &test[..test.len().min(14)], &id[20..]).into_boxed_str())
}

fn micros_now() -> OffsetDateTime {
    let n = OffsetDateTime::now_utc();
    n.replace_nanosecond(n.nanosecond() / 1000 * 1000)
        .unwrap_or(n)
}

async fn enqueue(
    db: &Db,
    kind: &'static str,
    n: usize,
    max_attempts: u32,
    at: OffsetDateTime,
) -> Vec<uuid::Uuid> {
    let mut ids = Vec::new();
    let mut tx = db.system_tx().await.expect("tx");
    for i in 0..n {
        let r = jobs::enqueue_system(
            &mut tx,
            &NewJob {
                kind,
                job_key: format!("{kind}:{i}"),
                payload: serde_json::json!({"i": i}),
                run_after: at,
                max_attempts,
                max_pending: None,
            },
            at,
        )
        .await
        .expect("enqueue");
        match r {
            jobs::Enqueued::New(id) => ids.push(id),
            jobs::Enqueued::Duplicate => panic!("duplicate"),
        }
    }
    tx.commit().await.expect("commit");
    ids
}

/// Configurable test handler.
struct H {
    kind: &'static str,
    timeout: Duration,
    work: Duration,
    /// Attempt 1 blocks on this gate (if set) instead of working.
    gate: Option<Arc<Notify>>,
    cap: usize,
    complete_in_tx: bool,
    runs: Mutex<HashMap<uuid::Uuid, u32>>,
    active: AtomicUsize,
    max_active: AtomicUsize,
}

impl H {
    fn new(kind: &'static str, timeout: Duration, work: Duration) -> Self {
        Self {
            kind,
            timeout,
            work,
            gate: None,
            cap: usize::MAX,
            complete_in_tx: false,
            runs: Mutex::default(),
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        }
    }
    fn runs(&self) -> HashMap<uuid::Uuid, u32> {
        self.runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl JobHandler for H {
    fn kind(&self) -> &'static str {
        self.kind
    }
    fn timeout(&self) -> Duration {
        self.timeout
    }
    fn max_concurrency(&self) -> usize {
        self.cap
    }
    fn completes_in_tx(&self) -> bool {
        self.complete_in_tx
    }
    async fn handle(&self, ctx: &JobContext) -> Result<(), JobError> {
        *self
            .runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(ctx.job.id())
            .or_insert(0) += 1;
        let a = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(a, Ordering::SeqCst);
        if let (Some(g), 1) = (&self.gate, ctx.job.attempts()) {
            g.notified().await;
        } else {
            tokio::time::sleep(self.work).await;
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        if self.complete_in_tx {
            ctx.complete_system().await?;
        }
        Ok(())
    }
}

fn registry(h: &Arc<H>) -> JobRegistry {
    let mut r = JobRegistry::new();
    r.register(Arc::clone(h) as Arc<dyn JobHandler>);
    r
}

fn fast_cfg(name: &str, concurrency: usize) -> RunnerConfig {
    let mut c = RunnerConfig::new(name.to_owned(), concurrency);
    c.poll_min = Duration::from_millis(10);
    c.poll_max = Duration::from_millis(40);
    c.reaper_every = Duration::from_secs(3600);
    c.heartbeat_every = Duration::from_secs(3600);
    c.shutdown_deadline = Duration::from_secs(5);
    c.shutdown_grace = Duration::from_secs(2);
    c
}

async fn wait_until<F: Fn() -> bool>(what: &str, f: F) {
    let t = Instant::now();
    while !f() {
        assert!(
            t.elapsed() < Duration::from_secs(30),
            "timeout waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_status(db: &Db, id: uuid::Uuid, want: &str) -> (String, u32) {
    let t = Instant::now();
    loop {
        let (s, a) = db.job_status(id).await.expect("status");
        if s == want {
            return (s, a);
        }
        assert!(
            t.elapsed() < Duration::from_secs(30),
            "job stuck in {s}, wanted {want}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn sys_clock() -> Arc<FixedClock> {
    Arc::new(FixedClock::new(micros_now()))
}

fn spawn_runner(r: &Arc<Runner>) -> tokio::task::JoinHandle<()> {
    let r = Arc::clone(r);
    // Test-only: the runner itself never uses tokio::spawn.
    #[allow(clippy::disallowed_methods)]
    tokio::spawn(async move { r.run().await })
}

fn make(db: &Db, h: &Arc<H>, clock: &Arc<FixedClock>, cfg: RunnerConfig) -> Arc<Runner> {
    let clk: Arc<dyn Clock> = Arc::clone(clock) as Arc<dyn Clock>;
    Arc::new(Runner::new(db.clone(), registry(h), clk, cfg))
}

#[tokio::test]
async fn two_runners_claim_disjoint_jobs_each_runs_once() {
    with_scratch("disjoint", |db| async move {
        let kind = kind_for("disjoint");
        let clock = sys_clock();
        let ids = enqueue(&db, kind, 30, 3, clock.now()).await;
        let h = Arc::new(H::new(
            kind,
            Duration::from_secs(10),
            Duration::from_millis(20),
        ));
        let a = make(&db, &h, &clock, fast_cfg("wa", 3));
        let b = make(&db, &h, &clock, fast_cfg("wb", 3));
        let (ja, jb) = (spawn_runner(&a), spawn_runner(&b));
        let (sa, sb): (Arc<RunnerStats>, Arc<RunnerStats>) = (a.stats(), b.stats());
        wait_until("all completed", || {
            sa.completed.load(Ordering::SeqCst) + sb.completed.load(Ordering::SeqCst) == 30
        })
        .await;
        a.shutdown_handle().trigger();
        b.shutdown_handle().trigger();
        ja.await.expect("a");
        jb.await.expect("b");
        let runs = h.runs();
        assert_eq!(runs.len(), 30);
        assert!(runs.values().all(|n| *n == 1), "a job ran twice");
        for id in ids {
            assert_eq!(
                db.job_status(id).await.expect("st"),
                ("succeeded".to_owned(), 1)
            );
        }
        assert_eq!(
            sa.claimed.load(Ordering::SeqCst) + sb.claimed.load(Ordering::SeqCst),
            30
        );
    })
    .await;
}

#[tokio::test]
async fn timeout_is_retried_then_dead_lettered() {
    with_scratch("timeout", |db| async move {
        let kind = kind_for("timeout");
        let clock = sys_clock();
        let ids = enqueue(&db, kind, 1, 2, clock.now()).await;
        let h = Arc::new(H::new(
            kind,
            Duration::from_millis(100),
            Duration::from_secs(3600),
        ));
        let r = make(&db, &h, &clock, fast_cfg("wt", 1));
        let j = spawn_runner(&r);
        let st = r.stats();
        wait_until("first retry", || st.retried.load(Ordering::SeqCst) == 1).await;
        assert_eq!(
            db.job_status(ids[0]).await.expect("st"),
            ("queued".to_owned(), 1)
        );
        clock.advance(time::Duration::hours(2)); // past the backoff
        wait_until("dead", || st.dead.load(Ordering::SeqCst) == 1).await;
        r.shutdown_handle().trigger();
        j.await.expect("run");
        assert_eq!(
            db.job_status(ids[0]).await.expect("st"),
            ("dead".to_owned(), 2)
        );
        assert_eq!(st.timeouts.load(Ordering::SeqCst), 2);
        assert_eq!(st.completed.load(Ordering::SeqCst), 0);
    })
    .await;
}

#[tokio::test]
async fn expired_lease_is_reaped_without_double_completion() {
    with_scratch("lease", |db| async move {
        let kind = kind_for("lease");
        let clock = sys_clock();
        let ids = enqueue(&db, kind, 1, 3, clock.now()).await;
        let gate = Arc::new(Notify::new());
        let mut h0 = H::new(kind, Duration::from_secs(60), Duration::ZERO);
        h0.gate = Some(Arc::clone(&gate));
        let h = Arc::new(h0);
        // A: no heartbeat, no reaping of its own; its attempt-1 handler blocks on the gate.
        let a = make(&db, &h, &clock, fast_cfg("wa", 1));
        let ja = spawn_runner(&a);
        wait_until("A running the job", || h.runs().len() == 1).await;
        // B: has a fast reaper. Lease (30 s) expires on the shared clock while A's handler still runs.
        let mut cb = fast_cfg("wb", 1);
        cb.reaper_every = Duration::from_millis(20);
        let b = make(&db, &h, &clock, cb);
        let jb = spawn_runner(&b);
        clock.advance(time::Duration::seconds(31));
        let (status, attempts) = wait_status(&db, ids[0], "succeeded").await;
        assert_eq!((status.as_str(), attempts), ("succeeded", 2));
        // A's handler now finishes: its completion must be rejected (lease lost), not applied twice.
        gate.notify_one();
        wait_until("A saw the lost lease", || {
            a.stats().lost_leases.load(Ordering::SeqCst) == 1
        })
        .await;
        a.shutdown_handle().trigger();
        b.shutdown_handle().trigger();
        ja.await.expect("a");
        jb.await.expect("b");
        assert_eq!(a.stats().completed.load(Ordering::SeqCst), 0);
        assert_eq!(b.stats().completed.load(Ordering::SeqCst), 1);
        assert_eq!(db.job_status(ids[0]).await.expect("st").0, "succeeded");
    })
    .await;
}

#[tokio::test]
async fn shutdown_releases_leases_of_unfinished_jobs() {
    with_scratch("shutdown", |db| async move {
        let kind = kind_for("shutdown");
        let clock = sys_clock();
        let ids = enqueue(&db, kind, 1, 3, clock.now()).await;
        let h = Arc::new(H::new(
            kind,
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        ));
        let mut cfg = fast_cfg("ws", 1);
        cfg.shutdown_deadline = Duration::from_millis(200);
        let r = make(&db, &h, &clock, cfg);
        let j = spawn_runner(&r);
        let st = r.stats();
        wait_until("job in flight", || st.in_flight.load(Ordering::SeqCst) == 1).await;
        assert_eq!(db.job_status(ids[0]).await.expect("st").0, "running");
        r.shutdown_handle().trigger();
        tokio::time::timeout(Duration::from_secs(10), j)
            .await
            .expect("run() returns after the deadline")
            .expect("join");
        // Lease released with release_job: queued again, attempt NOT consumed, nothing in flight.
        assert_eq!(
            db.job_status(ids[0]).await.expect("st"),
            ("queued".to_owned(), 0)
        );
        assert_eq!(st.interrupted.load(Ordering::SeqCst), 1);
        assert_eq!(st.in_flight.load(Ordering::SeqCst), 0);
    })
    .await;
}

#[tokio::test]
async fn shutdown_lets_in_flight_jobs_finish_within_deadline() {
    with_scratch("drain", |db| async move {
        let kind = kind_for("drain");
        let clock = sys_clock();
        let ids = enqueue(&db, kind, 1, 3, clock.now()).await;
        let h = Arc::new(H::new(
            kind,
            Duration::from_secs(60),
            Duration::from_millis(300),
        ));
        let r = make(&db, &h, &clock, fast_cfg("wd", 1));
        let j = spawn_runner(&r);
        let st = r.stats();
        wait_until("job in flight", || st.in_flight.load(Ordering::SeqCst) == 1).await;
        r.shutdown_handle().trigger();
        j.await.expect("run");
        assert_eq!(
            db.job_status(ids[0]).await.expect("st"),
            ("succeeded".to_owned(), 1)
        );
        assert_eq!(st.interrupted.load(Ordering::SeqCst), 0);
    })
    .await;
}

#[tokio::test]
async fn in_flight_never_exceeds_concurrency() {
    with_scratch("bound", |db| async move {
        let kind = kind_for("bound");
        let clock = sys_clock();
        let ids = enqueue(&db, kind, 24, 3, clock.now()).await;
        let h = Arc::new(H::new(
            kind,
            Duration::from_secs(10),
            Duration::from_millis(40),
        ));
        let r = make(&db, &h, &clock, fast_cfg("wc", 3));
        let j = spawn_runner(&r);
        let st = r.stats();
        wait_until("all completed", || {
            st.completed.load(Ordering::SeqCst) == 24
        })
        .await;
        r.shutdown_handle().trigger();
        j.await.expect("run");
        assert!(st.max_in_flight.load(Ordering::SeqCst) <= 3);
        assert!(h.max_active.load(Ordering::SeqCst) <= 3);
        assert!(
            h.max_active.load(Ordering::SeqCst) >= 2,
            "pool was never used in parallel"
        );
        assert_eq!(h.runs().len(), ids.len());
    })
    .await;
}

#[tokio::test]
async fn per_kind_cap_limits_parallelism_below_the_pool_size() {
    with_scratch("kindcap", |db| async move {
        let kind = kind_for("kindcap");
        let clock = sys_clock();
        enqueue(&db, kind, 8, 3, clock.now()).await;
        let mut h0 = H::new(kind, Duration::from_secs(10), Duration::from_millis(40));
        h0.cap = 1;
        let h = Arc::new(h0);
        let r = make(&db, &h, &clock, fast_cfg("wk", 4));
        let j = spawn_runner(&r);
        let st = r.stats();
        wait_until("all completed", || st.completed.load(Ordering::SeqCst) == 8).await;
        r.shutdown_handle().trigger();
        j.await.expect("run");
        assert_eq!(h.max_active.load(Ordering::SeqCst), 1);
        assert_eq!(st.max_in_flight.load(Ordering::SeqCst), 1);
    })
    .await;
}

#[tokio::test]
async fn handler_completes_the_job_inside_its_job_tx() {
    with_scratch("jobtx", |db| async move {
        let kind = kind_for("jobtx");
        let clock = sys_clock();
        let ids = enqueue(&db, kind, 3, 3, clock.now()).await;
        let mut h0 = H::new(kind, Duration::from_secs(10), Duration::from_millis(10));
        h0.complete_in_tx = true;
        let h = Arc::new(h0);
        let r = make(&db, &h, &clock, fast_cfg("wj", 2));
        let j = spawn_runner(&r);
        let st = r.stats();
        wait_until("all completed", || st.completed.load(Ordering::SeqCst) == 3).await;
        r.shutdown_handle().trigger();
        j.await.expect("run");
        for id in ids {
            assert_eq!(
                db.job_status(id).await.expect("st"),
                ("succeeded".to_owned(), 1)
            );
        }
        assert_eq!(st.lost_leases.load(Ordering::SeqCst), 0);
    })
    .await;
}

#[tokio::test]
async fn db_outbox_store_relays_in_order_once() {
    with_scratch("outbox", |db| async move {
        let t0 = micros_now();
        let mut ids = Vec::new();
        let mut tx = db.system_tx().await.expect("tx");
        for i in 0..5_i64 {
            let id = db::outbox_insert_system(
                &mut tx,
                &db::OutboxEvent {
                    event_type: "t.created",
                    aggregate_type: "t",
                    aggregate_id: uuid::Uuid::now_v7(),
                    payload: serde_json::json!({"i": i}),
                },
                t0 + time::Duration::microseconds(i),
            )
            .await
            .expect("insert");
            ids.push(id);
        }
        tx.commit().await.expect("commit");
        let store = Arc::new(DbOutboxStore::new(db.clone()));
        let publ = Arc::new(InMemoryPublisher::default());
        let clk: Arc<dyn Clock> = Arc::new(FixedClock::new(t0 + time::Duration::seconds(1)));
        let job =
            OutboxRelayJob::new(store, Arc::clone(&publ) as _, clk, "w".into()).with_limits(2, 10);
        job.relay_once(&|| false).await.expect("relay");
        assert_eq!(publ.effects(), ids);
        job.relay_once(&|| false)
            .await
            .expect("second run is a no-op");
        assert_eq!(
            publ.calls.load(Ordering::SeqCst),
            5,
            "published rows are not re-sent"
        );
    })
    .await;
}

#[tokio::test]
async fn db_idempotency_sweep_runs_on_an_empty_table() {
    with_scratch("idemp", |db| async move {
        let n = db::idempotency::expire_older_than(&db, micros_now(), 100)
            .await
            .expect("sweep");
        assert_eq!(n, 0);
    })
    .await;
}

#[tokio::test]
async fn relay_with_two_runners_and_a_slow_publisher_is_ordered_and_duplicate_free() {
    with_scratch("relayslow", |db| async move {
        let t0 = micros_now();
        let mut ids = Vec::new();
        let mut tx = db.system_tx().await.expect("tx");
        for i in 0..10_i64 {
            let id = db::outbox_insert_system(
                &mut tx,
                &db::OutboxEvent {
                    event_type: "t.created",
                    aggregate_type: "t",
                    aggregate_id: uuid::Uuid::now_v7(),
                    payload: serde_json::json!({"i": i}),
                },
                t0 + time::Duration::microseconds(i),
            )
            .await
            .expect("insert");
            ids.push(id);
        }
        tx.commit().await.expect("commit");
        let publ = Arc::new(InMemoryPublisher::with_delay(Duration::from_millis(40)));
        let clk: Arc<dyn Clock> = Arc::new(common::SystemClock);
        let job = Arc::new(
            OutboxRelayJob::new(
                Arc::new(DbOutboxStore::new(db.clone())),
                Arc::clone(&publ) as _,
                Arc::clone(&clk),
                "relay".into(),
            )
            .with_interval(Duration::from_millis(200)),
        );
        let runners: Vec<Arc<Runner>> = ["wa", "wb"]
            .iter()
            .map(|w| {
                let mut reg = JobRegistry::new();
                reg.register(Arc::clone(&job) as Arc<dyn JobHandler>);
                Arc::new(Runner::new(
                    db.clone(),
                    reg,
                    Arc::clone(&clk),
                    fast_cfg(w, 2),
                ))
            })
            .collect();
        let handles: Vec<_> = runners.iter().map(spawn_runner).collect();
        wait_until("all delivered", || publ.effects().len() == 10).await;
        // Several more chained runs must find nothing to re-send.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        for r in &runners {
            r.shutdown_handle().trigger();
        }
        for h in handles {
            h.await.expect("run");
        }
        assert_eq!(publ.effects(), ids, "delivered in order");
        assert_eq!(
            publ.calls.load(Ordering::SeqCst),
            10,
            "no duplicate delivery"
        );
    })
    .await;
}
