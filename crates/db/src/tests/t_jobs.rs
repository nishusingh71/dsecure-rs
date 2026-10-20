//! T-DB5: lease claim with concurrent workers (each job runs once), stuck lease recovered by the
//! reaper, lost lease -> NotPersisted, dead after max attempts, dedupe + per-tenant cap,
//! tenant tx from a claimed job.

use super::fixtures::{new_tenant, now, uniq_kind};
use super::harness::with_db;
use crate::error::DbError;
use crate::jobs::{self, Enqueued, NewJob};
use crate::repo::tenants;
use futures_util::future::join_all;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::Duration;

fn job(kind: &'static str, key: String, max_attempts: u32, at: time::OffsetDateTime) -> NewJob {
    NewJob {
        kind,
        job_key: format!("{kind}:{key}"),
        payload: serde_json::json!({"n": 1}),
        run_after: at,
        max_attempts,
        max_pending: None,
    }
}

#[tokio::test]
async fn concurrent_workers_run_each_job_once() {
    with_db("jobs_concurrent", |db, _| async move {
        let kind = uniq_kind("test");
        let t0 = now();
        let mut tx = db.system_tx().await.expect("tx");
        for i in 0..40 {
            let r = jobs::enqueue_system(&mut tx, &job(kind, format!("k{i}"), 3, t0), t0)
                .await
                .expect("enqueue");
            assert!(matches!(r, Enqueued::New(_)));
        }
        tx.commit().await.expect("c");

        let runs: Arc<Mutex<HashMap<uuid::Uuid, u32>>> = Arc::default();
        let workers = (0..4).map(|w| {
            let db = db.clone();
            let runs = Arc::clone(&runs);
            async move {
                let name = format!("w{w}");
                loop {
                    let claimed = db
                        .claim_jobs(&name, kind, t0, Duration::seconds(30), 5)
                        .await
                        .expect("claim");
                    if claimed.is_empty() {
                        break;
                    }
                    for j in claimed {
                        *runs
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .entry(j.id())
                            .or_insert(0) += 1;
                        db.complete_job(&j, t0).await.expect("complete");
                    }
                }
            }
        });
        join_all(workers).await;
        let runs = runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(runs.len(), 40);
        assert!(runs.values().all(|n| *n == 1), "{runs:?}");
        for id in runs.keys() {
            let (status, attempts) = db.job_status(*id).await.expect("status");
            assert_eq!((status.as_str(), attempts), ("succeeded", 1));
        }
    })
    .await;
}

#[tokio::test]
async fn stuck_lease_is_recovered_by_reaper() {
    with_db("jobs_reaper", |db, _| async move {
        let kind = uniq_kind("test");
        let t0 = now();
        let mut tx = db.system_tx().await.expect("tx");
        jobs::enqueue_system(&mut tx, &job(kind, "stuck".into(), 3, t0), t0)
            .await
            .expect("enqueue");
        jobs::enqueue_system(&mut tx, &job(kind, "doomed".into(), 1, t0), t0)
            .await
            .expect("enqueue");
        // Dedupe by job_key.
        assert_eq!(
            jobs::enqueue_system(&mut tx, &job(kind, "stuck".into(), 3, t0), t0)
                .await
                .expect("dup"),
            Enqueued::Duplicate
        );
        tx.commit().await.expect("c");

        let first = db
            .claim_jobs("w1", kind, t0, Duration::seconds(1), 10)
            .await
            .expect("claim");
        assert_eq!(first.len(), 2);
        // Nothing left to claim while leased.
        assert!(
            db.claim_jobs("w2", kind, t0, Duration::seconds(1), 10)
                .await
                .expect("claim")
                .is_empty()
        );
        // Worker w1 "dies". Lease expires; reaper recovers.
        let t1 = t0 + Duration::seconds(5);
        let reaped = db.reap_jobs_kind(t1, 100, Some(kind)).await.expect("reap");
        assert_eq!((reaped.requeued, reaped.dead), (1, 1));
        // Lost lease: old token cannot complete or heartbeat.
        for j in &first {
            assert!(matches!(
                db.complete_job(j, t1).await,
                Err(DbError::NotPersisted { .. })
            ));
        }
        let again = db
            .claim_jobs("w2", kind, t1, Duration::seconds(30), 10)
            .await
            .expect("claim");
        assert_eq!(again.len(), 1);
        let mut j = again.into_iter().next().expect("job");
        assert_eq!(j.attempts(), 2);
        db.heartbeat_job(&mut j, t1, Duration::seconds(60))
            .await
            .expect("heartbeat");
        // Failure path: retry with backoff, then success on reclaim.
        db.fail_job(&j, "test.transient", t1).await.expect("fail");
        let (status, _) = db.job_status(j.id()).await.expect("s");
        assert_eq!(status, "queued");
        let later = t1 + Duration::hours(2);
        let j = db
            .claim_jobs("w3", kind, later, Duration::seconds(30), 10)
            .await
            .expect("claim")
            .into_iter()
            .next()
            .expect("job");
        db.complete_job(&j, later).await.expect("complete");
        assert_eq!(db.job_status(j.id()).await.expect("s").0, "succeeded");
        assert!(db.fail_job(&j, "bad code!", later).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn tenant_job_cap_and_tenant_tx_from_job() {
    with_db("jobs_tenant", |db, _| async move {
        let kind = uniq_kind("test");
        let a = new_tenant(&db).await;
        let t0 = now();
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        let mut j1 = job(kind, "t1".into(), 3, t0);
        j1.max_pending = Some(1);
        jobs::enqueue(&mut tx, &j1, t0).await.expect("enqueue");
        let mut j2 = job(kind, "t2".into(), 3, t0);
        j2.max_pending = Some(1);
        assert!(matches!(
            jobs::enqueue(&mut tx, &j2, t0).await,
            Err(DbError::QuotaExceeded {
                quota: "jobs.max_pending",
                ..
            })
        ));
        tx.commit().await.expect("c");

        let claimed = db
            .claim_jobs("w", kind, t0, Duration::seconds(30), 1)
            .await
            .expect("claim");
        let j = claimed.first().expect("job");
        assert_eq!(j.tenant(), Some(a.tenant));
        let mut jtx = db.tenant_tx_for_job(j, t0).await.expect("job tx");
        assert_eq!(jtx.tx().tenant(), a.tenant);
        assert!(jtx.tx().actor().is_none());
        assert_eq!(tenants::get_own(jtx.tx()).await.expect("own").id, a.tenant);
        // Actor-requiring writes refuse in a job tx.
        assert!(matches!(
            crate::repo::groups::create(jtx.tx(), common::GroupId::new(), "g", None, t0).await,
            Err(DbError::ScopeMissing(_))
        ));
        // Business write + completion in ONE tx.
        crate::bump_epoch(jtx.tx(), t0)
            .await
            .expect("business write");
        jtx.complete(t0).await.expect("complete in same tx");
        assert_eq!(db.job_status(j.id()).await.expect("s").0, "succeeded");
        // Lease gone -> no tenant tx from that job any more.
        assert!(matches!(
            db.tenant_tx_for_job(j, t0).await,
            Err(DbError::NotFound(_))
        ));
    })
    .await;
}

#[tokio::test]
async fn expired_lease_has_no_job_tx_and_reaper_waits_for_open_job_tx() {
    with_db("jobs_lease_lock", |db, _| async move {
        let kind = uniq_kind("test");
        let a = new_tenant(&db).await;
        let t0 = now();
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        jobs::enqueue(&mut tx, &job(kind, "lease1".into(), 3, t0), t0)
            .await
            .expect("enqueue");
        jobs::enqueue(&mut tx, &job(kind, "lease2".into(), 3, t0), t0)
            .await
            .expect("enqueue");
        tx.commit().await.expect("c");
        let claimed = db
            .claim_jobs("w", kind, t0, Duration::seconds(2), 10)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 2);
        let (j1, j2) = (&claimed[0], &claimed[1]);
        // Expired lease (app time past lease_until): no business tx.
        assert!(matches!(
            db.tenant_tx_for_job(j1, t0 + Duration::seconds(3)).await,
            Err(DbError::NotFound("job lease"))
        ));
        // Open job tx (valid lease) holds the row lock; a reaper running "later" must wait, then
        // see the committed success and requeue nothing for that job.
        let later = t0 + Duration::seconds(10);
        let db1 = db.clone();
        let j2c = j2.clone();
        // Deterministic ordering: the reaper starts only after the job tx holds the lease lock.
        let (locked_tx, locked_rx) = tokio::sync::oneshot::channel::<()>();
        let worker = async move {
            let mut jtx = db1.tenant_tx_for_job(&j2c, t0).await.expect("job tx");
            crate::bump_epoch(jtx.tx(), t0).await.expect("write");
            let _ = locked_tx.send(());
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            jtx.complete(t0).await.expect("complete");
            std::time::Instant::now()
        };
        let db2 = db.clone();
        let reaper = async move {
            let _ = locked_rx.await;
            let r = db2
                .reap_jobs_kind(later, 100, Some(kind))
                .await
                .expect("reap");
            (r, std::time::Instant::now())
        };
        let (done_at, (reaped, reaped_at)) = tokio::join!(worker, reaper);
        assert!(reaped_at >= done_at, "reaper must wait for the open job tx");
        assert_eq!(reaped.requeued, 1, "only j1 (no open tx) is requeued");
        assert_eq!(db.job_status(j2.id()).await.expect("s").0, "succeeded");
        assert_eq!(db.job_status(j1.id()).await.expect("s").0, "queued");
    })
    .await;
}

#[tokio::test]
async fn max_pending_cap_holds_under_parallel_enqueues() {
    with_db("jobs_cap_race", |db, _| async move {
        let kind = uniq_kind("test");
        let a = new_tenant(&db).await;
        let t0 = now();
        let s = a.scope();
        let futs = (0..8).map(|i| {
            let db = db.clone();
            let s = s.clone();
            async move {
                let mut tx = db.tenant_tx(&s).await.expect("tx");
                let mut j = job(kind, format!("cap{i}"), 3, t0);
                j.max_pending = Some(1);
                let r = jobs::enqueue(&mut tx, &j, t0).await;
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                match r {
                    Ok(v) => {
                        tx.commit().await.expect("c");
                        Ok(v)
                    }
                    Err(e) => {
                        tx.rollback().await;
                        Err(e)
                    }
                }
            }
        });
        let results = join_all(futs).await;
        let ok = results
            .iter()
            .filter(|r| matches!(r, Ok(Enqueued::New(_))))
            .count();
        assert_eq!(ok, 1, "{results:?}");
        assert!(results.iter().all(|r| matches!(
            r,
            Ok(Enqueued::New(_))
                | Err(DbError::QuotaExceeded {
                    quota: "jobs.max_pending",
                    ..
                })
        )));
    })
    .await;
}
