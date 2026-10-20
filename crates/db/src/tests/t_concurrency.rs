//! F6 (lock order, no deadlocks), F9 (concurrent idempotency reserve), F10 (migration lock row).

use super::fixtures::{add_member, new_member, new_tenant, new_user, now};
use super::harness::with_db;
use crate::error::DbError;
use crate::idempotency::{self, Reservation};
use crate::migrate::MigrationLock;
use crate::repo::memberships::{self, MembershipStatus};
use domain::rbac::TenantRole;
use futures_util::future::join_all;
use time::Duration;

#[tokio::test]
async fn concurrent_member_inserts_and_status_changes_never_deadlock() {
    with_db("lock_order", |db, _| async move {
        let a = new_tenant(&db).await;
        let mut existing = Vec::new();
        for _ in 0..4 {
            existing.push(add_member(&db, &a, TenantRole::Member).await);
        }
        let mut users = Vec::new();
        // Remote TiDB: smaller fan-out (time budget), same contention pattern; 1213/1205 still fail.
        let fan_out = if super::harness::tidb_mode() { 3 } else { 6 };
        for _ in 0..fan_out {
            users.push(new_user(&db).await);
        }
        let s = a.scope();
        let mut futs = Vec::new();
        for (i, u) in users.into_iter().enumerate() {
            let db = db.clone();
            let s = s.clone();
            let parent = existing[i % existing.len()];
            futs.push(Box::pin(async move {
                let mut tx = db.tenant_tx(&s).await.expect("tx");
                let mut m = new_member(u, TenantRole::Viewer);
                m.parent_membership_id = Some(parent);
                let r = memberships::insert(&mut tx, &m, now()).await.map(|_| ());
                match r {
                    Ok(()) => tx.commit().await,
                    Err(e) => {
                        tx.rollback().await;
                        Err(e)
                    }
                }
            })
                as futures_util::future::BoxFuture<'static, Result<(), DbError>>);
        }
        for (i, m) in existing.iter().copied().enumerate() {
            let db = db.clone();
            let s = s.clone();
            futs.push(Box::pin(async move {
                let mut tx = db.tenant_tx(&s).await.expect("tx");
                let to = if i % 2 == 0 {
                    MembershipStatus::Disabled
                } else {
                    MembershipStatus::Active
                };
                let r = memberships::set_status(&mut tx, m, MembershipStatus::Disabled, now())
                    .await
                    .and(Ok(()));
                let r = match r {
                    Ok(()) => memberships::set_status(&mut tx, m, to, now()).await,
                    e => e,
                };
                match r {
                    Ok(()) => tx.commit().await,
                    Err(e) => {
                        tx.rollback().await;
                        Err(e)
                    }
                }
            }));
        }
        let results = join_all(futs).await;
        for r in &results {
            assert!(
                !matches!(r, Err(DbError::Transient { code: 1213 })),
                "deadlock: {results:?}"
            );
            assert!(r.is_ok(), "{r:?}");
        }
    })
    .await;
}

#[tokio::test]
async fn concurrent_idempotency_reserve_compares_body_hash() {
    with_db("idem_race", |db, _| async move {
        let a = new_tenant(&db).await;
        let p = a.owner.0;
        let s = a.scope();
        // 4 concurrent reserves of the same key and body: exactly one Fresh (committed reservation),
        // the others InProgress. Holds with TiDB lazy unique checks (COMMIT-time duplicate mapped).
        let futs = (0..4).map(|_| {
            let (db, s) = (db.clone(), s.clone());
            async move {
                idempotency::reserve_committed(
                    &db,
                    &s,
                    p,
                    "race",
                    &[1u8; 32],
                    now(),
                    Duration::hours(1),
                )
                .await
            }
        });
        let results = join_all(futs).await;
        let fresh = results
            .iter()
            .filter(|r| matches!(r, Ok(Reservation::Fresh)))
            .count();
        assert_eq!(fresh, 1, "{results:?}");
        assert!(
            results
                .iter()
                .all(|r| matches!(r, Ok(Reservation::Fresh | Reservation::InProgress))),
            "{results:?}"
        );
        // Different body for the same key -> Mismatch.
        let r = idempotency::reserve_committed(
            &db,
            &s,
            p,
            "race",
            &[2u8; 32],
            now(),
            Duration::hours(1),
        )
        .await;
        assert!(matches!(r, Ok(Reservation::Mismatch)), "{r:?}");
        // Business work failed -> abandon -> a retry reserves again (exactly once).
        assert!(
            idempotency::release(&db, &s, p, "race", &[1u8; 32], now())
                .await
                .expect("release")
        );
        // Not ours (other body hash) -> nothing released.
        assert!(
            !idempotency::release(&db, &s, p, "race", &[9u8; 32], now())
                .await
                .expect("release")
        );
        let futs = (0..3).map(|_| {
            let (db, s) = (db.clone(), s.clone());
            async move {
                idempotency::reserve_committed(
                    &db,
                    &s,
                    p,
                    "race",
                    &[1u8; 32],
                    now() + Duration::seconds(1),
                    Duration::hours(1),
                )
                .await
            }
        });
        let results = join_all(futs).await;
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Ok(Reservation::Fresh)))
                .count(),
            1,
            "{results:?}"
        );
        // Completing in the business tx makes the key replayable.
        let mut tx = db.tenant_tx(&s).await.expect("tx");
        idempotency::complete(&mut tx, p, "race", 201, Some(b"{}"), None)
            .await
            .expect("complete");
        tx.commit().await.expect("c");
        let r = idempotency::reserve_committed(
            &db,
            &s,
            p,
            "race",
            &[1u8; 32],
            now() + Duration::seconds(2),
            Duration::hours(1),
        )
        .await;
        assert!(
            matches!(
                r,
                Ok(Reservation::Replay {
                    status_code: 201,
                    ..
                })
            ),
            "{r:?}"
        );
        // A dead request (no release): after IN_PROGRESS_STALE a new reserve takes the key over.
        let t = now();
        let res = |at, d: &crate::Db, sc: &domain::rbac::TenantScope| {
            let (d, sc) = (d.clone(), sc.clone());
            async move {
                idempotency::reserve_committed(
                    &d,
                    &sc,
                    p,
                    "stale",
                    &[5u8; 32],
                    at,
                    Duration::hours(1),
                )
                .await
                .expect("reserve")
            }
        };
        assert_eq!(res(t, &db, &s).await, Reservation::Fresh);
        assert_eq!(
            res(t + Duration::seconds(10), &db, &s).await,
            Reservation::InProgress
        );
        assert_eq!(
            res(
                t + idempotency::IN_PROGRESS_STALE + Duration::seconds(1),
                &db,
                &s
            )
            .await,
            Reservation::Fresh
        );
    })
    .await;
}

#[tokio::test]
async fn migration_lock_row_is_exclusive_and_heartbeat_keeps_it() {
    if super::harness::tidb_skip(
        "migration_lock_row_is_exclusive_and_heartbeat_keeps_it",
        "would steal the shared _migration_lock row of the shared DB",
    ) {
        return;
    }
    with_db("migration_lock", |db, _| async move {
        let stale = std::time::Duration::from_secs(2);
        let l1 = MigrationLock::acquire(&db, stale).await.expect("first");
        assert!(matches!(
            MigrationLock::acquire(&db, stale).await,
            Err(DbError::Conflict("migrate.busy"))
        ));
        // Held past the stale window WHILE heartbeating: still busy.
        for _ in 0..6 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            l1.heartbeat(&db).await.expect("heartbeat");
        }
        assert!(matches!(
            MigrationLock::acquire(&db, stale).await,
            Err(DbError::Conflict("migrate.busy"))
        ));
        // No heartbeat for longer than the window (DB clock): taken over; old holder loses it.
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
        let l2 = MigrationLock::acquire(&db, stale)
            .await
            .expect("stale takeover");
        assert!(matches!(
            l1.heartbeat(&db).await,
            Err(DbError::NotPersisted { .. })
        ));
        assert!(matches!(
            l1.release(&db).await,
            Err(DbError::NotPersisted { .. })
        ));
        l2.release(&db).await.expect("release");
        // Migrations are idempotent under the lock.
        crate::migrate::run(&db).await.expect("re-run");
    })
    .await;
}

#[tokio::test]
async fn changed_applied_migration_is_refused() {
    if super::harness::tidb_skip(
        "changed_applied_migration_is_refused",
        "tampers migration bookkeeping (needs a fresh scratch DB)",
    ) {
        return;
    }
    with_db("checksum_mismatch", |db, _| async move {
        // Scratch DB only: corrupt the recorded checksum of one applied migration.
        crate::sql::dynamic(String::from(
            "UPDATE _sqlx_migrations SET checksum = X'00' WHERE version = 1000001",
        ))
        .execute(db.pool())
        .await
        .expect("tamper scratch bookkeeping");
        let e = crate::migrate::run(&db).await.expect_err("must refuse");
        assert!(
            matches!(&e, DbError::Migrate(m) if m == "checksum mismatch at version 1000001"),
            "{e:?}"
        );
    })
    .await;
}
