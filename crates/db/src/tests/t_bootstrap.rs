//! Review N2/M2: the first-run bootstrap is a singleton (marker row `platform_bootstrap(id = 1)`).
//!
//! Shared-DB rules (TiDB test engine: ONE database, tests of this binary run in parallel, and the CI
//! container starts empty): a test may never leave the marker committed WITHOUT a superadmin row (the
//! `superadmin` fixture of every other test would then be refused), and assertions only look at the
//! rows of the test's own users, never at global counts that parallel tests change.

use super::fixtures::{admin_audit, new_user, now};
use super::harness::{tidb_mode, with_db};
use crate::error::DbError;
use crate::platform_admin::PlatformAdminDb;
use crate::sql;
use common::UserId;

async fn staff_count(db: &crate::Db) -> i64 {
    let row = sql::dynamic(String::from("SELECT COUNT(*) AS n FROM platform_staff"))
        .fetch_one(db.pool())
        .await
        .expect("count");
    sql::col::<i64>(&row, "n").expect("n")
}

/// Staff rows of exactly these users (parallel-safe).
async fn staff_of(db: &crate::Db, users: &[UserId]) -> usize {
    let mut n = 0;
    for u in users {
        let r = sql::dynamic(String::from(
            "SELECT 1 FROM platform_staff WHERE user_id = ?",
        ))
        .bind(u.0)
        .fetch_optional(db.pool())
        .await
        .expect("staff of");
        n += usize::from(r.is_some());
    }
    n
}

async fn insert_marker(db: &crate::Db, owner: UserId) {
    sql::dynamic(String::from(
        "INSERT INTO platform_bootstrap (id, user_id, created_at) VALUES (1, ?, ?)",
    ))
    .bind(owner.0)
    .bind(now())
    .execute(db.pool())
    .await
    .expect("marker");
}

#[tokio::test]
async fn concurrent_bootstraps_create_at_most_one_superadmin() {
    with_db("concurrent_bootstraps", |db, _env| async move {
        let (u1, u2) = (new_user(&db).await, new_user(&db).await);
        let a = PlatformAdminDb::for_tests(db.clone());
        let b = PlatformAdminDb::for_tests(db.clone());
        let (au1, au2) = (
            admin_audit(u1, "system", "staff.bootstrap"),
            admin_audit(u2, "system", "staff.bootstrap"),
        );
        let (r1, r2) = tokio::join!(
            a.bootstrap_first_superadmin(u1, &au1, now()),
            b.bootstrap_first_superadmin(u2, &au2, now()),
        );
        let wins = usize::from(r1.is_ok()) + usize::from(r2.is_ok());
        for r in [&r1, &r2] {
            if let Err(e) = r {
                assert!(
                    matches!(e, DbError::Conflict("staff.bootstrap_done")),
                    "loser must see bootstrap_done, got {e:?}"
                );
            }
        }
        assert!(wins <= 1, "two bootstraps succeeded");
        assert_eq!(staff_of(&db, &[u1, u2]).await, wins);
        // Own scratch DB (MySQL): it was empty, so exactly one wins. Shared TiDB DB: a parallel test
        // may have bootstrapped first; then both are refused.
        if !tidb_mode() {
            assert_eq!(wins, 1, "fresh DB: exactly one bootstrap wins");
        }
        // A later, sequential bootstrap is always refused once one exists.
        let u3 = new_user(&db).await;
        let e = a
            .bootstrap_first_superadmin(u3, &admin_audit(u3, "system", "staff.bootstrap"), now())
            .await
            .expect_err("already bootstrapped");
        assert!(
            matches!(e, DbError::Conflict("staff.bootstrap_done")),
            "{e:?}"
        );
        assert_eq!(staff_of(&db, &[u3]).await, 0);
    })
    .await;
}

/// Review M2: the MARKER alone refuses a bootstrap. `platform_staff` is empty, only the singleton row
/// exists: `Conflict`, no staff row. Without the marker insert this bootstrap would succeed (the staff
/// count is 0). Own scratch DB only: it commits a marker without a superadmin, which the shared TiDB
/// DB must never contain.
#[tokio::test]
async fn marker_alone_refuses_bootstrap_on_empty_staff() {
    if super::harness::tidb_skip(
        "marker_alone_refuses_bootstrap_on_empty_staff",
        "needs an empty platform_staff and commits a marker without staff",
    ) {
        return;
    }
    with_db("marker_alone", |db, _env| async move {
        assert_eq!(staff_count(&db).await, 0);
        let marker_owner = new_user(&db).await;
        insert_marker(&db, marker_owner).await;
        let u = new_user(&db).await;
        let e = PlatformAdminDb::for_tests(db.clone())
            .bootstrap_first_superadmin(u, &admin_audit(u, "system", "staff.bootstrap"), now())
            .await
            .expect_err("marker taken");
        assert!(
            matches!(e, DbError::Conflict("staff.bootstrap_done")),
            "{e:?}"
        );
        assert_eq!(staff_count(&db).await, 0);
        let admin = PlatformAdminDb::for_tests(db.clone());
        assert!(
            admin
                .bootstrap_committed_for(marker_owner)
                .await
                .expect("q")
        );
        assert!(!admin.bootstrap_committed_for(u).await.expect("q"));
    })
    .await;
}

/// CI run #9 root cause: the `superadmin` fixture recursed without limit when the marker existed
/// without any superadmin row, and the test thread overflowed its stack. It must now fail fast with
/// a clear panic. Own scratch DB only (commits an orphan marker).
#[tokio::test]
async fn superadmin_fixture_fails_fast_on_orphan_marker() {
    if super::harness::tidb_skip(
        "superadmin_fixture_fails_fast_on_orphan_marker",
        "commits a marker without staff",
    ) {
        return;
    }
    with_db("orphan_marker_fixture", |db, _env| async move {
        insert_marker(&db, new_user(&db).await).await;
        let r = futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(
            super::fixtures::superadmin(&db),
        ))
        .await;
        let payload = r.expect_err("fixture must panic, not succeed");
        let msg = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default();
        assert!(msg.contains("no active platform_superadmin"), "{msg}");
    })
    .await;
}

/// Review M2: interleaving. Tx A holds the marker (uncommitted; its staff row is in the same tx, like a
/// real bootstrap); bootstrap B starts and must wait on the marker's PRIMARY KEY; A commits; B fails
/// with `Conflict`. Shared TiDB DB: if the marker already exists, A's insert is a duplicate (A then
/// rolls back) and B is still refused. A never commits a marker without its superadmin row.
#[tokio::test]
async fn open_marker_tx_blocks_then_refuses_second_bootstrap() {
    with_db("marker_interleave", |db, _env| async move {
        let a_user = new_user(&db).await;
        let mut a = crate::tx::Inner::begin(&db).await.expect("tx A");
        let a_holds = match a
            .execute(
                sql::q(crate::queries::PLATFORM_BOOTSTRAP_INSERT)
                    .bind(a_user.0)
                    .bind(now()),
            )
            .await
        {
            Ok(n) => {
                assert_eq!(n, 1);
                true
            }
            Err(DbError::Duplicate { .. }) => false,
            Err(e) => panic!("marker insert: {e:?}"),
        };
        if a_holds {
            let n = a
                .execute(
                    sql::q(crate::queries::PLATFORM_STAFF_INSERT)
                        .bind(a_user.0)
                        .bind(domain::rbac::StaffRole::Superadmin.as_str())
                        .bind(None::<uuid::Uuid>)
                        .bind(now()),
                )
                .await
                .expect("staff row of A");
            assert_eq!(n, 1);
        }
        let b_user = new_user(&db).await;
        let admin = PlatformAdminDb::for_tests(db.clone());
        let b_audit = admin_audit(b_user, "system", "staff.bootstrap");
        let (b, ()) = tokio::join!(
            admin.bootstrap_first_superadmin(b_user, &b_audit, now()),
            async {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if a_holds {
                    crate::tx::SystemTx { inner: a }
                        .commit()
                        .await
                        .expect("commit A");
                } else {
                    a.rollback().await;
                }
            }
        );
        let e = b.expect_err("B must be refused");
        assert!(
            matches!(e, DbError::Conflict("staff.bootstrap_done")),
            "{e:?}"
        );
        assert_eq!(staff_of(&db, &[b_user]).await, 0);
        assert_eq!(staff_of(&db, &[a_user]).await, usize::from(a_holds));
    })
    .await;
}
