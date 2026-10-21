//! Review N2: the first-run bootstrap is a singleton. Two concurrent
//! `bootstrap_first_superadmin` calls create at most one `platform_staff` row (exactly one on a fresh
//! scratch DB). Runs on local MySQL scratch DBs AND in the TiDB test engine (`with_db` uses the shared
//! DB there; it already has staff, so both calls must be refused and nothing is added).

use super::fixtures::{admin_audit, new_user, now};
use super::harness::with_db;
use crate::error::DbError;
use crate::platform_admin::PlatformAdminDb;
use crate::sql;

async fn staff_count(db: &crate::Db) -> i64 {
    let row = sql::dynamic(String::from("SELECT COUNT(*) AS n FROM platform_staff"))
        .fetch_one(db.pool())
        .await
        .expect("count");
    sql::col::<i64>(&row, "n").expect("n")
}

#[tokio::test]
async fn concurrent_bootstraps_create_at_most_one_superadmin() {
    with_db("concurrent_bootstraps", |db, _env| async move {
        let before = staff_count(&db).await;
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
        let wins = i64::from(r1.is_ok()) + i64::from(r2.is_ok());
        for r in [&r1, &r2] {
            if let Err(e) = r {
                assert!(
                    matches!(e, DbError::Conflict("staff.bootstrap_done")),
                    "loser must see bootstrap_done, got {e:?}"
                );
            }
        }
        assert!(wins <= 1, "two bootstraps succeeded");
        if before == 0 {
            assert_eq!(wins, 1, "fresh DB: exactly one bootstrap wins");
        }
        assert_eq!(staff_count(&db).await, before + wins);
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
    })
    .await;
}

/// Review M2: the MARKER alone refuses a bootstrap. `platform_staff` is empty, only the singleton row
/// exists (another bootstrap in flight / committed marker): `Conflict`, no staff row. Without the
/// marker insert this bootstrap would succeed (the staff count is 0). MySQL scratch only: the shared
/// TiDB DB is never empty.
#[tokio::test]
async fn marker_alone_refuses_bootstrap_on_empty_staff() {
    if super::harness::tidb_skip(
        "marker_alone_refuses_bootstrap_on_empty_staff",
        "needs an empty platform_staff",
    ) {
        return;
    }
    with_db("marker_alone", |db, _env| async move {
        assert_eq!(staff_count(&db).await, 0);
        let marker_owner = new_user(&db).await;
        sql::dynamic(String::from(
            "INSERT INTO platform_bootstrap (id, user_id, created_at) VALUES (1, ?, ?)",
        ))
        .bind(marker_owner.0)
        .bind(now())
        .execute(db.pool())
        .await
        .expect("marker");
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

/// Review M2: interleaving. Tx A holds the marker (uncommitted, no staff row); bootstrap B starts and
/// must wait on the marker's PRIMARY KEY; A commits; B fails with `Conflict`. The staff COUNT is 0 for
/// B the whole time, so only the marker can refuse it. Runs in TiDB mode too: if the shared DB already
/// has the marker, A's insert is a duplicate and B is still refused.
#[tokio::test]
async fn open_marker_tx_blocks_then_refuses_second_bootstrap() {
    with_db("marker_interleave", |db, _env| async move {
        let before = staff_count(&db).await;
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
        assert_eq!(staff_count(&db).await, before);
    })
    .await;
}
