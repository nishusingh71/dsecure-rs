//! F3: epoch poller pages through any number of rows with the same `updated_at` and still observes a
//! late commit carrying an older timestamp (overlap window).

use super::fixtures::{new_tenant, now};
use super::harness::with_db;
use crate::queries::AUTHZ_EPOCHS_INSERT;
use crate::sql;
use common::TenantId;
use time::Duration;

#[tokio::test]
async fn six_hundred_rows_same_timestamp_all_observed() {
    if super::harness::tidb_skip(
        "six_hundred_rows_same_timestamp_all_observed",
        "seeds 600 tenant-less epoch rows into the shared DB",
    ) {
        return;
    }
    with_db("epochs_same_ts", |db, _| async move {
        let ts = now() - Duration::minutes(1);
        let mut ids = Vec::new();
        let mut tx = db.system_tx().await.expect("tx");
        for _ in 0..600 {
            let t = TenantId::new();
            tx.inner
                .execute(sql::q(AUTHZ_EPOCHS_INSERT).bind(t.0).bind(ts))
                .await
                .expect("insert epoch row");
            ids.push(t);
        }
        tx.commit().await.expect("c");
        let n = db.poll_epochs(now()).await.expect("poll");
        assert!(n >= 600, "read {n}");
        assert!(ids.iter().all(|t| db.epochs().current(*t) == Some(1)));
        assert!(
            db.epochs().last_ok().is_some(),
            "fully consumed -> last_ok set"
        );
    })
    .await;
}

#[tokio::test]
async fn late_commit_with_older_timestamp_is_observed() {
    with_db("epochs_late", |db, _| async move {
        let a = new_tenant(&db).await;
        let b = new_tenant(&db).await;
        let t = now();
        // Tx for B takes its timestamp first but commits late.
        let mut late = db.tenant_tx(&b.scope()).await.expect("tx b");
        crate::bump_epoch(&mut late, t - Duration::seconds(2))
            .await
            .expect("bump b");
        // Meanwhile A bumps and the poller advances past B's timestamp.
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx a");
        crate::bump_epoch(&mut tx, t).await.expect("bump a");
        tx.commit().await.expect("c");
        db.poll_epochs(t).await.expect("poll 1");
        assert_eq!(db.epochs().current(a.tenant), Some(2));
        assert_eq!(db.epochs().current(b.tenant), Some(1));
        late.commit().await.expect("late commit");
        db.poll_epochs(t + Duration::seconds(1))
            .await
            .expect("poll 2");
        assert_eq!(
            db.epochs().current(b.tenant),
            Some(2),
            "late commit seen via overlap"
        );
    })
    .await;
}

/// Poller queries range-scan `ix_authz_epochs_poll` (no full scan; ru-report found one on TiDB).
#[tokio::test]
async fn poll_queries_use_the_poll_index() {
    with_db("epochs_plan", |db, _| async move {
        use sqlx::Row as _;
        let strip = |q: &str| -> String {
            q.lines()
                .filter(|l| !l.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let ties = strip(crate::queries::AUTHZ_EPOCHS_CHANGED_TIES);
        let after = strip(crate::queries::AUTHZ_EPOCHS_CHANGED_AFTER);
        let r1 = sql::dynamic(format!("EXPLAIN {ties}"))
            .bind(now())
            .bind(uuid::Uuid::nil())
            .bind(50_u32)
            .fetch_all(db.pool())
            .await
            .expect("explain ties");
        let r2 = sql::dynamic(format!("EXPLAIN {after}"))
            .bind(now())
            .bind(50_u32)
            .fetch_all(db.pool())
            .await
            .expect("explain after");
        let tidb = db.engine().is_tidb();
        let text = |r: &sqlx::mysql::MySqlRow, c: &str| -> String {
            r.try_get::<String, _>(c)
                .or_else(|_| {
                    r.try_get::<Vec<u8>, _>(c)
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                })
                .unwrap_or_default()
        };
        for (body, rows) in [(&ties, r1), (&after, r2)] {
            assert!(!rows.is_empty());
            if tidb {
                // TiDB EXPLAIN: id / estRows / task / access object / operator info.
                assert!(
                    rows.iter().all(|r| !text(r, "id").contains("TableFullScan")
                        && !text(r, "id").contains("IndexFullScan")),
                    "full scan: {body}"
                );
                assert!(
                    rows.iter()
                        .any(|r| text(r, "access object").contains("index:ix_authz_epochs_poll")),
                    "poll index not used: {body}"
                );
            } else {
                for r in &rows {
                    let ty: Option<String> = r.try_get("type").ok();
                    let key: Option<String> = r.try_get("key").ok();
                    assert_ne!(ty.as_deref(), Some("ALL"), "full scan: {body}");
                    assert_eq!(key.as_deref(), Some("ix_authz_epochs_poll"), "{body}");
                }
            }
        }
    })
    .await;
}
