//! T-DB2 equivalent: a reference to a parent in another tenant is rejected by the app-level parent
//! check AND (MySQL only) by the shadow composite FK even when the app check is bypassed.

use super::fixtures::{add_member, new_tenant, now};
use super::harness::with_db;
use crate::error::DbError;
use crate::queries::GROUP_MEMBERSHIPS_INSERT;
use crate::repo::groups;
use crate::sql;
use common::GroupId;
use domain::rbac::TenantRole;

#[tokio::test]
async fn cross_tenant_parent_rejected_by_app_and_shadow_fk() {
    if super::harness::tidb_skip(
        "cross_tenant_parent_rejected_by_app_and_shadow_fk",
        "shadow FKs are MySQL-CI only (D-55); app-level parent checks run in t_isolation",
    ) {
        return;
    }
    with_db("parents", |db, _| async move {
        let a = new_tenant(&db).await;
        let b = new_tenant(&db).await;
        let a_m = add_member(&db, &a, TenantRole::Member).await;
        let b_group = {
            let mut tx = db.tenant_tx(&b.scope()).await.expect("tx");
            let g = groups::create(&mut tx, GroupId::new(), "B", None, now())
                .await
                .expect("g");
            tx.commit().await.expect("c");
            g
        };
        // App-level check.
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        assert!(matches!(
            groups::add_member(&mut tx, b_group, a_m, now()).await,
            Err(DbError::NotFound("group"))
        ));
        // Bypass the app check: raw insert (tenant A, B's group id) -> shadow FK refuses.
        let e = tx
            .inner
            .execute(
                sql::q(GROUP_MEMBERSHIPS_INSERT)
                    .bind(a.tenant.0)
                    .bind(b_group.0)
                    .bind(a_m.0)
                    .bind(a.owner.0)
                    .bind(now()),
            )
            .await
            .expect_err("shadow FK must refuse");
        assert!(matches!(e, DbError::ForeignKey { number: 1452 }), "{e:?}");
        tx.rollback().await;
    })
    .await;
}

#[tokio::test]
async fn shadow_fks_are_installed() {
    if super::harness::tidb_skip(
        "shadow_fks_are_installed",
        "shadow FKs are MySQL-CI only (D-55)",
    ) {
        return;
    }
    with_db("shadow_count", |db, _| async move {
        let mut tx = db.system_tx().await.expect("tx");
        let row = tx
            .inner
            .fetch_optional(sql::dynamic(String::from(
                "SELECT COUNT(*) AS n FROM information_schema.REFERENTIAL_CONSTRAINTS \
                 WHERE CONSTRAINT_SCHEMA = DATABASE()",
            )))
            .await
            .expect("q")
            .expect("row");
        let n: i64 = sql::col(&row, "n").expect("n");
        assert_eq!(
            usize::try_from(n).expect("n"),
            crate::migration_files::SHADOW.len()
        );
        tx.rollback().await;
    })
    .await;
}
