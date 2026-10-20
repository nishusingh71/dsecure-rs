//! F4: staff grants are verified by the db layer (active, unexpired, same tenant, same staff user)
//! and re-verified inside every staff transaction; unverified scope grants are refused.

use super::fixtures::{new_tenant, now, scope_with, staff_audit, staff_grant, staff_grant_until};
use super::harness::with_db;
use crate::error::DbError;
use crate::repo::tenants;
use crate::sql;
use crate::staff_grant;
use common::{GrantId, UserId};
use domain::rbac::{TenantScope, Visibility};
use time::Duration;

#[tokio::test]
async fn expired_other_tenant_and_other_staff_grants_rejected() {
    with_db("staff_verify", |db, _| async move {
        let a = new_tenant(&db).await;
        let b = new_tenant(&db).await;
        let g = staff_grant(&db, a.tenant).await;
        let mut tx = db.system_tx().await.expect("tx");
        // Valid
        assert!(
            staff_grant::verify(&mut tx, g.staff_user(), g.grant(), a.tenant, now())
                .await
                .is_ok()
        );
        // Other tenant
        assert!(matches!(
            staff_grant::verify(&mut tx, g.staff_user(), g.grant(), b.tenant, now()).await,
            Err(DbError::Forbidden("staff grant not valid"))
        ));
        // Other staff user
        assert!(matches!(
            staff_grant::verify(&mut tx, UserId::new(), g.grant(), a.tenant, now()).await,
            Err(DbError::Forbidden("staff grant not valid"))
        ));
        // Unknown grant
        assert!(matches!(
            staff_grant::verify(&mut tx, g.staff_user(), GrantId::new(), a.tenant, now()).await,
            Err(DbError::Forbidden("staff grant not valid"))
        ));
        // Expired (verify time past expires_at)
        assert!(matches!(
            staff_grant::verify(
                &mut tx,
                g.staff_user(),
                g.grant(),
                a.tenant,
                now() + Duration::hours(2)
            )
            .await,
            Err(DbError::Forbidden("staff grant not valid"))
        ));
        tx.rollback().await;

        // Short grant: valid now, expired a moment later -> staff tx refused at open time.
        // Expiry is checked by passing a later `now`, never by waiting (remote latency safe).
        let short = staff_grant_until(&db, a.tenant, now() + Duration::seconds(60)).await;
        assert!(
            db.tenant_tx_for_staff(&short, &staff_audit(&short, "staff_access.used"), now())
                .await
                .is_ok()
        );
        assert!(matches!(
            db.tenant_tx_for_staff(
                &short,
                &staff_audit(&short, "staff_access.used"),
                now() + Duration::seconds(120)
            )
            .await,
            Err(DbError::Forbidden("staff grant not valid"))
        ));
    })
    .await;
}

#[tokio::test]
async fn staff_transactions_reverify_and_audit() {
    with_db("staff_tx", |db, _| async move {
        let a = new_tenant(&db).await;
        let g = staff_grant(&db, a.tenant).await;
        // A member scope carrying an (unverified) staff grant id is refused.
        let forged = TenantScope::for_tests(a.tenant, a.owner, Visibility::Tenant, Some(g.grant()));
        assert!(matches!(
            db.tenant_tx(&forged).await,
            Err(DbError::ScopeMissing(_))
        ));
        assert!(
            db.tenant_tx(&scope_with(a.tenant, a.owner, Visibility::Tenant))
                .await
                .is_ok()
        );

        // Staff tenant tx: tenant from the grant, no actor, grant recorded.
        let mut stx = db
            .tenant_tx_for_staff(&g, &staff_audit(&g, "staff_access.used"), now())
            .await
            .expect("staff tx");
        assert_eq!(stx.tenant(), a.tenant);
        assert!(stx.actor().is_none());
        assert_eq!(stx.staff_grant(), Some(g.grant()));
        assert_eq!(tenants::get_own(&mut stx).await.expect("own").id, a.tenant);
        stx.rollback().await;

        // Platform tx: audit row must match the grant.
        let mut bad = staff_audit(&g, "tenant.quota_update");
        bad.tenant_id = Some(uuid::Uuid::now_v7());
        assert!(matches!(
            db.platform_tx(&g, &bad, now()).await,
            Err(DbError::Invalid(_))
        ));
        let ok = staff_audit(&g, "tenant.quota_update");
        let mut ptx = db.platform_tx(&g, &ok, now()).await.expect("ptx");
        tenants::set_max_members(&mut ptx, Some(10), now())
            .await
            .expect("quota");
        ptx.commit().await.expect("c");
        // Audit row committed in the same tx.
        let mut tx = db.system_tx().await.expect("tx");
        let row = tx
            .inner
            .fetch_optional(
                sql::dynamic(String::from(
                    "SELECT COUNT(*) AS n FROM audit_events WHERE staff_grant_id = ?",
                ))
                .bind(g.grant().0),
            )
            .await
            .expect("q")
            .expect("row");
        // The staff tenant tx above was rolled back (its audit row with it); the platform tx committed.
        assert_eq!(sql::col::<i64>(&row, "n").expect("n"), 1);
        tx.rollback().await;
        // Expired grant: platform tx refused, no audit row written.
        assert!(matches!(
            db.platform_tx(&g, &staff_audit(&g, "x"), now() + Duration::hours(2))
                .await,
            Err(DbError::Forbidden("staff grant not valid"))
        ));
    })
    .await;
}

#[tokio::test]
async fn read_grant_is_read_only_and_platform_admin_needs_approver() {
    with_db("staff_read_only", |db, _| async move {
        let a = new_tenant(&db).await;
        let g = super::fixtures::staff_grant_scoped(
            &db,
            a.tenant,
            now() + Duration::hours(1),
            staff_grant::GrantScope::Read,
        )
        .await;
        assert_eq!(g.scope(), staff_grant::GrantScope::Read);
        let member = super::fixtures::add_member(&db, &a, domain::rbac::TenantRole::Member).await;
        let mut stx = db
            .tenant_tx_for_staff(&g, &staff_audit(&g, "staff_access.used"), now())
            .await
            .expect("read staff tx");
        // Reads work...
        assert!(
            crate::repo::memberships::get(&mut stx, a.owner)
                .await
                .expect("get")
                .is_some()
        );
        // ...every write is refused.
        assert!(matches!(
            crate::repo::memberships::set_role(
                &mut stx,
                member,
                domain::rbac::TenantRole::Admin,
                now()
            )
            .await,
            Err(DbError::ReadOnly)
        ));
        assert!(matches!(
            crate::bump_epoch(&mut stx, now()).await,
            Err(DbError::ReadOnly)
        ));
        stx.rollback().await;
        // A read grant cannot open a platform write tx either.
        assert!(matches!(
            db.platform_tx(&g, &staff_audit(&g, "tenant.quota_update"), now())
                .await,
            Err(DbError::Forbidden(_))
        ));

        // Platform-admin path: approver must be active staff with the permission.
        let admin = crate::platform_admin::PlatformAdminDb::for_tests(db.clone());
        let nobody = super::fixtures::new_user(&db).await;
        assert!(matches!(
            admin
                .admin_tx(
                    nobody,
                    domain::rbac::PlatformPerm::StaffManage,
                    &super::fixtures::admin_audit(nobody, "staff", "staff.create"),
                    now()
                )
                .await,
            Err(DbError::Forbidden(_))
        ));
        // Support staff lacks platform.staff.manage.
        assert!(matches!(
            admin
                .admin_tx(
                    g.staff_user(),
                    domain::rbac::PlatformPerm::StaffManage,
                    &super::fixtures::admin_audit(g.staff_user(), "staff", "staff.create"),
                    now()
                )
                .await,
            Err(DbError::Forbidden(_))
        ));
        // A tx opened for one permission cannot be used for another.
        let sa = super::fixtures::superadmin(&db).await;
        let mut tx = admin
            .admin_tx(
                sa,
                domain::rbac::PlatformPerm::StaffAccessOpen,
                &super::fixtures::admin_audit(sa, "staff", "staff_access.open"),
                now(),
            )
            .await
            .expect("admin tx");
        assert!(matches!(
            staff_grant::insert_staff(
                &mut tx,
                UserId::new(),
                domain::rbac::StaffRole::Support,
                now()
            )
            .await,
            Err(DbError::Forbidden(_))
        ));
        tx.rollback().await;
        // Bootstrap only once.
        let u = super::fixtures::new_user(&db).await;
        assert!(matches!(
            admin
                .bootstrap_first_superadmin(
                    u,
                    &super::fixtures::admin_audit(u, "system", "staff.bootstrap"),
                    now()
                )
                .await,
            Err(DbError::Conflict("staff.bootstrap_done"))
        ));
    })
    .await;
}

/// Review fix: `verify` on the APP pool (SELECT-only on staff tables) answers 403, never 1142/internal.
#[tokio::test]
async fn verify_on_app_pool_forbidden_for_expired_ok_for_valid() {
    let env = match crate::testing::load_env() {
        Ok(e) => e,
        Err(r) => {
            return super::harness::unavailable(
                "verify_app_pool",
                r,
                crate::testing::skip_allowed(),
            );
        }
    };
    if env.root_password.is_none() && !super::harness::tidb_mode() {
        return super::harness::unavailable(
            "verify_app_pool",
            "LOCAL_MYSQL_ROOT_PASSWORD missing",
            false,
        );
    }
    let scratch = crate::testing::ScratchDb::create_with(
        &env,
        crate::testing::ScratchOpts { max_connections: 2 },
    )
    .await
    .expect("scratch");
    let result = futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
        let mig = scratch.migrator().clone();
        let app = scratch.app().expect("app pool").clone();
        let a = new_tenant(&mig).await;
        let g = staff_grant_until(&mig, a.tenant, now() + Duration::seconds(60)).await;
        // Valid grant: Ok on the app pool (no locking read on a SELECT-only table).
        let mut tx = app.system_tx().await.expect("tx");
        assert!(
            staff_grant::verify(&mut tx, g.staff_user(), g.grant(), a.tenant, now())
                .await
                .is_ok()
        );
        tx.rollback().await;
        assert!(
            app.tenant_tx_for_staff(&g, &staff_audit(&g, "staff_access.used"), now())
                .await
                .is_ok()
        );
        // Expired grant: Forbidden, not an internal error.
        let mut tx = app.system_tx().await.expect("tx");
        let e = staff_grant::verify(
            &mut tx,
            g.staff_user(),
            g.grant(),
            a.tenant,
            now() + Duration::seconds(600),
        )
        .await
        .expect_err("expired");
        tx.rollback().await;
        assert!(matches!(e, DbError::Forbidden(_)), "{e:?}");
        let app_err: common::AppError = e.into();
        assert_eq!(app_err.kind, common::AppErrorKind::Forbidden);
    }))
    .await;
    scratch.drop_db(&env).await.expect("drop");
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}
