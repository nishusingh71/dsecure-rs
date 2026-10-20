//! T-DB1 equivalent (no RLS): tenant A's tx cannot read/update/insert B's rows through any repo fn;
//! row-tenant assert (T-DB12) fires; helpers refuse to run without a scope; visibility filters.

use super::fixtures::{
    CURSOR_KEY, add_member, group_vis, new_member, new_tenant, new_user, now, scope_with,
};
use super::harness::with_db;
use crate::error::DbError;
use crate::idempotency::{self, Reservation};
use crate::queries::MEMBERSHIPS_GET;
use crate::repo::memberships::{self, MembershipStatus};
use crate::repo::sessions::{self, ClientKind, NewSession, PrincipalKind};
use crate::repo::{counters, groups, tenants};
use crate::sql;
use common::{GroupId, MembershipId, Page, SessionId, TenantId};
use domain::rbac::{TenantRole, TenantScope, Visibility};
use time::Duration;

#[tokio::test]
async fn cross_tenant_reads_updates_inserts_are_blocked() {
    with_db("cross_tenant", |db, _| async move {
        let a = new_tenant(&db).await;
        let b = new_tenant(&db).await;
        let a_m = add_member(&db, &a, TenantRole::Member).await;
        let b_m = add_member(&db, &b, TenantRole::Member).await;
        let b_group = {
            let mut tx = db.tenant_tx(&b.scope()).await.expect("tx");
            let g = groups::create(&mut tx, GroupId::new(), "B team", None, now())
                .await
                .expect("group");
            tx.commit().await.expect("commit");
            g
        };
        // B member has a session (tenant-scoped activity list).
        let b_user = {
            let mut tx = db.tenant_tx(&b.scope()).await.expect("tx");
            let u = memberships::get(&mut tx, b_m)
                .await
                .expect("get")
                .expect("row")
                .user_id;
            tx.commit().await.expect("c");
            u
        };
        {
            let mut tx = db.identity_tx().await.expect("tx");
            sessions::insert(
                &mut tx,
                &NewSession {
                    id: SessionId::new(),
                    user_id: b_user,
                    tenant: Some((b.tenant, b_m)),
                    principal_kind: PrincipalKind::Member,
                    client_kind: ClientKind::Web,
                    product_code: None,
                    device_label: None,
                    expires_at: now() + Duration::days(1),
                },
                now(),
            )
            .await
            .expect("session");
            tx.commit().await.expect("c");
        }

        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx A");
        // Reads
        assert!(memberships::get(&mut tx, b_m).await.expect("get").is_none());
        assert!(
            memberships::get(&mut tx, b.owner)
                .await
                .expect("get")
                .is_none()
        );
        assert!(memberships::get(&mut tx, a_m).await.expect("get").is_some());
        let page = Page::parse(Some(200), None, CURSOR_KEY).expect("page");
        let list = memberships::list(&mut tx, &page, CURSOR_KEY)
            .await
            .expect("list");
        assert_eq!(list.data.len(), 2);
        assert!(list.data.iter().all(|m| m.tenant == a.tenant));
        let s = sessions::list_for_member(&mut tx, b_m, &page, CURSOR_KEY)
            .await
            .expect("sessions");
        assert!(s.data.is_empty());
        assert_eq!(tenants::get_own(&mut tx).await.expect("own").id, a.tenant);
        assert_eq!(counters::get(&mut tx).await.expect("ctr").members_active, 2);
        // Updates
        assert!(matches!(
            memberships::set_role(&mut tx, b_m, TenantRole::Admin, now()).await,
            Err(DbError::NotFound(_))
        ));
        assert!(matches!(
            memberships::set_status(&mut tx, b_m, MembershipStatus::Disabled, now()).await,
            Err(DbError::NotFound(_))
        ));
        // Inserts referencing B's rows
        assert!(matches!(
            groups::add_member(&mut tx, b_group, a_m, now()).await,
            Err(DbError::NotFound("group"))
        ));
        assert!(matches!(
            groups::create(&mut tx, GroupId::new(), "x", Some(b_group), now()).await,
            Err(DbError::NotFound("parent group"))
        ));
        let mut nm = new_member(new_user(&db).await, TenantRole::Member);
        nm.parent_membership_id = Some(b_m);
        assert!(matches!(
            memberships::insert(&mut tx, &nm, now()).await,
            Err(DbError::NotFound("parent membership"))
        ));
        tx.rollback().await;

        // B unchanged
        let mut tx = db.tenant_tx(&b.scope()).await.expect("tx B");
        let row = memberships::get(&mut tx, b_m)
            .await
            .expect("get")
            .expect("row");
        assert_eq!(row.role, TenantRole::Member);
        assert_eq!(row.status, MembershipStatus::Active);
        assert_eq!(row.version, 1);
        tx.commit().await.expect("c");
    })
    .await;
}

#[tokio::test]
async fn idempotency_keys_are_tenant_scoped() {
    with_db("idem_scope", |db, _| async move {
        let a = new_tenant(&db).await;
        let b = new_tenant(&db).await;
        let principal = uuid::Uuid::now_v7();
        let h = [7u8; 32];
        for t in [&a, &b] {
            let mut tx = db.tenant_tx(&t.scope()).await.expect("tx");
            let r = idempotency::reserve(&mut tx, principal, "k1", &h, now(), Duration::hours(1))
                .await
                .expect("reserve");
            assert_eq!(r, Reservation::Fresh);
            tx.commit().await.expect("c");
        }
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        idempotency::complete(&mut tx, principal, "k1", 201, Some(b"{}"), None)
            .await
            .expect("complete");
        tx.commit().await.expect("c");
        // B's key is still in progress (A's completion did not touch it).
        let mut tx = db.tenant_tx(&b.scope()).await.expect("tx");
        let r = idempotency::reserve(&mut tx, principal, "k1", &h, now(), Duration::hours(1))
            .await
            .expect("reserve");
        assert_eq!(r, Reservation::InProgress);
        tx.rollback().await;
    })
    .await;
}

#[tokio::test]
async fn row_tenant_assert_fires_on_foreign_row() {
    with_db("row_assert", |db, _| async move {
        let a = new_tenant(&db).await;
        let b = new_tenant(&db).await;
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        // Fault injection: fetch B's row with B's tenant bound (bypasses the repo on purpose).
        let row = tx
            .inner
            .fetch_optional(sql::q(MEMBERSHIPS_GET).bind(b.tenant.0).bind(b.owner.0))
            .await
            .expect("raw")
            .expect("row");
        assert!(matches!(
            memberships::map_row(&tx, &row),
            Err(DbError::TenantMismatch)
        ));
        assert!(matches!(
            tx.assert_row_tenant(b.tenant),
            Err(DbError::TenantMismatch)
        ));
        assert!(tx.assert_row_tenant(a.tenant).is_ok());
        assert!(crate::assert_row_tenant(a.tenant, b.tenant).is_err());
        tx.rollback().await;
    })
    .await;
}

#[tokio::test]
async fn helpers_refuse_without_scope() {
    with_db("no_scope", |db, _| async move {
        let a = new_tenant(&db).await;
        let nil_tenant = TenantScope::for_tests(
            TenantId(uuid::Uuid::nil()),
            a.owner,
            Visibility::Tenant,
            None,
        );
        assert!(matches!(
            db.tenant_tx(&nil_tenant).await,
            Err(DbError::ScopeMissing(_))
        ));
        let nil_actor = scope_with(
            a.tenant,
            MembershipId(uuid::Uuid::nil()),
            Visibility::Tenant,
        );
        assert!(matches!(
            db.tenant_tx(&nil_actor).await,
            Err(DbError::ScopeMissing(_))
        ));
        // Empty group visibility = sees nothing (fail closed).
        let empty = scope_with(a.tenant, a.owner, group_vis(&[]));
        let mut tx = db.tenant_tx(&empty).await.expect("tx");
        let page = Page::parse(Some(50), None, super::fixtures::CURSOR_KEY).expect("p");
        assert!(
            memberships::list(&mut tx, &page, CURSOR_KEY)
                .await
                .expect("list")
                .data
                .is_empty()
        );
        assert!(
            memberships::get(&mut tx, a.owner)
                .await
                .expect("get")
                .is_none()
        );
        tx.rollback().await;
    })
    .await;
}

#[tokio::test]
async fn visibility_self_and_groups() {
    with_db("visibility", |db, _| async move {
        let a = new_tenant(&db).await;
        let m1 = add_member(&db, &a, TenantRole::Member).await;
        let m2 = add_member(&db, &a, TenantRole::Member).await;
        let adm = add_member(&db, &a, TenantRole::Admin).await;
        let g = {
            let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
            let g = groups::create(&mut tx, GroupId::new(), "Ops", None, now())
                .await
                .expect("g");
            groups::add_member(&mut tx, g, m1, now())
                .await
                .expect("add");
            groups::add_member(&mut tx, g, adm, now())
                .await
                .expect("add");
            assert!(matches!(
                groups::add_member(&mut tx, g, m1, now()).await,
                Err(DbError::Conflict("groups.already_member"))
            ));
            tx.commit().await.expect("c");
            g
        };
        let page = Page::parse(Some(50), None, CURSOR_KEY).expect("p");
        // SelfOnly
        let mut tx = db
            .tenant_tx(&scope_with(a.tenant, m2, Visibility::SelfOnly))
            .await
            .expect("tx");
        let l = memberships::list(&mut tx, &page, CURSOR_KEY)
            .await
            .expect("l");
        assert_eq!(l.data.iter().map(|m| m.id).collect::<Vec<_>>(), vec![m2]);
        assert!(memberships::get(&mut tx, m1).await.expect("g").is_none());
        tx.rollback().await;
        // Groups: m1 (member rank 40) visible, admin (rank 80) and m2 (not in group) not.
        let mut tx = db
            .tenant_tx(&scope_with(a.tenant, m2, group_vis(&[g])))
            .await
            .expect("tx");
        let l = memberships::list(&mut tx, &page, CURSOR_KEY)
            .await
            .expect("l");
        assert_eq!(l.data.iter().map(|m| m.id).collect::<Vec<_>>(), vec![m1]);
        assert!(memberships::get(&mut tx, m1).await.expect("g").is_some());
        assert!(memberships::get(&mut tx, adm).await.expect("g").is_none());
        assert!(memberships::get(&mut tx, m2).await.expect("g").is_none());
        tx.rollback().await;
    })
    .await;
}

#[tokio::test]
async fn group_add_requires_visible_group_and_member() {
    with_db("group_add_visibility", |db, _| async move {
        let a = new_tenant(&db).await;
        let ga = add_member(&db, &a, TenantRole::Member).await;
        let m1 = add_member(&db, &a, TenantRole::Member).await;
        let outsider = add_member(&db, &a, TenantRole::Member).await;
        let adm = add_member(&db, &a, TenantRole::Admin).await;
        let (g, other_g) = {
            let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
            let g = groups::create(&mut tx, GroupId::new(), "G1", None, now())
                .await
                .expect("g");
            let o = groups::create(&mut tx, GroupId::new(), "G2", None, now())
                .await
                .expect("g2");
            groups::add_member(&mut tx, g, m1, now())
                .await
                .expect("add");
            tx.commit().await.expect("c");
            (g, o)
        };
        let mut tx = db
            .tenant_tx(&scope_with(a.tenant, ga, group_vis(&[g])))
            .await
            .expect("tx");
        // Member outside the caller's groups -> NotFound (invisible).
        assert!(matches!(
            groups::add_member(&mut tx, g, outsider, now()).await,
            Err(DbError::NotFound("membership"))
        ));
        // Admin (rank >= 60) is never visible to a group scope.
        assert!(matches!(
            groups::add_member(&mut tx, g, adm, now()).await,
            Err(DbError::NotFound("membership"))
        ));
        // Group outside the caller's groups -> NotFound.
        assert!(matches!(
            groups::add_member(&mut tx, other_g, m1, now()).await,
            Err(DbError::NotFound("group"))
        ));
        tx.rollback().await;
        // SelfOnly scope cannot add to any group.
        let mut tx = db
            .tenant_tx(&scope_with(a.tenant, ga, Visibility::SelfOnly))
            .await
            .expect("tx");
        assert!(matches!(
            groups::add_member(&mut tx, g, ga, now()).await,
            Err(DbError::NotFound("group"))
        ));
        tx.rollback().await;

        // F13: > 200 group ids are chunked, not refused.
        let mut many: Vec<GroupId> = (0..450).map(|_| GroupId::new()).collect();
        many.push(g);
        let mut tx = db
            .tenant_tx(&scope_with(a.tenant, ga, group_vis(&many)))
            .await
            .expect("tx");
        let page = Page::parse(Some(50), None, CURSOR_KEY).expect("p");
        let l = memberships::list(&mut tx, &page, CURSOR_KEY)
            .await
            .expect("list");
        assert_eq!(l.data.iter().map(|m| m.id).collect::<Vec<_>>(), vec![m1]);
        assert!(memberships::get(&mut tx, m1).await.expect("g").is_some());
        tx.rollback().await;
    })
    .await;
}
