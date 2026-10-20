//! T-DB3: last-owner protection under the tenant row mutex, including two concurrent demotions on
//! separate connections (exactly one succeeds). Also authz_version + epoch bump on success.

use super::fixtures::{add_member, new_tenant, now};
use super::harness::with_db;
use crate::epochs::current_epoch;
use crate::error::DbError;
use crate::repo::memberships::{self, MembershipStatus};
use domain::rbac::TenantRole;
use std::time::Duration;

#[tokio::test]
async fn sole_owner_cannot_be_demoted_or_disabled() {
    with_db("last_owner_single", |db, _| async move {
        let a = new_tenant(&db).await;
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        assert!(matches!(
            memberships::set_role(&mut tx, a.owner, TenantRole::Admin, now()).await,
            Err(DbError::LastOwner)
        ));
        assert!(matches!(
            memberships::set_status(&mut tx, a.owner, MembershipStatus::Disabled, now()).await,
            Err(DbError::LastOwner)
        ));
        // Non-owner changes are fine and bump authz_version + epoch.
        tx.rollback().await;
        let m = add_member(&db, &a, TenantRole::Member).await;
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        let e0 = current_epoch(&mut tx).await.expect("epoch");
        memberships::set_role(&mut tx, m, TenantRole::Admin, now())
            .await
            .expect("promote");
        let row = memberships::get(&mut tx, m).await.expect("g").expect("row");
        assert_eq!(row.role, TenantRole::Admin);
        assert_eq!(row.authz_version, 2);
        assert_eq!(current_epoch(&mut tx).await.expect("epoch"), e0 + 1);
        tx.commit().await.expect("c");
        // epoch poller sees it
        db.poll_epochs(now()).await.expect("poll");
        assert_eq!(db.epochs().current(a.tenant), Some(e0 + 1));
    })
    .await;
}

#[tokio::test]
async fn concurrent_demotions_exactly_one_wins() {
    with_db("last_owner_race", |db, _| async move {
        let a = new_tenant(&db).await;
        let o2 = add_member(&db, &a, TenantRole::Owner).await;
        let o1 = a.owner;

        let s = a.scope();
        let fut1 = {
            let db = db.clone();
            let s = s.clone();
            async move {
                let mut tx = db.tenant_tx(&s).await.expect("tx1");
                let r = memberships::set_role(&mut tx, o1, TenantRole::Admin, now()).await;
                // Hold the tenant mutex while tx2 queues behind it.
                tokio::time::sleep(Duration::from_millis(400)).await;
                match r {
                    Ok(()) => tx.commit().await,
                    Err(e) => {
                        tx.rollback().await;
                        Err(e)
                    }
                }
            }
        };
        let fut2 = {
            let db = db.clone();
            let s = s.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let mut tx = db.tenant_tx(&s).await.expect("tx2");
                let r = memberships::set_role(&mut tx, o2, TenantRole::Admin, now()).await;
                match r {
                    Ok(()) => tx.commit().await,
                    Err(e) => {
                        tx.rollback().await;
                        Err(e)
                    }
                }
            }
        };
        let (r1, r2) = tokio::join!(fut1, fut2);
        let oks = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
        assert_eq!(oks, 1, "r1={r1:?} r2={r2:?}");
        assert!(
            matches!(r1, Err(DbError::LastOwner)) || matches!(r2, Err(DbError::LastOwner)),
            "loser must get LastOwner: r1={r1:?} r2={r2:?}"
        );
        // Exactly one active owner left.
        let mut tx = db.tenant_tx(&s).await.expect("tx");
        let roles = [
            memberships::get(&mut tx, o1)
                .await
                .expect("g")
                .expect("r")
                .role,
            memberships::get(&mut tx, o2)
                .await
                .expect("g")
                .expect("r")
                .role,
        ];
        assert_eq!(roles.iter().filter(|r| **r == TenantRole::Owner).count(), 1);
        tx.rollback().await;
    })
    .await;
}

#[tokio::test]
async fn concurrent_disable_and_demote_exactly_one_wins() {
    with_db("last_owner_race2", |db, _| async move {
        let a = new_tenant(&db).await;
        let o2 = add_member(&db, &a, TenantRole::Owner).await;
        let s = a.scope();
        let (db1, db2, s1, s2, o1) = (db.clone(), db.clone(), s.clone(), s.clone(), a.owner);
        let f1 = async move {
            let mut tx = db1.tenant_tx(&s1).await.expect("tx1");
            let r = memberships::set_status(&mut tx, o1, MembershipStatus::Disabled, now()).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            match r {
                Ok(()) => tx.commit().await,
                Err(e) => {
                    tx.rollback().await;
                    Err(e)
                }
            }
        };
        let f2 = async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            let mut tx = db2.tenant_tx(&s2).await.expect("tx2");
            let r = memberships::set_role(&mut tx, o2, TenantRole::Member, now()).await;
            match r {
                Ok(()) => tx.commit().await,
                Err(e) => {
                    tx.rollback().await;
                    Err(e)
                }
            }
        };
        let (r1, r2) = tokio::join!(f1, f2);
        assert_eq!([&r1, &r2].iter().filter(|r| r.is_ok()).count(), 1);
        assert!(matches!(r2, Err(DbError::LastOwner)), "{r2:?}");
    })
    .await;
}
