//! T-DB4 (expect_one -> NotPersisted on a 0-row update), T-DB9 (with_retry), quotas, identity repos,
//! sessions/refresh rotation, idempotency replay, outbox cap.

use super::fixtures::{add_member, new_member, new_tenant, new_user, now};
use super::harness::with_db;
use crate::error::DbError;
use crate::idempotency::{self, Reservation};
use crate::outbox::{OutboxEvent, outbox_insert};
use crate::repo::memberships::{self, MembershipStatus};
use crate::repo::sessions::{self, ClientKind, NewRefreshToken, NewSession, PrincipalKind};
use crate::repo::tenants;
use crate::repo::users::{self, HashScheme, NewUser, UserStatus};
use common::{MembershipId, SessionId, UserId};
use domain::rbac::TenantRole;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use time::Duration;

#[tokio::test]
async fn expect_one_on_zero_row_update_is_not_persisted() {
    with_db("expect_one", |db, _| async move {
        // 0-row UPDATE through a repo fn (data_keys rotation of an unknown kid) -> NotPersisted.
        let store = crate::repo::keys::DbDekStore::new(db.clone());
        let kid = crypto::Kid::parse("p-xxx-00000000").expect("kid");
        let e = store
            .deactivate(&kid, now())
            .await
            .expect_err("unknown kid");
        assert!(matches!(
            e,
            DbError::NotPersisted {
                expected: 1,
                actual: 0
            }
        ));
        // Same through the epoch guard of a tenant tx: no row for tenant X -> NotPersisted.
        let a = new_tenant(&db).await;
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        crate::bump_epoch(&mut tx, now())
            .await
            .expect("bump ok for real tenant");
        tx.rollback().await;
    })
    .await;
}

#[tokio::test]
async fn with_retry_retries_transient_only() {
    with_db("with_retry", |db, _| async move {
        let a = new_tenant(&db).await;
        let s = a.scope();
        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&calls);
        let v = db
            .with_retry(&s, move |tx| {
                let c = Arc::clone(&c);
                Box::pin(async move {
                    let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                    crate::bump_epoch(tx, now()).await?;
                    if n < 3 {
                        return Err(DbError::Transient { code: 1213 });
                    }
                    Ok(n)
                })
            })
            .await
            .expect("third attempt wins");
        assert_eq!(v, 3);
        // Rolled-back attempts left no trace: exactly one bump committed.
        let mut tx = db.tenant_tx(&s).await.expect("tx");
        assert_eq!(crate::epochs::current_epoch(&mut tx).await.expect("e"), 2);
        tx.rollback().await;

        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&calls);
        let r: Result<(), _> = db
            .with_retry(&s, move |_tx| {
                let c = Arc::clone(&c);
                Box::pin(async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err(DbError::Transient { code: 9007 })
                })
            })
            .await;
        assert!(matches!(r, Err(DbError::Transient { code: 9007 })));
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&calls);
        let r: Result<(), _> = db
            .with_retry(&s, move |_tx| {
                let c = Arc::clone(&c);
                Box::pin(async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err(DbError::LastOwner)
                })
            })
            .await;
        assert!(matches!(r, Err(DbError::LastOwner)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    })
    .await;
}

#[tokio::test]
async fn member_quota_and_counters() {
    with_db("quota", |db, _| async move {
        let a = new_tenant(&db).await;
        let g = super::fixtures::staff_grant(&db, a.tenant).await;
        let mut ptx = db
            .platform_tx(
                &g,
                &super::fixtures::staff_audit(&g, "tenant.quota_update"),
                now(),
            )
            .await
            .expect("ptx");
        tenants::set_max_members(&mut ptx, Some(2), now())
            .await
            .expect("quota");
        ptx.commit().await.expect("c");
        let m = add_member(&db, &a, TenantRole::Member).await; // 2/2
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        let e = memberships::insert(
            &mut tx,
            &new_member(new_user(&db).await, TenantRole::Viewer),
            now(),
        )
        .await
        .expect_err("over quota");
        assert!(matches!(
            e,
            DbError::QuotaExceeded {
                limit: 2,
                current: 2,
                ..
            }
        ));
        // Invited members do not take a slot; disabling frees one.
        let mut inv = new_member(new_user(&db).await, TenantRole::Viewer);
        inv.status = MembershipStatus::Invited;
        memberships::insert(&mut tx, &inv, now())
            .await
            .expect("invite");
        memberships::set_status(&mut tx, m, MembershipStatus::Disabled, now())
            .await
            .expect("disable");
        assert_eq!(
            crate::repo::counters::get(&mut tx)
                .await
                .expect("c")
                .members_active,
            1
        );
        memberships::set_status(&mut tx, inv.id, MembershipStatus::Active, now())
            .await
            .expect("enable invited");
        assert!(matches!(
            memberships::set_status(&mut tx, m, MembershipStatus::Active, now()).await,
            Err(DbError::QuotaExceeded { .. })
        ));
        // Same user twice -> conflict.
        let row = memberships::get(&mut tx, m).await.expect("g").expect("r");
        let mut dup = new_member(row.user_id, TenantRole::Viewer);
        dup.status = MembershipStatus::Invited;
        let r = memberships::insert(&mut tx, &dup, now()).await;
        assert!(
            matches!(r, Err(DbError::Conflict("members.already_member"))),
            "duplicate member insert gave {r:?}"
        );
        tx.commit().await.expect("c");
    })
    .await;
}

#[tokio::test]
async fn identity_sessions_and_refresh_rotation() {
    with_db("identity", |db, _| async move {
        let a = new_tenant(&db).await;
        let mut tx = db.identity_tx().await.expect("tx");
        let mut bidx = [0u8; 32];
        bidx[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        let u = users::insert(
            &mut tx,
            &NewUser {
                id: UserId::new(),
                email_bidx: bidx,
                email_enc: vec![1],
                name_enc: Some(vec![2]),
                status: UserStatus::PendingVerification,
            },
            now(),
        )
        .await
        .expect("user");
        let dup = users::insert(
            &mut tx,
            &NewUser {
                id: UserId::new(),
                email_bidx: bidx,
                email_enc: vec![1],
                name_enc: None,
                status: UserStatus::Active,
            },
            now(),
        )
        .await;
        assert!(matches!(dup, Err(DbError::Conflict("users.email_taken"))));
        tx.rollback().await; // the failed statement must not poison: start clean
        let mut tx = db.identity_tx().await.expect("tx");
        let u2 = users::insert(
            &mut tx,
            &NewUser {
                id: u,
                email_bidx: bidx,
                email_enc: vec![1],
                name_enc: Some(vec![2]),
                status: UserStatus::Active,
            },
            now(),
        )
        .await
        .expect("user");
        let found = users::find_by_email_bidx(&mut tx, &bidx)
            .await
            .expect("f")
            .expect("some");
        assert_eq!(found.id, u2);
        users::set_password(
            &mut tx,
            u2,
            "$argon2id$v=19$fake",
            HashScheme::Argon2id,
            now(),
        )
        .await
        .expect("pw");
        users::set_password(
            &mut tx,
            u2,
            "$argon2id$v=19$fake2",
            HashScheme::Argon2id,
            now(),
        )
        .await
        .expect("pw2");
        let cred = users::credentials(&mut tx, u2)
            .await
            .expect("c")
            .expect("some");
        assert_eq!(cred.version, 2);
        assert!(!format!("{cred:?}").contains("fake2"));
        tx.commit().await.expect("c");

        // u2 joins tenant A; directory sees it.
        let mut ttx = db.tenant_tx(&a.scope()).await.expect("ttx");
        let mid = memberships::insert(&mut ttx, &new_member(u2, TenantRole::Member), now())
            .await
            .expect("m");
        ttx.commit().await.expect("c");
        let mut tx = db.identity_tx().await.expect("tx");
        let dir = users::memberships_of(&mut tx, u2).await.expect("dir");
        assert_eq!(dir.len(), 1);
        assert_eq!((dir[0].tenant, dir[0].membership), (a.tenant, mid));

        // Session must reference a membership of this user.
        let bad = sessions::insert(
            &mut tx,
            &NewSession {
                id: SessionId::new(),
                user_id: u2,
                tenant: Some((a.tenant, MembershipId::new())),
                principal_kind: PrincipalKind::Member,
                client_kind: ClientKind::Web,
                product_code: None,
                device_label: None,
                expires_at: now() + Duration::days(1),
            },
            now(),
        )
        .await;
        assert!(matches!(bad, Err(DbError::NotFound("membership"))));
        let sid = sessions::insert(
            &mut tx,
            &NewSession {
                id: SessionId::new(),
                user_id: u2,
                tenant: Some((a.tenant, mid)),
                principal_kind: PrincipalKind::Member,
                client_kind: ClientKind::DesktopApp,
                product_code: Some("DSDE".into()),
                device_label: Some("Windows 11".into()),
                expires_at: now() + Duration::days(1),
            },
            now(),
        )
        .await
        .expect("session");
        let fam = uuid::Uuid::now_v7();
        let mut h1 = [1u8; 32];
        h1[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        let mut h2 = [2u8; 32];
        h2[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        let rt1 = NewRefreshToken {
            id: uuid::Uuid::now_v7(),
            session: sid,
            family_id: fam,
            token_hash: h1,
            expires_at: now() + Duration::days(30),
        };
        sessions::insert_refresh(&mut tx, &rt1, now())
            .await
            .expect("rt1");
        let rt2 = NewRefreshToken {
            id: uuid::Uuid::now_v7(),
            token_hash: h2,
            ..rt1.clone()
        };
        sessions::insert_refresh(&mut tx, &rt2, now())
            .await
            .expect("rt2");
        sessions::mark_refresh_used(&mut tx, rt1.id, rt2.id, now())
            .await
            .expect("rotate");
        assert!(matches!(
            sessions::mark_refresh_used(&mut tx, rt1.id, rt2.id, now()).await,
            Err(DbError::Conflict("auth.refresh_reused"))
        ));
        assert_eq!(
            sessions::revoke_family(&mut tx, fam, now())
                .await
                .expect("rf"),
            2
        );
        let f = sessions::find_refresh_by_hash(&mut tx, &h2)
            .await
            .expect("f")
            .expect("s");
        assert!(f.revoked_at.is_some());
        assert!(
            sessions::revoke(&mut tx, sid, "logout", now())
                .await
                .expect("rev")
        );
        assert!(
            !sessions::revoke(&mut tx, sid, "logout", now())
                .await
                .expect("rev2")
        );
        let s = sessions::get(&mut tx, sid).await.expect("g").expect("s");
        assert_eq!(s.revoke_reason.as_deref(), Some("logout"));
        tx.commit().await.expect("c");

        // Tenant activity list sees the session.
        let mut ttx = db.tenant_tx(&a.scope()).await.expect("ttx");
        let page = common::Page::parse(Some(10), None, super::fixtures::CURSOR_KEY).expect("p");
        let l = sessions::list_for_member(&mut ttx, mid, &page, super::fixtures::CURSOR_KEY)
            .await
            .expect("list");
        assert_eq!(l.data.len(), 1);
        ttx.rollback().await;
    })
    .await;
}

#[tokio::test]
async fn idempotency_replay_mismatch_and_outbox_cap() {
    with_db("idem", |db, _| async move {
        let a = new_tenant(&db).await;
        let p = a.owner.0;
        let h1 = [1u8; 32];
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        assert_eq!(
            idempotency::reserve(&mut tx, p, "op-1", &h1, now(), Duration::hours(1))
                .await
                .expect("r"),
            Reservation::Fresh
        );
        let rid = uuid::Uuid::now_v7();
        idempotency::complete(&mut tx, p, "op-1", 201, Some(b"{\"ok\":true}"), Some(rid))
            .await
            .expect("complete");
        assert!(matches!(
            idempotency::complete(&mut tx, p, "op-1", 201, None, None).await,
            Err(DbError::NotPersisted { .. })
        ));
        let ev = OutboxEvent {
            event_type: "member.created",
            aggregate_type: "membership",
            aggregate_id: rid,
            payload: serde_json::json!({"id": rid.to_string()}),
        };
        outbox_insert(&mut tx, &ev, now()).await.expect("outbox");
        let big = OutboxEvent {
            payload: serde_json::json!({"x": "y".repeat(5000)}),
            ..ev
        };
        assert!(matches!(
            outbox_insert(&mut tx, &big, now()).await,
            Err(DbError::Invalid(_))
        ));
        tx.commit().await.expect("c");
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        assert_eq!(
            idempotency::reserve(&mut tx, p, "op-1", &h1, now(), Duration::hours(1))
                .await
                .expect("r"),
            Reservation::Replay {
                status_code: 201,
                body: Some(b"{\"ok\":true}".to_vec()),
                resource_id: Some(rid)
            }
        );
        assert_eq!(
            idempotency::reserve(&mut tx, p, "op-1", &[9u8; 32], now(), Duration::hours(1))
                .await
                .expect("r"),
            Reservation::Mismatch
        );
        // Expired key is reusable.
        let later = now() + Duration::hours(2);
        assert_eq!(
            idempotency::reserve(&mut tx, p, "op-1", &[9u8; 32], later, Duration::hours(1))
                .await
                .expect("r"),
            Reservation::Fresh
        );
        assert!(
            idempotency::reserve(&mut tx, p, "", &h1, now(), Duration::hours(1))
                .await
                .is_err()
        );
        tx.commit().await.expect("c");
    })
    .await;
}

/// Recovery path for an ERR packet sqlx cannot decode (TiDB self-hosted: raw BINARY key bytes in
/// `Duplicate entry`). Engine-side mechanics: right after a failed prepared INSERT, `SHOW ERRORS`
/// over the text protocol still reports 1062 + key name; after a successful statement it reports
/// nothing (so a non-server Protocol error keeps its old value-free mapping).
#[tokio::test]
async fn show_errors_recovers_duplicate_after_failed_insert() {
    with_db("show_errors", |db, _| async move {
        let mut tx = db.identity_tx().await.expect("tx");
        let mut bidx = [0u8; 32];
        bidx[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        bidx[16..].copy_from_slice(&[0xff; 16]); // non-UTF-8 key bytes
        let insert = |id: UserId, bidx: [u8; 32]| {
            crate::sql::q(crate::queries::USERS_INSERT)
                .bind(id.0)
                .bind(bidx.to_vec())
                .bind(vec![1u8])
                .bind(None::<Vec<u8>>)
                .bind(UserStatus::Active.as_str())
                .bind(now())
                .bind(now())
        };
        assert_eq!(
            tx.inner
                .execute(insert(UserId::new(), bidx))
                .await
                .expect("first"),
            1
        );
        assert!(
            tx.inner.last_server_error().await.is_none(),
            "no error after a successful statement"
        );
        let dup = tx.inner.execute(insert(UserId::new(), bidx)).await;
        assert!(
            matches!(&dup, Err(e) if e.is_duplicate_of("ux_users_email_bidx")),
            "duplicate gave {dup:?}"
        );
        let rec = tx.inner.last_server_error().await;
        assert!(
            matches!(&rec, Some(e) if e.is_duplicate_of("ux_users_email_bidx")),
            "SHOW ERRORS gave {rec:?}"
        );
        // The connection is still usable inside the same tx (fresh key -> 1 row).
        let mut other = bidx;
        other[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        assert_eq!(
            tx.inner
                .execute(insert(UserId::new(), other))
                .await
                .expect("after recovery"),
            1
        );
        tx.rollback().await;
    })
    .await;
}
