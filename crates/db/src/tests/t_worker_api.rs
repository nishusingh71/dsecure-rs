//! Worker APIs: outbox relay claim/publish/release, job release, idempotency sweep, platform
//! pseudo-tenant, and the public `testing::ScratchDb` harness running the app path as the
//! least-privilege scratch app user.

use super::fixtures::{new_member, new_tenant, new_user, now};
use super::harness::{unavailable, with_db};
use crate::error::DbError;
use crate::idempotency::{self, Reservation};
use crate::jobs::{self, NewJob};
use crate::outbox::{OutboxEvent, outbox_insert};
use crate::repo::{memberships, tenants};
use crate::sql;
use crate::{PLATFORM_TENANT_ID, testing};
use domain::rbac::{TenantRole, TenantScope, Visibility};
use time::Duration;

fn ev(n: u32) -> OutboxEvent {
    OutboxEvent {
        event_type: "member.created",
        aggregate_type: "membership",
        aggregate_id: uuid::Uuid::now_v7(),
        payload: serde_json::json!({ "n": n }),
    }
}

#[tokio::test]
async fn outbox_relay_claim_publish_release() {
    with_db("outbox_relay", |db, _| async move {
        let a = new_tenant(&db).await;
        let t0 = now();
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        let mut ids = Vec::new();
        for i in 0..3 {
            ids.push(
                outbox_insert(&mut tx, &ev(i), t0 + Duration::milliseconds(i64::from(i)))
                    .await
                    .expect("ins"),
            );
        }
        tx.commit().await.expect("c");
        let first = db
            .outbox_claim_batch_for("relay-1", Some(a.tenant), t0, 2, Duration::seconds(30))
            .await
            .expect("claim");
        assert_eq!(
            first.iter().map(|e| e.id).collect::<Vec<_>>(),
            ids[..2].to_vec(),
            "oldest first"
        );
        assert!(
            first
                .iter()
                .all(|e| e.tenant == Some(a.tenant) && e.attempts == 1)
        );
        let second = db
            .outbox_claim_batch_for("relay-1", Some(a.tenant), t0, 10, Duration::seconds(30))
            .await
            .expect("claim");
        assert_eq!(
            second.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![ids[2]]
        );
        assert!(
            db.outbox_claim_batch_for("relay-1", Some(a.tenant), t0, 10, Duration::seconds(30))
                .await
                .expect("c")
                .is_empty()
        );
        assert_eq!(db.outbox_mark_published(&first, t0).await.expect("pub"), 2);
        assert_eq!(db.outbox_release(&second).await.expect("rel"), 1);
        let again = db
            .outbox_claim_batch_for("relay-1", Some(a.tenant), t0, 10, Duration::seconds(30))
            .await
            .expect("claim");
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].attempts, 2);
        // Stale claim token cannot publish (at-least-once: the new holder publishes).
        assert_eq!(
            db.outbox_mark_published(&second, t0).await.expect("stale"),
            0
        );
        // Expired lease is reclaimable.
        let later = db
            .outbox_claim_batch_for(
                "relay-1",
                Some(a.tenant),
                t0 + Duration::minutes(1),
                10,
                Duration::seconds(30),
            )
            .await
            .expect("claim");
        assert_eq!(later.len(), 1);
        assert_eq!(db.outbox_mark_published(&later, t0).await.expect("pub"), 1);
        assert!(
            db.outbox_claim_batch_for(
                "relay-1",
                Some(a.tenant),
                t0 + Duration::hours(1),
                10,
                Duration::seconds(30)
            )
            .await
            .expect("c")
            .is_empty()
        );
    })
    .await;
}

#[tokio::test]
async fn release_job_returns_attempt_and_idempotency_sweep() {
    with_db("release_sweep", |db, _| async move {
        let kind = super::fixtures::uniq_kind("rel");
        let t0 = now();
        let mut tx = db.system_tx().await.expect("tx");
        jobs::enqueue_system(
            &mut tx,
            &NewJob {
                kind,
                job_key: format!("{kind}:rel"),
                payload: serde_json::json!({}),
                run_after: t0,
                max_attempts: 3,
                max_pending: None,
            },
            t0,
        )
        .await
        .expect("enq");
        tx.commit().await.expect("c");
        let j = db
            .claim_jobs("w", kind, t0, Duration::seconds(30), 1)
            .await
            .expect("claim")
            .remove(0);
        assert_eq!(j.attempts(), 1);
        db.release_job(&j).await.expect("release");
        assert_eq!(
            db.job_status(j.id()).await.expect("s"),
            ("queued".to_owned(), 0)
        );
        assert!(matches!(
            db.release_job(&j).await,
            Err(DbError::NotPersisted { .. })
        ));
        let j2 = db
            .claim_jobs("w", kind, t0, Duration::seconds(30), 1)
            .await
            .expect("claim")
            .remove(0);
        assert_eq!(
            j2.attempts(),
            1,
            "release did not consume an attempt, no backoff"
        );

        let a = new_tenant(&db).await;
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        let p = a.owner.0;
        for k in ["old", "new"] {
            let ttl = if k == "old" {
                Duration::hours(1)
            } else {
                Duration::days(3)
            };
            assert_eq!(
                idempotency::reserve(&mut tx, p, k, &[1; 32], t0, ttl)
                    .await
                    .expect("r"),
                Reservation::Fresh
            );
            idempotency::complete(&mut tx, p, k, 200, Some(b"body"), None)
                .await
                .expect("c");
        }
        tx.commit().await.expect("c");
        let later = t0 + Duration::hours(2);
        // The sweep is global: on the shared TiDB DB other tests' expired keys are swept too.
        let swept = idempotency::expire_older_than(&db, later, 500)
            .await
            .expect("sweep");
        if super::harness::tidb_mode() {
            assert!(swept >= 1, "{swept}");
        } else {
            assert_eq!(swept, 1);
            assert_eq!(
                idempotency::expire_older_than(&db, later, 100)
                    .await
                    .expect("sweep"),
                0
            );
        }
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        assert_eq!(
            idempotency::reserve(&mut tx, p, "old", &[1; 32], later, Duration::hours(1))
                .await
                .expect("r"),
            Reservation::Fresh,
            "expired key ignored by lookups"
        );
        assert!(matches!(
            idempotency::reserve(&mut tx, p, "new", &[1; 32], later, Duration::hours(1))
                .await
                .expect("r"),
            Reservation::Replay {
                status_code: 200,
                ..
            }
        ));
        tx.rollback().await;
    })
    .await;
}

#[tokio::test]
async fn platform_pseudo_tenant_is_reserved() {
    with_db("platform_tenant", |db, _| async move {
        let mut tx = db.system_tx().await.expect("tx");
        let row = tx
            .inner
            .fetch_optional(
                sql::dynamic(String::from("SELECT status FROM tenants WHERE id = ?"))
                    .bind(PLATFORM_TENANT_ID.0),
            )
            .await
            .expect("q")
            .expect("platform row exists");
        assert_eq!(sql::col::<String>(&row, "status").expect("s"), "platform");
        tx.rollback().await;
        let s = TenantScope::for_tests(
            PLATFORM_TENANT_ID,
            common::MembershipId::new(),
            Visibility::Tenant,
            None,
        );
        assert!(matches!(
            db.tenant_tx(&s).await,
            Err(DbError::ScopeMissing(_))
        ));
        let mut tx = db.system_tx().await.expect("tx");
        let r = tenants::create(
            &mut tx,
            &tenants::NewTenant {
                id: PLATFORM_TENANT_ID,
                kind: tenants::TenantKind::Organization,
                display_name_enc: vec![1],
            },
            &tenants::NewOwner {
                membership_id: common::MembershipId::new(),
                user_id: common::UserId::new(),
                display_name_enc: None,
            },
            now(),
        )
        .await;
        assert!(matches!(r, Err(DbError::Invalid(_))));
        tx.rollback().await;
        // Platform DEKs are owned by the pseudo-tenant in the DB, `None` towards crypto. Not in the
        // shared TiDB DB: it would leave a dummy active platform DEK behind.
        if super::harness::tidb_skip(
            "platform_pseudo_tenant (DEK part)",
            "would persist a dummy platform DEK",
        ) {
            return;
        }
        use crypto::DekStore as _;
        let store = crate::DbDekStore::new(db.clone());
        let kid = crypto::Kid::generate(crypto::KeyPurpose::Identity, None).expect("kid");
        store
            .insert(
                &kid,
                crypto::KeyPurpose::Identity,
                None,
                &crypto::WrappedDek {
                    kek_ref: "env:t".into(),
                    bytes: vec![1; 61],
                },
            )
            .await
            .expect("insert");
        let (_, t, _) = store.by_kid(&kid).await.expect("by kid").expect("some");
        assert_eq!(t, None);
        let mut tx = db.system_tx().await.expect("tx");
        let row = tx
            .inner
            .fetch_optional(
                sql::dynamic(String::from(
                    "SELECT tenant_id FROM data_keys WHERE kid = ?",
                ))
                .bind(kid.as_str()),
            )
            .await
            .expect("q")
            .expect("row");
        assert_eq!(
            sql::opt_uuid_col(&row, "tenant_id").expect("t"),
            Some(PLATFORM_TENANT_ID.0)
        );
        tx.rollback().await;
    })
    .await;
}

#[tokio::test]
async fn public_harness_app_user_runs_app_path() {
    if super::harness::tidb_skip(
        "public_harness_app_user_runs_app_path",
        "needs local root to create a scratch app user",
    ) {
        return;
    }
    let env = match testing::load_env() {
        Ok(e) => e,
        Err(r) => return unavailable("public_harness", r, testing::skip_allowed()),
    };
    if env.root_password.is_none() {
        return unavailable("public_harness", "LOCAL_MYSQL_ROOT_PASSWORD missing", false);
    }
    let scratch = testing::ScratchDb::create(&env).await.expect("scratch db");
    let name = scratch.name().to_owned();
    assert!(testing::valid_scratch(&name));
    let app = scratch.app().expect("app pool").clone();
    let result = futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
        // Full app path as the least-privilege user: tenant + member + epoch + job + outbox.
        let a = new_tenant(&app).await;
        let mut tx = app.tenant_tx(&a.scope()).await.expect("tx");
        memberships::insert(
            &mut tx,
            &new_member(new_user(&app).await, TenantRole::Member),
            now(),
        )
        .await
        .expect("member");
        crate::bump_epoch(&mut tx, now()).await.expect("epoch");
        outbox_insert(&mut tx, &ev(1), now()).await.expect("outbox");
        tx.commit().await.expect("c");
        // DELETE is refused for the app user.
        let e = sql::dynamic(String::from(
            "DELETE FROM outbox_events WHERE tenant_id = ?",
        ))
        .bind(a.tenant.0)
        .execute(app.pool())
        .await
        .map_err(sql::map_err)
        .expect_err("no delete");
        assert!(matches!(e, DbError::PermissionDenied { number: 1142 }));
    }))
    .await;
    scratch.drop_db(&env).await.expect("drop scratch");
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

/// 8 parallel ScratchDb create/use/drop cycles with the per-DB app user: no 1044/1045.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_scratch_dbs_have_independent_app_users() {
    if super::harness::tidb_skip(
        "parallel_scratch_dbs_have_independent_app_users",
        "needs CREATE/DROP DATABASE and scratch users",
    ) {
        return;
    }
    let env = match testing::load_env() {
        Ok(e) => e,
        Err(r) => return unavailable("parallel_scratch", r, testing::skip_allowed()),
    };
    if env.root_password.is_none() {
        return unavailable(
            "parallel_scratch",
            "LOCAL_MYSQL_ROOT_PASSWORD missing",
            false,
        );
    }
    let env = std::sync::Arc::new(env);
    let cycles = (0..8).map(|_| {
        let env = std::sync::Arc::clone(&env);
        async move {
            let scratch = testing::ScratchDb::create(&env).await?;
            let user = testing::scratch_app_user(scratch.name()).expect("user name");
            assert!(user.len() <= 32 && testing::valid_scratch_user(&user));
            let app = scratch.app().expect("app pool").clone();
            let r: Result<(), DbError> = async {
                for _ in 0..3 {
                    let a = new_tenant(&app).await;
                    let mut tx = app.tenant_tx(&a.scope()).await?;
                    crate::bump_epoch(&mut tx, now()).await?;
                    tx.commit().await?;
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Ok(())
            }
            .await;
            scratch.drop_db(&env).await?;
            r
        }
    });
    let results = futures_util::future::join_all(cycles).await;
    for r in &results {
        assert!(
            !matches!(
                r,
                Err(DbError::PermissionDenied {
                    number: 1044 | 1045
                })
            ),
            "{results:?}"
        );
        assert!(r.is_ok(), "{results:?}");
    }
}

#[tokio::test]
async fn raw_test_helpers_exec_and_fetch() {
    with_db("raw_helpers", |db, _| async move {
        use crate::testing::{RawBind, raw_exec, raw_fetch};
        use sqlx::Row as _;
        let t = common::TenantId::new();
        let n = raw_exec(
            &db,
            "INSERT INTO authz_epochs (tenant_id, epoch, updated_at) VALUES (?, ?, ?)",
            &[RawBind::Uuid(t.0), RawBind::I64(7), RawBind::Time(now())],
        )
        .await
        .expect("exec");
        assert_eq!(n, 1);
        let rows = raw_fetch(
            &db,
            "SELECT epoch FROM authz_epochs WHERE tenant_id = ?",
            &[RawBind::Uuid(t.0)],
        )
        .await
        .expect("fetch");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].try_get::<u64, _>("epoch").expect("epoch"), 7);
    })
    .await;
}
