//! `signing_keys` repo (platform-admin writes, app reads, rotation, dev bootstrap) and
//! `migrate::pending`.

use super::fixtures::{admin_audit, now, superadmin};
use super::harness::{admin_exec, cfg, scratch_name, unavailable, valid_scratch, with_database};
use crate::error::DbError;
use crate::platform_admin::PlatformAdminDb;
use crate::repo::signing_keys::{self, NewSigningKey, SigningKeyStatus, SigningRealm};
use crate::{DbDekStore, sql, testing};
use crypto::devkeys::generate_kek_b64;
use crypto::{AesGcmFieldEncryptor, EnvKeyProvider, KeyRing, SigAlg};
use domain::rbac::PlatformPerm;
use std::sync::Arc;
use time::Duration;
use zeroize::Zeroizing;

async fn encryptor(db: &crate::Db) -> AesGcmFieldEncryptor {
    let kek = generate_kek_b64().expect("kek");
    let provider = Arc::new(EnvKeyProvider::new("t1", [("t1", kek.to_string())]).expect("p"));
    let store = Arc::new(DbDekStore::new(db.clone()));
    KeyRing::ensure_platform_keys(&*provider, &*store)
        .await
        .expect("platform keys");
    let ring = KeyRing::load_platform(provider, store).await.expect("ring");
    AesGcmFieldEncryptor::new(Arc::new(ring))
}

fn key(kid: &str, realm: SigningRealm, nb: time::OffsetDateTime, secret: u8) -> NewSigningKey {
    NewSigningKey {
        kid: kid.into(),
        alg: SigAlg::Ed25519,
        realm,
        private_key: Zeroizing::new(vec![secret; 48]),
        public_key: vec![secret ^ 0xff; 32],
        not_before: nb,
        expires_at: None,
    }
}

fn rotate_audit(actor: common::UserId) -> crate::repo::audit::AuditRowRecord {
    let mut a = admin_audit(actor, "staff", "keys.rotate");
    a.metadata = Some(serde_json::json!({ "owner_approval_ref": "OWNER-APPROVAL-1" }));
    a
}

#[tokio::test]
async fn platform_admin_writes_app_reads_and_rotation() {
    if super::harness::tidb_skip(
        "platform_admin_writes_app_reads_and_rotation",
        "platform DEKs persist in the shared DB; a per-run test KEK cannot unwrap them",
    ) {
        return;
    }
    let env = match testing::load_env() {
        Ok(e) => e,
        Err(r) => return unavailable("signing_keys", r, testing::skip_allowed()),
    };
    if env.root_password.is_none() {
        return unavailable("signing_keys", "LOCAL_MYSQL_ROOT_PASSWORD missing", false);
    }
    let scratch = testing::ScratchDb::create(&env).await.expect("scratch");
    let result = futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
        let mig = scratch.migrator().clone();
        let app = scratch.app().expect("app").clone();
        let enc = encryptor(&mig).await;
        let admin = PlatformAdminDb::for_tests(mig.clone());
        let sa = superadmin(&mig).await;
        // keys.rotate needs owner approval: plain admin_tx refused, reference mandatory + recorded.
        assert!(matches!(
            admin
                .admin_tx(
                    sa,
                    PlatformPerm::KeysRotate,
                    &admin_audit(sa, "staff", "keys.rotate"),
                    now()
                )
                .await,
            Err(DbError::Forbidden(_))
        ));
        assert!(matches!(
            admin
                .admin_tx_owner_approved(
                    sa,
                    PlatformPerm::KeysRotate,
                    "OWNER-APPROVAL-1",
                    &admin_audit(sa, "staff", "keys.rotate"),
                    now()
                )
                .await,
            Err(DbError::Invalid(_))
        ));
        let t = now();
        let mut tx = admin
            .admin_tx_owner_approved(
                sa,
                PlatformPerm::KeysRotate,
                "OWNER-APPROVAL-1",
                &rotate_audit(sa),
                t,
            )
            .await
            .expect("admin tx");
        signing_keys::insert_signing_key(
            &mut tx,
            &enc,
            &key(
                "jwt-m-1",
                SigningRealm::JwtMember,
                t - Duration::minutes(10),
                1,
            ),
            t,
        )
        .await
        .expect("k1");
        tx.commit().await.expect("c");

        // Stored ciphertext only (never the raw private bytes).
        let mut stx = mig.system_tx().await.expect("tx");
        let row = stx
            .inner
            .fetch_optional(
                sql::dynamic(String::from(
                    "SELECT wrapped_private_key AS w FROM signing_keys WHERE kid = ?",
                ))
                .bind("jwt-m-1"),
            )
            .await
            .expect("q")
            .expect("row");
        let w: Vec<u8> = sql::col(&row, "w").expect("w");
        assert!(!w.windows(48).any(|x| x == [1u8; 48]), "plaintext stored");
        stx.rollback().await;

        // App user reads.
        let mut atx = app.system_tx().await.expect("tx");
        let k1 = signing_keys::active_for(&mut atx, SigningRealm::JwtMember, now())
            .await
            .expect("active")
            .expect("some");
        assert_eq!(k1.kid, "jwt-m-1");
        assert_eq!(
            &k1.private_key(&enc).await.expect("decrypt")[..],
            &[1u8; 48][..]
        );
        atx.rollback().await;
        // App user cannot write.
        let e = sql::dynamic(String::from("INSERT INTO signing_keys (kid) VALUES (?)"))
            .bind("x")
            .execute(app.pool())
            .await
            .map_err(sql::map_err)
            .expect_err("app insert");
        assert!(
            matches!(e, DbError::PermissionDenied { number: 1142 }),
            "{e:?}"
        );

        // Rotation: new active key, old one verify_only but still resolvable by kid.
        let t2 = now();
        let mut tx = admin
            .admin_tx_owner_approved(
                sa,
                PlatformPerm::KeysRotate,
                "OWNER-APPROVAL-1",
                &rotate_audit(sa),
                t2,
            )
            .await
            .expect("admin tx");
        signing_keys::insert_signing_key(
            &mut tx,
            &enc,
            &key(
                "jwt-m-2",
                SigningRealm::JwtMember,
                t2 - Duration::minutes(1),
                2,
            ),
            t2,
        )
        .await
        .expect("k2");
        signing_keys::set_status(&mut tx, "jwt-m-1", SigningKeyStatus::VerifyOnly)
            .await
            .expect("verify only");
        assert!(
            signing_keys::set_status(&mut tx, "jwt-m-1", SigningKeyStatus::Active)
                .await
                .is_err()
        );
        tx.commit().await.expect("c");
        let mut atx = app.system_tx().await.expect("tx");
        let active = signing_keys::active_for(&mut atx, SigningRealm::JwtMember, now())
            .await
            .expect("a")
            .expect("s");
        assert_eq!(active.kid, "jwt-m-2");
        let old = signing_keys::by_kid(&mut atx, "jwt-m-1")
            .await
            .expect("b")
            .expect("s");
        assert_eq!(old.status, SigningKeyStatus::VerifyOnly);
        assert_eq!(
            &old.private_key(&enc).await.expect("dec")[..],
            &[1u8; 48][..]
        );
        let jwks = signing_keys::list_public(&mut atx, now())
            .await
            .expect("list");
        let kids: Vec<_> = jwks.iter().map(|k| k.kid.as_str()).collect();
        assert!(kids.contains(&"jwt-m-1") && kids.contains(&"jwt-m-2"));
        assert!(
            signing_keys::by_kid(&mut atx, "nope")
                .await
                .expect("b")
                .is_none()
        );
        atx.rollback().await;

        // Dev bootstrap: refused in production; idempotent in test.
        let boot = admin_audit(sa, "system", "keys.dev_bootstrap");
        let k = [key(
            "dev-rep-1",
            SigningRealm::ReportCertificate,
            now() - Duration::minutes(1),
            9,
        )];
        assert!(matches!(
            signing_keys::dev_bootstrap(
                &mig,
                config::Environment::Production,
                &enc,
                &k,
                &boot,
                now()
            )
            .await,
            Err(DbError::Config(_))
        ));
        assert_eq!(
            signing_keys::dev_bootstrap(&mig, config::Environment::Test, &enc, &k, &boot, now())
                .await
                .expect("boot"),
            1
        );
        let k2 = [key(
            "dev-rep-2",
            SigningRealm::ReportCertificate,
            now() - Duration::minutes(1),
            8,
        )];
        assert_eq!(
            signing_keys::dev_bootstrap(&mig, config::Environment::Test, &enc, &k2, &boot, now())
                .await
                .expect("boot again"),
            0,
            "realm already has an active key"
        );
        // pending() as the app user after full migration: empty.
        assert!(
            crate::migrate::pending(&app)
                .await
                .expect("pending")
                .is_empty()
        );
    }))
    .await;
    scratch.drop_db(&env).await.expect("drop");
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

#[tokio::test]
async fn pending_lists_unapplied_versions_on_partial_db() {
    if super::harness::tidb_skip(
        "pending_lists_unapplied_versions_on_partial_db",
        "needs CREATE/DROP DATABASE",
    ) {
        return;
    }
    let Some((env, admin)) = super::harness::admin("pending_partial").await else {
        return;
    };
    let name = scratch_name();
    assert!(valid_scratch(&name));
    admin_exec(
        &admin,
        format!("CREATE DATABASE {name} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"),
    )
    .await
    .expect("create");
    let url = with_database(&env.test_url, &name);
    let result = futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
        let db = crate::Db::connect(
            &cfg(&url, config::DbEngine::MySql),
            config::Environment::Test,
        )
        .await
        .expect("connect");
        let all = crate::migrate::pending(&db)
            .await
            .expect("pending on empty");
        assert_eq!(
            all.len(),
            crate::migration_files::MAIN.len(),
            "nothing applied"
        );
        crate::migrate::run_to(&db, 1_500_001)
            .await
            .expect("partial");
        let p = crate::migrate::pending(&db).await.expect("pending");
        assert!(!p.is_empty());
        assert!(p.iter().all(|v| *v > 1_500_001), "{p:?}");
        crate::migrate::run(&db).await.expect("rest");
        assert!(
            crate::migrate::pending(&db)
                .await
                .expect("pending")
                .is_empty()
        );
        db.close().await;
    }))
    .await;
    if valid_scratch(&name) {
        let _ = admin_exec(&admin, format!("DROP DATABASE IF EXISTS {name}")).await;
    }
    admin.close().await;
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

fn ops_audit(claimed: common::UserId, owner_ref: &str) -> crate::repo::audit::AuditRowRecord {
    let mut a = admin_audit(claimed, "system", "keys.provision");
    a.actor_id = None;
    a.metadata = Some(serde_json::json!({
        "actor": crate::platform_admin::OPS_CLI_ACTOR,
        "claimed_approver": claimed.0.hyphenated().to_string(),
        "owner_approval_ref": owner_ref,
    }));
    a
}

/// Ops-CLI path: system audit row with the CLAIMED approver; approver must still be an active
/// superadmin; DEKs + signing keys commit in the same tx (or not at all). API path unchanged.
#[tokio::test]
async fn ops_cli_tx_audits_claimed_approver_and_writes_deks_atomically() {
    if super::harness::tidb_skip(
        "ops_cli_tx_audits_claimed_approver_and_writes_deks_atomically",
        "platform DEKs persist in the shared DB",
    ) {
        return;
    }
    let env = match testing::load_env() {
        Ok(e) => e,
        Err(r) => return unavailable("ops_cli_tx", r, testing::skip_allowed()),
    };
    let scratch = testing::ScratchDb::create(&env).await.expect("scratch");
    let result = futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
        use crate::repo::keys::{insert_platform_dek_in_tx, platform_active_in_tx};
        use crypto::{Dek, KeyProvider as _, KeyPurpose, Kid, WrapContext};
        let mig = scratch.migrator().clone();
        let admin = PlatformAdminDb::for_tests(mig.clone());
        let sa = superadmin(&mig).await;
        let count = |t: &'static str| {
            let mig = mig.clone();
            async move {
                let rows = testing::raw_fetch(&mig, &format!("SELECT COUNT(*) AS n FROM {t}"), &[])
                    .await
                    .expect("count");
                sql::col::<i64>(&rows[0], "n").expect("n")
            }
        };

        // Refusals (nothing written): wrong row shapes, missing ref, non-staff claimed approver.
        let audits_before = count("audit_events").await;
        let mut staff_row = ops_audit(sa, "OWNER-OPS");
        staff_row.actor_kind = "staff".into();
        let mut with_actor = ops_audit(sa, "OWNER-OPS");
        with_actor.actor_id = Some(sa.0);
        let mut no_cli = ops_audit(sa, "OWNER-OPS");
        no_cli.metadata = Some(serde_json::json!({
            "claimed_approver": sa.0.hyphenated().to_string(),
            "owner_approval_ref": "OWNER-OPS",
        }));
        let other = common::UserId(uuid::Uuid::now_v7());
        for bad in [staff_row, with_actor, no_cli, ops_audit(other, "OWNER-OPS")] {
            assert!(matches!(
                admin
                    .ops_tx_owner_approved(sa, PlatformPerm::KeysRotate, "OWNER-OPS", &bad, now())
                    .await,
                Err(DbError::Invalid(_))
            ));
        }
        assert!(matches!(
            admin
                .ops_tx_owner_approved(
                    sa,
                    PlatformPerm::KeysRotate,
                    " ",
                    &ops_audit(sa, " "),
                    now()
                )
                .await,
            Err(DbError::Invalid(_))
        ));
        assert!(matches!(
            admin
                .ops_tx_owner_approved(
                    other,
                    PlatformPerm::KeysRotate,
                    "OWNER-OPS",
                    &ops_audit(other, "OWNER-OPS"),
                    now()
                )
                .await,
            Err(DbError::Forbidden(_))
        ));
        // API path still demands a staff row (an ops row is refused there).
        assert!(matches!(
            admin
                .admin_tx_owner_approved(
                    sa,
                    PlatformPerm::KeysRotate,
                    "OWNER-OPS",
                    &ops_audit(sa, "OWNER-OPS"),
                    now()
                )
                .await,
            Err(DbError::Invalid(_))
        ));
        assert_eq!(count("audit_events").await, audits_before);

        // DEK + key in one tx: rollback leaves nothing, commit leaves both + one system audit row.
        let kek = generate_kek_b64().expect("kek");
        let provider = EnvKeyProvider::new("ops1", [("ops1", kek.to_string())]).expect("p");
        let deks_before = count("data_keys").await;
        let keys_before = count("signing_keys").await;
        for commit in [false, true] {
            let mut tx = admin
                .ops_tx_owner_approved(
                    sa,
                    PlatformPerm::KeysRotate,
                    "OWNER-OPS",
                    &ops_audit(sa, "OWNER-OPS"),
                    now(),
                )
                .await
                .expect("ops tx");
            let p = KeyPurpose::PLATFORM[0];
            let existing = platform_active_in_tx(&mut tx, p).await.expect("read");
            let kid = Kid::generate(p, None).expect("kid");
            let w = provider
                .wrap(
                    &Dek::generate().expect("dek"),
                    &WrapContext {
                        kid: &kid,
                        purpose: p,
                        tenant: None,
                    },
                )
                .await
                .expect("wrap");
            if existing.is_none() {
                insert_platform_dek_in_tx(&mut tx, &kid, p, &w, now())
                    .await
                    .expect("insert dek");
                let seen = platform_active_in_tx(&mut tx, p).await.expect("re-read");
                assert_eq!(
                    seen.map(|(k, _)| k),
                    Some(kid.clone()),
                    "tx sees its own insert"
                );
            }
            assert!(matches!(
                insert_platform_dek_in_tx(&mut tx, &kid, p, &w, now()).await,
                Err(DbError::Conflict(_))
            ));
            assert!(matches!(
                platform_active_in_tx(&mut tx, KeyPurpose::PLATFORM[0]).await,
                Ok(Some(_))
            ));
            if commit {
                tx.commit().await.expect("commit");
            } else {
                tx.rollback().await;
                assert_eq!(count("data_keys").await, deks_before, "rollback kept a DEK");
                assert_eq!(count("audit_events").await, audits_before);
            }
        }
        assert_eq!(count("signing_keys").await, keys_before);
        assert_eq!(count("audit_events").await, audits_before + 1);
        let rows = testing::raw_fetch(
            &mig,
            "SELECT actor_kind, actor_id FROM audit_events WHERE action = 'keys.provision'",
            &[],
        )
        .await
        .expect("audit");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            sql::col::<String>(&rows[0], "actor_kind").expect("k"),
            "system"
        );
        assert!(
            sql::opt_uuid_col(&rows[0], "actor_id")
                .expect("id")
                .is_none()
        );

        // A tx opened for another permission cannot touch data_keys.
        let mut tx = admin
            .admin_tx(
                sa,
                PlatformPerm::StaffManage,
                &admin_audit(sa, "staff", "staff.manage"),
                now(),
            )
            .await
            .expect("staff tx");
        assert!(matches!(
            platform_active_in_tx(&mut tx, KeyPurpose::PLATFORM[0]).await,
            Err(DbError::Forbidden(_))
        ));
        tx.rollback().await;
    }))
    .await;
    scratch.drop_db(&env).await.expect("drop");
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}
