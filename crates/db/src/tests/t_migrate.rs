//! B1: release step `dsecure-api migrate` (`migrate::run_from_config` / `pending_from_config`) on an
//! EMPTY local scratch database: status lists everything, run applies everything once under the lock,
//! a second run applies nothing, a held lock answers `Conflict("migrate.busy")`, the legacy database
//! is refused before any connection. Local MySQL only (needs CREATE/DROP DATABASE).

use super::harness::{admin_exec, cfg, scratch_name, valid_scratch, with_database};
use crate::error::DbError;
use crate::migrate::{self, MIGRATION_LOCK_STALE, MigrationLock};
use crate::migration_files::MAIN;
use secrecy::SecretString;

fn migrator_cfg(url: &str) -> config::DbConfig {
    let mut c = cfg(url, config::DbEngine::MySql);
    c.max_connections = 2;
    c.migrator_url = Some(SecretString::from(url.to_owned()));
    c
}

#[tokio::test]
async fn run_from_config_applies_once_and_reports() {
    if super::harness::tidb_skip(
        "run_from_config_applies_once_and_reports",
        "needs CREATE/DROP DATABASE",
    ) {
        return;
    }
    let Some((env, admin)) = super::harness::admin("migrate_release_step").await else {
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
        let c = migrator_cfg(&url);
        let env_t = config::Environment::Test;
        // Status on an empty DB: every embedded version pending, nothing written.
        let p = migrate::pending_from_config(&c, env_t)
            .await
            .expect("status");
        assert_eq!(p.len(), MAIN.len());
        assert_eq!(
            migrate::pending_from_config(&c, env_t)
                .await
                .expect("status")
                .len(),
            MAIN.len(),
            "status is read-only"
        );

        // Lock held by another migrator: busy, nothing applied.
        let db = crate::Db::connect_migrator(&c, env_t).await.expect("conn");
        let lock = MigrationLock::acquire(&db, MIGRATION_LOCK_STALE)
            .await
            .expect("lock");
        let e = migrate::run_from_config(&c, env_t).await.expect_err("busy");
        assert!(matches!(e, DbError::Conflict("migrate.busy")), "{e:?}");
        lock.release(&db).await.expect("release");
        db.close().await;
        assert_eq!(
            migrate::pending_from_config(&c, env_t)
                .await
                .expect("status")
                .len(),
            MAIN.len()
        );

        // Apply: everything once; then up to date; second run applies nothing.
        let r = migrate::run_from_config(&c, env_t).await.expect("run");
        assert_eq!(r.applied, p);
        assert!(
            migrate::pending_from_config(&c, env_t)
                .await
                .expect("status")
                .is_empty()
        );
        let r2 = migrate::run_from_config(&c, env_t).await.expect("rerun");
        assert!(r2.applied.is_empty());
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

/// No server needed: the legacy database and a missing TLS mode (staging) are refused at connect.
#[tokio::test]
async fn run_from_config_refuses_legacy_and_plain_tls() {
    let legacy = migrator_cfg("mysql://u:p@127.0.0.1:1/Cloud_Erase__App");
    let e = migrate::run_from_config(&legacy, config::Environment::Test)
        .await
        .expect_err("legacy");
    assert!(matches!(e, DbError::Config(_)), "{e:?}");
    let plain = migrator_cfg("mysql://u:p@127.0.0.1:1/dsecure_rs_staging");
    let e = migrate::pending_from_config(&plain, config::Environment::Staging)
        .await
        .expect_err("tls");
    assert!(matches!(e, DbError::Config(_)), "{e:?}");
}
