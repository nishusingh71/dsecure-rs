//! Engine detection, DB_EXPECT_ENGINE enforcement, TLS / legacy refusal, session init.

use super::harness::{cfg, connect_failed, dev_env};
use crate::error::DbError;
use crate::pool::{Db, connect_options};
use crate::queries_internal::SELECT_SESSION_STATE;
use crate::sql;
use config::{DbEngine, Environment};
use secrecy::SecretString;

fn s(u: &str) -> SecretString {
    SecretString::from(u.to_owned())
}

#[tokio::test]
async fn expect_tidb_on_mysql_is_refused_and_mysql_passes() {
    if super::harness::tidb_skip(
        "expect_tidb_on_mysql_is_refused_and_mysql_passes",
        "targets the local MySQL (TEST_DATABASE_URL)",
    ) {
        return;
    }
    let Some(env) = dev_env("expect_engine") else {
        return;
    };
    let r = Db::connect(&cfg(&env.test_url, DbEngine::TiDb), Environment::Test).await;
    match r {
        Err(DbError::EngineMismatch { expected, found }) => {
            assert_eq!((expected, found), ("tidb", "mysql"));
        }
        Err(
            e @ (DbError::Transient { .. }
            | DbError::PermissionDenied { .. }
            | DbError::Unavailable),
        ) => {
            return connect_failed("expect_engine", &e);
        }
        other => panic!("expected EngineMismatch, got {:?}", other.map(|_| ())),
    }
    let db = Db::connect(&cfg(&env.test_url, DbEngine::MySql), Environment::Test)
        .await
        .expect("mysql expected must connect");
    assert_eq!(db.engine().kind(), DbEngine::MySql);
    db.close().await;
}

#[tokio::test]
async fn session_init_applied_on_every_connection() {
    if super::harness::tidb_skip(
        "session_init_applied_on_every_connection",
        "targets the local MySQL (TEST_DATABASE_URL)",
    ) {
        return;
    }
    let Some(env) = dev_env("session_init") else {
        return;
    };
    let db = match Db::connect(&cfg(&env.test_url, DbEngine::MySql), Environment::Test).await {
        Ok(db) => db,
        Err(e) => return connect_failed("session_init", &e),
    };
    for _ in 0..3 {
        let mut tx = db.system_tx().await.expect("tx");
        let row = tx
            .inner
            .fetch_optional(sql::q(SELECT_SESSION_STATE))
            .await
            .expect("q")
            .expect("row");
        let tz: String = sql::col(&row, "tz").expect("tz");
        let iso: String = sql::col(&row, "iso").expect("iso");
        let mode: String = sql::col(&row, "sql_mode").expect("mode");
        let coll: String = sql::col(&row, "coll").expect("coll");
        let lock_wait: u64 = sql::col(&row, "lock_wait").expect("lw");
        assert_eq!(tz, "+00:00");
        assert_eq!(iso, "REPEATABLE-READ");
        assert!(mode.contains("STRICT_TRANS_TABLES"), "{mode}");
        assert!(!mode.contains("PIPES_AS_CONCAT"), "{mode}");
        assert_eq!(coll, "utf8mb4_bin");
        assert_eq!(lock_wait, 5);
        tx.commit().await.expect("commit");
    }
    db.close().await;
}

#[test]
fn legacy_database_refused_in_every_env() {
    for env in [
        Environment::Dev,
        Environment::Test,
        Environment::Staging,
        Environment::Production,
    ] {
        for u in [
            "mysql://app@127.0.0.1:3307/Cloud_Erase__App",
            "mysql://app@127.0.0.1:3307/cloud_erase__app?ssl-mode=VERIFY_IDENTITY",
            "mysql://app@127.0.0.1:3307/Cloud%5FErase__App",
        ] {
            assert!(
                matches!(
                    connect_options(&s(u), None, env, 16),
                    Err(DbError::Config(_))
                ),
                "{env:?}"
            );
        }
    }
}

#[test]
fn tls_verify_identity_required_outside_dev_test() {
    let plain = "mysql://app@db.example.invalid:4000/dsecure";
    let required = "mysql://app@db.example.invalid:4000/dsecure?ssl-mode=REQUIRED";
    let verified = "mysql://app@db.example.invalid:4000/dsecure?ssl-mode=VERIFY_IDENTITY";
    let dup =
        "mysql://app@db.example.invalid:4000/dsecure?ssl-mode=VERIFY_IDENTITY&sslmode=DISABLED";
    for env in [Environment::Staging, Environment::Production] {
        for bad in [plain, required, dup] {
            let e = connect_options(&s(bad), None, env, 16).expect_err("must refuse");
            assert!(matches!(e, DbError::Config(_)));
            // value-free message
            assert!(!e.to_string().contains("example.invalid"));
        }
        assert!(connect_options(&s(verified), None, env, 16).is_ok());
    }
    for env in [Environment::Dev, Environment::Test] {
        assert!(connect_options(&s(plain), None, env, 16).is_ok());
    }
    // DB_TLS_CA accepted as PEM text or path; empty refused.
    let pem = s("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    assert!(connect_options(&s(verified), Some(&pem), Environment::Production, 16).is_ok());
    assert!(
        connect_options(
            &s(verified),
            Some(&s("C:/ca.pem")),
            Environment::Production,
            16
        )
        .is_ok()
    );
    assert!(connect_options(&s(verified), Some(&s("  ")), Environment::Production, 16).is_err());
    assert!(connect_options(&s("not a url"), None, Environment::Dev, 16).is_err());
}
