//! Scratch-database harness. Never prints URLs or credentials.
//!
//! F1: a missing env file or an unreachable server FAILS the test (panic) unless the developer sets
//! `DSECURE_DB_TESTS=skip` explicitly. `DSECURE_DEV_ENV_FILE` overrides the env file path.

use crate::migrate;
use crate::pool::Db;
use crate::sql;
use common::config_util::Env;
use futures_util::FutureExt as _;
use secrecy::SecretString;
use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

pub(crate) struct DevEnv {
    pub(crate) test_url: String,
    pub(crate) app_url: String,
    pub(crate) root_password: Option<SecretString>,
}

fn skip_allowed() -> bool {
    matches!(Env::process().optional("DSECURE_DB_TESTS"), Ok(Some(v)) if v == "skip")
}

fn env_file_path() -> PathBuf {
    match Env::process().optional("DSECURE_DEV_ENV_FILE") {
        Ok(Some(p)) => PathBuf::from(p),
        _ => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/dev.env"),
    }
}

/// Parse a KEY=VALUE env file. Error reasons are value-free.
pub(crate) fn parse_dev_env(path: &Path) -> Result<DevEnv, &'static str> {
    let text = std::fs::read_to_string(path).map_err(|_| "env file not readable")?;
    let mut m = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            m.insert(
                k.trim().to_owned(),
                v.trim().trim_matches('"').trim_matches('\'').to_owned(),
            );
        }
    }
    Ok(DevEnv {
        test_url: m
            .remove("TEST_DATABASE_URL")
            .ok_or("TEST_DATABASE_URL missing")?,
        app_url: m.remove("DATABASE_URL").ok_or("DATABASE_URL missing")?,
        root_password: m
            .remove("LOCAL_MYSQL_ROOT_PASSWORD")
            .map(SecretString::from),
    })
}

/// DB not available: panic (default) or print SKIP when explicitly allowed.
pub(crate) fn unavailable(test: &str, reason: &str, allow_skip: bool) {
    assert!(
        allow_skip,
        "local MySQL test DB required for {test}: {reason} (set DSECURE_DB_TESTS=skip to skip)"
    );
    eprintln!("SKIP {test}: {reason} (DSECURE_DB_TESTS=skip)");
}

/// Env file of the local test DB; `None` only when skipping is explicitly allowed.
pub(crate) fn dev_env(test: &str) -> Option<DevEnv> {
    match parse_dev_env(&env_file_path()) {
        Ok(e) => Some(e),
        Err(reason) => {
            unavailable(test, reason, skip_allowed());
            None
        }
    }
}

/// Report a connect failure (value-free `DbError` text) through [`unavailable`].
pub(crate) fn connect_failed(test: &str, e: &crate::DbError) {
    unavailable(test, &format!("connect failed ({e})"), skip_allowed());
}

pub(crate) fn cfg(url: &str, expect: config::DbEngine) -> config::DbConfig {
    config::DbConfig {
        url: SecretString::from(url.to_owned()),
        tls_ca: None,
        expect_engine: expect,
        max_connections: 8,
        acquire_timeout_ms: 10_000,
        tx_timeout_ms: 5000,
        max_execution_ms: 5000,
        lock_wait_timeout_s: 5,
        retry_max_attempts: 3,
        retry_base_delay_ms: 20,
        statement_cache_capacity: 64,
        migrator_url: None,
    }
}

/// Replace the database (path) part of a mysql URL. Test-only helper.
pub(crate) fn with_database(url: &str, db: &str) -> String {
    let start = url.find("://").map_or(0, |i| i + 3);
    let auth_end = url[start..].find('/').map_or(url.len(), |i| start + i);
    let host_from = url[start..auth_end]
        .rfind('@')
        .map_or(start, |i| start + i + 1);
    let slash = url[host_from..]
        .find('/')
        .map_or(url.len(), |i| host_from + i);
    let end = url[slash..].find('?').map_or(url.len(), |i| slash + i);
    format!("{}/{}{}", &url[..slash], db, &url[end..])
}

/// Connect as migrator to `dsecure_test`. `None` only when skipping is explicitly allowed.
pub(crate) async fn admin(test: &str) -> Option<(DevEnv, Db)> {
    let env = dev_env(test)?;
    match Db::connect(
        &cfg(&env.test_url, config::DbEngine::MySql),
        config::Environment::Test,
    )
    .await
    {
        Ok(db) => Some((env, db)),
        Err(e) => {
            connect_failed(test, &e);
            None
        }
    }
}

#[test]
#[should_panic(expected = "local MySQL test DB required")]
fn missing_env_file_fails_instead_of_skipping() {
    // Same path the `DSECURE_DEV_ENV_FILE` override takes, pointed at a non-existent file.
    if let Err(reason) = parse_dev_env(Path::new("C:/definitely/not/here/dev.env")) {
        unavailable("missing_env_file", reason, false);
    }
}

#[test]
fn explicit_skip_does_not_panic() {
    unavailable("explicit_skip", "test", true);
}

pub(crate) fn scratch_name() -> String {
    let s = uuid::Uuid::now_v7().simple().to_string();
    format!("dsecure_t_{}", &s[16..])
}

pub(crate) fn valid_scratch(name: &str) -> bool {
    name.strip_prefix("dsecure_t_")
        .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub(crate) async fn admin_exec(admin: &Db, stmt: String) -> Result<(), crate::DbError> {
    sql::dynamic(stmt)
        .execute(admin.pool())
        .await
        .map(|_| ())
        .map_err(sql::map_err)
}

/// Run `f` against a fresh, fully migrated scratch DB (+ MySQL shadow FKs); always drops it.
pub(crate) async fn with_db<F, Fut>(test: &str, f: F)
where
    F: FnOnce(Db, DevEnv) -> Fut,
    Fut: Future<Output = ()>,
{
    if tidb_mode() {
        return with_shared_db(test, f).await;
    }
    let Some((env, admin)) = admin(test).await else {
        return;
    };
    let name = scratch_name();
    assert!(valid_scratch(&name));
    admin_exec(
        &admin,
        format!("CREATE DATABASE {name} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"),
    )
    .await
    .expect("create scratch db");
    let url = with_database(&env.test_url, &name);
    let result = AssertUnwindSafe(async {
        let db = Db::connect(
            &cfg(&url, config::DbEngine::MySql),
            config::Environment::Test,
        )
        .await
        .expect("connect scratch");
        migrate::run(&db).await.expect("migrations");
        migrate::run_shadow_fks(&db).await.expect("shadow fks");
        f(db.clone(), env).await;
        db.close().await;
    })
    .catch_unwind()
    .await;
    // Only ever drops the validated per-test scratch database.
    if valid_scratch(&name) {
        let _ = admin_exec(&admin, format!("DROP DATABASE IF EXISTS {name}")).await;
    }
    admin.close().await;
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

#[test]
fn with_database_rewrites_path_only() {
    assert_eq!(
        with_database(
            "mysql://u:p@127.0.0.1:3307/dsecure_test?ssl-mode=DISABLED",
            "x1"
        ),
        "mysql://u:p@127.0.0.1:3307/x1?ssl-mode=DISABLED"
    );
    assert_eq!(with_database("mysql://u:p@h/db", "x2"), "mysql://u:p@h/x2");
    assert_eq!(with_database("mysql://u@h:1", "x3"), "mysql://u@h:1/x3");
    assert!(valid_scratch(&scratch_name()));
    assert!(!valid_scratch("dsecure_test"));
}

/// `DSECURE_TEST_ENGINE=tidb`: tests run on the shared TiDB test DB (`crate::testing`).
pub(crate) fn tidb_mode() -> bool {
    crate::testing::test_engine() == crate::testing::TestEngine::TiDb
}

/// In TiDB mode print `SKIP (tidb): <test>: <reason>` and return true (caller returns).
pub(crate) fn tidb_skip(test: &str, reason: &str) -> bool {
    if tidb_mode() {
        eprintln!("SKIP (tidb): {test}: {reason}");
        true
    } else {
        false
    }
}

/// TiDB mode body of [`with_db`]: shared DB (migrated once per process), migrator pool for `f`.
async fn with_shared_db<F, Fut>(test: &str, f: F)
where
    F: FnOnce(Db, DevEnv) -> Fut,
    Fut: Future<Output = ()>,
{
    let env = match crate::testing::load_env() {
        Ok(e) => e,
        Err(r) => return unavailable(test, r, skip_allowed()),
    };
    let scratch = match crate::testing::ScratchDb::create(&env).await {
        Ok(s) => s,
        Err(e) => return connect_failed(test, &e),
    };
    let dev = DevEnv {
        test_url: String::new(),
        app_url: String::new(),
        root_password: None,
    };
    let result = AssertUnwindSafe(f(scratch.migrator().clone(), dev))
        .catch_unwind()
        .await;
    let _ = scratch.drop_db(&env).await; // shared: closes pools only
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}
