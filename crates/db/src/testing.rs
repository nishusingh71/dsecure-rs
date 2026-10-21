//! Public scratch-database harness for tests of OTHER crates (feature `test-fixtures`).
//!
//! - Local MySQL only: the env file `.dev/dev.env` (override path: `DSECURE_DEV_ENV_FILE`) provides
//!   `TEST_DATABASE_URL` (migrator), `DATABASE_URL` (app user) and optionally
//!   `LOCAL_MYSQL_ROOT_PASSWORD`. Nothing is ever printed except value-free reasons.
//! - Missing env/server = error. Callers decide; [`skip_allowed`] is true only when
//!   `DSECURE_DB_TESTS=skip` is set explicitly (otherwise tests must fail, review F1).
//! - [`ScratchDb::create`] makes `dsecure_t_<16 hex>`, runs main migrations + MySQL shadow FKs, and,
//!   when the root password is present, creates that database's OWN app user (`dsecure_ta_<hex>`,
//!   random password) with the generated least-privilege App grants on it ([`ScratchDb::app`]).
//!   [`ScratchDb::drop_db`] drops ONLY that scratch user and that scratch database.

use crate::error::DbError;
use crate::grants::{DbRole, grant_statements};
use crate::pool::Db;
use crate::sql;
use common::config_util::Env;
use secrecy::{ExposeSecret, SecretString};
use sqlx::mysql::{MySqlConnectOptions, MySqlConnection};
use sqlx::{ConnectOptions as _, Connection as _, Row as _};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

/// Prefix of the per-scratch-DB app users (`dsecure_ta_<16 hex>` = 27 chars, under MySQL's 32).
pub const SCRATCH_APP_USER_PREFIX: &str = "dsecure_ta_";

/// App user name belonging to scratch database `dsecure_t_<hex>`.
#[must_use]
pub fn scratch_app_user(scratch_db: &str) -> Option<String> {
    let hex = scratch_db.strip_prefix("dsecure_t_")?;
    let u = format!("{SCRATCH_APP_USER_PREFIX}{hex}");
    valid_scratch_user(&u).then_some(u)
}

/// Prefix of the per-scratch-DB platform-admin users (`dsecure_tp_<16 hex>`, created on demand by
/// [`ScratchDb::platform_admin`]).
pub const SCRATCH_PADM_USER_PREFIX: &str = "dsecure_tp_";

/// Platform-admin user name belonging to scratch database `dsecure_t_<hex>`.
#[must_use]
pub fn scratch_padm_user(scratch_db: &str) -> Option<String> {
    let hex = scratch_db.strip_prefix("dsecure_t_")?;
    let u = format!("{SCRATCH_PADM_USER_PREFIX}{hex}");
    valid_scratch_padm_user(&u).then_some(u)
}

/// Only users produced by [`scratch_padm_user`] may ever be dropped.
#[must_use]
pub fn valid_scratch_padm_user(user: &str) -> bool {
    user.len() <= 32
        && user
            .strip_prefix(SCRATCH_PADM_USER_PREFIX)
            .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Only users produced by [`scratch_app_user`] may ever be dropped.
#[must_use]
pub fn valid_scratch_user(user: &str) -> bool {
    user.len() <= 32
        && user
            .strip_prefix(SCRATCH_APP_USER_PREFIX)
            .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Local test DB credentials. `Debug` never shows values.
pub struct TestEnv {
    pub test_url: SecretString,
    pub app_url: SecretString,
    pub root_password: Option<SecretString>,
    /// TiDB mode: migrator / app URLs of the shared test DB (`TIDB_DEV_URL` / `TIDB_DEV_APP_URL`, or
    /// the local stand-in overrides `DSECURE_TEST_TIDB_URL` / `DSECURE_TEST_TIDB_APP_URL`).
    pub tidb_url: Option<SecretString>,
    pub tidb_app_url: Option<SecretString>,
    /// URLs came from the stand-in overrides (local MySQL pretending to be the shared DB).
    pub tidb_standin: bool,
}

/// Which engine the db tests target (`DSECURE_TEST_ENGINE=tidb`, default MySQL scratch DBs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestEngine {
    MySql,
    TiDb,
}

#[must_use]
pub fn test_engine() -> TestEngine {
    match Env::process().optional("DSECURE_TEST_ENGINE") {
        Ok(Some(v)) if v.eq_ignore_ascii_case("tidb") => TestEngine::TiDb,
        _ => TestEngine::MySql,
    }
}

/// The ONLY database TiDB mode may use (shared test DB, never created or dropped by tests).
pub const SHARED_TIDB_DB: &str = "dsecure_rs_test";
/// The local MySQL stand-in for TiDB mode (verification without TiDB).
pub const STANDIN_DB: &str = "dsecure_test";

impl std::fmt::Debug for TestEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestEnv([redacted])")
    }
}

/// `DSECURE_DB_TESTS=skip` set explicitly.
#[must_use]
pub fn skip_allowed() -> bool {
    matches!(Env::process().optional("DSECURE_DB_TESTS"), Ok(Some(v)) if v == "skip")
}

/// Env file path (`DSECURE_DEV_ENV_FILE` or `<workspace>/.dev/dev.env`).
#[must_use]
pub fn env_file_path() -> PathBuf {
    match Env::process().optional("DSECURE_DEV_ENV_FILE") {
        Ok(Some(p)) => PathBuf::from(p),
        _ => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/dev.env"),
    }
}

/// Parse a KEY=VALUE env file.
///
/// # Errors
/// Value-free reason.
pub fn parse_env_file(path: &Path) -> Result<TestEnv, &'static str> {
    let text = std::fs::read_to_string(path).map_err(|_| "env file not readable")?;
    // Stand-in overrides (process env) win over the file, so a local run never reaches TiDB.
    let standin_url = Env::process()
        .optional("DSECURE_TEST_TIDB_URL")
        .ok()
        .flatten()
        .filter(|v| !v.is_empty());
    let standin_app = Env::process()
        .optional("DSECURE_TEST_TIDB_APP_URL")
        .ok()
        .flatten()
        .filter(|v| !v.is_empty());
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
    Ok(TestEnv {
        test_url: SecretString::from(
            m.remove("TEST_DATABASE_URL")
                .ok_or("TEST_DATABASE_URL missing")?,
        ),
        app_url: SecretString::from(m.remove("DATABASE_URL").ok_or("DATABASE_URL missing")?),
        root_password: m
            .remove("LOCAL_MYSQL_ROOT_PASSWORD")
            .map(SecretString::from),
        tidb_url: standin_url
            .clone()
            .or_else(|| m.remove("TIDB_DEV_URL"))
            .map(SecretString::from),
        tidb_app_url: standin_app
            .clone()
            .or_else(|| m.remove("TIDB_DEV_APP_URL"))
            .map(SecretString::from),
        tidb_standin: standin_url.is_some(),
    })
}

/// [`parse_env_file`] on [`env_file_path`].
///
/// # Errors
/// Value-free reason.
pub fn load_env() -> Result<TestEnv, &'static str> {
    parse_env_file(&env_file_path())
}

/// Test `DbConfig` for a URL (local MySQL, 8 connections).
#[must_use]
pub fn test_config(url: &SecretString) -> config::DbConfig {
    test_config_with(url, 8)
}

/// Test `DbConfig` with an explicit pool size.
#[must_use]
pub fn test_config_with(url: &SecretString, max_connections: u32) -> config::DbConfig {
    test_config_engine(url, max_connections, config::DbEngine::MySql)
}

/// Test `DbConfig` with pool size and expected engine.
#[must_use]
pub fn test_config_engine(
    url: &SecretString,
    max_connections: u32,
    engine: config::DbEngine,
) -> config::DbConfig {
    config::DbConfig {
        url: url.clone(),
        tls_ca: None,
        expect_engine: engine,
        max_connections: max_connections.max(1),
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

/// Replace the database (path) of a mysql URL.
#[must_use]
pub fn with_database(url: &str, db: &str) -> String {
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

/// `dsecure_t_<16 hex>`.
#[must_use]
pub fn scratch_name() -> String {
    let s = uuid::Uuid::now_v7().simple().to_string();
    format!("dsecure_t_{}", s.get(16..).unwrap_or("0000000000000000"))
}

/// Only names produced by [`scratch_name`] may ever be dropped.
#[must_use]
pub fn valid_scratch(name: &str) -> bool {
    name.strip_prefix("dsecure_t_")
        .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'%' | b'_' | b'-' | b':'))
}

async fn exec_conn(conn: &mut MySqlConnection, stmt: String) -> Result<(), DbError> {
    sql::dynamic(stmt)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(sql::map_err)
}

/// Root connection to the LOCAL server (options of `TEST_DATABASE_URL`, user root).
///
/// # Errors
/// `Config` (no root password / bad URL), connection errors.
pub async fn root_connection(env: &TestEnv, database: &str) -> Result<MySqlConnection, DbError> {
    let pw = env
        .root_password
        .as_ref()
        .ok_or(DbError::Config("LOCAL_MYSQL_ROOT_PASSWORD missing"))?;
    MySqlConnectOptions::from_str(env.test_url.expose_secret())
        .map_err(|_| DbError::Config("TEST_DATABASE_URL could not be parsed"))?
        .username("root")
        .password(pw.expose_secret())
        .database(database)
        .connect()
        .await
        .map_err(sql::map_err)
}

/// Host part MySQL uses for local TCP clients (from `USER()`).
async fn client_host(conn: &mut MySqlConnection) -> Result<String, DbError> {
    let row = sql::dynamic(String::from("SELECT USER() AS u"))
        .fetch_one(&mut *conn)
        .await
        .map_err(sql::map_err)?;
    let who: String = row.try_get("u").map_err(|_| DbError::Corrupt("USER()"))?;
    let host = who
        .rsplit_once('@')
        .map_or("localhost", |(_, h)| h)
        .to_owned();
    if host_ok(&host) {
        Ok(host)
    } else {
        Err(DbError::Corrupt("client host"))
    }
}

/// Scratch DB options. `max_connections` applies to the migrator and app pools (default 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScratchOpts {
    pub max_connections: u32,
}

impl Default for ScratchOpts {
    fn default() -> Self {
        Self { max_connections: 2 }
    }
}

/// A migrated scratch database plus pools.
#[derive(Debug)]
pub struct ScratchDb {
    name: String,
    admin: Db,
    migrator: Db,
    app: Option<Db>,
    /// URL of the scratch app user (`Debug` redacted).
    app_url: Option<SecretString>,
    /// (user, grantee) of this scratch DB's own app user.
    app_user: Option<(String, String)>,
    /// (user, grantee) of this scratch DB's own platform-admin user (on demand).
    padm_user: Option<(String, String)>,
    /// TiDB mode: the shared DB, never dropped.
    shared: bool,
}

static SHARED_MIGRATED: tokio::sync::OnceCell<Result<(), String>> =
    tokio::sync::OnceCell::const_new();

fn is_local_host(h: &str) -> bool {
    matches!(h, "127.0.0.1" | "localhost" | "::1")
}

impl ScratchDb {
    /// Create, migrate (+ shadow FKs) and, with a root password, grant the scratch app user.
    ///
    /// # Errors
    /// Connection/migration errors (the scratch DB is dropped again on failure where possible).
    pub async fn create(env: &TestEnv) -> Result<Self, DbError> {
        Self::create_with(env, ScratchOpts::default()).await
    }

    /// Same as [`ScratchDb::create`] with explicit options (pool sizes).
    ///
    /// # Errors
    /// See [`ScratchDb::create`].
    pub async fn create_with(env: &TestEnv, opts: ScratchOpts) -> Result<Self, DbError> {
        if test_engine() == TestEngine::TiDb {
            return Self::open_shared(env, opts).await;
        }
        let admin = Db::connect(&test_config(&env.test_url), config::Environment::Test).await?;
        let name = scratch_name();
        if !valid_scratch(&name) {
            return Err(DbError::Invalid("scratch name"));
        }
        sql::dynamic(format!(
            "CREATE DATABASE {name} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"
        ))
        .execute(admin.pool())
        .await
        .map_err(sql::map_err)?;
        let url = with_database(env.test_url.expose_secret(), &name);
        let migrator = match Db::connect(
            &test_config_with(&SecretString::from(url), opts.max_connections),
            config::Environment::Test,
        )
        .await
        {
            Ok(m) => m,
            Err(e) => {
                let _ = sql::dynamic(format!("DROP DATABASE IF EXISTS {name}"))
                    .execute(admin.pool())
                    .await;
                return Err(e);
            }
        };
        let mut me = Self {
            name,
            admin,
            migrator,
            app: None,
            app_url: None,
            app_user: None,
            padm_user: None,
            shared: false,
        };
        match me.setup(env, opts).await {
            Ok(()) => Ok(me),
            Err(e) => {
                let _ = me.drop_db(env).await;
                Err(e)
            }
        }
    }

    /// TiDB mode: reuse the shared DB (`dsecure_rs_test`; the local stand-in may only be
    /// `dsecure_test` on localhost). Migrations run once per process; nothing is created or dropped.
    async fn open_shared(env: &TestEnv, opts: ScratchOpts) -> Result<Self, DbError> {
        let url = env
            .tidb_url
            .as_ref()
            .ok_or(DbError::Config("TIDB_DEV_URL missing"))?;
        let app_url = env
            .tidb_app_url
            .as_ref()
            .ok_or(DbError::Config("TIDB_DEV_APP_URL missing"))?;
        let mut name = String::new();
        for u in [url, app_url] {
            let o = MySqlConnectOptions::from_str(u.expose_secret())
                .map_err(|_| DbError::Config("TiDB test URL could not be parsed"))?;
            let db = o.get_database().unwrap_or("").to_owned();
            let ok = if env.tidb_standin {
                db == STANDIN_DB && is_local_host(o.get_host())
            } else {
                db == SHARED_TIDB_DB
            };
            if !ok {
                return Err(DbError::Config(
                    "TiDB mode only uses dsecure_rs_test (stand-in: local dsecure_test)",
                ));
            }
            name = db;
        }
        let engine = if env.tidb_standin {
            config::DbEngine::MySql
        } else {
            config::DbEngine::TiDb
        };
        // Remote TiDB: every statement is a network round trip, so the time BUDGET is larger (tx 30 s,
        // lock wait 20 s, pool 8). Errors are unchanged: 1213 / 1205 still surface and fail tests.
        let shared_cfg = |u: &SecretString, n: u32| {
            let mut c = test_config_engine(u, n, engine);
            c.tx_timeout_ms = 30_000;
            c.lock_wait_timeout_s = 20;
            c.acquire_timeout_ms = 30_000;
            c
        };
        let migrator = Db::connect(
            &shared_cfg(url, opts.max_connections.max(8)),
            config::Environment::Test,
        )
        .await?;
        let r = SHARED_MIGRATED
            .get_or_init(|| async {
                crate::migrate::run(&migrator)
                    .await
                    .map_err(|e| e.to_string())
            })
            .await;
        if let Err(e) = r {
            migrator.close().await;
            return Err(DbError::Migrate(e.clone()));
        }
        let app = Db::connect(
            &shared_cfg(app_url, opts.max_connections.max(4)),
            config::Environment::Test,
        )
        .await?;
        Ok(Self {
            name,
            admin: migrator.clone(),
            migrator,
            app: Some(app),
            app_url: Some(app_url.clone()),
            app_user: None,
            padm_user: None,
            shared: true,
        })
    }

    async fn setup(&mut self, env: &TestEnv, opts: ScratchOpts) -> Result<(), DbError> {
        let url = with_database(env.test_url.expose_secret(), &self.name);
        crate::migrate::run(&self.migrator).await?;
        crate::migrate::run_shadow_fks(&self.migrator).await?;
        if env.root_password.is_some() {
            let mut root = root_connection(env, &self.name).await?;
            let host = client_host(&mut root).await?;
            // One app user PER scratch DB (parallel tests never share or reset each other's user).
            let user = scratch_app_user(&self.name).ok_or(DbError::Invalid("scratch user name"))?;
            let grantee = format!("'{user}'@'{host}'");
            let pw = uuid::Uuid::now_v7().simple().to_string();
            exec_conn(
                &mut root,
                format!("CREATE USER {grantee} IDENTIFIED BY '{pw}'"),
            )
            .await?;
            self.app_user = Some((user.clone(), grantee.clone()));
            for g in grant_statements(DbRole::App, &self.name, &grantee) {
                exec_conn(&mut root, g).await?;
            }
            let _ = root.close().await;
            let app_opts = MySqlConnectOptions::from_str(&url)
                .map_err(|_| DbError::Config("TEST_DATABASE_URL could not be parsed"))?
                .username(&user)
                .password(&pw);
            // App pool through the normal connect path (same checks); URL carries the scratch user
            // and its random hex password, never printed.
            let app_url = format!(
                "mysql://{user}:{pw}@{}:{}/{}",
                app_opts.get_host(),
                app_opts.get_port(),
                self.name
            );
            let app_url = SecretString::from(app_url);
            self.app = Some(
                Db::connect(
                    &test_config_with(&app_url, opts.max_connections),
                    config::Environment::Test,
                )
                .await?,
            );
            self.app_url = Some(app_url);
        }
        Ok(())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Migrator-user pool on the scratch DB (DDL + data).
    #[must_use]
    pub const fn migrator(&self) -> &Db {
        &self.migrator
    }

    /// Least-privilege app pool (`None` without a local root password).
    #[must_use]
    pub const fn app(&self) -> Option<&Db> {
        self.app.as_ref()
    }

    /// URL of the least-privilege app user (`None` without a local root password). Never print it.
    #[must_use]
    pub const fn app_url(&self) -> Option<&SecretString> {
        self.app_url.as_ref()
    }

    /// URL of the migrator user on this scratch DB (TiDB mode: the shared DB URL). Never print it.
    #[must_use]
    pub fn migrator_url(&self, env: &TestEnv) -> SecretString {
        if self.shared {
            return env
                .tidb_url
                .clone()
                .unwrap_or_else(|| SecretString::from(String::new()));
        }
        SecretString::from(with_database(env.test_url.expose_secret(), &self.name))
    }

    /// Create (once) this scratch DB's OWN platform-admin user (`dsecure_tp_<hex>`, random password)
    /// with the generated `DbRole::PlatformAdmin` grants and return its URL (never printed). Local
    /// MySQL with root password only; dropped again by [`ScratchDb::drop_db`].
    ///
    /// # Errors
    /// `Config` (TiDB mode / no root password / already created), server errors.
    pub async fn platform_admin_url(&mut self, env: &TestEnv) -> Result<SecretString, DbError> {
        if self.shared {
            return Err(DbError::Config(
                "no scratch platform-admin user in TiDB mode",
            ));
        }
        if self.padm_user.is_some() {
            return Err(DbError::Config(
                "scratch platform-admin user already created",
            ));
        }
        let mut root = root_connection(env, &self.name).await?;
        let host = client_host(&mut root).await?;
        let user = scratch_padm_user(&self.name).ok_or(DbError::Invalid("scratch user name"))?;
        let grantee = format!("'{user}'@'{host}'");
        let pw = uuid::Uuid::now_v7().simple().to_string();
        exec_conn(
            &mut root,
            format!("CREATE USER {grantee} IDENTIFIED BY '{pw}'"),
        )
        .await?;
        self.padm_user = Some((user.clone(), grantee.clone()));
        for g in grant_statements(DbRole::PlatformAdmin, &self.name, &grantee) {
            exec_conn(&mut root, g).await?;
        }
        let _ = root.close().await;
        let base = MySqlConnectOptions::from_str(env.test_url.expose_secret())
            .map_err(|_| DbError::Config("TEST_DATABASE_URL could not be parsed"))?;
        Ok(SecretString::from(format!(
            "mysql://{user}:{pw}@{}:{}/{}",
            base.get_host(),
            base.get_port(),
            self.name
        )))
    }

    /// Revoke the scratch app grants and drop ONLY this scratch database.
    ///
    /// # Errors
    /// Server errors.
    pub async fn drop_db(self, env: &TestEnv) -> Result<(), DbError> {
        if let Some(app) = &self.app {
            app.close().await;
        }
        self.migrator.close().await;
        if self.shared {
            // TiDB mode: the shared DB is never dropped; fixture rows stay under test tenants.
            return Ok(());
        }
        // Drop ONLY this scratch DB's own platform-admin user (name validated against its pattern).
        if let Some((user, grantee)) = &self.padm_user
            && valid_scratch_padm_user(user)
            && let Ok(mut root) = root_connection(env, "dsecure_test").await
        {
            let _ = exec_conn(&mut root, format!("DROP USER IF EXISTS {grantee}")).await;
            let _ = root.close().await;
        }
        // Drop ONLY this scratch DB's own app user (name validated against the scratch pattern).
        if let Some((user, grantee)) = &self.app_user
            && valid_scratch_user(user)
            && let Ok(mut root) = root_connection(env, "dsecure_test").await
        {
            let _ = exec_conn(&mut root, format!("DROP USER IF EXISTS {grantee}")).await;
            let _ = root.close().await;
        }
        let r = if valid_scratch(&self.name) {
            sql::dynamic(format!("DROP DATABASE IF EXISTS {}", self.name))
                .execute(self.admin.pool())
                .await
                .map(|_| ())
                .map_err(sql::map_err)
        } else {
            Err(DbError::Invalid("not a scratch database"))
        };
        self.admin.close().await;
        r
    }
}

/// Bind value for [`raw_exec`] / [`raw_fetch`].
#[derive(Clone, Debug)]
pub enum RawBind {
    Uuid(uuid::Uuid),
    Str(String),
    Bytes(Vec<u8>),
    I64(i64),
    Time(time::OffsetDateTime),
    Null,
}

fn bind_all<'q>(mut q: crate::sql::Q<'q>, binds: &[RawBind]) -> crate::sql::Q<'q> {
    for b in binds {
        q = match b {
            RawBind::Uuid(u) => q.bind(*u),
            RawBind::Str(s) => q.bind(s.clone()),
            RawBind::Bytes(v) => q.bind(v.clone()),
            RawBind::I64(i) => q.bind(*i),
            RawBind::Time(t) => q.bind(*t),
            RawBind::Null => q.bind(None::<String>),
        };
    }
    q
}

/// Raw statement for OTHER crates' tests (e.g. audit tamper tests), so they never call `sqlx::query`
/// themselves. Only with feature `test-fixtures`. Returns rows affected.
///
/// # Errors
/// Value-free `DbError`.
pub async fn raw_exec(db: &Db, sql_text: &str, binds: &[RawBind]) -> Result<u64, DbError> {
    bind_all(sql::dynamic(sql_text.to_owned()), binds)
        .execute(db.pool())
        .await
        .map(|r| r.rows_affected())
        .map_err(sql::map_err)
}

/// Raw query returning rows (read with `sqlx::Row::try_get`). Only with feature `test-fixtures`.
///
/// # Errors
/// Value-free `DbError`.
pub async fn raw_fetch(
    db: &Db,
    sql_text: &str,
    binds: &[RawBind],
) -> Result<Vec<sqlx::mysql::MySqlRow>, DbError> {
    bind_all(sql::dynamic(sql_text.to_owned()), binds)
        .fetch_all(db.pool())
        .await
        .map_err(sql::map_err)
}
