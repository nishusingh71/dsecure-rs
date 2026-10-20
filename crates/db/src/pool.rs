//! `Db`: bounded `MySqlPool` + detected engine + options + authz epoch map.
//!
//! Connect sequence (fail closed, every refusal value-free; URL/credentials kabhi log/print nahi):
//! 1. Legacy database (`Cloud_Erase__App`) refused in EVERY environment (`config::dburl` + parsed options).
//! 2. Outside dev/test: TLS must be `VERIFY_IDENTITY` both by `config::dburl::has_verified_tls` (raw URL)
//!    and by the parsed `MySqlConnectOptions::get_ssl_mode()` (second line of defence). `DB_TLS_CA`
//!    (path or PEM) is used as CA when set.
//! 3. One probe connection detects the engine (`SELECT VERSION()` / `tidb_version()`); mismatch with
//!    `DB_EXPECT_ENGINE` refuses to start.
//! 4. Pool: bounded size, acquire timeout, statement cache cap; every new connection runs session init
//!    (sql_mode, UTC, utf8mb4_bin, REPEATABLE READ, timeouts, TiDB pessimistic mode).

use crate::engine::Engine;
use crate::epochs::EpochMap;
use crate::error::DbError;
use crate::options::DbOptions;
use crate::queries_internal::{
    SESSION_SQL_MODE, SESSION_TIDB_CONSTRAINT_CHECK, SESSION_TIDB_PESSIMISTIC,
    SESSION_TZ_ISOLATION, session_timeouts,
};
use crate::sql;
use config::dburl;
use secrecy::{ExposeSecret, SecretString};
use sqlx::ConnectOptions as _;
use sqlx::Connection as _;
use sqlx::mysql::{
    MySqlConnectOptions, MySqlConnection, MySqlPool, MySqlPoolOptions, MySqlSslMode,
};
use std::str::FromStr as _;
use std::sync::Arc;

pub(crate) struct Shared {
    pub(crate) pool: MySqlPool,
    pub(crate) engine: Engine,
    pub(crate) opts: DbOptions,
    pub(crate) epochs: EpochMap,
}

/// Cheap to clone (Arc). `Debug` shows only engine kind and pool size.
#[derive(Clone)]
pub struct Db {
    pub(crate) shared: Arc<Shared>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("engine", &self.shared.engine.name())
            .field("max_connections", &self.shared.opts.max_connections)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct SessionInit {
    tidb: bool,
    max_execution_time_ms: u32,
    lock_wait_timeout_s: u32,
}

impl SessionInit {
    async fn apply(self, conn: &mut MySqlConnection) -> Result<(), sqlx::Error> {
        sql::q(SESSION_SQL_MODE).execute(&mut *conn).await?;
        sql::q(SESSION_TZ_ISOLATION).execute(&mut *conn).await?;
        sql::dynamic(session_timeouts(
            self.max_execution_time_ms,
            self.lock_wait_timeout_s,
        ))
        .execute(&mut *conn)
        .await?;
        if self.tidb {
            sql::q(SESSION_TIDB_PESSIMISTIC).execute(&mut *conn).await?;
            // Refused on some TiDB offerings: not fatal, the code is correct with lazy checks too
            // (idempotency reserve commits on its own and maps COMMIT-time duplicates).
            if sql::q(SESSION_TIDB_CONSTRAINT_CHECK)
                .execute(&mut *conn)
                .await
                .is_err()
            {
                tracing::warn!(
                    "tidb_constraint_check_in_place_pessimistic could not be set; lazy unique checks"
                );
            }
        }
        Ok(())
    }
}

/// Parse + check `DATABASE_URL` (steps 1-2 of the module docs).
///
/// # Errors
/// `DbError::Config` with a value-free reason.
pub fn connect_options(
    url: &SecretString,
    tls_ca: Option<&SecretString>,
    env: config::Environment,
    statement_cache_capacity: usize,
) -> Result<MySqlConnectOptions, DbError> {
    let raw = url.expose_secret();
    if dburl::targets_legacy_db(raw) {
        return Err(DbError::Config("legacy database is refused"));
    }
    let mut opts = MySqlConnectOptions::from_str(raw)
        .map_err(|_| DbError::Config("DATABASE_URL could not be parsed"))?;
    if opts.get_database().is_some_and(|d| {
        d.trim_matches('/')
            .eq_ignore_ascii_case(dburl::LEGACY_DB_NAME)
    }) {
        return Err(DbError::Config("legacy database is refused"));
    }
    if !env.is_local() {
        let parsed_verified = matches!(opts.get_ssl_mode(), MySqlSslMode::VerifyIdentity);
        if !dburl::has_verified_tls(raw) || !parsed_verified {
            return Err(DbError::Config(
                "TLS ssl-mode=VERIFY_IDENTITY is required outside dev/test",
            ));
        }
    }
    if let Some(ca) = tls_ca {
        let ca = ca.expose_secret().trim();
        if ca.is_empty() {
            return Err(DbError::Config("DB_TLS_CA is empty"));
        }
        opts = if ca.starts_with("-----BEGIN") {
            opts.ssl_ca_from_pem(ca.as_bytes().to_vec())
        } else {
            opts.ssl_ca(ca)
        };
    }
    Ok(opts
        .pipes_as_concat(false)
        .no_engine_substitution(true)
        .charset("utf8mb4")
        .collation("utf8mb4_bin")
        .timezone(Some(String::from("+00:00")))
        .statement_cache_capacity(statement_cache_capacity)
        .disable_statement_logging())
}

impl Db {
    /// Connect with `DbOptions::from_config` defaults.
    ///
    /// # Errors
    /// See [`Db::connect_with`].
    pub async fn connect(
        cfg: &config::DbConfig,
        env: config::Environment,
    ) -> Result<Self, DbError> {
        Self::connect_with(cfg, env, DbOptions::from_config(cfg)).await
    }

    /// Full connect sequence (module docs).
    ///
    /// # Errors
    /// `Config` (URL/TLS/legacy refusal), `EngineMismatch`, connection errors (value-free).
    pub async fn connect_with(
        cfg: &config::DbConfig,
        env: config::Environment,
        opts: DbOptions,
    ) -> Result<Self, DbError> {
        Self::connect_url(&cfg.url, cfg, env, opts).await
    }

    /// Migrator connection: `migrator_url` when set, else `url`. Same TLS / legacy / engine checks.
    ///
    /// # Errors
    /// See [`Db::connect_with`].
    pub async fn connect_migrator(
        cfg: &config::DbConfig,
        env: config::Environment,
    ) -> Result<Self, DbError> {
        let url = cfg.migrator_url.as_ref().unwrap_or(&cfg.url);
        Self::connect_url(url, cfg, env, DbOptions::from_config(cfg)).await
    }

    async fn connect_url(
        url: &SecretString,
        cfg: &config::DbConfig,
        env: config::Environment,
        opts: DbOptions,
    ) -> Result<Self, DbError> {
        let conn_opts =
            connect_options(url, cfg.tls_ca.as_ref(), env, opts.statement_cache_capacity)?;
        let mut probe = conn_opts.connect().await.map_err(sql::map_err)?;
        let engine = Engine::detect(&mut probe).await;
        let _ = probe.close().await;
        let engine = engine?;
        engine.ensure(cfg.expect_engine)?;

        let init = SessionInit {
            tidb: engine.is_tidb(),
            max_execution_time_ms: opts.max_execution_time_ms,
            lock_wait_timeout_s: opts.lock_wait_timeout_s,
        };
        let pool = MySqlPoolOptions::new()
            .max_connections(opts.max_connections)
            .min_connections(0)
            .acquire_timeout(opts.acquire_timeout)
            .after_connect(move |conn, _meta| Box::pin(async move { init.apply(conn).await }))
            .connect_with(conn_opts)
            .await
            .map_err(sql::map_err)?;
        Ok(Self {
            shared: Arc::new(Shared {
                pool,
                engine,
                opts,
                epochs: EpochMap::default(),
            }),
        })
    }

    #[must_use]
    pub fn engine(&self) -> &Engine {
        &self.shared.engine
    }

    #[must_use]
    pub fn options(&self) -> &DbOptions {
        &self.shared.opts
    }

    /// In-process authz epoch map (filled by [`Db::poll_epochs`]).
    #[must_use]
    pub fn epochs(&self) -> &EpochMap {
        &self.shared.epochs
    }

    pub(crate) fn pool(&self) -> &MySqlPool {
        &self.shared.pool
    }

    /// Graceful shutdown.
    pub async fn close(&self) {
        self.shared.pool.close().await;
    }
}
