//! Scratch database access (local MySQL 127.0.0.1:3307 via `.dev/dev.env`, see `db::testing`).
//! Only `dsecure_t_*` scratch databases are created/dropped; nothing is printed except value-free
//! reasons. TiDB engine mode is refused (never run from agents).

use std::panic::AssertUnwindSafe;

use db::Db;
use db::testing::{ScratchDb, TestEngine, TestEnv};
use futures_util::FutureExt as _;

/// A created scratch DB plus the env needed to drop it again.
pub struct ScratchHandle {
    pub env: TestEnv,
    pub scratch: ScratchDb,
}

impl ScratchHandle {
    /// Create a migrated scratch DB on the LOCAL MySQL.
    ///
    /// # Errors
    /// Value-free reason (env missing, TiDB mode requested, server unreachable).
    pub async fn create() -> Result<Self, String> {
        if db::testing::test_engine() == TestEngine::TiDb {
            return Err("testkit refuses DSECURE_TEST_ENGINE=tidb (local MySQL only)".to_owned());
        }
        let env = db::testing::load_env().map_err(|r| format!("local test DB env: {r}"))?;
        let scratch = ScratchDb::create(&env)
            .await
            .map_err(|e| format!("scratch DB: {e}"))?;
        Ok(Self { env, scratch })
    }

    /// App-role pool when the local root password exists, else the migrator pool.
    #[must_use]
    pub fn app(&self) -> Db {
        self.scratch
            .app()
            .cloned()
            .unwrap_or_else(|| self.scratch.migrator().clone())
    }

    #[must_use]
    pub fn migrator(&self) -> Db {
        self.scratch.migrator().clone()
    }

    /// Drop the scratch DB (and its scratch app user).
    pub async fn drop_db(self) {
        let _ = self.scratch.drop_db(&self.env).await;
    }
}

/// Run `f(app_db, migrator_db)` against a fresh scratch DB; always dropped afterwards (also on
/// panic). Missing env fails the test unless `DSECURE_DB_TESTS=skip` is set explicitly.
pub async fn with_scratch<F, Fut>(test: &str, f: F)
where
    F: FnOnce(Db, Db) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let h = match ScratchHandle::create().await {
        Ok(h) => h,
        Err(reason) if db::testing::skip_allowed() => {
            eprintln!("SKIP {test}: {reason} (DSECURE_DB_TESTS=skip)");
            return;
        }
        Err(reason) => panic!("{test}: {reason}"),
    };
    let (app, migrator) = (h.app(), h.migrator());
    let r = AssertUnwindSafe(f(app, migrator)).catch_unwind().await;
    h.drop_db().await;
    if let Err(p) = r {
        std::panic::resume_unwind(p);
    }
}
