//! Harness for the audit integration tests: `db::testing::ScratchDb` (LOCAL MySQL only, own scratch DB and
//! own least-privilege app user per test). No raw `sqlx::query` here (xtask no-raw-sql): tamper and count
//! statements go through `db::testing::raw_exec` / `raw_fetch`.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use crypto::{EnvKeyProvider, InMemoryDekStore, KeyProvider, KeyRing};
use db::Db;
use db::testing::{RawBind, ScratchDb, ScratchOpts, TestEnv, raw_exec, raw_fetch, skip_allowed};
use futures_util::FutureExt as _;
use sqlx::Row as _;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

/// `None` = skip explicitly allowed (`DSECURE_DB_TESTS=skip`); otherwise a missing DB fails the test.
pub fn env_or_skip(test: &str) -> Option<TestEnv> {
    match db::testing::load_env() {
        Ok(e) => Some(e),
        Err(reason) => {
            assert!(skip_allowed(), "{test}: {reason}");
            eprintln!("SKIP {test}: {reason}");
            None
        }
    }
}

pub async fn scratch(test: &str, opts: ScratchOpts) -> Option<(TestEnv, ScratchDb)> {
    let env = env_or_skip(test)?;
    match ScratchDb::create_with(&env, opts).await {
        Ok(s) => Some((env, s)),
        Err(e) => {
            assert!(skip_allowed(), "{test}: scratch db failed: {e}");
            eprintln!("SKIP {test}: scratch db failed");
            None
        }
    }
}

/// Run `f(writer, raw)` on a fresh scratch DB. `writer` = least-privilege app pool (falls back to the
/// migrator without a root password); `raw` = migrator pool, for tamper statements and counts.
pub async fn with_db<F, Fut>(test: &str, f: F)
where
    F: FnOnce(Db, Db) -> Fut,
    Fut: Future<Output = ()>,
{
    with_db_opts(test, ScratchOpts::default(), f).await;
}

pub async fn with_db_opts<F, Fut>(test: &str, opts: ScratchOpts, f: F)
where
    F: FnOnce(Db, Db) -> Fut,
    Fut: Future<Output = ()>,
{
    let Some((env, s)) = scratch(test, opts).await else {
        return;
    };
    let raw = s.migrator().clone();
    let writer = s.app().cloned().unwrap_or_else(|| raw.clone());
    let r = AssertUnwindSafe(f(writer, raw)).catch_unwind().await;
    let _ = s.drop_db(&env).await;
    if let Err(p) = r {
        std::panic::resume_unwind(p);
    }
}

/// Platform key ring (in-memory DEKs, dev KEK) for `EncryptedBlobStore`.
pub async fn ring() -> Arc<KeyRing> {
    let store = Arc::new(InMemoryDekStore::new());
    let p: Arc<dyn KeyProvider> = Arc::new(
        EnvKeyProvider::new("k1", [("k1", STANDARD.encode([9u8; 32]))]).expect("provider"),
    );
    KeyRing::ensure_platform_keys(&*p, &*store)
        .await
        .expect("ensure");
    Arc::new(KeyRing::load_platform(p, store).await.expect("load"))
}

pub async fn ex(raw: &Db, sql: &str, b: &[RawBind]) -> u64 {
    raw_exec(raw, sql, b).await.expect("raw exec")
}

pub async fn q(raw: &Db, sql: &str, b: &[RawBind]) -> Vec<sqlx::mysql::MySqlRow> {
    raw_fetch(raw, sql, b).await.expect("raw fetch")
}

pub async fn count(raw: &Db, table: &str) -> i64 {
    assert!(
        matches!(
            table,
            "audit_events" | "audit_chain_blocks" | "outbox_events"
        ),
        "table not allowed in count()"
    );
    let rows = q(raw, &format!("SELECT COUNT(*) AS c FROM {table}"), &[]).await;
    rows[0].try_get::<i64, _>("c").expect("c")
}

/// Values accepted by `bind_of` (one call per bind keeps test code short).
pub trait ToBind {
    fn to_bind(self) -> RawBind;
}

impl ToBind for uuid::Uuid {
    fn to_bind(self) -> RawBind {
        RawBind::Uuid(self)
    }
}

impl ToBind for Option<uuid::Uuid> {
    fn to_bind(self) -> RawBind {
        self.map_or(RawBind::Null, RawBind::Uuid)
    }
}

impl ToBind for &String {
    fn to_bind(self) -> RawBind {
        RawBind::Str(self.clone())
    }
}

impl ToBind for &str {
    fn to_bind(self) -> RawBind {
        RawBind::Str(self.to_owned())
    }
}

impl ToBind for &[u8] {
    fn to_bind(self) -> RawBind {
        RawBind::Bytes(self.to_vec())
    }
}

impl ToBind for time::OffsetDateTime {
    fn to_bind(self) -> RawBind {
        RawBind::Time(self)
    }
}

pub fn b<T: ToBind>(v: T) -> RawBind {
    v.to_bind()
}
