//! Migration runner (DATABASE.md §11.1). Release step `dsecure-api migrate` (migrator user), never
//! on app startup.
//!
//! - Files: `migrations/SSSS_NNNN_<desc>.sql` (set + sequence), **one DDL per file** (MySQL/TiDB DDL
//!   commits implicitly; a multi-statement file could half-apply). sqlx's own filename parser would
//!   read only `SSSS` as the version, so this small runner embeds the files and uses
//!   `version = SSSS * 10_000 + NNNN` with sqlx's `Migrator` (checksums + `_sqlx_migrations`).
//!   Do not apply these files with `sqlx-cli`.
//! - Engine differences: TiDB-only options are written as executable comments
//!   (`/*T![clustered_index] CLUSTERED */`, `/*T! SHARD_ROW_ID_BITS=4 */`): TiDB executes them,
//!   MySQL treats them as comments. So one file serves both engines; no per-engine variants needed.
//! - Locking: sqlx's MySQL migrator uses `GET_LOCK` (limited on TiDB, DATABASE.md §1.4), so it is OFF;
//!   [`MigrationLock`] (row in `_migration_lock`) serialises migrators on both engines.
//! - Shadow FKs (`migrations_shadow/9100_*`, D-55): MySQL CI/dev only, tracked in a separate table
//!   `_sqlx_migrations_shadow` so the main history never contains them. Refused on TiDB.

use crate::error::DbError;
use crate::migration_files::{MAIN, SHADOW};
use crate::pool::Db;
use crate::queries_internal::{
    MIGRATION_LOCK_ACQUIRE, MIGRATION_LOCK_CREATE, MIGRATION_LOCK_HEARTBEAT_SQL,
    MIGRATION_LOCK_RELEASE, MIGRATION_LOCK_SEED, MIGRATIONS_APPLIED,
};
use crate::sql;
use sqlx::SqlSafeStr as _;
use sqlx::migrate::{Migration, MigrationType, Migrator};
use std::borrow::Cow;

pub(crate) const SHADOW_TABLE: &str = "_sqlx_migrations_shadow";

/// `0100_0001_create_tenants` -> (1000001, "create tenants").
pub(crate) fn parse_name(name: &str) -> Result<(i64, String), DbError> {
    let mut parts = name.splitn(3, '_');
    let (Some(set), Some(seq), Some(desc)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(DbError::Migrate(format!("bad migration name {name}")));
    };
    if set.len() != 4 || seq.len() != 4 {
        return Err(DbError::Migrate(format!("bad migration name {name}")));
    }
    let set: i64 = set
        .parse()
        .map_err(|_| DbError::Migrate(format!("bad migration set in {name}")))?;
    let seq: i64 = seq
        .parse()
        .map_err(|_| DbError::Migrate(format!("bad migration sequence in {name}")))?;
    Ok((set * 10_000 + seq, desc.replace('_', " ")))
}

fn build(files: &'static [(&'static str, &'static str)]) -> Result<Migrator, DbError> {
    let mut v = Vec::with_capacity(files.len());
    for (name, sql_text) in files {
        let (version, desc) = parse_name(name)?;
        v.push(Migration::new(
            version,
            Cow::Owned(desc),
            MigrationType::Simple,
            sql_text.into_sql_str(),
            false,
        ));
    }
    Ok(Migrator::with_migrations(v))
}

fn migrate_err(e: &sqlx::migrate::MigrateError) -> DbError {
    use sqlx::migrate::MigrateError as M;
    match e {
        M::Execute(inner) | M::ExecuteMigration(inner, _) => {
            DbError::Migrate(format!("execute: {}", DbError::from_sqlx(inner)))
        }
        M::VersionMismatch(v) => DbError::Migrate(format!("checksum mismatch at version {v}")),
        M::VersionMissing(v) => DbError::Migrate(format!("applied version {v} missing")),
        M::Dirty(v) => DbError::Migrate(format!("dirty (partially applied) version {v}")),
        _ => DbError::Migrate(String::from("migrator error")),
    }
}

/// Apply all pending main migrations (sets 0100/0150/0200/0800).
///
/// # Errors
/// `Migrate` (version + category only).
pub async fn run(db: &Db) -> Result<(), DbError> {
    let mut m = build(MAIN)?;
    // Lock-row table instead of GET_LOCK (F10): identical on MySQL and TiDB.
    m.set_locking(false);
    let lock = MigrationLock::acquire(db, MIGRATION_LOCK_STALE).await?;
    // Heartbeat while migrating so a long DDL never looks stale (review R3). No spawn: the
    // heartbeat loop runs concurrently in this task via `select!`.
    let migrate = m.run(db.pool());
    let beat = async {
        loop {
            tokio::time::sleep(MIGRATION_LOCK_HEARTBEAT).await;
            if let Err(e) = lock.heartbeat(db).await {
                return e;
            }
        }
    };
    let r = tokio::select! {
        r = migrate => r.map_err(|e| migrate_err(&e)),
        e = beat => Err(e),
    };
    lock.release(db).await?;
    r
}

/// Single-row lock in `_migration_lock` (tooling table, not app data). All times are the DB clock
/// (`NOW(6)`), never the caller's. Acquire = conditional UPDATE of row `id = 1` (free, or not
/// heartbeated for `stale`); 0 rows = held -> `Conflict("migrate.busy")`. The holder refreshes
/// `acquired_at` every [`MIGRATION_LOCK_HEARTBEAT`]; a lost heartbeat (taken over) aborts the run.
/// No DELETE needed (release = `holder = NULL`).
#[derive(Debug)]
pub struct MigrationLock {
    holder: String,
}

/// A lock not heartbeated for this long is considered abandoned (crashed release step).
pub const MIGRATION_LOCK_STALE: std::time::Duration = std::time::Duration::from_secs(15 * 60);
/// Heartbeat period while migrating.
pub const MIGRATION_LOCK_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(30);

impl MigrationLock {
    /// # Errors
    /// `Conflict("migrate.busy")`, server errors.
    pub async fn acquire(db: &Db, stale: std::time::Duration) -> Result<Self, DbError> {
        sql::q(MIGRATION_LOCK_CREATE)
            .execute(db.pool())
            .await
            .map_err(sql::map_err)?;
        sql::q(MIGRATION_LOCK_SEED)
            .execute(db.pool())
            .await
            .map_err(sql::map_err)?;
        let holder = uuid::Uuid::now_v7().simple().to_string();
        let stale_us = i64::try_from(stale.as_micros()).unwrap_or(i64::MAX);
        let n = sql::q(MIGRATION_LOCK_ACQUIRE)
            .bind(holder.as_str())
            .bind(stale_us)
            .execute(db.pool())
            .await
            .map_err(sql::map_err)?
            .rows_affected();
        if n == 1 {
            Ok(Self { holder })
        } else {
            Err(DbError::Conflict("migrate.busy"))
        }
    }

    /// Refresh `acquired_at = NOW(6)`.
    ///
    /// # Errors
    /// `NotPersisted` if the lock was taken over, server errors.
    pub async fn heartbeat(&self, db: &Db) -> Result<(), DbError> {
        let n = sql::q(MIGRATION_LOCK_HEARTBEAT_SQL)
            .bind(self.holder.as_str())
            .execute(db.pool())
            .await
            .map_err(sql::map_err)?
            .rows_affected();
        crate::write_guard::WriteOutcome::expect_one(n)
    }

    /// # Errors
    /// `NotPersisted` if the lock was taken over (stale), server errors.
    pub async fn release(self, db: &Db) -> Result<(), DbError> {
        let n = sql::q(MIGRATION_LOCK_RELEASE)
            .bind(self.holder.as_str())
            .execute(db.pool())
            .await
            .map_err(sql::map_err)?
            .rows_affected();
        crate::write_guard::WriteOutcome::expect_one(n)
    }
}

/// Embedded main-set versions not applied yet (readiness check). Read-only; works as the app user
/// (it already holds SELECT on `_sqlx_migrations`; `_migration_lock` is not read). A changed applied
/// migration or a failed one is an error, never "ready".
///
/// # Errors
/// `Migrate` (checksum mismatch / failed migration), server errors.
pub async fn pending(db: &Db) -> Result<Vec<i64>, DbError> {
    let rows = match sql::q(MIGRATIONS_APPLIED).fetch_all(db.pool()).await {
        Ok(r) => r,
        // 1146 = table does not exist: nothing applied yet.
        Err(e) => match DbError::from_sqlx(&e) {
            DbError::Database { number: 1146, .. } => Vec::new(),
            other => return Err(other),
        },
    };
    let mut applied = std::collections::HashMap::new();
    for r in &rows {
        let v: i64 = sql::col(r, "version")?;
        let c: Vec<u8> = sql::col(r, "checksum")?;
        let ok: bool = sql::col(r, "success")?;
        if !ok {
            return Err(DbError::Migrate(format!(
                "dirty (partially applied) version {v}"
            )));
        }
        applied.insert(v, c);
    }
    let mut out = Vec::new();
    for m in build(MAIN)?.iter() {
        match applied.get(&m.version) {
            None => out.push(m.version),
            Some(c) if c.as_slice() != &*m.checksum => {
                return Err(DbError::Migrate(format!(
                    "checksum mismatch at version {}",
                    m.version
                )));
            }
            Some(_) => {}
        }
    }
    Ok(out)
}

/// Apply main migrations up to and including `version` (tests: partially migrated DBs).
///
/// # Errors
/// `Migrate`.
#[cfg(test)]
pub(crate) async fn run_to(db: &Db, version: i64) -> Result<(), DbError> {
    let mut m = build(MAIN)?;
    m.set_locking(false);
    m.run_to(version, db.pool())
        .await
        .map_err(|e| migrate_err(&e))
}

/// Release step: connect with `migrator_url` (falls back to `url`) and apply main migrations.
///
/// # Errors
/// Connect refusals (TLS / legacy / engine), `Migrate`.
pub async fn run_from_config(
    cfg: &config::DbConfig,
    env: config::Environment,
) -> Result<(), DbError> {
    let db = Db::connect_migrator(cfg, env).await?;
    let r = run(&db).await;
    db.close().await;
    r
}

/// Apply MySQL shadow FKs (CI/dev only). Refused on TiDB (D-55: no DB FKs there).
///
/// # Errors
/// `Config` on TiDB, `Migrate`.
pub async fn run_shadow_fks(db: &Db) -> Result<(), DbError> {
    if db.engine().is_tidb() {
        return Err(DbError::Config("shadow FKs are MySQL-only"));
    }
    let mut m = build(SHADOW)?;
    m.dangerous_set_table_name(SHADOW_TABLE);
    m.set_locking(true);
    m.run(db.pool()).await.map_err(|e| migrate_err(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_parse_and_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for (n, _) in MAIN.iter().chain(SHADOW.iter()) {
            let (v, _) = parse_name(n).expect("name");
            assert!(seen.insert(v), "duplicate version {v}");
        }
        assert_eq!(
            parse_name("0100_0001_create_tenants").expect("ok").0,
            1_000_001
        );
        assert!(parse_name("100_1_x").is_err());
    }

    /// Embedded lists must match the directories exactly (no forgotten file).
    #[test]
    fn embedded_lists_match_directories() {
        for (dir, list) in [("migrations", MAIN), ("migrations_shadow", SHADOW)] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
            let mut on_disk: Vec<String> = std::fs::read_dir(&path)
                .expect("dir")
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|f| f.ends_with(".sql"))
                .map(|f| f.trim_end_matches(".sql").to_owned())
                .collect();
            on_disk.sort();
            let listed: Vec<String> = list.iter().map(|(n, _)| (*n).to_owned()).collect();
            assert_eq!(on_disk, listed, "{dir}");
        }
    }

    /// §11.1: exactly one statement per file (comments stripped, `;` only as terminator).
    #[test]
    fn one_ddl_per_file() {
        for (name, text) in MAIN.iter().chain(SHADOW.iter()) {
            let code: String = text
                .lines()
                .map(|l| l.split("--").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n");
            let stmts = code.split(';').filter(|s| !s.trim().is_empty()).count();
            assert_eq!(stmts, 1, "{name}");
            let upper = code.trim_start().to_ascii_uppercase();
            assert!(
                upper.starts_with("CREATE TABLE")
                    || upper.starts_with("ALTER TABLE")
                    || upper.starts_with("INSERT INTO"),
                "{name}"
            );
            // Every table is utf8mb4_bin, never default collation (§1.4).
            if upper.starts_with("CREATE TABLE") {
                assert!(code.contains("COLLATE=utf8mb4_bin"), "{name}");
                assert!(!upper.contains("AUTO_INCREMENT"), "{name}");
                assert!(
                    !upper.contains("FOREIGN KEY"),
                    "{name}: FKs only in shadow set"
                );
            }
        }
    }
}
