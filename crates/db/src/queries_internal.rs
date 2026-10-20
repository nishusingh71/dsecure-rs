//! Engine / session SQL that is not table access (no tenant data), kept as `const` strings.

pub(crate) const SELECT_VERSION: &str = "SELECT VERSION() AS v";
pub(crate) const SELECT_TIDB_VERSION: &str = "SELECT tidb_version() AS v";
pub(crate) const SELECT_CURRENT_USER: &str = "SELECT CURRENT_USER() AS u";
/// sqlx bookkeeping (readiness). Tooling table, SELECT for the app user.
pub(crate) const MIGRATIONS_APPLIED: &str =
    "SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version";

/// Strict, engine-neutral sql_mode (no `PIPES_AS_CONCAT`, no `ANSI_QUOTES`). TiDB accepts the same list.
pub(crate) const SESSION_SQL_MODE: &str = "SET SESSION sql_mode = 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,\
NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'";

/// UTC always (DATABASE.md §1.1: DATETIME(6) is UTC) + REPEATABLE READ (TiDB: snapshot isolation).
pub(crate) const SESSION_TZ_ISOLATION: &str =
    "SET SESSION time_zone = '+00:00', SESSION transaction_isolation = 'REPEATABLE-READ'";

/// TiDB only: unique-key conflicts detected at INSERT (not lazily at COMMIT) in pessimistic mode.
pub(crate) const SESSION_TIDB_CONSTRAINT_CHECK: &str =
    "SET SESSION tidb_constraint_check_in_place_pessimistic = ON";

/// TiDB only (DATABASE.md §1.2). Never sent to MySQL (unknown variable there).
pub(crate) const SESSION_TIDB_PESSIMISTIC: &str = "SET SESSION tidb_txn_mode = 'pessimistic'";

/// Timeouts are formatted from typed integers (u32) only.
pub(crate) fn session_timeouts(max_execution_time_ms: u32, lock_wait_timeout_s: u32) -> String {
    format!(
        "SET SESSION max_execution_time = {max_execution_time_ms}, \
         SESSION innodb_lock_wait_timeout = {lock_wait_timeout_s}"
    )
}

/// Read back the session settings (tests).
#[cfg(test)]
pub(crate) const SELECT_SESSION_STATE: &str = "SELECT @@session.time_zone AS tz, \
@@session.transaction_isolation AS iso, @@session.sql_mode AS sql_mode, \
@@session.collation_connection AS coll, @@session.innodb_lock_wait_timeout AS lock_wait";

/// Migration lock table (tooling, created by the migrator user; never touched by the app).
pub(crate) const MIGRATION_LOCK_CREATE: &str = "CREATE TABLE IF NOT EXISTS _migration_lock (\
id TINYINT UNSIGNED NOT NULL, holder VARCHAR(64) NULL, acquired_at DATETIME(6) NULL, \
PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin";
pub(crate) const MIGRATION_LOCK_SEED: &str = "INSERT IGNORE INTO _migration_lock (id) VALUES (1)";
/// DB clock only (review R3). params: holder, stale_microseconds
pub(crate) const MIGRATION_LOCK_ACQUIRE: &str = "UPDATE _migration_lock SET holder = ?, acquired_at = NOW(6) \
WHERE id = 1 AND (holder IS NULL OR acquired_at < NOW(6) - INTERVAL ? MICROSECOND)";
/// params: holder
pub(crate) const MIGRATION_LOCK_HEARTBEAT_SQL: &str =
    "UPDATE _migration_lock SET acquired_at = NOW(6) WHERE id = 1 AND holder = ?";
pub(crate) const MIGRATION_LOCK_RELEASE: &str =
    "UPDATE _migration_lock SET holder = NULL, acquired_at = NULL WHERE id = 1 AND holder = ?";
