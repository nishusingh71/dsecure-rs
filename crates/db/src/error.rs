//! `DbError`: value-free errors of the data layer.
//!
//! Rule: koi variant SQL text, bind values, URL, server message ya row data nahi rakhta. MySQL/TiDB
//! error messages mein duplicate values (e.g. blind index bytes) aa sakte hain, isliye sirf error
//! number + SQLSTATE rakhte hain.

use common::{AppError, AppErrorKind};

/// Server error numbers that are safe to retry for an idempotent closure (DATABASE.md §1.2).
/// 1213 deadlock, 1205 lock wait timeout, 9007 TiDB write conflict, 8027/8028 schema changed during
/// tx, 9001/9002/9005 TiKV/PD busy or timeout. (TiDB codes from the design doc, not verified on
/// Serverless; MySQL 8.4 codes 1213/1205 verified by the local tests.)
pub const RETRYABLE_CODES: &[u16] = &[1213, 1205, 9007, 8027, 8028, 9001, 9002, 9005];

/// MySQL client-side "server gone / lost connection" numbers (used for I/O failures before COMMIT).
pub const CONNECTION_LOST: u16 = 2013;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// Row not found inside the caller's tenant (cross-tenant ids look exactly like this: 404).
    #[error("not found: {0}")]
    NotFound(&'static str),
    /// A write that had to change rows changed a different number (WriteOutcome guard).
    #[error("write not persisted (expected {expected} rows, got {actual})")]
    NotPersisted { expected: u64, actual: u64 },
    /// Business conflict (`409`), stable code e.g. `users.email_taken`.
    #[error("conflict: {0}")]
    Conflict(&'static str),
    /// Last active owner would be removed (`409 members.last_owner`).
    #[error("last owner")]
    LastOwner,
    /// Tenant quota exceeded (`409/422 quota.exceeded`).
    #[error("quota exceeded: {quota}")]
    QuotaExceeded {
        quota: &'static str,
        limit: u32,
        current: u32,
    },
    /// Row-tenant assert (L6) failed: a row of another tenant reached a mapper. Fail closed.
    #[error("tenant mismatch on row read")]
    TenantMismatch,
    /// A tenant tx was requested without a usable scope (nil tenant/actor, job without tenant).
    #[error("tenant scope missing: {0}")]
    ScopeMissing(&'static str),
    /// Invalid input to a repository fn (caller bug or bad request), value-free reason.
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    /// Not allowed for this approver / grant (`403`), value-free reason.
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    /// Write attempted in a read-only (staff `read` grant) transaction.
    #[error("read-only transaction")]
    ReadOnly,
    /// Unique key violation (key name only, never the value).
    #[error("duplicate key `{key}`")]
    Duplicate { key: String },
    /// FK violation (only possible with MySQL shadow FKs, D-55).
    #[error("foreign key violation ({number})")]
    ForeignKey { number: u16 },
    /// Privilege error from the server (e.g. app user DELETE = 1142).
    #[error("permission denied ({number})")]
    PermissionDenied { number: u16 },
    /// Retryable server/connection error (deadlock, lock wait, write conflict, lost connection).
    #[error("transient database error ({code})")]
    Transient { code: u16 },
    /// COMMIT was sent but the outcome is unknown (connection lost). Never retried blindly.
    #[error("commit outcome unknown")]
    CommitUnknown,
    /// App-side transaction deadline (`DB_TX_TIMEOUT_MS`) passed.
    #[error("transaction timed out")]
    Timeout,
    /// Pool exhausted / closed (fail fast -> 503).
    #[error("database unavailable")]
    Unavailable,
    /// Startup / connect refusal (TLS, legacy database, engine mismatch). Value-free reason.
    #[error("database configuration refused: {0}")]
    Config(&'static str),
    /// Detected engine differs from `DB_EXPECT_ENGINE`.
    #[error("database engine mismatch (expected {expected}, found {found})")]
    EngineMismatch {
        expected: &'static str,
        found: &'static str,
    },
    /// Stored value could not be decoded (corrupt row / schema drift). Internal.
    #[error("corrupt row: {0}")]
    Corrupt(&'static str),
    /// Any other server error (number + SQLSTATE only).
    #[error("database error {number} ({sqlstate})")]
    Database { number: u16, sqlstate: String },
    /// Client-side sqlx failure category (no message).
    #[error("database client error: {0}")]
    Client(&'static str),
    /// Migration failure (version only).
    #[error("migration failed: {0}")]
    Migrate(String),
}

impl DbError {
    /// Map a sqlx error into a value-free `DbError`.
    #[must_use]
    pub fn from_sqlx(e: &sqlx::Error) -> Self {
        match e {
            sqlx::Error::Database(d) => {
                let number = d
                    .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                    .map_or(0, sqlx::mysql::MySqlDatabaseError::number);
                Self::from_server(number, d.code().as_deref().unwrap_or(""), d.message())
            }
            sqlx::Error::RowNotFound => Self::NotFound("row"),
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => Self::Unavailable,
            sqlx::Error::Io(_) => Self::Transient {
                code: CONNECTION_LOST,
            },
            sqlx::Error::Tls(_) => Self::Client("tls"),
            sqlx::Error::Protocol(_) => Self::Client("protocol"),
            sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => {
                Self::Corrupt("column decode")
            }
            sqlx::Error::ColumnNotFound(_) | sqlx::Error::ColumnIndexOutOfBounds { .. } => {
                Self::Corrupt("column missing")
            }
            sqlx::Error::Configuration(_) => Self::Config("connection options"),
            sqlx::Error::Encode(_) => Self::Client("encode"),
            _ => Self::Client("other"),
        }
    }

    /// `message` is only parsed for the unique key *name* (`... for key 'tbl.ux_name'`).
    fn from_server(number: u16, sqlstate: &str, message: &str) -> Self {
        match number {
            n if RETRYABLE_CODES.contains(&n) => Self::Transient { code: n },
            1062 => Self::Duplicate {
                key: duplicate_key_name(message),
            },
            1216 | 1217 | 1451 | 1452 => Self::ForeignKey { number },
            1044 | 1045 | 1142 | 1143 | 1227 | 1370 => Self::PermissionDenied { number },
            _ => Self::Database {
                number,
                sqlstate: sqlstate
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .take(5)
                    .collect(),
            },
        }
    }

    /// Safe to rerun the whole (idempotent) transaction?
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Transient { .. })
    }

    /// Duplicate on exactly this unique key (`ux_users_email_bidx`, `PRIMARY`, ...).
    #[must_use]
    pub fn is_duplicate_of(&self, key: &str) -> bool {
        matches!(self, Self::Duplicate { key: k } if key_matches(k, key))
    }
}

/// Key-name match tolerant to engine formats: MySQL 8 `tbl.ux_name`, TiDB `ux_name` / `tbl.ux_name`,
/// any case (TiDB reports `PRIMARY` as `PRIMARY` or `primary`).
fn key_matches(reported: &str, key: &str) -> bool {
    let r = reported.rsplit('.').next().unwrap_or(reported);
    r.eq_ignore_ascii_case(key)
}

/// `Duplicate entry '<value>' for key 'users.ux_users_email_bidx'` -> `ux_users_email_bidx`.
/// The value part is never kept.
fn duplicate_key_name(message: &str) -> String {
    // MySQL: `for key 'tbl.name'`; TiDB: `for key 'tbl.name'` or `for key 'name'` (also backticks).
    let message = message.replace("for key `", "for key '").replace('`', "'");
    message
        .rsplit_once("for key '")
        .map(|(_, rest)| rest.trim_end_matches('\''))
        .map(|k| k.rsplit_once('.').map_or(k, |(_, n)| n))
        .unwrap_or("unknown")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect()
}

impl From<DbError> for AppError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::NotFound(_) => Self::not_found("not_found", "resource not found"),
            DbError::NotPersisted { .. } => Self::new(
                AppErrorKind::NotPersisted,
                "not_persisted",
                "the change was not saved",
            ),
            DbError::Conflict(code) => Self::new(AppErrorKind::Conflict, code, "conflict"),
            DbError::LastOwner => Self::new(
                AppErrorKind::Conflict,
                "members.last_owner",
                "the tenant needs at least one active owner",
            ),
            DbError::QuotaExceeded { .. } => Self::new(
                AppErrorKind::QuotaExceeded,
                "quota.exceeded",
                "quota exceeded",
            ),
            DbError::Invalid(_) => Self::bad_request("invalid", "invalid request"),
            DbError::Forbidden(_) | DbError::ReadOnly => {
                Self::new(AppErrorKind::Forbidden, "forbidden", "not allowed")
            }
            DbError::Duplicate { .. } => {
                Self::new(AppErrorKind::Conflict, "conflict", "already exists")
            }
            DbError::Unavailable | DbError::Timeout | DbError::Transient { .. } => Self::new(
                AppErrorKind::Unavailable { retry_after_s: 1 },
                "db.unavailable",
                "temporarily unavailable",
            ),
            other => Self::internal(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_key_name_drops_value() {
        let m = "Duplicate entry 'secret@example.com' for key 'users.ux_users_email_bidx'";
        assert_eq!(duplicate_key_name(m), "ux_users_email_bidx");
        assert_eq!(
            duplicate_key_name("Duplicate entry 'x' for key 'PRIMARY'"),
            "PRIMARY"
        );
        assert_eq!(duplicate_key_name("garbage"), "unknown");
        assert_eq!(
            duplicate_key_name("Duplicate entry 'x' for key `memberships.ux_memberships_user`"),
            "ux_memberships_user"
        );
        assert!(
            DbError::Duplicate {
                key: "primary".into()
            }
            .is_duplicate_of("PRIMARY")
        );
        assert!(
            DbError::Duplicate {
                key: "ux_memberships_user".into()
            }
            .is_duplicate_of("ux_memberships_user")
        );
    }

    #[test]
    fn classification() {
        assert!(DbError::from_server(1213, "40001", "").is_retryable());
        assert!(DbError::from_server(9007, "HY000", "").is_retryable());
        assert!(!DbError::from_server(1062, "23000", "for key 'PRIMARY'").is_retryable());
        assert!(matches!(
            DbError::from_server(1142, "42000", "DELETE command denied"),
            DbError::PermissionDenied { number: 1142 }
        ));
        let e = DbError::from_server(1064, "42000", "near 'secret'");
        assert!(!e.to_string().contains("secret"));
    }

    #[test]
    fn app_error_mapping() {
        let a: AppError = DbError::NotPersisted {
            expected: 1,
            actual: 0,
        }
        .into();
        assert_eq!(a.kind, AppErrorKind::NotPersisted);
        let a: AppError = DbError::TenantMismatch.into();
        assert_eq!(a.kind, AppErrorKind::Internal);
        let a: AppError = DbError::LastOwner.into();
        assert_eq!(a.code, "members.last_owner");
    }
}
