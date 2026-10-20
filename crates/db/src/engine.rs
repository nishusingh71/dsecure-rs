//! Engine detection: MySQL vs TiDB (`SELECT VERSION()`; TiDB reports e.g. `8.0.11-TiDB-v7.5.0`).
//! Agar VERSION() se pata na chale to `tidb_version()` try karte hain (MySQL par woh function nahi hai).
//!
//! Limit (F14): detection trusts what the server reports. A proxy or a misconfigured server can spoof
//! `VERSION()` / `tidb_version()`, so `DB_EXPECT_ENGINE` is a guard against operator mistakes (pointing
//! production at a MySQL), not against a hostile server. The real defence against a wrong/hostile
//! endpoint is TLS `VERIFY_IDENTITY` against the configured CA (`pool::connect_options`).

use crate::error::DbError;
use crate::queries_internal::{SELECT_TIDB_VERSION, SELECT_VERSION};
use crate::sql;
use sqlx::mysql::MySqlConnection;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Engine {
    TiDb { version: String },
    MySql { version: String },
}

impl Engine {
    #[must_use]
    pub const fn is_tidb(&self) -> bool {
        matches!(self, Self::TiDb { .. })
    }

    #[must_use]
    pub const fn kind(&self) -> config::DbEngine {
        match self {
            Self::TiDb { .. } => config::DbEngine::TiDb,
            Self::MySql { .. } => config::DbEngine::MySql,
        }
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        engine_name(self.kind())
    }

    /// Classify a `VERSION()` string.
    #[must_use]
    pub fn from_version(v: &str) -> Self {
        if v.to_ascii_lowercase().contains("tidb") {
            Self::TiDb {
                version: v.to_owned(),
            }
        } else {
            Self::MySql {
                version: v.to_owned(),
            }
        }
    }

    /// Detect on a live connection.
    ///
    /// # Errors
    /// Server/connection errors.
    pub async fn detect(conn: &mut MySqlConnection) -> Result<Self, DbError> {
        let row = sql::q(SELECT_VERSION)
            .fetch_one(&mut *conn)
            .await
            .map_err(sql::map_err)?;
        let v: String = sql::col(&row, "v")?;
        let e = Self::from_version(&v);
        if e.is_tidb() {
            return Ok(e);
        }
        // Fallback: kuch proxies VERSION() rewrite karte hain; tidb_version() sirf TiDB par chalta hai.
        match sql::q(SELECT_TIDB_VERSION).fetch_one(&mut *conn).await {
            Ok(_) => Ok(Self::TiDb { version: v }),
            Err(_) => Ok(e),
        }
    }

    /// Refuse when the detected engine is not the configured one (`DB_EXPECT_ENGINE`).
    ///
    /// # Errors
    /// `EngineMismatch`.
    pub fn ensure(&self, expected: config::DbEngine) -> Result<(), DbError> {
        if self.kind() == expected {
            Ok(())
        } else {
            Err(DbError::EngineMismatch {
                expected: engine_name(expected),
                found: self.name(),
            })
        }
    }
}

const fn engine_name(e: config::DbEngine) -> &'static str {
    match e {
        config::DbEngine::TiDb => "tidb",
        config::DbEngine::MySql => "mysql",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_versions() {
        assert!(Engine::from_version("8.0.11-TiDB-v7.5.1").is_tidb());
        assert!(!Engine::from_version("8.4.3").is_tidb());
        let m = Engine::from_version("8.4.3");
        assert!(m.ensure(config::DbEngine::MySql).is_ok());
        assert!(matches!(
            m.ensure(config::DbEngine::TiDb),
            Err(DbError::EngineMismatch {
                expected: "tidb",
                found: "mysql"
            })
        ));
    }
}
