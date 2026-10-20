//! Write guards: a write that must change rows never succeeds silently (legacy NoTracking lesson).
//! sqlx MySQL sets `CLIENT_FOUND_ROWS`, so `rows_affected` = matched rows (not only changed ones).

use crate::error::DbError;

pub trait WriteOutcome {
    /// Exactly one row.
    ///
    /// # Errors
    /// `NotPersisted` otherwise.
    fn expect_one(self) -> Result<(), DbError>;

    /// Exactly `n` rows.
    ///
    /// # Errors
    /// `NotPersisted` otherwise.
    fn expect_n(self, n: u64) -> Result<(), DbError>;
}

impl WriteOutcome for u64 {
    fn expect_one(self) -> Result<(), DbError> {
        self.expect_n(1)
    }

    fn expect_n(self, n: u64) -> Result<(), DbError> {
        if self == n {
            Ok(())
        } else {
            Err(DbError::NotPersisted {
                expected: n,
                actual: self,
            })
        }
    }
}

impl WriteOutcome for sqlx::mysql::MySqlQueryResult {
    fn expect_one(self) -> Result<(), DbError> {
        self.rows_affected().expect_one()
    }

    fn expect_n(self, n: u64) -> Result<(), DbError> {
        self.rows_affected().expect_n(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guards() {
        assert!(1u64.expect_one().is_ok());
        assert!(matches!(
            0u64.expect_one(),
            Err(DbError::NotPersisted {
                expected: 1,
                actual: 0
            })
        ));
        assert!(3u64.expect_n(3).is_ok());
        assert!(2u64.expect_n(3).is_err());
    }
}
