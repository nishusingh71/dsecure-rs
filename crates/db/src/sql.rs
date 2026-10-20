//! The ONLY module that calls `sqlx::query` (L4). Baaki db crate yahin ke helpers use karta hai;
//! db ke bahar `sqlx::query*` clippy `disallowed_methods` se banned hai.
//!
//! Static SQL sirf `crate::queries` (query files) se aata hai. `dynamic` sirf do cases ke liye:
//! (a) placeholder expansion (`?, ?, ...`, kabhi values nahi), (b) session init / test harness
//! statements jinme sirf validated integers ya `[a-z0-9_]` identifiers format hote hain.

use crate::error::DbError;
use sqlx::mysql::{MySql, MySqlArguments, MySqlRow};
use sqlx::query::Query;

pub(crate) type Q<'q> = Query<'q, MySql, MySqlArguments>;

/// Static SQL (query file constant).
// L4: db crate ka single sanctioned entry point; yahin allow, aur kahin nahi.
#[allow(clippy::disallowed_methods)]
pub(crate) fn q<'q>(sql: &'static str) -> Q<'q> {
    sqlx::query(sql)
}

/// Runtime-built SQL. Caller guarantees it only contains placeholders / validated identifiers.
// L4: same single entry point (see module docs for the two allowed uses).
#[allow(clippy::disallowed_methods)]
pub(crate) fn dynamic<'q>(sql: String) -> Q<'q> {
    sqlx::query(sqlx::AssertSqlSafe(sql))
}

/// Max ids per IN list; callers chunk longer lists.
pub(crate) const MAX_IDS: usize = 200;

/// Expand the `/*GROUP_IDS*/` marker of a query file into `n` placeholders.
pub(crate) fn expand_ids(template: &'static str, n: usize) -> Result<String, DbError> {
    const MARKER: &str = "/*GROUP_IDS*/";
    if n == 0 || n > MAX_IDS {
        return Err(DbError::Invalid("id list must have 1..=200 entries"));
    }
    if !template.contains(MARKER) {
        return Err(DbError::Corrupt("query template without id marker"));
    }
    let ph = vec!["?"; n].join(", ");
    Ok(template.replacen(MARKER, &ph, 1))
}

pub(crate) fn map_err(e: sqlx::Error) -> DbError {
    DbError::from_sqlx(&e)
}

/// Read a column, mapping decode failures to a value-free error.
pub(crate) fn col<'r, T>(row: &'r MySqlRow, name: &'static str) -> Result<T, DbError>
where
    T: sqlx::Decode<'r, MySql> + sqlx::Type<MySql>,
{
    use sqlx::Row as _;
    row.try_get(name).map_err(|_| DbError::Corrupt(name))
}

/// `BINARY(16)` column -> UUID.
pub(crate) fn uuid_col(row: &MySqlRow, name: &'static str) -> Result<uuid::Uuid, DbError> {
    col::<uuid::Uuid>(row, name)
}

pub(crate) fn opt_uuid_col(
    row: &MySqlRow,
    name: &'static str,
) -> Result<Option<uuid::Uuid>, DbError> {
    col::<Option<uuid::Uuid>>(row, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_ids_placeholders_only() {
        let t = "a IN (/*GROUP_IDS*/) b";
        assert_eq!(expand_ids(t, 3).expect("ok"), "a IN (?, ?, ?) b");
        assert!(expand_ids(t, 0).is_err());
        assert!(expand_ids(t, 201).is_err());
        assert!(expand_ids("no marker", 1).is_err());
    }
}
