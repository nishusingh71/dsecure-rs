//! Keyset pagination helper over `common::Page` / `PageOut` (DATABASE.md §1.3 rule 2: never OFFSET).
//!
//! Lists are `ORDER BY id DESC` with `id < :after` (UUIDv7 = creation order, clustered PK range scan).
//! First page uses the max UUID as sentinel so one query file serves every page. The cursor is the
//! HMAC-tagged `common::Cursor` (tamper -> `cursor_invalid`, decoded by `Page::parse` in the API).

use crate::error::DbError;
use common::{Cursor, Page, PageOut};
use time::OffsetDateTime;
use uuid::Uuid;

/// `id < ?` bind value for this page.
#[must_use]
pub fn after_id(page: &Page) -> Uuid {
    page.after.map_or(Uuid::from_u128(u128::MAX), |c| c.id)
}

/// `LIMIT ?` bind value (`limit + 1` overfetch to detect the next page).
#[must_use]
pub fn fetch_limit(page: &Page) -> u32 {
    page.fetch_size()
}

/// Build the page output; the cursor of the last kept row carries `(sort_key, id)`.
///
/// # Errors
/// `Internal`-class error if the cursor key is too short.
pub fn finish<T>(
    rows: Vec<T>,
    page: &Page,
    cursor_key: &[u8],
    key_of: impl Fn(&T) -> (OffsetDateTime, Uuid),
) -> Result<PageOut<T>, DbError> {
    PageOut::from_overfetch(rows, page, cursor_key, |r| {
        let (ts, id) = key_of(r);
        Cursor::new(ts, id)
    })
    .map_err(|_| DbError::Config("cursor key invalid"))
}
