//! Keyset pagination: opaque, tamper-evident cursors.
//!
//! Wire format: `base64url_nopad( version(1) || sort_key_unix_nanos(i128 BE, 16) || id(16) || tag(32) )`
//! where `tag = HMAC-SHA256(key, "dsecure-cursor-v1" || version || sort_key || id)`.
//! The key is passed in by the caller (the `crypto` crate does not exist yet; later it derives it
//! via HKDF from a platform key). Any malformed or tampered cursor yields the same
//! `AppError::BadRequest` with code `cursor_invalid` (no oracle about which part failed).

use crate::error::{AppError, AppErrorKind, FieldError};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use time::OffsetDateTime;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"dsecure-cursor-v1";
const PAYLOAD_LEN: usize = 1 + 16 + 16;
const TAG_LEN: usize = 32;
/// Minimum HMAC key length we accept (bytes).
pub const MIN_KEY_LEN: usize = 16;
pub const MIN_LIMIT: u16 = 1;
pub const MAX_LIMIT: u16 = 200;
pub const DEFAULT_LIMIT: u16 = 50;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub sort_key: OffsetDateTime,
    pub id: Uuid,
}

fn invalid() -> AppError {
    AppError::bad_request("cursor_invalid", "cursor is invalid").with_field(FieldError::new(
        "cursor",
        "invalid",
        "cursor is invalid or has been tampered with",
    ))
}

fn mac(key: &[u8]) -> Result<HmacSha256, AppError> {
    if key.len() < MIN_KEY_LEN {
        return Err(AppError::new(
            AppErrorKind::Internal,
            "cursor_key_invalid",
            "cursor key is too short",
        ));
    }
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).map_err(|_| {
        AppError::new(
            AppErrorKind::Internal,
            "cursor_key_invalid",
            "cursor key is invalid",
        )
    })?;
    m.update(DOMAIN);
    Ok(m)
}

impl Cursor {
    #[must_use]
    pub const fn new(sort_key: OffsetDateTime, id: Uuid) -> Self {
        Self { sort_key, id }
    }

    /// Encode to an opaque base64url string with an HMAC tag.
    ///
    /// # Errors
    /// `Internal` if `key` is shorter than [`MIN_KEY_LEN`].
    pub fn encode(&self, key: &[u8]) -> Result<String, AppError> {
        let mut buf = Vec::with_capacity(PAYLOAD_LEN + TAG_LEN);
        buf.push(VERSION);
        buf.extend_from_slice(&self.sort_key.unix_timestamp_nanos().to_be_bytes());
        buf.extend_from_slice(self.id.as_bytes());
        let mut m = mac(key)?;
        m.update(&buf);
        buf.extend_from_slice(&m.finalize().into_bytes());
        Ok(URL_SAFE_NO_PAD.encode(buf))
    }

    /// Decode and verify (constant-time tag compare).
    ///
    /// # Errors
    /// `BadRequest` / `cursor_invalid` for any malformed, wrong-version or tampered cursor;
    /// `Internal` if `key` is too short.
    pub fn decode(token: &str, key: &[u8]) -> Result<Self, AppError> {
        let m = mac(key)?;
        let raw = URL_SAFE_NO_PAD.decode(token).map_err(|_| invalid())?;
        if raw.len() != PAYLOAD_LEN + TAG_LEN {
            return Err(invalid());
        }
        let (payload, tag) = raw.split_at(PAYLOAD_LEN);
        let mut m = m;
        m.update(payload);
        m.verify_slice(tag).map_err(|_| invalid())?;
        if payload[0] != VERSION {
            return Err(invalid());
        }
        let nanos = i128::from_be_bytes(payload[1..17].try_into().map_err(|_| invalid())?);
        let id = Uuid::from_bytes(payload[17..33].try_into().map_err(|_| invalid())?);
        let sort_key = OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| invalid())?;
        Ok(Self { sort_key, id })
    }
}

/// Parsed page request. `limit` is always within `MIN_LIMIT..=MAX_LIMIT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    pub limit: u16,
    pub after: Option<Cursor>,
}

impl Page {
    /// Clamp any requested limit into `1..=200`.
    #[must_use]
    pub fn clamp_limit(requested: u32) -> u16 {
        u16::try_from(requested.clamp(u32::from(MIN_LIMIT), u32::from(MAX_LIMIT)))
            .unwrap_or(MAX_LIMIT)
    }

    /// Build from raw query parameters. Missing limit -> [`DEFAULT_LIMIT`].
    ///
    /// # Errors
    /// `cursor_invalid` if `after` is present but bad.
    pub fn parse(limit: Option<u32>, after: Option<&str>, key: &[u8]) -> Result<Self, AppError> {
        Ok(Self {
            limit: limit.map_or(DEFAULT_LIMIT, Self::clamp_limit),
            after: after.map(|t| Cursor::decode(t, key)).transpose()?,
        })
    }

    /// Rows to fetch from the DB (`limit + 1`) so we can tell whether a next page exists.
    #[must_use]
    pub fn fetch_size(&self) -> u32 {
        u32::from(self.limit) + 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PageOut<T> {
    pub data: Vec<T>,
    pub next_cursor: Option<String>,
}

impl<T> PageOut<T> {
    /// Build from rows fetched with `limit + 1` (see [`Page::fetch_size`]): extra row means more
    /// data; the cursor points at the last row that is kept.
    ///
    /// # Errors
    /// `Internal` if `key` is too short.
    pub fn from_overfetch(
        mut rows: Vec<T>,
        page: &Page,
        key: &[u8],
        cursor_of: impl Fn(&T) -> Cursor,
    ) -> Result<Self, AppError> {
        let limit = usize::from(page.limit);
        let next_cursor = if rows.len() > limit {
            rows.truncate(limit);
            rows.last().map(|r| cursor_of(r).encode(key)).transpose()?
        } else {
            None
        };
        Ok(Self {
            data: rows,
            next_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const OTHER: &[u8] = b"fedcba9876543210fedcba9876543210";

    fn cur(secs: i64, nanos: i128, id: u128) -> Cursor {
        let ts =
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(secs) * 1_000_000_000 + nanos)
                .expect("ts");
        Cursor::new(ts, Uuid::from_u128(id))
    }

    #[test]
    fn round_trip() {
        let c = cur(1_800_000_000, 123_456_789, 42);
        let t = c.encode(KEY).expect("enc");
        assert!(!t.contains(['+', '/', '=']));
        assert_eq!(Cursor::decode(&t, KEY).expect("dec"), c);
    }

    #[test]
    fn wrong_key_rejected() {
        let t = cur(1_800_000_000, 0, 1).encode(KEY).expect("enc");
        let e = Cursor::decode(&t, OTHER).expect_err("must fail");
        assert_eq!(e.code, "cursor_invalid");
        assert_eq!(e.kind, AppErrorKind::BadRequest);
    }

    #[test]
    fn short_key_is_internal_error() {
        let c = cur(1, 0, 1);
        assert_eq!(
            c.encode(b"short").expect_err("short").kind,
            AppErrorKind::Internal
        );
        assert!(Cursor::decode("x", b"short").is_err());
    }

    #[test]
    fn garbage_and_truncated_rejected() {
        let t = cur(1_800_000_000, 0, 1).encode(KEY).expect("enc");
        for bad in ["", "!!!", "AAAA", &t[..t.len() - 2], &format!("{t}AA")] {
            assert!(Cursor::decode(bad, KEY).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn limit_is_clamped() {
        assert_eq!(Page::clamp_limit(0), 1);
        assert_eq!(Page::clamp_limit(1), 1);
        assert_eq!(Page::clamp_limit(200), 200);
        assert_eq!(Page::clamp_limit(201), 200);
        assert_eq!(Page::clamp_limit(u32::MAX), 200);
        let p = Page::parse(None, None, KEY).expect("ok");
        assert_eq!(p.limit, DEFAULT_LIMIT);
        assert_eq!(p.fetch_size(), 51);
        assert_eq!(Page::parse(Some(0), None, KEY).expect("ok").limit, 1);
    }

    #[test]
    fn page_parse_rejects_bad_cursor() {
        assert!(Page::parse(Some(10), Some("junk"), KEY).is_err());
        let t = cur(5, 0, 9).encode(KEY).expect("enc");
        let p = Page::parse(Some(10), Some(&t), KEY).expect("ok");
        assert_eq!(p.after, Some(cur(5, 0, 9)));
    }

    #[test]
    fn page_out_overfetch() {
        let page = Page::parse(Some(2), None, KEY).expect("ok");
        let rows: Vec<u32> = vec![1, 2, 3];
        let out =
            PageOut::from_overfetch(rows, &page, KEY, |n| cur(i64::from(*n), 0, u128::from(*n)))
                .expect("ok");
        assert_eq!(out.data, vec![1, 2]);
        let next = Cursor::decode(&out.next_cursor.expect("has next"), KEY).expect("dec");
        assert_eq!(next, cur(2, 0, 2));

        let last = PageOut::from_overfetch(vec![1u32, 2], &page, KEY, |n| cur(i64::from(*n), 0, 0))
            .expect("ok");
        assert_eq!(last.data.len(), 2);
        assert!(last.next_cursor.is_none());
    }

    proptest! {
        #[test]
        fn prop_round_trip(secs in -62_000_000_000_i64..250_000_000_000_i64,
                           nanos in 0_i128..1_000_000_000, id in any::<u128>(),
                           key in proptest::collection::vec(any::<u8>(), MIN_KEY_LEN..64)) {
            let c = cur(secs, nanos, id);
            let t = c.encode(&key).expect("enc");
            prop_assert_eq!(Cursor::decode(&t, &key).expect("dec"), c);
        }

        #[test]
        fn prop_any_mutation_is_rejected(secs in 0_i64..4_000_000_000_i64, id in any::<u128>(),
                                         idx in any::<prop::sample::Index>(), bit in 0u8..8) {
            let c = cur(secs, 0, id);
            let t = c.encode(KEY).expect("enc");
            let mut raw = URL_SAFE_NO_PAD.decode(&t).expect("b64");
            let i = idx.index(raw.len());
            raw[i] ^= 1 << bit;
            let tampered = URL_SAFE_NO_PAD.encode(raw);
            prop_assert!(Cursor::decode(&tampered, KEY).is_err());
        }

        #[test]
        fn prop_arbitrary_strings_never_panic(s in ".{0,200}") {
            let _ = Cursor::decode(&s, KEY);
        }

        #[test]
        fn prop_clamp_in_range(n in any::<u32>()) {
            let l = Page::clamp_limit(n);
            prop_assert!((MIN_LIMIT..=MAX_LIMIT).contains(&l));
        }
    }
}
