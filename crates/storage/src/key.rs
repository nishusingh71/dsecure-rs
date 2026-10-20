//! `BlobKey`: validated, tenant-prefixed, path-traversal-proof key.
//!
//! Format: `<tenant-uuid-hyphenated-lowercase>/<seg>/<seg>/...` (1..=7 segments tenant ke baad).
//! Segment: `[a-z0-9._-]`, 1..=128 bytes, pehla char alnum, aakhri `.` nahi, Windows reserved naam
//! (CON, NUL, COM1...) nahi. Lowercase-only taaki case-insensitive filesystems par collision na ho.
//! `/`, `\`, `:`, NUL, `..`, absolute path, drive letter sab is wajah se automatically bahar.

use crate::error::StorageError;
use common::TenantId;
use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BlobKey {
    tenant: TenantId,
    full: String,
}

impl BlobKey {
    pub const MAX_LEN: usize = 512;
    /// Tenant + 7 segments.
    pub const MAX_SEGMENTS: usize = 8;
    pub const MAX_SEGMENT_LEN: usize = 128;

    /// Tenant + relative path (`reports/2026/abc.bin`).
    ///
    /// # Errors
    /// `InvalidKey` agar rule toota.
    pub fn new(tenant: TenantId, rel: &str) -> Result<Self, StorageError> {
        Self::parse(&format!("{}/{rel}", tenant.as_uuid().hyphenated()))
    }

    /// Poori key string parse + validate (tenant prefix compulsory).
    ///
    /// # Errors
    /// `InvalidKey`.
    pub fn parse(s: &str) -> Result<Self, StorageError> {
        if s.is_empty() || s.len() > Self::MAX_LEN {
            return Err(StorageError::InvalidKey("length must be 1..=512"));
        }
        let mut it = s.split('/');
        let first = it.next().unwrap_or_default();
        let uuid = uuid::Uuid::parse_str(first)
            .map_err(|_| StorageError::InvalidKey("missing tenant prefix"))?;
        if uuid.hyphenated().to_string() != first {
            return Err(StorageError::InvalidKey("tenant prefix not canonical"));
        }
        let mut n = 1;
        for seg in it {
            n += 1;
            if n > Self::MAX_SEGMENTS {
                return Err(StorageError::InvalidKey("too many segments"));
            }
            validate_segment(seg)?;
        }
        if n < 2 {
            return Err(StorageError::InvalidKey("no object name after tenant"));
        }
        Ok(Self {
            tenant: TenantId::from_uuid(uuid),
            full: s.to_owned(),
        })
    }

    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.full
    }

    /// Tenant ke baad ke segments.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.full.split('/').skip(1)
    }
}

fn validate_segment(seg: &str) -> Result<(), StorageError> {
    if seg.is_empty() || seg.len() > BlobKey::MAX_SEGMENT_LEN {
        return Err(StorageError::InvalidKey("segment length must be 1..=128"));
    }
    let b = seg.as_bytes();
    if !b
        .iter()
        .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        return Err(StorageError::InvalidKey("segment allows only [a-z0-9._-]"));
    }
    if !b.first().is_some_and(u8::is_ascii_alphanumeric) {
        return Err(StorageError::InvalidKey(
            "segment must start with a letter or digit",
        ));
    }
    if b.last() == Some(&b'.') {
        return Err(StorageError::InvalidKey("segment must not end with a dot"));
    }
    let stem = seg.split('.').next().unwrap_or_default();
    // com0-com9 / lpt0-lpt9 (superscript variants non-ASCII hain; charset check pehle hi rok deta hai).
    let numbered = (stem.starts_with("com") || stem.starts_with("lpt"))
        && stem.len() == 4
        && stem.as_bytes().get(3).is_some_and(u8::is_ascii_digit);
    if matches!(stem, "con" | "prn" | "aux" | "nul") || numbered {
        return Err(StorageError::InvalidKey("reserved device name"));
    }
    Ok(())
}

impl fmt::Debug for BlobKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BlobKey").field(&self.full).finish()
    }
}

impl fmt::Display for BlobKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.full)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_and_rejects_hostile_keys() {
        let t = TenantId::new();
        assert!(BlobKey::new(t, "reports/2026/abc-1.bin").is_ok());
        for bad in [
            "../x",
            "a/../b",
            "/abs",
            "a//b",
            "C:/x",
            "c:\\x",
            "a\\b",
            "a/b\0",
            "",
            ".",
            "..",
            "a/.",
            ".hidden",
            "a/b.",
            "con",
            "nul.txt",
            "COM1",
            "com0",
            "com1",
            "com9.txt",
            "lpt0",
            "lpt9.x",
            "prn.log",
            "aux",
            "com\u{b2}",
            "lpt\u{b9}",
            "A/UPPER",
            "a b",
            "a/b:ads",
            "a/%2e%2e",
            "\u{e9}",
        ] {
            assert!(BlobKey::new(t, bad).is_err(), "must reject {bad:?}");
        }
        let hyph = t.as_uuid().hyphenated().to_string();
        assert!(BlobKey::parse("no-tenant/x").is_err());
        assert!(BlobKey::parse(&hyph).is_err());
        assert!(BlobKey::parse(&format!("{}/x", t.as_uuid().simple())).is_err());
        assert!(BlobKey::parse(&format!("{}/x", hyph.to_uppercase())).is_err());
        assert!(BlobKey::new(t, "a/b/c/d/e/f/g/h").is_err());
        assert!(BlobKey::new(t, &"a".repeat(129)).is_err());
        assert!(BlobKey::parse("../../etc/passwd").is_err());
    }

    #[test]
    fn roundtrips_tenant() {
        let t = TenantId::new();
        let k = BlobKey::new(t, "r/x.bin").unwrap();
        assert_eq!(k.tenant(), t);
        assert_eq!(BlobKey::parse(k.as_str()).unwrap(), k);
        assert_eq!(k.segments().collect::<Vec<_>>(), ["r", "x.bin"]);
    }
}
