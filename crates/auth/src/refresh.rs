//! Refresh tokens: opaque `rt1_` + base64url(32 random bytes). Only `HMAC-SHA256(key, token)` is
//! stored (`refresh_tokens.token_hash`), so a DB dump cannot be replayed and no hash table lookup can
//! be pre-computed without the key. Key = platform-DEK-derived (SECURITY.md §2) and injected by the
//! caller; never logged.

use aws_lc_rs::hmac;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use crate::error::{AuthError, Rejection};

pub const REFRESH_PREFIX: &str = "rt1_";
const RAW_LEN: usize = 32;
/// `rt1_` + 43 base64url chars.
const TOKEN_LEN: usize = 4 + 43;

/// The secret handed to the client once. `Debug` never shows it.
pub struct RefreshSecret(Zeroizing<String>);

impl RefreshSecret {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for RefreshSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshSecret([redacted])")
    }
}

/// New random refresh secret.
///
/// # Errors
/// `Internal` if the RNG fails.
pub fn generate() -> Result<RefreshSecret, AuthError> {
    generate_opaque(REFRESH_PREFIX).map(RefreshSecret)
}

/// `prefix` + base64url(32 random bytes). Prefixes are 4 ASCII chars (`rt1_`, `su1_`).
pub(crate) fn generate_opaque(prefix: &str) -> Result<Zeroizing<String>, AuthError> {
    let mut raw = Zeroizing::new([0u8; RAW_LEN]);
    SystemRandom::new()
        .fill(&mut raw[..])
        .map_err(|_| AuthError::Internal("rng failure"))?;
    let mut s = String::with_capacity(TOKEN_LEN);
    s.push_str(prefix);
    s.push_str(&URL_SAFE_NO_PAD.encode(&raw[..]));
    Ok(Zeroizing::new(s))
}

/// Keyed hash of refresh tokens.
pub struct RefreshHasher {
    key: hmac::Key,
}

impl std::fmt::Debug for RefreshHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshHasher([redacted])")
    }
}

impl RefreshHasher {
    /// `key`: 32 bytes from the key hierarchy (HKDF purpose "refresh-token-hash").
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
        }
    }

    /// Validate the format and hash. Malformed input never reaches the DB.
    ///
    /// # Errors
    /// `Malformed`.
    pub fn hash(&self, token: &str) -> Result<[u8; 32], Rejection> {
        self.hash_opaque(REFRESH_PREFIX, token)
    }

    /// Domain-separated MAC of arbitrary data (recovery codes: domain `b"rc1:"`).
    pub(crate) fn mac(&self, domain: &[u8], data: &[u8]) -> [u8; 32] {
        let mut ctx = hmac::Context::with_key(&self.key);
        ctx.update(domain);
        ctx.update(data);
        let tag = ctx.sign();
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        out
    }

    /// Same keyed hash for another opaque token kind. The prefix is part of the MAC input, so a
    /// refresh token and a step-up token can never collide or be swapped.
    pub(crate) fn hash_opaque(&self, prefix: &str, token: &str) -> Result<[u8; 32], Rejection> {
        let body = token
            .strip_prefix(prefix)
            .filter(|_| prefix.len() == 4 && token.len() == TOKEN_LEN)
            .ok_or(Rejection::Malformed)?;
        let raw = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| Rejection::Malformed)?,
        );
        if raw.len() != RAW_LEN {
            return Err(Rejection::Malformed);
        }
        let tag = hmac::sign(&self.key, token.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_hash_roundtrip_and_format() {
        let h = RefreshHasher::new(&[7u8; 32]);
        let a = generate().expect("gen");
        let b = generate().expect("gen");
        assert_ne!(a.expose(), b.expose());
        assert_eq!(a.expose().len(), TOKEN_LEN);
        assert_eq!(h.hash(a.expose()), h.hash(a.expose()));
        assert_ne!(h.hash(a.expose()), h.hash(b.expose()));
        assert_eq!(format!("{a:?}"), "RefreshSecret([redacted])");
        assert_eq!(h.hash("rt1_short"), Err(Rejection::Malformed));
        assert_eq!(
            h.hash(&a.expose().replace("rt1_", "rt2_")),
            Err(Rejection::Malformed)
        );
        // different key = different stored hash
        let h2 = RefreshHasher::new(&[8u8; 32]);
        assert_ne!(h.hash(a.expose()), h2.hash(a.expose()));
    }
}
