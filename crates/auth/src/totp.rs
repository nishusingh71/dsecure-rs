//! TOTP (RFC 6238 over RFC 4226 HOTP): HMAC-SHA1, 30 s step, 6 digits, ±1 step window. Pure.
//!
//! SHA-1 here is the RFC/authenticator-app standard for HOTP truncation (HMAC-SHA1 is not affected
//! by SHA-1 collision attacks); aws-lc exposes it as `HMAC_SHA1_FOR_LEGACY_USE_ONLY`.

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::error::AuthError;

pub const STEP_SECS: i64 = 30;
pub const DIGITS: u32 = 6;
/// Accept codes of the previous, current and next step.
pub const WINDOW: i64 = 1;
/// 160-bit secret (RFC 4226 recommendation).
pub const SECRET_LEN: usize = 20;
pub const RECOVERY_CODES: usize = 10;

/// RFC 4226 HOTP value (`digits` <= 9).
#[must_use]
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let h = tag.as_ref();
    let offset = usize::from(h.last().copied().unwrap_or(0) & 0x0f);
    let bin = h
        .get(offset..offset + 4)
        .map_or(0, |b| u32::from_be_bytes([b[0] & 0x7f, b[1], b[2], b[3]]));
    bin % 10u32.pow(digits.min(9))
}

/// Time step of a unix time (floor division, negative times = step 0).
#[must_use]
pub const fn step_of(unix: i64) -> i64 {
    if unix < 0 { 0 } else { unix / STEP_SECS }
}

/// RFC 6238 TOTP at a unix time.
#[must_use]
pub fn totp_at(secret: &[u8], unix: i64, digits: u32) -> u32 {
    hotp(secret, u64::try_from(step_of(unix)).unwrap_or(0), digits)
}

/// Unix time where `step` starts.
#[must_use]
pub const fn step_start(step: i64) -> i64 {
    step * STEP_SECS
}

/// Check `code` (exactly 6 ASCII digits) against steps `now-1..=now+1` that are strictly later than
/// `after_step`. Returns the matched step. Every candidate is compared in constant time.
#[must_use]
pub fn verify_code(
    secret: &[u8],
    code: &str,
    now_unix: i64,
    after_step: Option<i64>,
) -> Option<i64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = step_of(now_unix);
    let mut found = None;
    for step in (now - WINDOW)..=(now + WINDOW) {
        if step < 0 || after_step.is_some_and(|a| step <= a) {
            continue;
        }
        let expect = format!(
            "{:06}",
            hotp(secret, u64::try_from(step).unwrap_or(0), DIGITS)
        );
        if verify_slices_are_equal(expect.as_bytes(), code.as_bytes()).is_ok() && found.is_none() {
            found = Some(step);
        }
    }
    found
}

/// Fresh random secret.
///
/// # Errors
/// `Internal` on RNG failure.
pub fn generate_secret() -> Result<Zeroizing<Vec<u8>>, AuthError> {
    let mut s = Zeroizing::new(vec![0u8; SECRET_LEN]);
    SystemRandom::new()
        .fill(&mut s[..])
        .map_err(|_| AuthError::Internal("rng failure"))?;
    Ok(s)
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding (authenticator apps' secret format).
#[must_use]
pub fn base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for &b in data {
        buf = (buf << 8) | u64::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = usize::try_from((buf >> bits) & 31).unwrap_or(0);
            out.push(char::from(B32[idx]));
        }
    }
    if bits > 0 {
        let idx = usize::try_from((buf << (5 - bits)) & 31).unwrap_or(0);
        out.push(char::from(B32[idx]));
    }
    out
}

fn uri_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'@') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `otpauth://totp/<issuer>:<account>?secret=..&issuer=..&algorithm=SHA1&digits=6&period=30`.
#[must_use]
pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        uri_escape(issuer),
        uri_escape(account),
        base32(secret),
        uri_escape(issuer)
    )
}

/// New recovery code: 80 random bits as `XXXX-XXXX-XXXX-XXXX` (base32).
///
/// # Errors
/// `Internal` on RNG failure.
pub fn generate_recovery_code() -> Result<Zeroizing<String>, AuthError> {
    let mut raw = Zeroizing::new([0u8; 10]);
    SystemRandom::new()
        .fill(&mut raw[..])
        .map_err(|_| AuthError::Internal("rng failure"))?;
    let b = Zeroizing::new(base32(&raw[..]));
    let mut out = String::with_capacity(19);
    for (i, c) in b.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(c);
    }
    Ok(Zeroizing::new(out))
}

/// Normalised form for hashing: uppercase, no separators/whitespace. `None` = not a recovery code.
#[must_use]
pub fn normalise_recovery(code: &str) -> Option<Zeroizing<String>> {
    let n: String = code
        .chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (n.len() == 16 && n.bytes().all(|b| B32.contains(&b))).then(|| Zeroizing::new(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B, SHA-1 column (8 digits), secret = ASCII "12345678901234567890".
    #[test]
    fn rfc6238_sha1_vectors() {
        let secret = b"12345678901234567890";
        for (t, want) in [
            (59_i64, 94_287_082_u32),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
            (20_000_000_000, 65_353_130),
        ] {
            assert_eq!(totp_at(secret, t, 8), want, "t={t}");
            // 6-digit codes are the same value mod 10^6
            assert_eq!(totp_at(secret, t, 6), want % 1_000_000, "t={t}");
        }
    }

    /// RFC 4226 Appendix D HOTP vectors.
    #[test]
    fn rfc4226_hotp_vectors() {
        let secret = b"12345678901234567890";
        let want = [
            755_224, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871,
            520_489,
        ];
        for (c, w) in want.iter().enumerate() {
            assert_eq!(hotp(secret, c as u64, 6), *w, "counter {c}");
        }
    }

    #[test]
    fn window_and_replay_floor() {
        let s = b"12345678901234567890";
        let t = 1_111_111_111;
        let now = step_of(t);
        let code = |step: i64| format!("{:06}", hotp(s, step as u64, 6));
        assert_eq!(verify_code(s, &code(now), t, None), Some(now));
        assert_eq!(verify_code(s, &code(now - 1), t, None), Some(now - 1));
        assert_eq!(verify_code(s, &code(now + 1), t, None), Some(now + 1));
        assert_eq!(verify_code(s, &code(now - 2), t, None), None);
        assert_eq!(verify_code(s, &code(now + 2), t, None), None);
        // replay floor: the same step (or older) is refused
        assert_eq!(verify_code(s, &code(now), t, Some(now)), None);
        assert_eq!(verify_code(s, &code(now + 1), t, Some(now)), Some(now + 1));
        for bad in ["", "12345", "1234567", "12a456", " 1234 "] {
            assert_eq!(verify_code(s, bad, t, None), None, "{bad:?}");
        }
    }

    #[test]
    fn base32_and_uri() {
        // RFC 4648 test vectors
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foo"), "MZXW6");
        assert_eq!(base32(b"foob"), "MZXW6YQ");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        let u = otpauth_uri("DSecure", "a b@x.test", b"12345678901234567890");
        assert_eq!(
            u,
            "otpauth://totp/DSecure:a%20b@x.test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=DSecure&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn recovery_code_format() {
        let c = generate_recovery_code().expect("rc");
        assert_eq!(c.len(), 19);
        let n = normalise_recovery(&c.to_lowercase()).expect("normalised");
        assert_eq!(n.len(), 16);
        assert!(normalise_recovery("not a code").is_none());
        assert_ne!(*c, *generate_recovery_code().expect("rc"));
    }
}
