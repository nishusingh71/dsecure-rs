//! Minimal compact JWS (RFC 7515), ES256 only.
//!
//! Why own code instead of `jsonwebtoken`: (1) signing must go through `crypto::Signer` (keys are
//! KEK-wrapped today and may move into a KMS; `jsonwebtoken::EncodingKey` needs the raw private key
//! in process memory); (2) verification must go through `crypto::verify`, which enforces low-S for
//! ES256 (the crypto re-review requirement) and is constant-time inside aws-lc; (3) the accepted
//! surface is tiny and fixed: exactly three base64url segments, header with exactly
//! `alg`/`kid`/`typ`, `alg == "ES256"` byte-exact, no `jku`/`jwk`/`x5u`/`crit`/`b64`, no JSON
//! serialisation, no unencoded payload, no `none`, no HMAC code path at all (so an HS256 token
//! "signed" with the public key cannot even reach a MAC check).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::error::Rejection;

/// The only accepted `alg`.
pub const ALG_ES256: &str = "ES256";
/// Hard cap on the compact token length (header + claims + signature are all small).
pub const MAX_TOKEN_LEN: usize = 4096;
/// ES256 fixed `r || s` signature length.
pub const ES256_SIG_LEN: usize = 64;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
}

/// `kid`: 1..=64 chars of `[A-Za-z0-9_.-]` (same family as crypto kids; never echoed anywhere).
#[must_use]
pub fn valid_kid(kid: &str) -> bool {
    (1..=64).contains(&kid.len())
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// `base64url(header) "." base64url(payload)` for a payload; the signature goes on these bytes.
pub(crate) fn signing_input(kid: &str, payload: &[u8]) -> Result<String, Rejection> {
    if !valid_kid(kid) {
        return Err(Rejection::UnknownKid);
    }
    let header = serde_json::to_vec(&Header {
        alg: ALG_ES256.to_owned(),
        kid: kid.to_owned(),
        typ: Some("JWT".to_owned()),
    })
    .map_err(|_| Rejection::Malformed)?;
    let mut out = URL_SAFE_NO_PAD.encode(header);
    out.push('.');
    out.push_str(&URL_SAFE_NO_PAD.encode(payload));
    Ok(out)
}

pub(crate) fn assemble(signing_input: &str, sig: &[u8]) -> String {
    let mut out = String::with_capacity(signing_input.len() + 90);
    out.push_str(signing_input);
    out.push('.');
    out.push_str(&URL_SAFE_NO_PAD.encode(sig));
    out
}

/// A parsed but NOT yet verified token.
pub(crate) struct Parts<'a> {
    pub kid: String,
    pub signing_input: &'a str,
    pub payload: Vec<u8>,
    pub sig: Vec<u8>,
}

fn b64(seg: &str) -> Result<Vec<u8>, Rejection> {
    if seg.is_empty() {
        return Err(Rejection::Malformed);
    }
    // URL_SAFE_NO_PAD: padding and non-canonical trailing bits are rejected.
    URL_SAFE_NO_PAD
        .decode(seg)
        .map_err(|_| Rejection::Malformed)
}

/// Structural parse + algorithm allowlist. Signature is checked by the caller with the key that the
/// `kid` selects.
pub(crate) fn parse(token: &str) -> Result<Parts<'_>, Rejection> {
    if token.len() > MAX_TOKEN_LEN || !token.is_ascii() {
        return Err(Rejection::Malformed);
    }
    let mut it = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(Rejection::Malformed);
    };
    let header: Header = serde_json::from_slice(&b64(h)?).map_err(|_| Rejection::Malformed)?;
    if header.alg != ALG_ES256 {
        return Err(Rejection::BadAlgorithm);
    }
    if header.typ.as_deref().is_some_and(|t| t != "JWT") {
        return Err(Rejection::Malformed);
    }
    if !valid_kid(&header.kid) {
        return Err(Rejection::UnknownKid);
    }
    let sig = b64(s)?;
    if sig.len() != ES256_SIG_LEN {
        return Err(Rejection::BadSignature);
    }
    let payload = b64(p)?;
    let signing_input = &token[..h.len() + 1 + p.len()];
    Ok(Parts {
        kid: header.kid,
        signing_input,
        payload,
        sig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kid_charset() {
        assert!(valid_kid("member-2026.10_a"));
        assert!(!valid_kid(""));
        assert!(!valid_kid("a/b"));
        assert!(!valid_kid(&"k".repeat(65)));
    }

    #[test]
    fn structural_rejections() {
        assert_eq!(parse("a.b").err(), Some(Rejection::Malformed));
        assert_eq!(parse("a.b.c.d").err(), Some(Rejection::Malformed));
        assert_eq!(parse(&"a".repeat(5000)).err(), Some(Rejection::Malformed));
        // padded base64 is not accepted
        let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"k1"}"#);
        let t = format!("{h}=.e30.{}", URL_SAFE_NO_PAD.encode([0u8; 64]));
        assert_eq!(parse(&t).err(), Some(Rejection::Malformed));
    }

    #[test]
    fn header_extras_rejected() {
        for hdr in [
            r#"{"alg":"ES256","kid":"k1","jku":"https://x"}"#,
            r#"{"alg":"ES256","kid":"k1","crit":["b64"]}"#,
            r#"{"alg":"ES256","kid":"k1","jwk":{}}"#,
            r#"{"alg":"ES256","kid":"k1","typ":"at+jwt2"}"#,
        ] {
            let t = format!(
                "{}.e30.{}",
                URL_SAFE_NO_PAD.encode(hdr),
                URL_SAFE_NO_PAD.encode([0u8; 64])
            );
            assert_eq!(parse(&t).err(), Some(Rejection::Malformed), "{hdr}");
        }
    }

    #[test]
    fn algorithm_allowlist() {
        for alg in ["none", "HS256", "RS256", "PS256", "ES384", "EdDSA", "es256"] {
            let hdr = format!(r#"{{"alg":"{alg}","kid":"k1"}}"#);
            let t = format!(
                "{}.e30.{}",
                URL_SAFE_NO_PAD.encode(hdr),
                URL_SAFE_NO_PAD.encode([0u8; 64])
            );
            assert_eq!(parse(&t).err(), Some(Rejection::BadAlgorithm), "{alg}");
        }
    }
}
