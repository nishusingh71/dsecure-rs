//! Encrypted value envelope (DATABASE.md section 3), pure parse/build, no keys.
//!
//! ```text
//! byte 0     : format version (0x01)
//! byte 1     : flags (must be 0x00 today; bit0 = gzip is reserved and REJECTED, see below)
//! byte 2     : kid length n (1..=32)
//! bytes 3..  : kid (ASCII)
//! next 12    : nonce (random 96-bit)
//! rest       : ciphertext || 16-byte GCM tag
//! AAD        = "dsecure|v1|" || kid || "|" || table || "." || column || "|" || tenant_id || "|" || row_id
//! ```
//! Flags AAD mein nahi hain (DATABASE.md exact format), isliye koi bhi non-zero flag reject hota hai:
//! warna attacker gzip bit flip karke interpretation badal sakta. Compression abhi implement nahi.
//! Platform-scope (tenant `None`) ke liye `tenant_id` field literal `platform` hota hai.

use crate::error::CryptoError;
use crate::gcm::{NONCE, TAG};
use crate::keys::Kid;
use common::TenantId;

pub const VERSION: u8 = 1;
pub const FLAGS: u8 = 0;

/// Parsed view; koi allocation nahi, kuch trust nahi (AEAD verify baad mein).
#[derive(Debug)]
pub struct Envelope<'a> {
    pub kid: Kid,
    pub nonce: [u8; NONCE],
    /// ciphertext || tag (>= 16 bytes)
    pub ct_and_tag: &'a [u8],
}

/// Arbitrary bytes par kabhi panic nahi; sirf `Err`.
///
/// # Errors
/// `MalformedEnvelope` / `UnsupportedVersion` / `InvalidKid`.
pub fn parse(bytes: &[u8]) -> Result<Envelope<'_>, CryptoError> {
    let (Some(&version), Some(&flags), Some(&n)) = (bytes.first(), bytes.get(1), bytes.get(2))
    else {
        return Err(CryptoError::MalformedEnvelope("too short"));
    };
    if version != VERSION || flags != FLAGS {
        return Err(CryptoError::UnsupportedVersion);
    }
    let n = usize::from(n);
    if n == 0 || n > Kid::MAX_LEN {
        return Err(CryptoError::MalformedEnvelope("bad kid length"));
    }
    let kid_end = 3 + n;
    let nonce_end = kid_end + NONCE;
    let (Some(kid_bytes), Some(nonce_bytes), Some(rest)) = (
        bytes.get(3..kid_end),
        bytes.get(kid_end..nonce_end),
        bytes.get(nonce_end..),
    ) else {
        return Err(CryptoError::MalformedEnvelope("truncated"));
    };
    if rest.len() < TAG {
        return Err(CryptoError::MalformedEnvelope("missing tag"));
    }
    let kid_str =
        std::str::from_utf8(kid_bytes).map_err(|_| CryptoError::InvalidKid("not ascii"))?;
    let kid = Kid::parse(kid_str)?;
    let nonce: [u8; NONCE] = nonce_bytes
        .try_into()
        .map_err(|_| CryptoError::MalformedEnvelope("nonce"))?;
    Ok(Envelope {
        kid,
        nonce,
        ct_and_tag: rest,
    })
}

/// `version || flags || n || kid || nonce` (ciphertext baad mein append hota hai).
pub(crate) fn header(kid: &Kid, nonce: &[u8; NONCE]) -> Result<Vec<u8>, CryptoError> {
    Kid::validate(kid.as_str())?;
    let n = u8::try_from(kid.as_str().len()).map_err(|_| CryptoError::InvalidKid("length"))?;
    let mut h = Vec::with_capacity(3 + kid.as_str().len() + NONCE + 64);
    h.push(VERSION);
    h.push(FLAGS);
    h.push(n);
    h.extend_from_slice(kid.as_str().as_bytes());
    h.extend_from_slice(nonce);
    Ok(h)
}

/// Table/column labels: non-empty `[A-Za-z0-9_]` (separator ambiguity band).
fn valid_label(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// AAD bytes per DATABASE.md section 3, version parametrised (tests ke liye).
///
/// # Errors
/// `InvalidContext` agar table/column label galat.
pub fn aad_for_version(
    version: u8,
    kid: &Kid,
    table: &str,
    column: &str,
    tenant: Option<TenantId>,
    row_id: uuid::Uuid,
) -> Result<Vec<u8>, CryptoError> {
    if !valid_label(table) || !valid_label(column) {
        return Err(CryptoError::InvalidContext(
            "table/column must be [A-Za-z0-9_]+",
        ));
    }
    let tenant = tenant.map_or_else(
        || "platform".to_owned(),
        |t| t.as_uuid().hyphenated().to_string(),
    );
    Ok(format!(
        "dsecure|v{version}|{kid}|{table}.{column}|{tenant}|{}",
        row_id.hyphenated()
    )
    .into_bytes())
}

/// Current-version AAD.
///
/// # Errors
/// See [`aad_for_version`].
pub fn aad(
    kid: &Kid,
    table: &str,
    column: &str,
    tenant: Option<TenantId>,
    row_id: uuid::Uuid,
) -> Result<Vec<u8>, CryptoError> {
    aad_for_version(VERSION, kid, table, column, tenant, row_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn aad_exact_format() {
        let kid = Kid::parse("p-id-aabbccdd").expect("kid");
        let t = TenantId::from_uuid(uuid::Uuid::from_u128(1));
        let r = uuid::Uuid::from_u128(2);
        let a = aad(&kid, "users", "email_enc", Some(t), r).expect("aad");
        assert_eq!(
            String::from_utf8(a).expect("utf8"),
            "dsecure|v1|p-id-aabbccdd|users.email_enc|00000000-0000-0000-0000-000000000001|00000000-0000-0000-0000-000000000002"
        );
        let p = aad(&kid, "users", "email_enc", None, r).expect("aad");
        assert!(String::from_utf8(p).expect("utf8").contains("|platform|"));
    }

    #[test]
    fn aad_rejects_ambiguous_labels() {
        let kid = Kid::parse("k").expect("kid");
        let r = uuid::Uuid::nil();
        for (t, c) in [
            ("a.b", "c"),
            ("a", "b|c"),
            ("", "c"),
            ("a", ""),
            ("a b", "c"),
        ] {
            assert!(aad(&kid, t, c, None, r).is_err(), "{t}/{c}");
        }
    }

    #[test]
    fn parse_known_layout() {
        let kid = Kid::parse("abc").expect("kid");
        let mut v = header(&kid, &[7u8; 12]).expect("h");
        v.extend_from_slice(&[9u8; 16]);
        let e = parse(&v).expect("parse");
        assert_eq!(e.kid, kid);
        assert_eq!(e.nonce, [7u8; 12]);
        assert_eq!(e.ct_and_tag, &[9u8; 16]);
        assert_eq!(&v[..4], &[1, 0, 3, b'a']);
    }

    #[test]
    fn parse_rejects_bad_shapes() {
        let kid = Kid::parse("abc").expect("kid");
        let mut ok = header(&kid, &[0u8; 12]).expect("h");
        ok.extend_from_slice(&[0u8; 16]);
        assert!(parse(&ok).is_ok());
        let mut bad = ok.clone();
        bad[0] = 2;
        assert!(matches!(parse(&bad), Err(CryptoError::UnsupportedVersion)));
        let mut bad = ok.clone();
        bad[1] = 1;
        assert!(matches!(parse(&bad), Err(CryptoError::UnsupportedVersion)));
        let mut bad = ok.clone();
        bad[2] = 0;
        assert!(parse(&bad).is_err());
        let mut bad = ok.clone();
        bad[2] = 33;
        assert!(parse(&bad).is_err());
        let mut bad = ok.clone();
        bad[3] = b'|';
        assert!(parse(&bad).is_err());
        assert!(parse(&ok[..ok.len() - 1]).is_err());
        assert!(parse(&[]).is_err());
    }

    proptest! {
        // T-C2
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse(&bytes);
        }

        #[test]
        fn structured_prefix_never_panics(
            n in 0u8..=255,
            kid in proptest::collection::vec(any::<u8>(), 0..40),
            tail in proptest::collection::vec(any::<u8>(), 0..80),
        ) {
            let mut v = vec![1u8, 0u8, n];
            v.extend_from_slice(&kid);
            v.extend_from_slice(&tail);
            let _ = parse(&v);
        }

        #[test]
        fn valid_roundtrip_parse(
            kid in "[A-Za-z0-9_.-]{1,32}",
            nonce in proptest::array::uniform12(any::<u8>()),
            ct in proptest::collection::vec(any::<u8>(), 16..64),
        ) {
            let k = Kid::parse(kid).expect("kid");
            let mut v = header(&k, &nonce).expect("h");
            v.extend_from_slice(&ct);
            let e = parse(&v).expect("parse");
            prop_assert_eq!(e.kid, k);
            prop_assert_eq!(e.nonce, nonce);
            prop_assert_eq!(e.ct_and_tag, &ct[..]);
        }
    }
}
