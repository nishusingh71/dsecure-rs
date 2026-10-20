//! `BlindIndexer`: deterministic HMAC-SHA256 lookup tokens for encrypted columns.
//!
//! `index = HMAC-SHA256(K, normalise(kind, raw))` where `K = HKDF-SHA256(ikm = DEK bytes,
//! salt = "dsecure|bidx|v1", info = "<kind>|<scope>")`, `<scope>` = `global` or `tenant:<uuid>`.
//! Is se kind aur scope domain-separated hain: same value, alag tenant/kind => alag index.
//!
//! Roots: Global Email -> platform `BidxEmail` DEK, Global LicenseKey -> platform `BidxLicense` DEK,
//! Tenant(t) (any kind) -> tenant `BidxTenant` DEK (crypto-shred ke saath index bhi unusable).
//! `Global` sirf Email aur LicenseKey ke liye allowed hai (baaki kinds tenant-scoped hone chahiye).
//!
//! Zaroori: bidx purposes ki DEK **in-place rotate nahi** hoti (index values badal jaayenge); rotation =
//! naya `*_bidx2` column + dual-write + backfill (SECURITY.md section 2.1).
//!
//! `index` sync hai (trait contract), isliye tenant key pehle cache mein honi chahiye:
//! `prepare_tenant(t).await` (tenant tx shuru karte waqt) warna `KeyNotLoaded`.

use crate::error::CryptoError;
use crate::keyring::KeyRing;
use crate::keys::{Dek, KeyPurpose};
use aws_lc_rs::{hkdf, hmac};
use common::{Email, TenantId};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlindScope {
    Global,
    Tenant(TenantId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlindKind {
    Email,
    LicenseKey,
    Serial,
    Mac,
    Fingerprint,
    Hwid,
}

impl BlindKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::LicenseKey => "license_key",
            Self::Serial => "serial",
            Self::Mac => "mac",
            Self::Fingerprint => "fingerprint",
            Self::Hwid => "hwid",
        }
    }
}

pub trait BlindIndexer: Send + Sync {
    /// Normalise per kind, then HMAC.
    fn index(&self, kind: BlindKind, scope: BlindScope, raw: &str)
    -> Result<[u8; 32], CryptoError>;
}

const MAX_RAW_LEN: usize = 256;
const HKDF_SALT: &[u8] = b"dsecure|bidx|v1";

/// Per-kind normalisation (SECURITY.md section 3):
/// - Email: `common::Email` (trim, NFKC, lowercase, validated)
/// - LicenseKey / Serial: trim + uppercase
/// - Mac: separators (`:` `-` `.` space) hata ke lowercase hex (12 ya 16 digits)
/// - Fingerprint / Hwid: trim + lowercase
///
/// # Errors
/// `InvalidInput` (value kabhi echo nahi hoti).
pub fn normalise(kind: BlindKind, raw: &str) -> Result<Zeroizing<String>, CryptoError> {
    if raw.len() > MAX_RAW_LEN {
        return Err(CryptoError::InvalidInput("value too long"));
    }
    let out = match kind {
        BlindKind::Email => Email::parse(raw)
            .map(|e| e.as_str().to_owned())
            .map_err(|_| CryptoError::InvalidInput("invalid email"))?,
        BlindKind::LicenseKey | BlindKind::Serial => raw.trim().to_uppercase(),
        BlindKind::Fingerprint | BlindKind::Hwid => raw.trim().to_lowercase(),
        BlindKind::Mac => {
            let s: String = raw
                .trim()
                .chars()
                .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
                .collect::<String>()
                .to_ascii_lowercase();
            if !(s.len() == 12 || s.len() == 16) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(CryptoError::InvalidInput("invalid mac"));
            }
            s
        }
    };
    let out = Zeroizing::new(out);
    if out.is_empty() {
        return Err(CryptoError::InvalidInput("empty value"));
    }
    Ok(out)
}

struct Len32;
impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// Pure derivation + MAC (known-answer testable).
pub(crate) fn compute(
    root: &Dek,
    kind: BlindKind,
    scope: BlindScope,
    normalised: &str,
) -> Result<[u8; 32], CryptoError> {
    let scope_label = match scope {
        BlindScope::Global => "global".to_owned(),
        BlindScope::Tenant(t) => format!("tenant:{}", t.as_uuid().hyphenated()),
    };
    let info = format!("{}|{scope_label}", kind.label());
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT).extract(root.as_bytes());
    let info_parts = [info.as_bytes()];
    let okm = prk
        .expand(&info_parts, Len32)
        .map_err(|_| CryptoError::Internal("hkdf expand"))?;
    let mut k = Zeroizing::new([0u8; 32]);
    okm.fill(&mut k[..])
        .map_err(|_| CryptoError::Internal("hkdf fill"))?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, &k[..]);
    let tag = hmac::sign(&key, normalised.as_bytes());
    tag.as_ref()
        .try_into()
        .map_err(|_| CryptoError::Internal("hmac length"))
}

pub struct HmacBlindIndexer {
    ring: Arc<KeyRing>,
}

impl std::fmt::Debug for HmacBlindIndexer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HmacBlindIndexer")
    }
}

impl HmacBlindIndexer {
    #[must_use]
    pub const fn new(ring: Arc<KeyRing>) -> Self {
        Self { ring }
    }

    /// Tenant ki `BidxTenant` DEK cache mein load/create karo (index sync hai).
    ///
    /// # Errors
    /// Key store/unwrap errors.
    pub async fn prepare_tenant(&self, tenant: TenantId) -> Result<(), CryptoError> {
        self.ring
            .active(KeyPurpose::BidxTenant, Some(tenant))
            .await
            .map(|_| ())
    }
}

impl BlindIndexer for HmacBlindIndexer {
    fn index(
        &self,
        kind: BlindKind,
        scope: BlindScope,
        raw: &str,
    ) -> Result<[u8; 32], CryptoError> {
        let (purpose, tenant) = match scope {
            BlindScope::Global => match kind {
                BlindKind::Email => (KeyPurpose::BidxEmail, None),
                BlindKind::LicenseKey => (KeyPurpose::BidxLicense, None),
                _ => {
                    return Err(CryptoError::InvalidScope(
                        "global scope only for email and license key",
                    ));
                }
            },
            BlindScope::Tenant(t) => (KeyPurpose::BidxTenant, Some(t)),
        };
        let norm = normalise(kind, raw)?;
        let (_, root) = self
            .ring
            .cached_active(purpose, tenant)
            .ok_or(CryptoError::KeyNotLoaded)?;
        compute(&root, kind, scope, &norm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dek_store::InMemoryDekStore;
    use crate::kek_env::{EnvKeyProvider, KeyProvider};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    async fn indexer() -> HmacBlindIndexer {
        let p: Arc<dyn KeyProvider> =
            Arc::new(EnvKeyProvider::new("k1", [("k1", STANDARD.encode([9u8; 32]))]).expect("p"));
        let store = Arc::new(InMemoryDekStore::new());
        KeyRing::ensure_platform_keys(&*p, &*store)
            .await
            .expect("e");
        HmacBlindIndexer::new(Arc::new(
            KeyRing::load_platform(p, store).await.expect("ring"),
        ))
    }

    #[tokio::test]
    async fn email_normalisation() {
        let ix = indexer().await;
        let g = BlindScope::Global;
        let base = ix
            .index(BlindKind::Email, g, "user@example.com")
            .expect("a");
        for v in [
            "USER@Example.COM",
            "  user@example.com\n",
            "\tUser@EXAMPLE.com ",
            // NFKC: fullwidth letters
            "\u{ff55}ser@example.com",
        ] {
            assert_eq!(ix.index(BlindKind::Email, g, v).expect(v), base, "{v:?}");
        }
        assert_ne!(
            base,
            ix.index(BlindKind::Email, g, "user2@example.com")
                .expect("b")
        );
        for bad in ["", "   ", "no-at", "a@b", &"x".repeat(300)] {
            assert!(matches!(
                ix.index(BlindKind::Email, g, bad),
                Err(CryptoError::InvalidInput(_))
            ));
        }
    }

    #[tokio::test]
    async fn mac_serial_license_normalisation() {
        let ix = indexer().await;
        let tid = TenantId::new();
        let t = BlindScope::Tenant(tid);
        ix.prepare_tenant(tid).await.expect("prep");
        let m = |v: &str| ix.index(BlindKind::Mac, t, v);
        let base = m("AA-BB-CC-DD-EE-FF").expect("base");
        for v in [
            "aa:bb:cc:dd:ee:ff",
            "aabbccddeeff",
            "AABB.CCDD.EEFF",
            " aa-bb-cc-dd-ee-ff ",
        ] {
            assert_eq!(m(v).expect(v), base, "{v}");
        }
        assert!(m("aa-bb-cc").is_err());
        assert!(m("zz:bb:cc:dd:ee:ff").is_err());
        assert!(m("").is_err());

        let s = |v: &str| ix.index(BlindKind::Serial, t, v);
        assert_eq!(s(" abc123 ").expect("s"), s("ABC123").expect("s"));
        assert_ne!(s("ABC123").expect("s"), s("ABC124").expect("s"));
        assert!(s("   ").is_err());

        let lk = |v: &str| ix.index(BlindKind::LicenseKey, BlindScope::Global, v);
        assert_eq!(lk(" abcd-1234 ").expect("l"), lk("ABCD-1234").expect("l"));
        // dashes license key ka hissa hain (strip nahi hote)
        assert_ne!(lk("ABCD1234").expect("l"), lk("ABCD-1234").expect("l"));
    }

    #[tokio::test]
    async fn scope_and_kind_separation() {
        let ix = indexer().await;
        let (a, b) = (TenantId::new(), TenantId::new());
        ix.prepare_tenant(a).await.expect("a");
        ix.prepare_tenant(b).await.expect("b");
        let ia = ix
            .index(BlindKind::Serial, BlindScope::Tenant(a), "SN-1")
            .expect("ia");
        let ib = ix
            .index(BlindKind::Serial, BlindScope::Tenant(b), "SN-1")
            .expect("ib");
        assert_ne!(ia, ib, "same value, different tenant");
        assert_eq!(
            ia,
            ix.index(BlindKind::Serial, BlindScope::Tenant(a), "sn-1")
                .expect("again")
        );
        // same value, different kind (same tenant)
        let ih = ix
            .index(BlindKind::Hwid, BlindScope::Tenant(a), "sn-1")
            .expect("h");
        let is = ix
            .index(BlindKind::Fingerprint, BlindScope::Tenant(a), "sn-1")
            .expect("f");
        assert_ne!(ih, is);
        assert_ne!(ia, ih);
        // global vs tenant, same kind
        let g = ix
            .index(BlindKind::LicenseKey, BlindScope::Global, "KEY")
            .expect("g");
        let tn = ix
            .index(BlindKind::LicenseKey, BlindScope::Tenant(a), "KEY")
            .expect("t");
        assert_ne!(g, tn);
        // email global vs license global: alag roots
        let e = ix
            .index(BlindKind::Email, BlindScope::Global, "k@e.com")
            .expect("e");
        assert_ne!(e, g);
    }

    #[tokio::test]
    async fn scope_errors() {
        let ix = indexer().await;
        assert!(matches!(
            ix.index(BlindKind::Serial, BlindScope::Global, "x"),
            Err(CryptoError::InvalidScope(_))
        ));
        assert!(matches!(
            ix.index(BlindKind::Mac, BlindScope::Global, "aabbccddeeff"),
            Err(CryptoError::InvalidScope(_))
        ));
        // tenant key prepare nahi hui
        assert!(matches!(
            ix.index(BlindKind::Serial, BlindScope::Tenant(TenantId::new()), "x"),
            Err(CryptoError::KeyNotLoaded)
        ));
    }

    #[test]
    fn different_roots_give_different_indexes_and_output_is_32_bytes() {
        let r1 = Dek::from_slice(&[1u8; 32]).expect("r1");
        let r2 = Dek::from_slice(&[2u8; 32]).expect("r2");
        let a = compute(&r1, BlindKind::Email, BlindScope::Global, "a@b.co").expect("a");
        let b = compute(&r2, BlindKind::Email, BlindScope::Global, "a@b.co").expect("b");
        assert_ne!(a, b);
        assert_eq!(
            a,
            compute(&r1, BlindKind::Email, BlindScope::Global, "a@b.co").expect("a2")
        );
    }

    /// Known-answer: HKDF/HMAC derivation independently (python hmac) se verify ki gayi; format badla to yeh toot'ta hai.
    #[test]
    fn known_answer_vectors() {
        let root = Dek::from_slice(&[0x42u8; 32]).expect("root");
        let hex = |b: [u8; 32]| crate::keys::hex(&b);
        assert_eq!(
            hex(compute(&root, BlindKind::Email, BlindScope::Global, "a@b.co").expect("a")),
            "42c54921ad62154feedd2f88360a5c79d6e1f38666d824d302e130174c6d7090"
        );
        let t = TenantId::from_uuid(uuid::Uuid::from_u128(7));
        assert_eq!(
            hex(compute(&root, BlindKind::Serial, BlindScope::Tenant(t), "SN-1").expect("b")),
            "2977cbd6228561746760b03786bd0788b8c443f56dffee3cd38f0e6a9f22dca8"
        );
    }

    #[test]
    fn errors_do_not_echo_input() {
        let err = normalise(BlindKind::Email, "secret-person@@bad").expect_err("bad");
        assert!(!format!("{err} {err:?}").contains("secret-person"));
    }
}
