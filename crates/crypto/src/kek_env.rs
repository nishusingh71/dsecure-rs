//! `KeyProvider` trait + `EnvKeyProvider` (dev/test/staging KEK from env, passed in by `config`).
//!
//! Is module mein env access nahi hota: `config` crate (id, base64 key) pairs deta hai.
//!
//! Wrap algorithm (format v2): AES-256-GCM, random 96-bit nonce,
//! AAD = `dsecure|kek-wrap|v2|<kek_ref>|<kid>|<purpose>|<tenant-uuid or platform>`.
//! Wrapped blob isliye sirf apni (kid, purpose, tenant) identity ke liye unwrap hota hai: DB-write attacker
//! ek row ka wrapped DEK doosri row mein paste kare to `UnwrapFailed`. v1 (identity ke bina) reject hota hai
//! (koi `data_keys` rows exist nahi the, isliye compatibility nahi rakhi).
//! Kyun AES-KW nahi: AES-KW mein AAD hota hi nahi; GCM se identity bind hoti hai, aur field encryption wala
//! hi audited primitive (aws-lc-rs) use hota hai; overhead (28 bytes) negligible.
//!
//! Wrapped bytes layout: `0x02 || nonce(12) || ciphertext(32) || tag(16)` = 61 bytes.
//!
//! Future Azure Key Vault provider (plan, implement nahi kiya): Key Vault `wrapKey`/`unwrapKey` mein AAD
//! nahi hota. Isliye ya to (a) DEK ko pehle local AES-256-GCM (identity AAD ke saath, per-wrap random key)
//! se seal karo aur sirf woh local key Key Vault se wrap karo, ya (b) wrapped blob ke saath identity par HMAC
//! commitment rakho (HMAC key KEK se derived/Key Vault sign). Dono mein swap attack `UnwrapFailed` dega.

use crate::devkeys::is_dev_fingerprint;
use crate::error::CryptoError;
use crate::gcm;
use crate::keys::{Dek, WrapContext, WrappedDek};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use zeroize::Zeroizing;

const WRAP_VERSION: u8 = 2;

/// KEK holder: env (dev/test) ya Azure Key Vault (prod). Production dev providers refuse karta hai.
#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {
    fn active_kek_ref(&self) -> &str;
    /// `ctx` wrapped blob ko (kid, purpose, tenant) se bind karta hai.
    async fn wrap(&self, dek: &Dek, ctx: &WrapContext<'_>) -> Result<WrappedDek, CryptoError>;
    /// Wahi `ctx` chahiye jisse wrap hua tha; warna `UnwrapFailed`.
    async fn unwrap(&self, w: &WrappedDek, ctx: &WrapContext<'_>) -> Result<Dek, CryptoError>;
    fn is_dev(&self) -> bool;
}

pub struct EnvKeyProvider {
    active_ref: String,
    keys: HashMap<String, Zeroizing<[u8; 32]>>,
    dev: bool,
}

impl std::fmt::Debug for EnvKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvKeyProvider")
            .field("active", &self.active_ref)
            .field("kek_count", &self.keys.len())
            .field("dev", &self.dev)
            .finish()
    }
}

impl EnvKeyProvider {
    /// `keys`: (id, base64 of exactly 32 bytes). `active_id` un mein se hona chahiye.
    /// `kek_ref` = `env:<id>`.
    ///
    /// # Errors
    /// `InvalidKey` agar base64/length galat, duplicate id, ya active id missing.
    pub fn new<I, K, V>(active_id: &str, keys: I) -> Result<Self, CryptoError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<SecretString>,
    {
        let mut map = HashMap::new();
        let mut dev = false;
        for (id, b64) in keys {
            let id: String = id.into();
            if id.is_empty() || id.bytes().any(|b| b.is_ascii_whitespace() || b == b'|') {
                return Err(CryptoError::InvalidKey(
                    "KEK id empty or contains whitespace/|",
                ));
            }
            let b64: SecretString = b64.into();
            let raw = Zeroizing::new(
                STANDARD
                    .decode(b64.expose_secret().trim())
                    .map_err(|_| CryptoError::InvalidKey("KEK is not valid base64"))?,
            );
            if raw.len() != 32 {
                return Err(CryptoError::InvalidKey("KEK must be 32 bytes"));
            }
            let mut kek = Zeroizing::new([0u8; 32]);
            kek.copy_from_slice(&raw);
            let kek_ref = format!("env:{id}");
            dev |= is_dev_fingerprint(&kek_ref);
            if map.insert(kek_ref, kek).is_some() {
                return Err(CryptoError::InvalidKey("duplicate KEK id"));
            }
        }
        let active_ref = format!("env:{active_id}");
        if !map.contains_key(&active_ref) {
            return Err(CryptoError::InvalidKey("active KEK id not in KEK set"));
        }
        Ok(Self {
            active_ref,
            keys: map,
            dev,
        })
    }

    fn kek(&self, kek_ref: &str) -> Result<&[u8; 32], CryptoError> {
        self.keys
            .get(kek_ref)
            .map(|k| &**k)
            .ok_or_else(|| CryptoError::UnknownKek(kek_ref.to_owned()))
    }

    fn aad(kek_ref: &str, ctx: &WrapContext<'_>) -> Vec<u8> {
        let tenant = ctx.tenant.map_or_else(
            || "platform".to_owned(),
            |t| t.as_uuid().hyphenated().to_string(),
        );
        format!(
            "dsecure|kek-wrap|v{WRAP_VERSION}|{kek_ref}|{}|{}|{tenant}",
            ctx.kid,
            ctx.purpose.as_str()
        )
        .into_bytes()
    }
}

#[async_trait::async_trait]
impl KeyProvider for EnvKeyProvider {
    fn active_kek_ref(&self) -> &str {
        &self.active_ref
    }

    async fn wrap(&self, dek: &Dek, ctx: &WrapContext<'_>) -> Result<WrappedDek, CryptoError> {
        let kek = self.kek(&self.active_ref)?;
        let nonce = gcm::random_nonce()?;
        let sealed = gcm::seal(
            kek,
            nonce,
            &Self::aad(&self.active_ref, ctx),
            dek.as_bytes(),
        )?;
        let mut bytes = Vec::with_capacity(1 + gcm::NONCE + sealed.len());
        bytes.push(WRAP_VERSION);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&sealed);
        Ok(WrappedDek {
            kek_ref: self.active_ref.clone(),
            bytes,
        })
    }

    async fn unwrap(&self, w: &WrappedDek, ctx: &WrapContext<'_>) -> Result<Dek, CryptoError> {
        let kek = self.kek(&w.kek_ref)?;
        let (Some(&ver), Some(rest)) = (w.bytes.first(), w.bytes.get(1..)) else {
            return Err(CryptoError::UnwrapFailed);
        };
        if ver != WRAP_VERSION || rest.len() < gcm::NONCE + gcm::TAG {
            return Err(CryptoError::UnwrapFailed);
        }
        let (nonce, ct) = rest.split_at(gcm::NONCE);
        let nonce: [u8; gcm::NONCE] = nonce.try_into().map_err(|_| CryptoError::UnwrapFailed)?;
        let plain = gcm::open(kek, nonce, &Self::aad(&w.kek_ref, ctx), ct)
            .map_err(|_| CryptoError::UnwrapFailed)?;
        Dek::from_slice(&plain).map_err(|_| CryptoError::UnwrapFailed)
    }

    fn is_dev(&self) -> bool {
        self.dev
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devkeys::{dev_kek_id, generate_kek_b64};
    use crate::keys::{KeyPurpose, Kid};
    use common::TenantId;

    fn b64(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }

    fn kid(s: &str) -> Kid {
        Kid::parse(s).expect("kid")
    }

    fn ctx(kid: &Kid, purpose: KeyPurpose, tenant: Option<TenantId>) -> WrapContext<'_> {
        WrapContext {
            kid,
            purpose,
            tenant,
        }
    }

    #[tokio::test]
    async fn wrap_unwrap_round_trip() {
        let p = EnvKeyProvider::new("k1", [("k1", b64(1))]).expect("provider");
        let dek = Dek::generate().expect("dek");
        let k = kid("p-id-0001");
        let c = ctx(&k, KeyPurpose::Identity, None);
        let w = p.wrap(&dek, &c).await.expect("wrap");
        assert_eq!(w.kek_ref, "env:k1");
        assert_eq!(w.bytes.len(), 61);
        assert_eq!(w.bytes[0], 2);
        let back = p.unwrap(&w, &c).await.expect("unwrap");
        assert_eq!(back.as_bytes(), dek.as_bytes());
        // random nonce: do wrap alag
        let w2 = p.wrap(&dek, &c).await.expect("wrap2");
        assert_ne!(w.bytes, w2.bytes);
    }

    #[tokio::test]
    async fn tamper_and_wrong_kek_fail() {
        let p = EnvKeyProvider::new("k1", [("k1", b64(1)), ("k2", b64(2))]).expect("provider");
        let dek = Dek::generate().expect("dek");
        let k = kid("p-id-0001");
        let c = ctx(&k, KeyPurpose::Identity, None);
        let w = p.wrap(&dek, &c).await.expect("wrap");
        for i in 0..w.bytes.len() {
            let mut t = w.clone();
            t.bytes[i] ^= 0x01;
            assert!(
                matches!(p.unwrap(&t, &c).await, Err(CryptoError::UnwrapFailed)),
                "byte {i}"
            );
        }
        // blob ko dusri KEK label ke saath chalao
        let relabeled = WrappedDek {
            kek_ref: "env:k2".into(),
            bytes: w.bytes.clone(),
        };
        assert!(p.unwrap(&relabeled, &c).await.is_err());
        let unknown = WrappedDek {
            kek_ref: "env:nope".into(),
            bytes: w.bytes,
        };
        assert!(matches!(
            p.unwrap(&unknown, &c).await,
            Err(CryptoError::UnknownKek(_))
        ));
        let short = WrappedDek {
            kek_ref: "env:k1".into(),
            bytes: vec![],
        };
        assert!(p.unwrap(&short, &c).await.is_err());
    }

    /// CR-1: wrapped bytes swap (kid / tenant / purpose) = UnwrapFailed.
    #[tokio::test]
    async fn swapped_wrapped_bytes_fail_for_kid_tenant_purpose() {
        let p = EnvKeyProvider::new("k1", [("k1", b64(1))]).expect("provider");
        let (t1, t2) = (TenantId::new(), TenantId::new());
        let (k1, k2) = (kid("t-aaaa-pii-0001"), kid("t-aaaa-pii-0002"));
        let dek = Dek::generate().expect("dek");
        let w = p
            .wrap(&dek, &ctx(&k1, KeyPurpose::Pii, Some(t1)))
            .await
            .expect("wrap");
        // sahi context chalta hai
        assert!(
            p.unwrap(&w, &ctx(&k1, KeyPurpose::Pii, Some(t1)))
                .await
                .is_ok()
        );
        // dusra kid
        assert!(matches!(
            p.unwrap(&w, &ctx(&k2, KeyPurpose::Pii, Some(t1))).await,
            Err(CryptoError::UnwrapFailed)
        ));
        // dusra tenant
        assert!(matches!(
            p.unwrap(&w, &ctx(&k1, KeyPurpose::Pii, Some(t2))).await,
            Err(CryptoError::UnwrapFailed)
        ));
        // tenant ke bajay platform
        assert!(matches!(
            p.unwrap(&w, &ctx(&k1, KeyPurpose::Pii, None)).await,
            Err(CryptoError::UnwrapFailed)
        ));
        // dusra purpose
        assert!(matches!(
            p.unwrap(&w, &ctx(&k1, KeyPurpose::Reports, Some(t1))).await,
            Err(CryptoError::UnwrapFailed)
        ));
    }

    /// v1 format (identity ke bina) reject.
    #[tokio::test]
    async fn v1_blob_rejected() {
        let p = EnvKeyProvider::new("k1", [("k1", b64(1))]).expect("provider");
        let k = kid("p-id-0001");
        let c = ctx(&k, KeyPurpose::Identity, None);
        let dek = Dek::generate().expect("dek");
        let mut w = p.wrap(&dek, &c).await.expect("wrap");
        w.bytes[0] = 1;
        assert!(matches!(
            p.unwrap(&w, &c).await,
            Err(CryptoError::UnwrapFailed)
        ));
    }

    #[test]
    fn constructor_validates() {
        assert!(EnvKeyProvider::new("k1", [("k1", "!!!notb64")]).is_err());
        assert!(EnvKeyProvider::new("k1", [("k1", STANDARD.encode([0u8; 16]))]).is_err());
        assert!(EnvKeyProvider::new("missing", [("k1", b64(1))]).is_err());
        assert!(EnvKeyProvider::new("k1", [("k1", b64(1)), ("k1", b64(2))]).is_err());
        assert!(EnvKeyProvider::new("k1", Vec::<(String, String)>::new()).is_err());
    }

    #[test]
    fn error_does_not_leak_key() {
        let secret = b64(7);
        let err = EnvKeyProvider::new("k1", [("k1", format!("{secret}AA"))]).expect_err("bad");
        assert!(!format!("{err} {err:?}").contains(&secret));
    }

    #[test]
    fn dev_detection() {
        let prod = EnvKeyProvider::new("k1", [("k1", b64(1))]).expect("p");
        assert!(!prod.is_dev());
        let id = dev_kek_id().expect("id");
        let dev = EnvKeyProvider::new(
            &id,
            [(id.clone(), generate_kek_b64().expect("kek").to_string())],
        )
        .expect("d");
        assert!(dev.is_dev());
        assert!(is_dev_fingerprint(dev.active_kek_ref()));
        // purani dev KEK sirf decrypt ke liye bhi ho to dev hi maana jaayega
        let mixed =
            EnvKeyProvider::new("k1", [("k1".to_owned(), b64(1)), (id, b64(2))]).expect("m");
        assert!(mixed.is_dev());
    }

    #[test]
    fn debug_has_no_key_bytes() {
        let p = EnvKeyProvider::new("k1", [("k1", b64(1))]).expect("p");
        let s = format!("{p:?}");
        assert!(!s.contains(&b64(1)) && !s.contains("AQEB"));
    }
}
