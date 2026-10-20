//! `FieldEncryptor`: AES-256-GCM field encryption (envelope: `envelope_format`).
//!
//! Nonce: fresh random 96-bit har encrypt par. AAD: version, kid, table.column, tenant, row id.
//! Decrypt fail closed: koi bhi problem (tag, AAD, scope, malformed) = error; plaintext kabhi partial nahi.

use crate::envelope_format as env;
use crate::error::CryptoError;
use crate::gcm;
use crate::keyring::KeyRing;
use crate::keys::{Dek, KeyPurpose, Kid};
use common::TenantId;
use std::marker::PhantomData;
use std::sync::Arc;
use zeroize::Zeroizing;

pub struct FieldContext<'a> {
    pub table: &'static str,
    pub column: &'static str,
    pub tenant: Option<TenantId>,
    pub row_id: uuid::Uuid,
    pub purpose: KeyPurpose,
    pub _p: PhantomData<&'a ()>,
}

impl FieldContext<'_> {
    #[must_use]
    pub const fn new(
        table: &'static str,
        column: &'static str,
        tenant: Option<TenantId>,
        row_id: uuid::Uuid,
        purpose: KeyPurpose,
    ) -> Self {
        Self {
            table,
            column,
            tenant,
            row_id,
            purpose,
            _p: PhantomData,
        }
    }

    fn validate(&self) -> Result<(), CryptoError> {
        if self.purpose.is_tenant_scoped() != self.tenant.is_some() {
            return Err(CryptoError::InvalidContext(
                "tenant must be set exactly for tenant-scoped purposes",
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for FieldContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldContext")
            .field("table", &self.table)
            .field("column", &self.column)
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
pub trait FieldEncryptor: Send + Sync {
    async fn encrypt(
        &self,
        plaintext: &[u8],
        ctx: &FieldContext<'_>,
    ) -> Result<Vec<u8>, CryptoError>;
    async fn decrypt(
        &self,
        stored: &[u8],
        ctx: &FieldContext<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
    /// Kid jo stored value ke header mein hai (re-encrypt job ke liye); AEAD verify nahi karta.
    fn kid_of(&self, stored: &[u8]) -> Result<Kid, CryptoError>;
}

/// Envelope seal with an explicit key (KeyRing-independent; tests ise direct use karte hain).
pub(crate) fn seal_with(
    dek: &Dek,
    kid: &Kid,
    ctx: &FieldContext<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = gcm::random_nonce()?;
    seal_with_nonce(dek, kid, ctx, plaintext, nonce)
}

pub(crate) fn seal_with_nonce(
    dek: &Dek,
    kid: &Kid,
    ctx: &FieldContext<'_>,
    plaintext: &[u8],
    nonce: [u8; gcm::NONCE],
) -> Result<Vec<u8>, CryptoError> {
    let aad = env::aad(kid, ctx.table, ctx.column, ctx.tenant, ctx.row_id)?;
    let mut out = env::header(kid, &nonce)?;
    out.extend_from_slice(&gcm::seal(dek.as_bytes(), nonce, &aad, plaintext)?);
    Ok(out)
}

/// Envelope open with an explicit key. AAD stored header ke kid se banta hai.
pub(crate) fn open_with(
    dek: &Dek,
    ctx: &FieldContext<'_>,
    stored: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let e = env::parse(stored)?;
    let aad = env::aad(&e.kid, ctx.table, ctx.column, ctx.tenant, ctx.row_id)
        .map_err(|_| CryptoError::DecryptFailed)?;
    gcm::open(dek.as_bytes(), e.nonce, &aad, e.ct_and_tag)
}

pub struct AesGcmFieldEncryptor {
    ring: Arc<KeyRing>,
}

impl std::fmt::Debug for AesGcmFieldEncryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesGcmFieldEncryptor")
    }
}

impl AesGcmFieldEncryptor {
    #[must_use]
    pub const fn new(ring: Arc<KeyRing>) -> Self {
        Self { ring }
    }
}

#[async_trait::async_trait]
impl FieldEncryptor for AesGcmFieldEncryptor {
    async fn encrypt(
        &self,
        plaintext: &[u8],
        ctx: &FieldContext<'_>,
    ) -> Result<Vec<u8>, CryptoError> {
        ctx.validate()?;
        let (kid, dek) = self.ring.active(ctx.purpose, ctx.tenant).await?;
        seal_with(&dek, &kid, ctx, plaintext)
    }

    async fn decrypt(
        &self,
        stored: &[u8],
        ctx: &FieldContext<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        ctx.validate()?;
        let e = env::parse(stored)?;
        // Kid ka purpose/tenant context se match hona chahiye (cross-tenant guard), phir AEAD.
        let dek = self
            .ring
            .get_scoped(&e.kid, ctx.purpose, ctx.tenant)
            .await?;
        open_with(&dek, ctx, stored)
    }

    fn kid_of(&self, stored: &[u8]) -> Result<Kid, CryptoError> {
        env::parse(stored).map(|e| e.kid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dek_store::InMemoryDekStore;
    use crate::kek_env::{EnvKeyProvider, KeyProvider};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use std::collections::HashSet;

    async fn setup() -> (Arc<KeyRing>, AesGcmFieldEncryptor) {
        let p: Arc<dyn KeyProvider> = Arc::new(
            EnvKeyProvider::new("k1", [("k1", STANDARD.encode([5u8; 32]))]).expect("provider"),
        );
        let store = Arc::new(InMemoryDekStore::new());
        KeyRing::ensure_platform_keys(&*p, &*store)
            .await
            .expect("ensure");
        let ring = Arc::new(KeyRing::load_platform(p, store).await.expect("ring"));
        (ring.clone(), AesGcmFieldEncryptor::new(ring))
    }

    fn ctx(t: Option<TenantId>, row: uuid::Uuid) -> FieldContext<'static> {
        FieldContext::new(
            "members",
            "email_enc",
            t,
            row,
            if t.is_some() {
                KeyPurpose::Pii
            } else {
                KeyPurpose::Identity
            },
        )
    }

    #[tokio::test]
    async fn round_trip_tenant_and_platform() {
        let (_, enc) = setup().await;
        let t = TenantId::new();
        let row = uuid::Uuid::now_v7();
        for tenant in [Some(t), None] {
            let c = ctx(tenant, row);
            for pt in [&b""[..], b"a@b.com", &[0u8; 5000]] {
                let ct = enc.encrypt(pt, &c).await.expect("enc");
                assert_eq!(ct[0], 1);
                assert_eq!(ct[1], 0);
                assert!(
                    pt.len() < 8 || !ct.windows(8).any(|w| w == &pt[..8]),
                    "ciphertext mein plaintext nahi hona chahiye"
                );
                let back = enc.decrypt(&ct, &c).await.expect("dec");
                assert_eq!(back.as_slice(), pt);
                assert!(enc.kid_of(&ct).expect("kid").as_str().len() <= 32);
            }
        }
    }

    #[tokio::test]
    async fn tenant_scope_must_match_purpose() {
        let (_, enc) = setup().await;
        let row = uuid::Uuid::now_v7();
        let bad = FieldContext::new("t", "c", None, row, KeyPurpose::Pii);
        assert!(enc.encrypt(b"x", &bad).await.is_err());
        let bad = FieldContext::new("t", "c", Some(TenantId::new()), row, KeyPurpose::Identity);
        assert!(enc.encrypt(b"x", &bad).await.is_err());
    }

    /// T-C1: har byte region tamper = error.
    #[tokio::test]
    async fn tamper_every_region_fails() {
        let (_, enc) = setup().await;
        let t = TenantId::new();
        let row = uuid::Uuid::now_v7();
        let c = ctx(Some(t), row);
        let ct = enc.encrypt(b"secret value", &c).await.expect("enc");
        let kid_len = usize::from(ct[2]);
        let nonce_at = 3 + kid_len;
        let tag_at = ct.len() - 1;
        // version, flags, kid length, kid bytes, nonce, ciphertext, tag: har byte flip
        for i in 0..ct.len() {
            let mut t2 = ct.clone();
            t2[i] ^= 0x01;
            assert!(
                enc.decrypt(&t2, &c).await.is_err(),
                "byte {i} tamper accepted"
            );
        }
        // named regions bhi (documentation of coverage)
        for i in [0, 1, 2, 3, nonce_at, nonce_at + 11, nonce_at + 12, tag_at] {
            let mut t2 = ct.clone();
            t2[i] ^= 0x80;
            assert!(enc.decrypt(&t2, &c).await.is_err());
        }
        // truncation / extension
        assert!(enc.decrypt(&ct[..ct.len() - 1], &c).await.is_err());
        let mut longer = ct.clone();
        longer.push(0);
        assert!(enc.decrypt(&longer, &c).await.is_err());
        // untouched still ok
        assert!(enc.decrypt(&ct, &c).await.is_ok());
    }

    /// AAD binding: table, column, tenant, row alag-alag; explicit key se (scope guard bypass) taaki AAD hi test ho.
    #[tokio::test]
    async fn aad_binds_table_column_tenant_row_at_aead_level() {
        let dek = Dek::generate().expect("dek");
        let kid = Kid::parse("t-test-pii-0001").expect("kid");
        let t = TenantId::new();
        let row = uuid::Uuid::now_v7();
        let c = FieldContext::new("members", "email_enc", Some(t), row, KeyPurpose::Pii);
        let ct = seal_with(&dek, &kid, &c, b"v").expect("seal");
        assert!(open_with(&dek, &c, &ct).is_ok());
        let variants = [
            FieldContext::new("other", "email_enc", Some(t), row, KeyPurpose::Pii),
            FieldContext::new("members", "other", Some(t), row, KeyPurpose::Pii),
            FieldContext::new(
                "members",
                "email_enc",
                Some(TenantId::new()),
                row,
                KeyPurpose::Pii,
            ),
            FieldContext::new("members", "email_enc", None, row, KeyPurpose::Pii),
            FieldContext::new(
                "members",
                "email_enc",
                Some(t),
                uuid::Uuid::now_v7(),
                KeyPurpose::Pii,
            ),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert!(
                matches!(open_with(&dek, v, &ct), Err(CryptoError::DecryptFailed)),
                "variant {i}"
            );
        }
        // alag key
        assert!(open_with(&Dek::generate().expect("d"), &c, &ct).is_err());
        // AAD ka version component: v2 AAD se seal kiya hua v1 context se open nahi hota
        let nonce = [3u8; 12];
        let aad_v2 =
            env::aad_for_version(2, &kid, "members", "email_enc", Some(t), row).expect("aad");
        let mut forged = env::header(&kid, &nonce).expect("h");
        forged.extend_from_slice(&gcm::seal(dek.as_bytes(), nonce, &aad_v2, b"v").expect("s"));
        assert!(open_with(&dek, &c, &forged).is_err());
    }

    /// Public API level: doosre tenant ka context (aur uski DEK) se decrypt = error.
    #[tokio::test]
    async fn wrong_tenant_fails_via_api() {
        let (ring, enc) = setup().await;
        let (a, b) = (TenantId::new(), TenantId::new());
        let row = uuid::Uuid::now_v7();
        let ca = ctx(Some(a), row);
        let cb = ctx(Some(b), row);
        let ct = enc.encrypt(b"tenant a data", &ca).await.expect("enc");
        assert!(matches!(
            enc.decrypt(&ct, &cb).await,
            Err(CryptoError::KeyScopeMismatch)
        ));
        // Tenant B ki DEK ke saath hi forged envelope (B ki kid, A ka ciphertext) bhi fail
        let (kid_b, _) = ring.active(KeyPurpose::Pii, Some(b)).await.expect("b");
        let kid_a = enc.kid_of(&ct).expect("kid");
        assert_ne!(kid_a, kid_b);
        let mut forged = ct.clone();
        forged.splice(3..3 + kid_a.as_str().len(), kid_b.as_str().bytes());
        forged[2] = u8::try_from(kid_b.as_str().len()).expect("len");
        assert!(enc.decrypt(&forged, &cb).await.is_err());
        // purpose swap: Pii ciphertext ko Reports context se
        let cr = FieldContext::new("members", "email_enc", Some(a), row, KeyPurpose::Reports);
        assert!(enc.decrypt(&ct, &cr).await.is_err());
        // row swap
        assert!(
            enc.decrypt(&ct, &ctx(Some(a), uuid::Uuid::now_v7()))
                .await
                .is_err()
        );
        assert!(enc.decrypt(&ct, &ca).await.is_ok());
    }

    #[tokio::test]
    async fn crypto_shredding_makes_data_unreadable() {
        let p: Arc<dyn KeyProvider> = Arc::new(
            EnvKeyProvider::new("k1", [("k1", STANDARD.encode([5u8; 32]))]).expect("provider"),
        );
        let store = Arc::new(InMemoryDekStore::new());
        KeyRing::ensure_platform_keys(&*p, &*store)
            .await
            .expect("ensure");
        let ring = Arc::new(
            KeyRing::load_platform(p, store.clone())
                .await
                .expect("ring"),
        );
        let enc = AesGcmFieldEncryptor::new(ring.clone());
        let t = TenantId::new();
        let c = ctx(Some(t), uuid::Uuid::now_v7());
        let ct = enc.encrypt(b"x", &c).await.expect("enc");
        store.destroy(&enc.kid_of(&ct).expect("kid")).await;
        ring.clear_cache();
        assert!(matches!(
            enc.decrypt(&ct, &c).await,
            Err(CryptoError::KeyNotFound(_))
        ));
    }

    /// 10k encryptions: nonces unique, aur ek hi value ke ciphertext alag.
    #[tokio::test]
    async fn ten_thousand_nonces_unique() {
        let (_, enc) = setup().await;
        let c = ctx(Some(TenantId::new()), uuid::Uuid::now_v7());
        let mut nonces = HashSet::new();
        let mut cts = HashSet::new();
        for _ in 0..10_000 {
            let ct = enc.encrypt(b"same", &c).await.expect("enc");
            let e = env::parse(&ct).expect("parse");
            assert!(nonces.insert(e.nonce), "nonce repeat");
            assert!(cts.insert(ct));
        }
        assert_eq!(nonces.len(), 10_000);
    }

    #[tokio::test]
    async fn decrypt_garbage_never_panics_and_errors() {
        let (_, enc) = setup().await;
        let c = ctx(None, uuid::Uuid::now_v7());
        for g in [
            &b""[..],
            b"\x01",
            b"\x01\x00\x01",
            b"not a ciphertext at all, definitely not",
        ] {
            assert!(enc.decrypt(g, &c).await.is_err());
        }
    }

    #[tokio::test]
    async fn errors_do_not_contain_plaintext_or_key() {
        let (_, enc) = setup().await;
        let c = ctx(Some(TenantId::new()), uuid::Uuid::now_v7());
        let ct = enc.encrypt(b"TOP-SECRET-PLAINTEXT", &c).await.expect("enc");
        let mut bad = ct.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let err = enc.decrypt(&bad, &c).await.expect_err("fail");
        let s = format!("{err} {err:?}");
        assert!(!s.contains("TOP-SECRET"));
    }
}
