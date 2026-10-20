//! `KeyRing`: kid -> DEK resolution with bounded cache, pinned platform DEKs, lazy tenant DEKs.
//!
//! - Platform DEKs (`KeyPurpose::PLATFORM`) startup par load hoti hain aur pinned rehti hain (eviction nahi).
//!   `load_platform` fail closed: koi active platform DEK missing/unwrappable ho to error (API start nahi hota).
//! - Tenant DEKs bounded `moka` cache (default `MAX_TENANT_DEKS_CACHED` = 5000) mein; TTL 15 min taaki
//!   rotation / crypto-shred doosre instances par bhi bounded time mein asar kare.
//! - Tenant DEK pehli use par lazily banti hai (creation ek gate se serialise; DB unique index final arbiter).

use crate::dek_store::DekStore;
use crate::error::CryptoError;
use crate::kek_env::KeyProvider;
use crate::keys::{Dek, KeyPurpose, Kid, WrapContext};
use common::TenantId;
use moka::sync::Cache;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

pub const DEFAULT_MAX_TENANT_DEKS_CACHED: u64 = 5000;
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);

/// Resolved key + uska metadata (scope check ke liye).
pub struct KeyEntry {
    pub kid: Kid,
    pub purpose: KeyPurpose,
    pub tenant: Option<TenantId>,
    pub dek: Arc<Dek>,
}

impl std::fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEntry")
            .field("kid", &self.kid)
            .field("purpose", &self.purpose)
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

pub struct KeyRing {
    provider: Arc<dyn KeyProvider>,
    store: Arc<dyn DekStore>,
    platform_active: HashMap<KeyPurpose, Arc<KeyEntry>>,
    pinned: HashMap<Kid, Arc<KeyEntry>>,
    by_kid: Cache<Kid, Arc<KeyEntry>>,
    active_cache: Cache<(KeyPurpose, TenantId), Arc<KeyEntry>>,
    create_gate: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("platform_keys", &self.platform_active.len())
            .field("cached_kids", &self.by_kid.entry_count())
            .finish_non_exhaustive()
    }
}

impl KeyRing {
    /// Platform DEKs load karo (fail closed) with default cache size.
    ///
    /// # Errors
    /// `NoActiveKey` agar koi platform purpose ki active DEK nahi; unwrap/store errors propagate.
    pub async fn load_platform(
        provider: Arc<dyn KeyProvider>,
        store: Arc<dyn DekStore>,
    ) -> Result<Self, CryptoError> {
        Self::load_platform_with(provider, store, DEFAULT_MAX_TENANT_DEKS_CACHED).await
    }

    /// Same, explicit cache bound (`MAX_TENANT_DEKS_CACHED`).
    ///
    /// # Errors
    /// See [`KeyRing::load_platform`].
    pub async fn load_platform_with(
        provider: Arc<dyn KeyProvider>,
        store: Arc<dyn DekStore>,
        max_cached: u64,
    ) -> Result<Self, CryptoError> {
        let mut platform_active = HashMap::new();
        let mut pinned = HashMap::new();
        for p in KeyPurpose::PLATFORM {
            let (kid, wrapped) = store
                .active(p, None)
                .await?
                .ok_or(CryptoError::NoActiveKey(p))?;
            let dek = provider
                .unwrap(
                    &wrapped,
                    &WrapContext {
                        kid: &kid,
                        purpose: p,
                        tenant: None,
                    },
                )
                .await?;
            let entry = Arc::new(KeyEntry {
                kid: kid.clone(),
                purpose: p,
                tenant: None,
                dek: Arc::new(dek),
            });
            pinned.insert(kid, Arc::clone(&entry));
            platform_active.insert(p, entry);
        }
        Ok(Self {
            provider,
            store,
            platform_active,
            pinned,
            by_kid: Cache::builder()
                .max_capacity(max_cached)
                .time_to_live(CACHE_TTL)
                .build(),
            active_cache: Cache::builder()
                .max_capacity(max_cached)
                .time_to_live(CACHE_TTL)
                .build(),
            create_gate: tokio::sync::Mutex::new(()),
        })
    }

    /// First-run/dev/test bootstrap: jo platform DEKs missing hain wo banao (production startup yeh
    /// nahi chalata; wo `load_platform` fail-closed hi rakhta hai). Returns created count.
    ///
    /// # Errors
    /// Rng/wrap/store errors.
    pub async fn ensure_platform_keys(
        provider: &dyn KeyProvider,
        store: &dyn DekStore,
    ) -> Result<usize, CryptoError> {
        let mut created = 0;
        for p in KeyPurpose::PLATFORM {
            if store.active(p, None).await?.is_none() {
                create_dek(provider, store, p, None).await?;
                created += 1;
            }
        }
        Ok(created)
    }

    /// Active DEK for writes. Platform purpose => `tenant` None; tenant purpose => `Some` (lazily created).
    ///
    /// # Errors
    /// `InvalidContext` (purpose/tenant mismatch), store/unwrap errors.
    pub async fn active(
        &self,
        p: KeyPurpose,
        tenant: Option<TenantId>,
    ) -> Result<(Kid, Arc<Dek>), CryptoError> {
        let e = self.active_entry(p, tenant).await?;
        Ok((e.kid.clone(), Arc::clone(&e.dek)))
    }

    pub(crate) async fn active_entry(
        &self,
        p: KeyPurpose,
        tenant: Option<TenantId>,
    ) -> Result<Arc<KeyEntry>, CryptoError> {
        match (p.is_tenant_scoped(), tenant) {
            (false, None) => self
                .platform_active
                .get(&p)
                .cloned()
                .ok_or(CryptoError::NoActiveKey(p)),
            (true, Some(t)) => {
                if let Some(e) = self.active_cache.get(&(p, t)) {
                    return Ok(e);
                }
                if let Some(e) = self.load_active_tenant(p, t).await? {
                    return Ok(e);
                }
                // Lazy create: gate ke andar dubara check (race), phir banao.
                let _gate = self.create_gate.lock().await;
                if let Some(e) = self.load_active_tenant(p, t).await? {
                    return Ok(e);
                }
                let (kid, dek) = match create_dek(&*self.provider, &*self.store, p, Some(t)).await {
                    Ok(v) => v,
                    Err(CryptoError::Conflict) => {
                        // Doosre instance ne bana di; wahi use karo.
                        return self
                            .load_active_tenant(p, t)
                            .await?
                            .ok_or(CryptoError::NoActiveKey(p));
                    }
                    Err(e) => return Err(e),
                };
                let entry = Arc::new(KeyEntry {
                    kid: kid.clone(),
                    purpose: p,
                    tenant: Some(t),
                    dek: Arc::new(dek),
                });
                self.by_kid.insert(kid, Arc::clone(&entry));
                self.active_cache.insert((p, t), Arc::clone(&entry));
                Ok(entry)
            }
            (false, Some(_)) => Err(CryptoError::InvalidContext(
                "platform purpose must not have a tenant",
            )),
            (true, None) => Err(CryptoError::InvalidContext("tenant purpose needs a tenant")),
        }
    }

    async fn load_active_tenant(
        &self,
        p: KeyPurpose,
        t: TenantId,
    ) -> Result<Option<Arc<KeyEntry>>, CryptoError> {
        let Some((kid, wrapped)) = self.store.active(p, Some(t)).await? else {
            return Ok(None);
        };
        let dek = self
            .provider
            .unwrap(
                &wrapped,
                &WrapContext {
                    kid: &kid,
                    purpose: p,
                    tenant: Some(t),
                },
            )
            .await?;
        let entry = Arc::new(KeyEntry {
            kid: kid.clone(),
            purpose: p,
            tenant: Some(t),
            dek: Arc::new(dek),
        });
        self.by_kid.insert(kid, Arc::clone(&entry));
        self.active_cache.insert((p, t), Arc::clone(&entry));
        Ok(Some(entry))
    }

    /// Kid se DEK (decrypt path; rotated/decrypt-only keys bhi).
    ///
    /// # Errors
    /// `KeyNotFound`, unwrap/store errors.
    pub async fn get(&self, kid: &Kid) -> Result<Arc<Dek>, CryptoError> {
        Ok(Arc::clone(&self.entry(kid).await?.dek))
    }

    pub(crate) async fn entry(&self, kid: &Kid) -> Result<Arc<KeyEntry>, CryptoError> {
        if let Some(e) = self.pinned.get(kid) {
            return Ok(Arc::clone(e));
        }
        if let Some(e) = self.by_kid.get(kid) {
            return Ok(e);
        }
        let (purpose, tenant, wrapped) = self
            .store
            .by_kid(kid)
            .await?
            .ok_or_else(|| CryptoError::KeyNotFound(kid.clone()))?;
        // Store ka (purpose, tenant) hi unwrap context hai: swapped rows yahin UnwrapFailed dete hain.
        let dek = self
            .provider
            .unwrap(
                &wrapped,
                &WrapContext {
                    kid,
                    purpose,
                    tenant,
                },
            )
            .await?;
        let entry = Arc::new(KeyEntry {
            kid: kid.clone(),
            purpose,
            tenant,
            dek: Arc::new(dek),
        });
        self.by_kid.insert(kid.clone(), Arc::clone(&entry));
        Ok(entry)
    }

    /// Decrypt path: kid resolve + verify ki DEK ka purpose/tenant caller ke context ke barabar hai.
    /// Isse ek tenant ke kid se doosre tenant ka data khulna (confused deputy) pehle hi ruk jaata hai.
    ///
    /// # Errors
    /// `KeyScopeMismatch` plus `get` errors.
    pub(crate) async fn get_scoped(
        &self,
        kid: &Kid,
        purpose: KeyPurpose,
        tenant: Option<TenantId>,
    ) -> Result<Arc<Dek>, CryptoError> {
        let e = self.entry(kid).await?;
        if e.purpose != purpose || e.tenant != tenant {
            return Err(CryptoError::KeyScopeMismatch);
        }
        Ok(Arc::clone(&e.dek))
    }

    /// Sync lookup (blind index jaise sync paths ke liye): sirf cache/pinned se, store nahi.
    #[must_use]
    pub fn cached_active(
        &self,
        p: KeyPurpose,
        tenant: Option<TenantId>,
    ) -> Option<(Kid, Arc<Dek>)> {
        let e = match tenant {
            None => self.platform_active.get(&p).cloned(),
            Some(t) => self.active_cache.get(&(p, t)),
        }?;
        Some((e.kid.clone(), Arc::clone(&e.dek)))
    }

    /// Active DEK se HKDF-SHA256 subkey: info = `"dsecure|subkey|v1|" label "|" purpose "|" tenant-or-platform`.
    /// Deterministic aur label/purpose/tenant se separated; raw DEK kabhi bahar nahi aati.
    ///
    /// **Rotation:** active DEK badalne par subkey badal jaati hai. Jise rotation ke baad bhi stability chahiye
    /// (e.g. cursor HMAC) woh kid pin kare aur [`KeyRing::derive_subkey_for_kid`] use kare.
    ///
    /// # Errors
    /// `active` ke errors; `Internal` agar HKDF fail.
    pub async fn derive_subkey(
        &self,
        purpose: KeyPurpose,
        tenant: Option<TenantId>,
        label: &'static str,
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let e = self.active_entry(purpose, tenant).await?;
        derive(&e, label)
    }

    /// Pinned kid (decrypt-only/rotated bhi) se subkey; purpose/tenant kid ke store metadata se aate hain.
    ///
    /// # Errors
    /// `KeyNotFound`, unwrap/store errors, `Internal`.
    pub async fn derive_subkey_for_kid(
        &self,
        kid: &Kid,
        label: &'static str,
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let e = self.entry(kid).await?;
        derive(&e, label)
    }

    /// Cache saaf (rotation/shred ke baad turant asar chahiye ho to). Pinned platform keys rehti hain.
    pub fn clear_cache(&self) {
        self.by_kid.invalidate_all();
        self.active_cache.invalidate_all();
    }
}

struct Len32;
impl aws_lc_rs::hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

fn derive(e: &KeyEntry, label: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let tenant = e.tenant.map_or_else(
        || "platform".to_owned(),
        |t| t.as_uuid().hyphenated().to_string(),
    );
    let info = format!("dsecure|subkey|v1|{label}|{}|{tenant}", e.purpose.as_str());
    let prk = aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA256, b"dsecure|subkey|v1")
        .extract(e.dek.as_bytes());
    let parts = [info.as_bytes()];
    let okm = prk
        .expand(&parts, Len32)
        .map_err(|_| CryptoError::Internal("hkdf expand"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    okm.fill(&mut out[..])
        .map_err(|_| CryptoError::Internal("hkdf fill"))?;
    Ok(out)
}

async fn create_dek(
    provider: &dyn KeyProvider,
    store: &dyn DekStore,
    p: KeyPurpose,
    tenant: Option<TenantId>,
) -> Result<(Kid, Dek), CryptoError> {
    let dek = Dek::generate()?;
    let kid = Kid::generate(p, tenant)?;
    let wrapped = provider
        .wrap(
            &dek,
            &WrapContext {
                kid: &kid,
                purpose: p,
                tenant,
            },
        )
        .await?;
    store.insert(&kid, p, tenant, &wrapped).await?;
    Ok((kid, dek))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dek_store::InMemoryDekStore;
    use crate::kek_env::EnvKeyProvider;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    pub fn provider(byte: u8) -> Arc<dyn KeyProvider> {
        Arc::new(
            EnvKeyProvider::new("k1", [("k1", STANDARD.encode([byte; 32]))]).expect("provider"),
        )
    }

    pub async fn ring_with(store: Arc<InMemoryDekStore>) -> KeyRing {
        let p = provider(1);
        KeyRing::ensure_platform_keys(&*p, &*store)
            .await
            .expect("ensure");
        KeyRing::load_platform(p, store).await.expect("load")
    }

    #[tokio::test]
    async fn load_platform_fails_closed_when_missing() {
        let store = Arc::new(InMemoryDekStore::new());
        let err = KeyRing::load_platform(provider(1), store)
            .await
            .expect_err("must fail");
        assert!(matches!(err, CryptoError::NoActiveKey(_)));
    }

    #[tokio::test]
    async fn load_platform_fails_closed_on_wrong_kek_or_corruption() {
        let store = Arc::new(InMemoryDekStore::new());
        let p = provider(1);
        assert_eq!(
            KeyRing::ensure_platform_keys(&*p, &*store)
                .await
                .expect("e"),
            5
        );
        // dobara chalao: kuch create nahi hota
        assert_eq!(
            KeyRing::ensure_platform_keys(&*p, &*store)
                .await
                .expect("e"),
            0
        );
        // alag KEK bytes (same id) => unwrap fail
        assert!(matches!(
            KeyRing::load_platform(provider(2), store.clone()).await,
            Err(CryptoError::UnwrapFailed)
        ));
        let (kid, _) = store
            .active(KeyPurpose::Audit, None)
            .await
            .expect("a")
            .expect("some");
        store.corrupt(&kid).await;
        assert!(KeyRing::load_platform(p, store).await.is_err());
    }

    #[tokio::test]
    async fn tenant_dek_is_lazy_stable_and_isolated() {
        let store = Arc::new(InMemoryDekStore::new());
        let ring = ring_with(store.clone()).await;
        assert_eq!(store.len().await, 5);
        let (a, b) = (TenantId::new(), TenantId::new());
        let (ka, da) = ring.active(KeyPurpose::Pii, Some(a)).await.expect("a");
        assert_eq!(store.len().await, 6);
        let (ka2, _) = ring.active(KeyPurpose::Pii, Some(a)).await.expect("a2");
        assert_eq!(ka, ka2);
        assert_eq!(store.len().await, 6);
        let (kb, db) = ring.active(KeyPurpose::Pii, Some(b)).await.expect("b");
        assert_ne!(ka, kb);
        assert_ne!(da.as_bytes(), db.as_bytes());
        assert!(ka.as_str().len() <= Kid::MAX_LEN);
        // alag purpose = alag key
        let (kr, _) = ring.active(KeyPurpose::Reports, Some(a)).await.expect("r");
        assert_ne!(ka, kr);
        // get() by kid, fresh ring (cold cache) bhi wahi key de
        let ring2 = KeyRing::load_platform(provider(1), store.clone())
            .await
            .expect("ring2");
        let again = ring2.get(&ka).await.expect("get");
        assert_eq!(again.as_bytes(), da.as_bytes());
        // active on cold ring wahi kid, naya nahi banata
        let (ka3, _) = ring2.active(KeyPurpose::Pii, Some(a)).await.expect("a3");
        assert_eq!(ka, ka3);
        assert_eq!(store.len().await, 8);
    }

    /// CR-1: store mein wrapped bytes swap (do tenants, do purposes, platform<->tenant) = UnwrapFailed.
    #[tokio::test]
    async fn swapped_wrapped_rows_fail_closed() {
        let store = Arc::new(InMemoryDekStore::new());
        let ring = ring_with(store.clone()).await;
        let (a, b) = (TenantId::new(), TenantId::new());
        let (ka, _) = ring.active(KeyPurpose::Pii, Some(a)).await.expect("a");
        let (kb, _) = ring.active(KeyPurpose::Pii, Some(b)).await.expect("b");
        let (kar, _) = ring.active(KeyPurpose::Reports, Some(a)).await.expect("ar");
        let (kp, _) = ring.active(KeyPurpose::Identity, None).await.expect("p");

        for (x, y) in [(&ka, &kb), (&ka, &kar), (&ka, &kp)] {
            store.swap_wrapped(x, y).await;
            // fresh ring (cold cache) store se load karta hai
            let fresh = KeyRing::load_platform(provider(1), store.clone()).await;
            match fresh {
                // platform key swap hui to load_platform hi fail closed
                Err(e) => assert!(matches!(e, CryptoError::UnwrapFailed), "{e}"),
                Ok(r) => {
                    assert!(matches!(r.get(x).await, Err(CryptoError::UnwrapFailed)));
                    assert!(matches!(r.get(y).await, Err(CryptoError::UnwrapFailed)));
                }
            }
            store.swap_wrapped(x, y).await; // wapas theek
            let ok = KeyRing::load_platform(provider(1), store.clone())
                .await
                .expect("restored");
            assert!(ok.get(x).await.is_ok() && ok.get(y).await.is_ok());
        }
    }

    #[tokio::test]
    async fn subkeys_deterministic_separated_and_rotation_aware() {
        let store = Arc::new(InMemoryDekStore::new());
        let ring = ring_with(store.clone()).await;
        let t = TenantId::new();
        let base = ring
            .derive_subkey(KeyPurpose::Identity, None, "cursor")
            .await
            .expect("a");
        assert_eq!(
            *base,
            *ring
                .derive_subkey(KeyPurpose::Identity, None, "cursor")
                .await
                .expect("b"),
            "deterministic"
        );
        assert_ne!(*base, [0u8; 32]);
        let other_label = ring
            .derive_subkey(KeyPurpose::Identity, None, "digest")
            .await
            .expect("l");
        let other_purpose = ring
            .derive_subkey(KeyPurpose::Audit, None, "cursor")
            .await
            .expect("p");
        assert_ne!(*base, *other_label);
        assert_ne!(*base, *other_purpose);
        let ta = ring
            .derive_subkey(KeyPurpose::Pii, Some(t), "cursor")
            .await
            .expect("t");
        let tb = ring
            .derive_subkey(KeyPurpose::Pii, Some(TenantId::new()), "cursor")
            .await
            .expect("t2");
        assert_ne!(*ta, *tb);
        assert_ne!(*ta, *base);
        // scope rules same as active()
        assert!(
            ring.derive_subkey(KeyPurpose::Pii, None, "x")
                .await
                .is_err()
        );
        // fresh ring (restart) same keys => same subkey
        let ring2 = KeyRing::load_platform(provider(1), store.clone())
            .await
            .expect("ring2");
        assert_eq!(
            *base,
            *ring2
                .derive_subkey(KeyPurpose::Identity, None, "cursor")
                .await
                .expect("restart")
        );

        // rotation: active DEK badli => subkey badli; pinned kid se purani wahi.
        let (old_kid, _) = ring.active(KeyPurpose::Pii, Some(t)).await.expect("kid");
        let pinned_before = ring
            .derive_subkey_for_kid(&old_kid, "cursor")
            .await
            .expect("pin");
        assert_eq!(*pinned_before, *ta, "for_kid(active kid) == derive_subkey");
        store.deactivate(&old_kid).await;
        ring.clear_cache();
        let after = ring
            .derive_subkey(KeyPurpose::Pii, Some(t), "cursor")
            .await
            .expect("after");
        assert_ne!(*after, *ta, "rotation changes the subkey");
        let pinned_after = ring
            .derive_subkey_for_kid(&old_kid, "cursor")
            .await
            .expect("pin2");
        assert_eq!(
            *pinned_after, *ta,
            "pinned kid stays stable across rotation"
        );
        assert!(matches!(
            ring.derive_subkey_for_kid(&Kid::parse("nope").expect("k"), "x")
                .await,
            Err(CryptoError::KeyNotFound(_))
        ));
    }

    #[tokio::test]
    async fn scope_rules() {
        let ring = ring_with(Arc::new(InMemoryDekStore::new())).await;
        let t = TenantId::new();
        assert!(ring.active(KeyPurpose::Pii, None).await.is_err());
        assert!(ring.active(KeyPurpose::Identity, Some(t)).await.is_err());
        let (kid, _) = ring.active(KeyPurpose::Pii, Some(t)).await.expect("k");
        assert!(matches!(
            ring.get_scoped(&kid, KeyPurpose::Pii, Some(TenantId::new()))
                .await,
            Err(CryptoError::KeyScopeMismatch)
        ));
        assert!(matches!(
            ring.get_scoped(&kid, KeyPurpose::Reports, Some(t)).await,
            Err(CryptoError::KeyScopeMismatch)
        ));
        assert!(
            ring.get_scoped(&kid, KeyPurpose::Pii, Some(t))
                .await
                .is_ok()
        );
        assert!(matches!(
            ring.get(&Kid::parse("nope").expect("kid")).await,
            Err(CryptoError::KeyNotFound(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_first_use_creates_one_key() {
        let store = Arc::new(InMemoryDekStore::new());
        let ring = Arc::new(ring_with(store.clone()).await);
        let t = TenantId::new();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let r = ring.clone();
            set.spawn(async move { r.active(KeyPurpose::Pii, Some(t)).await.map(|(k, _)| k) });
        }
        let mut kids = std::collections::HashSet::new();
        while let Some(res) = set.join_next().await {
            kids.insert(res.expect("join").expect("active"));
        }
        assert_eq!(kids.len(), 1);
        assert_eq!(store.len().await, 6);
    }

    #[tokio::test]
    async fn rotation_old_kid_still_decrypts_new_kid_is_active() {
        let store = Arc::new(InMemoryDekStore::new());
        let ring = ring_with(store.clone()).await;
        let t = TenantId::new();
        let (old, _) = ring.active(KeyPurpose::Pii, Some(t)).await.expect("old");
        store.deactivate(&old).await;
        ring.clear_cache();
        let (new, _) = ring.active(KeyPurpose::Pii, Some(t)).await.expect("new");
        assert_ne!(old, new);
        assert!(ring.get(&old).await.is_ok());
    }

    #[tokio::test]
    async fn cached_active_is_sync_and_cache_only() {
        let ring = ring_with(Arc::new(InMemoryDekStore::new())).await;
        let t = TenantId::new();
        assert!(ring.cached_active(KeyPurpose::BidxEmail, None).is_some());
        assert!(
            ring.cached_active(KeyPurpose::BidxTenant, Some(t))
                .is_none()
        );
        ring.active(KeyPurpose::BidxTenant, Some(t))
            .await
            .expect("k");
        assert!(
            ring.cached_active(KeyPurpose::BidxTenant, Some(t))
                .is_some()
        );
    }

    #[test]
    fn debug_has_no_key_material() {
        let d = Dek::generate().expect("d");
        assert_eq!(format!("{d:?}"), "Dek([redacted])");
    }
}
