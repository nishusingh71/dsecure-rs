//! `DekStore`: wrapped DEKs ka persistent store (real impl `db` crate mein, `data_keys` table).
//! `InMemoryDekStore` sirf tests/dev ke liye.

use crate::error::CryptoError;
use crate::keys::{KeyPurpose, Kid, WrappedDek};
use common::TenantId;
use tokio::sync::Mutex;

#[async_trait::async_trait]
pub trait DekStore: Send + Sync {
    /// Is (purpose, tenant) ki active (writes ke liye) DEK; `None` agar abhi nahi bani.
    async fn active(
        &self,
        p: KeyPurpose,
        tenant: Option<TenantId>,
    ) -> Result<Option<(Kid, WrappedDek)>, CryptoError>;

    /// Kisi bhi kid (active ya decrypt-only) ki DEK + uska purpose/tenant.
    async fn by_kid(
        &self,
        kid: &Kid,
    ) -> Result<Option<(KeyPurpose, Option<TenantId>, WrappedDek)>, CryptoError>;

    /// Nayi DEK active ke taur par. Agar is (purpose, tenant) ki active pehle se hai to
    /// `CryptoError::Conflict` (DB mein partial unique index) taaki lazy creation race mein ek hi jeete.
    async fn insert(
        &self,
        kid: &Kid,
        p: KeyPurpose,
        tenant: Option<TenantId>,
        w: &WrappedDek,
    ) -> Result<(), CryptoError>;
}

struct Row {
    kid: Kid,
    purpose: KeyPurpose,
    tenant: Option<TenantId>,
    wrapped: WrappedDek,
    active: bool,
}

#[derive(Default)]
pub struct InMemoryDekStore {
    rows: Mutex<Vec<Row>>,
}

impl InMemoryDekStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total rows (tests).
    pub async fn len(&self) -> usize {
        self.rows.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.rows.lock().await.is_empty()
    }

    /// Rotation simulate: kid ko decrypt-only banao (naya insert ab allowed).
    pub async fn deactivate(&self, kid: &Kid) {
        for r in self.rows.lock().await.iter_mut() {
            if &r.kid == kid {
                r.active = false;
            }
        }
    }

    /// Crypto-shred simulate: kid ki row hata do (tests).
    pub async fn destroy(&self, kid: &Kid) {
        self.rows.lock().await.retain(|r| &r.kid != kid);
    }

    /// DB-write attacker simulate: do rows ke wrapped bytes aapas mein swap (tests).
    pub async fn swap_wrapped(&self, a: &Kid, b: &Kid) {
        let mut rows = self.rows.lock().await;
        let ia = rows.iter().position(|r| &r.kid == a);
        let ib = rows.iter().position(|r| &r.kid == b);
        if let (Some(ia), Some(ib)) = (ia, ib) {
            let wa = rows[ia].wrapped.clone();
            rows[ia].wrapped = std::mem::replace(&mut rows[ib].wrapped, wa);
        }
    }

    /// Tampering simulate: stored wrapped bytes badlo (tests).
    pub async fn corrupt(&self, kid: &Kid) {
        for r in self.rows.lock().await.iter_mut() {
            if &r.kid == kid
                && let Some(b) = r.wrapped.bytes.last_mut()
            {
                *b ^= 0x01;
            }
        }
    }
}

#[async_trait::async_trait]
impl DekStore for InMemoryDekStore {
    async fn active(
        &self,
        p: KeyPurpose,
        tenant: Option<TenantId>,
    ) -> Result<Option<(Kid, WrappedDek)>, CryptoError> {
        Ok(self
            .rows
            .lock()
            .await
            .iter()
            .find(|r| r.active && r.purpose == p && r.tenant == tenant)
            .map(|r| (r.kid.clone(), r.wrapped.clone())))
    }

    async fn by_kid(
        &self,
        kid: &Kid,
    ) -> Result<Option<(KeyPurpose, Option<TenantId>, WrappedDek)>, CryptoError> {
        Ok(self
            .rows
            .lock()
            .await
            .iter()
            .find(|r| &r.kid == kid)
            .map(|r| (r.purpose, r.tenant, r.wrapped.clone())))
    }

    async fn insert(
        &self,
        kid: &Kid,
        p: KeyPurpose,
        tenant: Option<TenantId>,
        w: &WrappedDek,
    ) -> Result<(), CryptoError> {
        let mut rows = self.rows.lock().await;
        if rows.iter().any(|r| &r.kid == kid)
            || rows
                .iter()
                .any(|r| r.active && r.purpose == p && r.tenant == tenant)
        {
            return Err(CryptoError::Conflict);
        }
        rows.push(Row {
            kid: kid.clone(),
            purpose: p,
            tenant,
            wrapped: w.clone(),
            active: true,
        });
        Ok(())
    }
}
