//! `data_keys`: the real `crypto::DekStore` (platform class).
//!
//! "One active key per (purpose, tenant)" without partial indexes: `active_marker = 'Y'` while active,
//! `NULL` otherwise, and `UNIQUE (purpose, scope_key, active_marker)` (multiple NULLs allowed).
//! `scope_key` = tenant id or 16 zero bytes for platform keys. Duplicate -> `CryptoError::Conflict`
//! (the KeyRing lazy-create race relies on it).

use crate::error::DbError;
use crate::pool::Db;
use crate::queries::{DATA_KEYS_ACTIVE, DATA_KEYS_BY_KID, DATA_KEYS_DEACTIVATE, DATA_KEYS_INSERT};
use crate::sql;
use crate::tx::SystemTx;
use crate::write_guard::WriteOutcome;
use common::TenantId;
use crypto::{CryptoError, DekStore, KeyPurpose, Kid, WrappedDek};
use time::OffsetDateTime;

/// Platform-scope keys belong to the platform pseudo-tenant (`PLATFORM_TENANT_ID`), so `tenant_id` is
/// never NULL and the shadow FK to `tenants` holds; `crypto` still sees `None` for them.
fn db_tenant(tenant: Option<TenantId>) -> TenantId {
    tenant.unwrap_or(crate::PLATFORM_TENANT_ID)
}

fn scope_key(tenant: Option<TenantId>) -> uuid::Uuid {
    db_tenant(tenant).0
}

fn store_err(e: &DbError) -> CryptoError {
    // Value-free: only the DbError category (no SQL, no key bytes).
    CryptoError::Store(format!("data_keys: {e}"))
}

/// `DekStore` over the `data_keys` table. Each call is its own short transaction.
#[derive(Clone, Debug)]
pub struct DbDekStore {
    db: Db,
}

impl DbDekStore {
    #[must_use]
    pub const fn new(db: Db) -> Self {
        Self { db }
    }

    /// Rotation: active -> decrypt_only (frees the active slot for a new key).
    ///
    /// # Errors
    /// `NotPersisted` if `kid` is not active, server errors.
    pub async fn deactivate(&self, kid: &Kid, now: OffsetDateTime) -> Result<(), DbError> {
        let mut tx = self.db.system_tx().await?;
        tx.inner
            .execute(sql::q(DATA_KEYS_DEACTIVATE).bind(now).bind(kid.as_str()))
            .await?
            .expect_one()?;
        tx.commit().await
    }

    async fn tx(&self) -> Result<SystemTx, CryptoError> {
        self.db.system_tx().await.map_err(|e| store_err(&e))
    }
}

fn wrapped(row: &sqlx::mysql::MySqlRow) -> Result<WrappedDek, DbError> {
    Ok(WrappedDek {
        kek_ref: sql::col(row, "kek_ref")?,
        bytes: sql::col(row, "wrapped_dek")?,
    })
}

#[async_trait::async_trait]
impl DekStore for DbDekStore {
    async fn active(
        &self,
        p: KeyPurpose,
        tenant: Option<TenantId>,
    ) -> Result<Option<(Kid, WrappedDek)>, CryptoError> {
        let mut tx = self.tx().await?;
        let row = tx
            .inner
            .fetch_optional(
                sql::q(DATA_KEYS_ACTIVE)
                    .bind(p.as_str())
                    .bind(scope_key(tenant)),
            )
            .await
            .map_err(|e| store_err(&e))?;
        tx.commit().await.map_err(|e| store_err(&e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let kid: String = sql::col(&row, "kid").map_err(|e| store_err(&e))?;
        Ok(Some((
            Kid::parse(kid)?,
            wrapped(&row).map_err(|e| store_err(&e))?,
        )))
    }

    async fn by_kid(
        &self,
        kid: &Kid,
    ) -> Result<Option<(KeyPurpose, Option<TenantId>, WrappedDek)>, CryptoError> {
        let mut tx = self.tx().await?;
        let row = tx
            .inner
            .fetch_optional(sql::q(DATA_KEYS_BY_KID).bind(kid.as_str()))
            .await
            .map_err(|e| store_err(&e))?;
        tx.commit().await.map_err(|e| store_err(&e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let status: String = sql::col(&row, "status").map_err(|e| store_err(&e))?;
        if status == "destroyed" {
            return Ok(None); // crypto-shredded
        }
        let purpose: String = sql::col(&row, "purpose").map_err(|e| store_err(&e))?;
        let tenant = sql::opt_uuid_col(&row, "tenant_id")
            .map_err(|e| store_err(&e))?
            .map(TenantId)
            .filter(|t| *t != crate::PLATFORM_TENANT_ID);
        Ok(Some((
            purpose.parse::<KeyPurpose>()?,
            tenant,
            wrapped(&row).map_err(|e| store_err(&e))?,
        )))
    }

    async fn insert(
        &self,
        kid: &Kid,
        p: KeyPurpose,
        tenant: Option<TenantId>,
        w: &WrappedDek,
    ) -> Result<(), CryptoError> {
        if p.is_tenant_scoped() != tenant.is_some() || tenant == Some(crate::PLATFORM_TENANT_ID) {
            return Err(CryptoError::InvalidContext("purpose/tenant scope mismatch"));
        }
        let mut tx = self.tx().await?;
        let r = tx
            .inner
            .execute(
                sql::q(DATA_KEYS_INSERT)
                    .bind(kid.as_str())
                    .bind(p.as_str())
                    .bind(db_tenant(tenant).0)
                    .bind(scope_key(tenant))
                    .bind(w.kek_ref.as_str())
                    .bind(w.bytes.as_slice())
                    .bind(OffsetDateTime::now_utc()),
            )
            .await;
        match r {
            Ok(n) => {
                n.expect_one().map_err(|e| store_err(&e))?;
                match tx.commit().await {
                    Ok(()) => Ok(()),
                    // TiDB lazy unique check: the active-key conflict can surface at COMMIT.
                    Err(DbError::Duplicate { .. }) => Err(CryptoError::Conflict),
                    Err(e) => Err(store_err(&e)),
                }
            }
            Err(DbError::Duplicate { .. }) => {
                tx.rollback().await;
                Err(CryptoError::Conflict)
            }
            Err(e) => {
                tx.rollback().await;
                Err(store_err(&e))
            }
        }
    }
}
