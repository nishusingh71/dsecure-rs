//! `data_keys`: the real `crypto::DekStore` (platform class).
//!
//! "One active key per (purpose, tenant)" without partial indexes: `active_marker = 'Y'` while active,
//! `NULL` otherwise, and `UNIQUE (purpose, scope_key, active_marker)` (multiple NULLs allowed).
//! `scope_key` = tenant id or 16 zero bytes for platform keys. Duplicate -> `CryptoError::Conflict`
//! (the KeyRing lazy-create race relies on it).

use crate::error::DbError;
use crate::platform_admin::PlatformAdminTx;
use crate::pool::Db;
use crate::queries::{DATA_KEYS_ACTIVE, DATA_KEYS_BY_KID, DATA_KEYS_DEACTIVATE, DATA_KEYS_INSERT};
use crate::sql;
use crate::tx::{Inner, SystemTx};
use crate::write_guard::WriteOutcome;
use common::TenantId;
use crypto::{CryptoError, DekStore, KeyProvider, KeyPurpose, Kid, WrapContext, WrappedDek};
use domain::rbac::PlatformPerm;
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

/// Active PLATFORM DEK of `p`, read inside a platform-admin tx (sees the tx's own inserts).
/// For first-run provisioning (`xtask provision-keys seed-db`), together with
/// [`insert_platform_dek_in_tx`], so the DEKs commit atomically with the signing keys and audit row.
///
/// # Errors
/// `Forbidden` (tx opened for another permission), `Invalid` (tenant-scoped purpose), server/decode errors.
pub async fn platform_active_in_tx(
    tx: &mut PlatformAdminTx,
    p: KeyPurpose,
) -> Result<Option<(Kid, WrappedDek)>, DbError> {
    tx.require(PlatformPerm::KeysRotate)?;
    platform_active_inner(&mut tx.inner, p).await
}

/// Active PLATFORM DEK of `p` inside any platform-admin transaction (bootstrap + keys tx).
pub(crate) async fn platform_active_inner(
    inner: &mut Inner,
    p: KeyPurpose,
) -> Result<Option<(Kid, WrappedDek)>, DbError> {
    if p.is_tenant_scoped() {
        return Err(DbError::Invalid("platform purpose required"));
    }
    let Some(row) = inner
        .fetch_optional(
            sql::q(DATA_KEYS_ACTIVE)
                .bind(p.as_str())
                .bind(scope_key(None)),
        )
        .await?
    else {
        return Ok(None);
    };
    let kid: String = sql::col(&row, "kid")?;
    Ok(Some((
        Kid::parse(kid).map_err(|_| DbError::Corrupt("data_keys.kid"))?,
        wrapped(&row)?,
    )))
}

/// Insert a new active PLATFORM DEK inside a platform-admin tx opened for `platform.keys.rotate`
/// (owner-approved). Duplicate active slot = `Conflict("data_keys.active_taken")` (on TiDB it may
/// only surface at COMMIT, which then fails as a whole).
///
/// # Errors
/// `Forbidden`, `Invalid`, `Conflict`, server errors.
pub async fn insert_platform_dek_in_tx(
    tx: &mut PlatformAdminTx,
    kid: &Kid,
    p: KeyPurpose,
    w: &WrappedDek,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    tx.require(PlatformPerm::KeysRotate)?;
    insert_platform_dek_inner(&mut tx.inner, kid, p, w, now).await
}

/// Insert a new active PLATFORM DEK inside any platform-admin transaction.
pub(crate) async fn insert_platform_dek_inner(
    inner: &mut Inner,
    kid: &Kid,
    p: KeyPurpose,
    w: &WrappedDek,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    if p.is_tenant_scoped() {
        return Err(DbError::Invalid("platform purpose required"));
    }
    match inner
        .execute(
            sql::q(DATA_KEYS_INSERT)
                .bind(kid.as_str())
                .bind(p.as_str())
                .bind(db_tenant(None).0)
                .bind(scope_key(None))
                .bind(w.kek_ref.as_str())
                .bind(w.bytes.as_slice())
                .bind(now),
        )
        .await
    {
        Ok(n) => n.expect_one(),
        Err(DbError::Duplicate { .. }) => Err(DbError::Conflict("data_keys.active_taken")),
        Err(e) => Err(e),
    }
}

/// One platform DEK of a first-run plan ([`plan_platform_deks`]): an existing active row (guarded:
/// same KEK, unwraps) or a NEW one, generated and wrapped in memory but not written yet.
#[derive(Clone, Debug)]
pub struct PlatformDekPlan {
    pub purpose: KeyPurpose,
    pub kid: Kid,
    pub wrapped: WrappedDek,
    /// `true` = already in `data_keys`; `false` = to be inserted by the caller's transaction.
    pub existing: bool,
}

/// KEK guard / planning failure. Messages carry only kids and KEK ids (never key bytes).
#[derive(Debug, thiserror::Error)]
pub enum DekPlanError {
    #[error(
        "platform DEK `{kid}` is wrapped by another KEK (`{found}`), not by this KEK (`{expected}`);          use the keys that created it; nothing was written"
    )]
    OtherKek {
        kid: String,
        found: String,
        expected: String,
    },
    #[error(
        "platform DEK `{kid}` does not unwrap with this KEK (same id, different value?); nothing was          written"
    )]
    NoUnwrap { kid: String },
    #[error("platform DEK planning failed: {0}")]
    Crypto(String),
}

/// KEK guard for one existing platform DEK: it must carry this KEK's `kek_ref` AND unwrap with it.
/// Shared by `dsecure-api staff-bootstrap` and `xtask provision-keys seed-db` (review N1).
///
/// # Errors
/// [`DekPlanError`].
pub async fn guard_platform_dek(
    provider: &dyn KeyProvider,
    p: KeyPurpose,
    kid: &Kid,
    w: &WrappedDek,
) -> Result<(), DekPlanError> {
    if w.kek_ref != provider.active_kek_ref() {
        return Err(DekPlanError::OtherKek {
            kid: kid.to_string(),
            found: w.kek_ref.clone(),
            expected: provider.active_kek_ref().to_owned(),
        });
    }
    provider
        .unwrap(
            w,
            &WrapContext {
                kid,
                purpose: p,
                tenant: None,
            },
        )
        .await
        .map(|_| ())
        .map_err(|_| DekPlanError::NoUnwrap {
            kid: kid.to_string(),
        })
}

/// Plan the platform DEKs BEFORE anything is written (read-only): every existing active platform
/// DEK is guarded ([`guard_platform_dek`]), every missing purpose gets a fresh kid + DEK wrapped by
/// this KEK. The caller inserts the new ones inside ONE transaction together with its other rows,
/// re-checking the active slots there ([`PlatformAdminDb::bootstrap_first_superadmin_with_deks`] /
/// `platform_active_in_tx`), so a mixed-KEK state can never be committed.
///
/// Limitation: only ACTIVE platform rows are visible; decrypt-only rows (after a rotation) are not
/// checked. A fresh database has none.
///
/// # Errors
/// [`DekPlanError`].
///
/// [`PlatformAdminDb::bootstrap_first_superadmin_with_deks`]: crate::platform_admin::PlatformAdminDb::bootstrap_first_superadmin_with_deks
pub async fn plan_platform_deks(
    provider: &dyn KeyProvider,
    store: &dyn DekStore,
) -> Result<Vec<PlatformDekPlan>, DekPlanError> {
    let mut plan = Vec::with_capacity(KeyPurpose::PLATFORM.len());
    for p in KeyPurpose::PLATFORM {
        let found = store
            .active(p, None)
            .await
            .map_err(|e| DekPlanError::Crypto(e.to_string()))?;
        match found {
            Some((kid, w)) => {
                guard_platform_dek(provider, p, &kid, &w).await?;
                plan.push(PlatformDekPlan {
                    purpose: p,
                    kid,
                    wrapped: w,
                    existing: true,
                });
            }
            None => {
                let kid =
                    Kid::generate(p, None).map_err(|e| DekPlanError::Crypto(e.to_string()))?;
                let dek =
                    crypto::Dek::generate().map_err(|e| DekPlanError::Crypto(e.to_string()))?;
                let w = provider
                    .wrap(
                        &dek,
                        &WrapContext {
                            kid: &kid,
                            purpose: p,
                            tenant: None,
                        },
                    )
                    .await
                    .map_err(|e| DekPlanError::Crypto(e.to_string()))?;
                plan.push(PlatformDekPlan {
                    purpose: p,
                    kid,
                    wrapped: w,
                    existing: false,
                });
            }
        }
    }
    Ok(plan)
}
