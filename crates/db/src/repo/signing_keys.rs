//! `signing_keys` (set 0150): JWT / report / offline-licence signing keys.
//!
//! - The PRIVATE key is stored only as `crypto::FieldEncryptor` ciphertext (`Secrets` purpose, platform
//!   scope; AAD = `signing_keys.wrapped_private_key` + row id = SHA-256(kid)[..16]). Plaintext/PEM is
//!   never written.
//! - Reads (`active_for`, `by_kid`, `list_public`) run as the app user (SELECT only on this table).
//! - Writes only through a [`PlatformAdminTx`] opened for `platform.keys.rotate` (audited in that tx).
//!   That matrix cell needs OWNER approval, so the tx must come from
//!   `PlatformAdminDb::admin_tx_owner_approved`.
//! - [`dev_bootstrap`]: dev/test only (production refuses), so the api can create dev keys itself.

use crate::error::DbError;
use crate::platform_admin::PlatformAdminTx;
use crate::pool::Db;
use crate::queries::{
    SIGNING_KEYS_ACTIVE_FOR, SIGNING_KEYS_BY_KID, SIGNING_KEYS_INSERT, SIGNING_KEYS_LIST_PUBLIC,
    SIGNING_KEYS_SET_STATUS,
};
use crate::repo::audit::AuditRowRecord;
use crate::sql;
use crate::tx::{Inner, SystemTx};
use crate::write_guard::WriteOutcome;
use crypto::{FieldContext, FieldEncryptor, KeyPurpose, SigAlg};
use domain::rbac::PlatformPerm;
use sha2::{Digest as _, Sha256};
use sqlx::mysql::MySqlRow;
use time::OffsetDateTime;
use zeroize::Zeroizing;

const TABLE: &str = "signing_keys";
const COLUMN: &str = "wrapped_private_key";

/// What a key signs (`signing_keys.purpose`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigningRealm {
    ReportCertificate,
    JwtMember,
    JwtDevice,
    JwtStaff,
    JwtCleaner,
    OfflineLicense,
}

impl SigningRealm {
    pub const ALL: [Self; 6] = [
        Self::ReportCertificate,
        Self::JwtMember,
        Self::JwtDevice,
        Self::JwtStaff,
        Self::JwtCleaner,
        Self::OfflineLicense,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReportCertificate => "report_certificate",
            Self::JwtMember => "jwt_member",
            Self::JwtDevice => "jwt_device",
            Self::JwtStaff => "jwt_staff",
            Self::JwtCleaner => "jwt_cleaner",
            Self::OfflineLicense => "offline_license",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningKeyStatus {
    Active,
    VerifyOnly,
    Retired,
}

impl SigningKeyStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::VerifyOnly => "verify_only",
            Self::Retired => "retired",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Active, Self::VerifyOnly, Self::Retired]
            .into_iter()
            .find(|v| v.as_str() == s)
    }
}

const fn alg_str(a: SigAlg) -> &'static str {
    match a {
        SigAlg::Ed25519 => "Ed25519",
        SigAlg::Es256 => "ES256",
    }
}

fn alg_parse(s: &str) -> Option<SigAlg> {
    match s {
        "Ed25519" => Some(SigAlg::Ed25519),
        "ES256" => Some(SigAlg::Es256),
        _ => None,
    }
}

/// New key. `private_key` = raw key bytes (e.g. PKCS#8 DER); encrypted before it reaches the DB.
pub struct NewSigningKey {
    pub kid: String,
    pub alg: SigAlg,
    pub realm: SigningRealm,
    pub private_key: Zeroizing<Vec<u8>>,
    pub public_key: Vec<u8>,
    pub not_before: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
}

impl std::fmt::Debug for NewSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSigningKey")
            .field("kid", &self.kid)
            .field("realm", &self.realm)
            .finish_non_exhaustive()
    }
}

/// A stored key. The private key stays encrypted until [`SigningKeyRow::private_key`].
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKeyRow {
    pub kid: String,
    pub alg: SigAlg,
    pub realm: SigningRealm,
    pub public_key: Vec<u8>,
    pub status: SigningKeyStatus,
    pub not_before: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    wrapped: Option<Vec<u8>>,
}

impl std::fmt::Debug for SigningKeyRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyRow")
            .field("kid", &self.kid)
            .field("realm", &self.realm)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// JWKS entry (no private material at all).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyInfo {
    pub kid: String,
    pub alg: SigAlg,
    pub realm: SigningRealm,
    pub public_key: Vec<u8>,
    pub status: SigningKeyStatus,
    pub not_before: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
}

fn kid_ok(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= 48
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// AAD row id: SHA-256(kid)[..16] (the table is keyed by the string kid).
fn row_id(kid: &str) -> uuid::Uuid {
    let d = Sha256::digest(kid.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    uuid::Uuid::from_bytes(b)
}

fn ctx(kid: &str) -> FieldContext<'static> {
    FieldContext::new(TABLE, COLUMN, None, row_id(kid), KeyPurpose::Secrets)
}

impl SigningKeyRow {
    /// Decrypt the private key (only the signer needs it; never logged).
    ///
    /// # Errors
    /// `NotFound` (verify-only row without private key), `Corrupt` (decrypt failure).
    pub async fn private_key(
        &self,
        enc: &dyn FieldEncryptor,
    ) -> Result<Zeroizing<Vec<u8>>, DbError> {
        let w = self
            .wrapped
            .as_ref()
            .ok_or(DbError::NotFound("signing private key"))?;
        enc.decrypt(w, &ctx(&self.kid))
            .await
            .map_err(|_| DbError::Corrupt("signing_keys.wrapped_private_key"))
    }
}

fn map_row(r: &MySqlRow) -> Result<SigningKeyRow, DbError> {
    let alg: String = sql::col(r, "alg")?;
    let realm: String = sql::col(r, "purpose")?;
    let status: String = sql::col(r, "status")?;
    Ok(SigningKeyRow {
        kid: sql::col(r, "kid")?,
        alg: alg_parse(&alg).ok_or(DbError::Corrupt("signing_keys.alg"))?,
        realm: SigningRealm::parse(&realm).ok_or(DbError::Corrupt("signing_keys.purpose"))?,
        public_key: sql::col(r, "public_key")?,
        status: SigningKeyStatus::parse(&status).ok_or(DbError::Corrupt("signing_keys.status"))?,
        not_before: sql::col(r, "not_before")?,
        expires_at: sql::col(r, "not_after")?,
        wrapped: sql::col(r, "wrapped_private_key")?,
    })
}

async fn insert_inner(
    inner: &mut Inner,
    enc: &dyn FieldEncryptor,
    k: &NewSigningKey,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    if !kid_ok(&k.kid) {
        return Err(DbError::Invalid("kid must be 1..=48 [A-Za-z0-9_.-]"));
    }
    if k.private_key.is_empty() || k.public_key.is_empty() || k.public_key.len() > 1024 {
        return Err(DbError::Invalid("key material size"));
    }
    if k.expires_at.is_some_and(|e| e <= k.not_before) {
        return Err(DbError::Invalid("expires_at must be after not_before"));
    }
    let wrapped = enc
        .encrypt(&k.private_key, &ctx(&k.kid))
        .await
        .map_err(|_| DbError::Config("signing key encryption failed (Secrets DEK)"))?;
    if wrapped.len() > 1024 {
        return Err(DbError::Invalid("encrypted private key too large"));
    }
    match inner
        .execute(
            sql::q(SIGNING_KEYS_INSERT)
                .bind(k.kid.as_str())
                .bind(k.realm.as_str())
                .bind(alg_str(k.alg))
                .bind(k.public_key.as_slice())
                .bind(wrapped.as_slice())
                .bind(k.not_before)
                .bind(k.expires_at)
                .bind(now),
        )
        .await
    {
        Ok(n) => n.expect_one(),
        Err(e) if e.is_duplicate_of("PRIMARY") => Err(DbError::Conflict("signing_keys.kid_taken")),
        Err(e) => Err(e),
    }
}

/// Insert a key (platform admin, `platform.keys.rotate`; the tx already holds the audit row).
///
/// # Errors
/// `Forbidden`, `Invalid`, `Conflict("signing_keys.kid_taken")`, server errors.
pub async fn insert_signing_key(
    tx: &mut PlatformAdminTx,
    enc: &dyn FieldEncryptor,
    k: &NewSigningKey,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    tx.require(PlatformPerm::KeysRotate)?;
    insert_inner(&mut tx.inner, enc, k, now).await
}

/// Rotation step: an old key becomes `verify_only` (still served by `by_kid` / JWKS) or `retired`.
///
/// # Errors
/// `Forbidden`, `Invalid` (cannot set back to active), `NotPersisted`, server errors.
pub async fn set_status(
    tx: &mut PlatformAdminTx,
    kid: &str,
    status: SigningKeyStatus,
) -> Result<(), DbError> {
    tx.require(PlatformPerm::KeysRotate)?;
    if status == SigningKeyStatus::Active {
        return Err(DbError::Invalid(
            "insert a new key instead of re-activating",
        ));
    }
    tx.inner
        .execute(
            sql::q(SIGNING_KEYS_SET_STATUS)
                .bind(status.as_str())
                .bind(kid),
        )
        .await?
        .expect_one()
}

/// Newest valid active key of `realm` (signing).
///
/// # Errors
/// Server / decode errors.
pub async fn active_for(
    tx: &mut SystemTx,
    realm: SigningRealm,
    now: OffsetDateTime,
) -> Result<Option<SigningKeyRow>, DbError> {
    tx.inner
        .fetch_optional(
            sql::q(SIGNING_KEYS_ACTIVE_FOR)
                .bind(realm.as_str())
                .bind(now)
                .bind(now),
        )
        .await?
        .as_ref()
        .map(map_row)
        .transpose()
}

/// Any key by kid, whatever its status (verification during rotation).
///
/// # Errors
/// Server / decode errors.
pub async fn by_kid(tx: &mut SystemTx, kid: &str) -> Result<Option<SigningKeyRow>, DbError> {
    if !kid_ok(kid) {
        return Ok(None);
    }
    tx.inner
        .fetch_optional(sql::q(SIGNING_KEYS_BY_KID).bind(kid))
        .await?
        .as_ref()
        .map(map_row)
        .transpose()
}

/// Public keys for JWKS: active + verify_only, not expired (max 200).
///
/// # Errors
/// Server / decode errors.
pub async fn list_public(
    tx: &mut SystemTx,
    now: OffsetDateTime,
) -> Result<Vec<PublicKeyInfo>, DbError> {
    let rows = tx
        .inner
        .fetch_all(sql::q(SIGNING_KEYS_LIST_PUBLIC).bind(now))
        .await?;
    rows.iter()
        .map(|r| {
            let alg: String = sql::col(r, "alg")?;
            let realm: String = sql::col(r, "purpose")?;
            let status: String = sql::col(r, "status")?;
            Ok(PublicKeyInfo {
                kid: sql::col(r, "kid")?,
                alg: alg_parse(&alg).ok_or(DbError::Corrupt("signing_keys.alg"))?,
                realm: SigningRealm::parse(&realm)
                    .ok_or(DbError::Corrupt("signing_keys.purpose"))?,
                public_key: sql::col(r, "public_key")?,
                status: SigningKeyStatus::parse(&status)
                    .ok_or(DbError::Corrupt("signing_keys.status"))?,
                not_before: sql::col(r, "not_before")?,
                expires_at: sql::col(r, "not_after")?,
            })
        })
        .collect()
}

/// DEV/TEST ONLY bootstrap: insert each key whose realm has no valid active key yet, with `audit`
/// (built by the caller, `actor_kind` = `system`) in the same tx. `db` must be a pool with INSERT on
/// `signing_keys` (dev migrator / platform-admin user; the app user has SELECT only). Returns the
/// number inserted.
///
/// # Errors
/// `Config("dev bootstrap refused outside dev/test")`, `Invalid`, server errors.
pub async fn dev_bootstrap(
    db: &Db,
    env: config::Environment,
    enc: &dyn FieldEncryptor,
    keys: &[NewSigningKey],
    audit: &AuditRowRecord,
    now: OffsetDateTime,
) -> Result<usize, DbError> {
    if !env.is_local() {
        return Err(DbError::Config("dev bootstrap refused outside dev/test"));
    }
    if audit.actor_kind != "system" || audit.action.is_empty() {
        return Err(DbError::Invalid("dev bootstrap needs a system audit row"));
    }
    let mut tx = db.system_tx().await?;
    let mut n = 0;
    let r: Result<(), DbError> = async {
        for k in keys {
            if active_for(&mut tx, k.realm, now).await?.is_some() {
                continue;
            }
            insert_inner(&mut tx.inner, enc, k, now).await?;
            n += 1;
        }
        if n > 0 {
            crate::repo::audit::insert_event_system(&mut tx, audit).await?;
        }
        Ok(())
    }
    .await;
    match r {
        Ok(()) => {
            tx.commit().await?;
            Ok(n)
        }
        Err(e) => {
            tx.rollback().await;
            Err(e)
        }
    }
}
