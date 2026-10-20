//! `POST /api/v1/dev/fixtures` (feature `dev-fixtures`, debug builds only, registered only when
//! `DSECURE_ENV` is dev/test): seed one verified user + its own tenant (owner) for local testing.
//! Never compiled into a release binary (`debug_assertions` off).

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use common::{MembershipId, TenantId, UserId};
use crypto::{
    AesGcmFieldEncryptor, Argon2Params, Argon2idHasher, BlindIndexer, BlindKind, BlindScope,
    FieldContext, FieldEncryptor, HmacBlindIndexer, KeyPurpose, ParamPolicy, PasswordHasher,
};
use db::repo::tenants::{self, NewOwner, NewTenant, TenantKind};
use db::repo::users::{self, HashScheme, NewUser, UserStatus};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::errors::ApiError;
use crate::json::JsonBody;
use crate::state::AppState;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedIn {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct SeedOut {
    pub user_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub membership_id: uuid::Uuid,
}

pub async fn seed(
    State(s): State<AppState>,
    JsonBody(input): JsonBody<SeedIn>,
) -> Result<(StatusCode, Json<SeedOut>), ApiError> {
    if !s.environment().is_local() {
        return Err(ApiError::not_found());
    }
    let keys = s
        .keys()
        .cloned()
        .ok_or_else(|| ApiError::unavailable("keys.not_loaded"))?;
    let indexer = HmacBlindIndexer::new(Arc::clone(&keys));
    let enc = AesGcmFieldEncryptor::new(keys);
    let hasher = Argon2idHasher::new(
        Argon2Params {
            m_kib: 19_456,
            t: 2,
            p: 1,
        },
        1,
        std::time::Duration::from_secs(5),
        ParamPolicy::Relaxed,
    )?;
    let email = common::Email::parse(&input.email).map_err(ApiError::from)?;
    let user_id = UserId::new();
    let bidx = indexer.index(BlindKind::Email, BlindScope::Global, email.as_str())?;
    let email_enc = enc
        .encrypt(
            email.as_str().as_bytes(),
            &FieldContext::new("users", "email_enc", None, user_id.0, KeyPurpose::Identity),
        )
        .await?;
    let phc = hasher.hash(SecretString::from(input.password)).await?;
    let now = time::OffsetDateTime::now_utc();

    let mut tx = s.db().identity_tx().await?;
    users::insert(
        &mut tx,
        &NewUser {
            id: user_id,
            email_bidx: bidx,
            email_enc,
            name_enc: None,
            status: UserStatus::Active,
        },
        now,
    )
    .await?;
    users::set_password(&mut tx, user_id, &phc, HashScheme::Argon2id, now).await?;
    db::repo::auth_account::mark_email_verified(&mut tx, user_id, "staff", now).await?;
    tx.commit().await?;

    let mut tx = s.db().system_tx().await?;
    let created = tenants::create(
        &mut tx,
        &NewTenant {
            id: TenantId::new(),
            kind: TenantKind::Organization,
            // Dev placeholder (tenant DEKs need the tenant row first).
            display_name_enc: b"dev".to_vec(),
        },
        &NewOwner {
            membership_id: MembershipId::new(),
            user_id,
            display_name_enc: None,
        },
        now,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(SeedOut {
            user_id: user_id.0,
            tenant_id: created.tenant.0,
            membership_id: created.owner.0,
        }),
    ))
}
