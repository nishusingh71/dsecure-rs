//! `sessions` + `refresh_tokens` (identity class; DATABASE.md §5). Member activity lists are read
//! through `TenantTx` (tenant from the scope, row-tenant assert on every row).

use crate::error::DbError;
use crate::keyset;
use crate::queries::{
    MEMBERSHIPS_BELONGS_TO_USER, REFRESH_TOKENS_FIND_BY_HASH, REFRESH_TOKENS_INSERT,
    REFRESH_TOKENS_MARK_USED, REFRESH_TOKENS_REVOKE_FAMILY, SESSIONS_GET, SESSIONS_INSERT,
    SESSIONS_LIST_MEMBER, SESSIONS_REVOKE,
};
use crate::repo::memberships;
use crate::sql;
use crate::tx::{IdentityTx, TenantTx};
use crate::write_guard::WriteOutcome;
use common::{MembershipId, Page, PageOut, SessionId, TenantId, UserId};
use sqlx::mysql::MySqlRow;
use time::OffsetDateTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalKind {
    Member,
    Staff,
    Cleaner,
}

impl PrincipalKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Staff => "staff",
            Self::Cleaner => "cleaner",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientKind {
    Web,
    DesktopApp,
    PlatformConsole,
}

impl ClientKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::DesktopApp => "desktop_app",
            Self::PlatformConsole => "platform_console",
        }
    }
}

/// `tenant` + `membership` come from the verified directory lookup at login (both or neither).
#[derive(Clone, Debug)]
pub struct NewSession {
    pub id: SessionId,
    pub user_id: UserId,
    pub tenant: Option<(TenantId, MembershipId)>,
    pub principal_kind: PrincipalKind,
    pub client_kind: ClientKind,
    pub product_code: Option<String>,
    pub device_label: Option<String>,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    pub id: SessionId,
    pub user_id: UserId,
    pub tenant: Option<TenantId>,
    pub membership: Option<MembershipId>,
    pub principal_kind: String,
    pub client_kind: String,
    pub product_code: Option<String>,
    pub device_label: Option<String>,
    pub mfa_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoke_reason: Option<String>,
}

fn map_session(row: &MySqlRow) -> Result<SessionRow, DbError> {
    Ok(SessionRow {
        id: SessionId(sql::uuid_col(row, "id")?),
        user_id: UserId(sql::uuid_col(row, "user_id")?),
        tenant: sql::opt_uuid_col(row, "tenant_id")?.map(TenantId),
        membership: sql::opt_uuid_col(row, "membership_id")?.map(MembershipId),
        principal_kind: sql::col(row, "principal_kind")?,
        client_kind: sql::col(row, "client_kind")?,
        product_code: sql::col(row, "product_code")?,
        device_label: sql::col(row, "device_label")?,
        mfa_at: sql::col(row, "mfa_at")?,
        created_at: sql::col(row, "created_at")?,
        last_seen_at: sql::col(row, "last_seen_at")?,
        expires_at: sql::col(row, "expires_at")?,
        revoked_at: sql::col(row, "revoked_at")?,
        revoke_reason: sql::col(row, "revoke_reason")?,
    })
}

/// Create a session. A member session's membership must belong to `user_id` in that tenant and be
/// active (parent check).
///
/// # Errors
/// `NotFound("membership")`, server errors.
pub async fn insert(
    tx: &mut IdentityTx,
    s: &NewSession,
    now: OffsetDateTime,
) -> Result<SessionId, DbError> {
    if let Some((t, m)) = s.tenant
        && !tx
            .inner
            .exists(
                sql::q(MEMBERSHIPS_BELONGS_TO_USER)
                    .bind(t.0)
                    .bind(m.0)
                    .bind(s.user_id.0),
            )
            .await?
    {
        return Err(DbError::NotFound("membership"));
    }
    tx.inner
        .execute(
            sql::q(SESSIONS_INSERT)
                .bind(s.id.0)
                .bind(s.user_id.0)
                .bind(s.tenant.map(|(t, _)| t.0))
                .bind(s.tenant.map(|(_, m)| m.0))
                .bind(s.principal_kind.as_str())
                .bind(s.client_kind.as_str())
                .bind(s.product_code.as_deref())
                .bind(s.device_label.as_deref())
                .bind(now)
                .bind(now)
                .bind(s.expires_at),
        )
        .await?
        .expect_one()?;
    Ok(s.id)
}

/// Point get by session id (from the token).
///
/// # Errors
/// Server / decode errors.
pub async fn get(tx: &mut IdentityTx, id: SessionId) -> Result<Option<SessionRow>, DbError> {
    tx.inner
        .fetch_optional(sql::q(SESSIONS_GET).bind(id.0))
        .await?
        .as_ref()
        .map(map_session)
        .transpose()
}

/// Revoke; `false` = already revoked or unknown.
///
/// # Errors
/// Server errors.
pub async fn revoke(
    tx: &mut IdentityTx,
    id: SessionId,
    reason: &'static str,
    now: OffsetDateTime,
) -> Result<bool, DbError> {
    let n = tx
        .inner
        .execute(sql::q(SESSIONS_REVOKE).bind(now).bind(reason).bind(id.0))
        .await?;
    Ok(n == 1)
}

/// Sessions of one member of the tx tenant (keyset, newest first), within tx visibility.
///
/// # Errors
/// `TenantMismatch`, server / decode errors. Invisible member = empty page.
pub async fn list_for_member(
    tx: &mut TenantTx,
    membership: MembershipId,
    page: &Page,
    cursor_key: &[u8],
) -> Result<PageOut<SessionRow>, DbError> {
    if memberships::get(tx, membership).await?.is_none() {
        return keyset::finish(Vec::new(), page, cursor_key, |s: &SessionRow| {
            (s.created_at, s.id.0)
        });
    }
    let tid = tx.tid();
    let rows = tx
        .inner
        .fetch_all(
            sql::q(SESSIONS_LIST_MEMBER)
                .bind(tid)
                .bind(membership.0)
                .bind(keyset::after_id(page))
                .bind(keyset::fetch_limit(page)),
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        // L6 first (F11): tenant checked before any other column is decoded.
        let row_tenant =
            sql::opt_uuid_col(r, "tenant_id")?.map_or(TenantId(uuid::Uuid::nil()), TenantId);
        tx.assert_row_tenant(row_tenant)?;
        out.push(map_session(r)?);
    }
    keyset::finish(out, page, cursor_key, |s| (s.created_at, s.id.0))
}

#[derive(Clone, Debug)]
pub struct NewRefreshToken {
    pub id: uuid::Uuid,
    pub session: SessionId,
    pub family_id: uuid::Uuid,
    pub token_hash: [u8; 32],
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshTokenRow {
    pub id: uuid::Uuid,
    pub session: SessionId,
    pub family_id: uuid::Uuid,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    pub replaced_by: Option<uuid::Uuid>,
    pub revoked_at: Option<OffsetDateTime>,
}

/// # Errors
/// Server errors.
pub async fn insert_refresh(
    tx: &mut IdentityTx,
    t: &NewRefreshToken,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    tx.inner
        .execute(
            sql::q(REFRESH_TOKENS_INSERT)
                .bind(t.id)
                .bind(t.session.0)
                .bind(t.family_id)
                .bind(&t.token_hash[..])
                .bind(now)
                .bind(t.expires_at),
        )
        .await?
        .expect_one()
}

/// # Errors
/// Server / decode errors.
pub async fn find_refresh_by_hash(
    tx: &mut IdentityTx,
    token_hash: &[u8; 32],
) -> Result<Option<RefreshTokenRow>, DbError> {
    let Some(r) = tx
        .inner
        .fetch_optional(sql::q(REFRESH_TOKENS_FIND_BY_HASH).bind(&token_hash[..]))
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(RefreshTokenRow {
        id: sql::uuid_col(&r, "id")?,
        session: SessionId(sql::uuid_col(&r, "session_id")?),
        family_id: sql::uuid_col(&r, "family_id")?,
        issued_at: sql::col(&r, "issued_at")?,
        expires_at: sql::col(&r, "expires_at")?,
        used_at: sql::col(&r, "used_at")?,
        replaced_by: sql::opt_uuid_col(&r, "replaced_by")?,
        revoked_at: sql::col(&r, "revoked_at")?,
    }))
}

/// Rotation step: mark `id` used exactly once.
///
/// # Errors
/// `Conflict("auth.refresh_reused")` when already used/revoked (caller revokes the family).
pub async fn mark_refresh_used(
    tx: &mut IdentityTx,
    id: uuid::Uuid,
    replaced_by: uuid::Uuid,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    let n = tx
        .inner
        .execute(
            sql::q(REFRESH_TOKENS_MARK_USED)
                .bind(now)
                .bind(replaced_by)
                .bind(id),
        )
        .await?;
    if n == 1 {
        Ok(())
    } else {
        Err(DbError::Conflict("auth.refresh_reused"))
    }
}

/// Reuse detection: revoke every live token of the family. Returns revoked count.
///
/// # Errors
/// Server errors.
pub async fn revoke_family(
    tx: &mut IdentityTx,
    family_id: uuid::Uuid,
    now: OffsetDateTime,
) -> Result<u64, DbError> {
    tx.inner
        .execute(
            sql::q(REFRESH_TOKENS_REVOKE_FAMILY)
                .bind(now)
                .bind(family_id),
        )
        .await
}
