//! `GET /api/v1/me` (proves authn + live state) and `GET /api/v1/me/sessions` (keyset pagination).
//! Identity always from the gate's live principal; nothing from the request body or query decides
//! whose data is returned.

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use common::{AppErrorKind, Page, PageOut};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::authz::{Authz, Caller};
use crate::errors::ApiError;
use crate::state::AppState;

#[derive(Serialize, Debug)]
pub struct MeOut {
    pub user_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub membership_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub role: &'static str,
    pub audience: &'static str,
}

pub async fn me(authz: Authz) -> Result<Json<MeOut>, ApiError> {
    match authz.caller() {
        Caller::Member {
            user,
            tenant,
            membership,
            session,
            role,
            audience,
        } => Ok(Json(MeOut {
            user_id: user.0,
            tenant_id: tenant.0,
            membership_id: membership.0,
            session_id: session.0,
            role: role.as_str(),
            audience,
        })),
        _ => Err(ApiError::misconfigured("/me on a non-member principal")),
    }
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct SessionOut {
    pub id: uuid::Uuid,
    pub client_kind: String,
    pub product_code: Option<String>,
    pub created_at: String,
    pub last_seen_at: String,
    pub expires_at: String,
    pub revoked: bool,
    /// The session of THIS request.
    pub current: bool,
}

fn rfc3339(t: OffsetDateTime) -> Result<String, ApiError> {
    t.format(&Rfc3339)
        .map_err(|e| ApiError(common::AppError::internal(e)))
}

pub async fn sessions(
    State(s): State<AppState>,
    authz: Authz,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<PageOut<SessionOut>>, ApiError> {
    let Ok(Query(q)) = query else {
        return Err(ApiError::new(
            AppErrorKind::BadRequest,
            "request.query_invalid",
            "invalid query parameters (allowed: limit, cursor)",
        ));
    };
    let Caller::Member { session, .. } = authz.caller() else {
        return Err(ApiError::misconfigured(
            "/me/sessions on a non-member principal",
        ));
    };
    let current = *session;
    let page = Page::parse(q.limit, q.cursor.as_deref(), s.cursor_key())?;
    let mut tx = s.db().tenant_tx(authz.scope()).await?;
    // Own membership only (scope actor = caller's live membership).
    let rows =
        db::repo::sessions::list_for_member(&mut tx, authz.scope().actor(), &page, s.cursor_key())
            .await;
    tx.rollback().await;
    let rows = rows?;
    let mut data = Vec::with_capacity(rows.data.len());
    for r in rows.data {
        data.push(SessionOut {
            id: r.id.0,
            client_kind: r.client_kind,
            product_code: r.product_code,
            created_at: rfc3339(r.created_at)?,
            last_seen_at: rfc3339(r.last_seen_at)?,
            expires_at: rfc3339(r.expires_at)?,
            revoked: r.revoked_at.is_some(),
            current: r.id == current,
        });
    }
    Ok(Json(PageOut {
        data,
        next_cursor: rows.next_cursor,
    }))
}
