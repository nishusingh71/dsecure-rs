//! `GET /.well-known/jwks.json`: public JWT verification keys (active + verify-only, not expired),
//! from `signing_keys::list_public`. Cached in memory for [`TTL`] so a busy endpoint costs at most
//! one DB read per minute; clients may cache for the same time (`Cache-Control`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::errors::ApiError;
use crate::state::AppState;

pub const TTL: Duration = Duration::from_secs(60);

async fn build(s: &AppState) -> Result<Arc<Vec<u8>>, ApiError> {
    let mut tx = s.db().system_tx().await?;
    let keys = db::repo::signing_keys::list_public(&mut tx, time::OffsetDateTime::now_utc()).await;
    tx.rollback().await;
    let doc = crate::keys::jwks(&keys?);
    serde_json::to_vec(&doc)
        .map(Arc::new)
        .map_err(|e| ApiError(common::AppError::internal(e)))
}

pub async fn serve(State(s): State<AppState>) -> Result<Response, ApiError> {
    let mut cache = s.jwks_cache().lock().await;
    let body = match cache.as_ref() {
        Some((at, b)) if at.elapsed() < TTL => Arc::clone(b),
        _ => {
            let b = build(&s).await?;
            *cache = Some((Instant::now(), Arc::clone(&b)));
            b
        }
    };
    drop(cache);
    Ok((
        [
            (header::CONTENT_TYPE, "application/jwk-set+json"),
            (header::CACHE_CONTROL, "public, max-age=60"),
        ],
        body.as_ref().clone(),
    )
        .into_response())
}
