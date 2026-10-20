//! Layers 5-7 (ARCHITECTURE.md §5, §12.3): global in-flight limit with load shed (no queue),
//! request timeout, JSON body limit. Sab rejections problem+json.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::Semaphore;

use crate::errors::ApiError;
use common::AppErrorKind;

/// Liveness must answer even when the instance is saturated (a failed liveness probe = restart =
/// worse overload). Readiness is NOT exempt.
const SHED_EXEMPT: &[&str] = &["/health/live"];

/// Default route-class timeout (ARCHITECTURE.md §5 layer 6).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Layer 5: `MAX_INFLIGHT_REQUESTS`; full -> 503 + `Retry-After: 1` immediately.
pub async fn inflight(State(sem): State<Arc<Semaphore>>, req: Request, next: Next) -> Response {
    if SHED_EXEMPT.contains(&req.uri().path()) {
        return next.run(req).await;
    }
    match Arc::clone(&sem).try_acquire_owned() {
        Ok(permit) => {
            let res = next.run(req).await;
            drop(permit);
            res
        }
        Err(_) => {
            metrics::counter!("http_load_shed_total").increment(1);
            ApiError::unavailable("service.overloaded").into_response()
        }
    }
}

/// Layer 6: request timeout -> 503 + `Retry-After` (the dropped handler future rolls its tx back).
pub async fn timeout(State(limit): State<Duration>, req: Request, next: Next) -> Response {
    match tokio::time::timeout(limit, next.run(req)).await {
        Ok(res) => res,
        Err(_) => {
            metrics::counter!("http_timeouts_total").increment(1);
            ApiError::new(
                AppErrorKind::Unavailable {
                    retry_after_s: crate::errors::RETRY_AFTER_S,
                },
                "service.timeout",
                "request timed out, retry later",
            )
            .into_response()
        }
    }
}

/// Layer 7: declared `Content-Length` over the limit -> 413 at once; otherwise the body is wrapped
/// in `Limited`, so a chunked body fails while being read (extractors map that to 413).
pub async fn body_limit(State(max): State<usize>, req: Request, next: Next) -> Response {
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|n| n > max as u64) {
        return ApiError::payload_too_large().into_response();
    }
    let (parts, body) = req.into_parts();
    let limited = Body::new(http_body_util::Limited::new(body, max));
    next.run(Request::from_parts(parts, limited)).await
}

/// Was a body read error caused by the size limit?
#[must_use]
pub fn is_length_limit(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if e.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        cur = e.source();
    }
    false
}

/// Read a (already `Limited`) request body; size errors -> 413, others -> 400.
///
/// # Errors
/// `ApiError` 413 / 400.
pub async fn read_body(body: Body) -> Result<bytes::Bytes, ApiError> {
    axum::body::to_bytes(body, usize::MAX).await.map_err(|e| {
        if is_length_limit(&e) {
            ApiError::payload_too_large()
        } else {
            ApiError::new(
                AppErrorKind::BadRequest,
                "request.body_unreadable",
                "request body could not be read",
            )
        }
    })
}
