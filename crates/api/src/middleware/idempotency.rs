//! Layer 14: `Idempotency-Key` for routes marked `Policy::idempotent()` (ARCHITECTURE.md §4.1),
//! on top of `db::idempotency` (scope = tx tenant, principal = acting membership).
//!
//! Flow:
//! 1. key required (1..=128 ASCII) else 400; body buffered (already size-limited) and hashed with
//!    method + path: SHA-256;
//! 2. `reserve_committed` (db, its own committed tx; safe on TiDB: exactly one concurrent request
//!    gets `Fresh`). A concurrent duplicate gets 409 `idempotency.in_progress` (+ `Retry-After`)
//!    at once; `Replay` -> stored response (+ `Idempotent-Replayed: true`); `Mismatch` (same key,
//!    different body) -> 409 `idempotency.key_reused`. In-progress keys older than
//!    `db::idempotency::IN_PROGRESS_STALE` (60 s) are taken over by db automatically;
//! 3. the handler gets the BUSINESS transaction through [`IdempotentTx`]; `complete` runs in that
//!    same tx, so the write and the stored response commit together (exactly once);
//! 4. outcome:
//!    - 2xx / 4xx: `complete` (status + `Content-Type` + `Location` + body if the record fits the
//!      16 KB db cap; bodies over [`MAX_CAPTURE_BYTES`] = 256 KB are never buffered) + COMMIT. A
//!      replay of a record without body answers 409 `idempotency.replay_unavailable`;
//!    - 5xx, handler timeout ([`HANDLER_TIMEOUT`], inside the global layer-6 timeout) or panic:
//!      ROLLBACK + `release`, so the client can retry with the same key and body.
//!
//! A client that disconnects mid-request drops this future before `release`: the key stays in
//! progress until the 60 s stale takeover (no spawned clean-up task: tasks must stay bounded).

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use auth::Authorized;
use axum::body::{Body, HttpBody as _};
use axum::extract::{FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use common::AppErrorKind;
use db::TenantTx;
use db::idempotency::{self, MAX_KEY_LEN, MAX_RESPONSE_BYTES, Reservation};
use futures_util::FutureExt as _;
use tokio::sync::Mutex;

use crate::authz::{GateDeps, Granted};
use crate::errors::{ApiError, RETRY_AFTER_S};
use crate::middleware::limits::read_body;

pub const HEADER: &str = "idempotency-key";
pub const REPLAYED_HEADER: &str = "idempotent-replayed";
/// Key retention (ARCHITECTURE.md §4.1: 24 h).
pub const TTL: time::Duration = time::Duration::hours(24);
/// Handler budget inside the global 15 s request timeout, so a slow handler is released here
/// (the outer timeout would drop this future before `release`).
pub const HANDLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(13);
/// Responses bigger than this are never buffered (streamed through; completed without body).
pub const MAX_CAPTURE_BYTES: usize = 256 * 1024;
const _: () = assert!(MAX_CAPTURE_BYTES >= MAX_RESPONSE_BYTES);

/// The business transaction of an idempotent request (the key's `complete` runs in it too).
#[derive(Clone)]
pub struct IdempotentTx(Arc<Mutex<Option<TenantTx>>>);

impl IdempotentTx {
    /// Lock the shared transaction (`None` inside = already finished; handler bug).
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, Option<TenantTx>> {
        self.0.lock().await
    }
}

impl<S: Send + Sync> FromRequestParts<S> for IdempotentTx {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_else(|| ApiError::misconfigured("IdempotentTx on a non-idempotent route"))
    }
}

fn bad_key(code: &'static str, detail: &'static str) -> Response {
    ApiError::new(AppErrorKind::BadRequest, code, detail).into_response()
}

fn conflict(code: &'static str, detail: &'static str, retry: bool) -> Response {
    let mut r = ApiError::new(AppErrorKind::Conflict, code, detail).into_response();
    if retry {
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(RETRY_AFTER_S));
    }
    r
}

fn request_hash(method: &str, path: &str, body: &[u8]) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    ctx.update(method.as_bytes());
    ctx.update(&[0]);
    ctx.update(path.as_bytes());
    ctx.update(&[0]);
    ctx.update(body);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Stored replay record: `MAGIC` + `content-type` line + `location` line + body flag line + body.
/// Header values cannot contain a newline (`HeaderValue` refuses it), so the lines are unambiguous.
/// Only these two headers are replayed (others are per-request: request id, security headers).
const MAGIC: &[u8] = b"\0dsi1\n";
const REPLAYED_HEADERS: [header::HeaderName; 2] = [header::CONTENT_TYPE, header::LOCATION];

/// `body = None` (not captured) or a record over the db cap -> flag `-` (completed without body).
fn encode(headers: &axum::http::HeaderMap, body: Option<&[u8]>) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    for h in &REPLAYED_HEADERS {
        if let Some(v) = headers.get(h) {
            out.extend_from_slice(v.as_bytes());
        }
        out.push(b'\n');
    }
    match body {
        Some(b) if out.len() + 2 + b.len() <= MAX_RESPONSE_BYTES => {
            out.extend_from_slice(b"b\n");
            out.extend_from_slice(b);
        }
        _ => out.extend_from_slice(b"-\n"),
    }
    out
}

fn split_line(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = b.iter().position(|c| *c == b'\n')?;
    Some((&b[..i], &b[i + 1..]))
}

fn replay(status_code: u16, stored: Option<Vec<u8>>) -> Response {
    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK);
    let mut res = status.into_response();
    if let Some(rec) = stored.as_deref().and_then(|b| b.strip_prefix(MAGIC)) {
        let mut rest = rec;
        for h in &REPLAYED_HEADERS {
            let Some((line, tail)) = split_line(rest) else {
                break;
            };
            rest = tail;
            if let Ok(v) = HeaderValue::from_bytes(line)
                && !line.is_empty()
            {
                res.headers_mut().insert(h.clone(), v);
            }
        }
        match split_line(rest) {
            Some((flag, body)) if flag == b"b" => *res.body_mut() = Body::from(body.to_vec()),
            _ => {
                metrics::counter!("idempotency_total", "outcome" => "replay_unavailable")
                    .increment(1);
                return conflict(
                    "idempotency.replay_unavailable",
                    "the original response was too large to store; use a new Idempotency-Key",
                    false,
                );
            }
        }
    } else if let Some(b) = stored {
        // Record without envelope (written before headers were stored): JSON body.
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        *res.body_mut() = Body::from(b);
    }
    res.headers_mut()
        .insert(REPLAYED_HEADER, HeaderValue::from_static("true"));
    res
}

pub(crate) async fn run(deps: &GateDeps, granted: &Granted, req: Request, next: Next) -> Response {
    let Authorized::Tenant { scope, .. } = &granted.authorized else {
        return ApiError::misconfigured("idempotent() on a non-tenant policy").into_response();
    };
    let key = match req.headers().get(HEADER).map(HeaderValue::to_str) {
        None => {
            return bad_key(
                "idempotency.key_required",
                "Idempotency-Key header is required",
            );
        }
        Some(Ok(k)) if !k.is_empty() && k.len() <= MAX_KEY_LEN && k.is_ascii() => k.to_owned(),
        Some(_) => {
            return bad_key(
                "idempotency.key_invalid",
                "Idempotency-Key must be 1..=128 ASCII characters",
            );
        }
    };
    let Some(db) = deps.db.clone() else {
        return ApiError::unavailable("service.unavailable").into_response();
    };
    let (parts, body) = req.into_parts();
    let bytes = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let path = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path(), |p| p.as_str());
    let hash = request_hash(parts.method.as_str(), path, &bytes);
    let principal = scope.actor().0;

    let reserved =
        idempotency::reserve_committed(&db, scope, principal, &key, &hash, deps.clock.now(), TTL)
            .await;
    match reserved {
        Ok(Reservation::Fresh) => {}
        Ok(Reservation::Replay {
            status_code, body, ..
        }) => {
            metrics::counter!("idempotency_total", "outcome" => "replay").increment(1);
            return replay(status_code, body);
        }
        Ok(Reservation::Mismatch) => {
            metrics::counter!("idempotency_total", "outcome" => "mismatch").increment(1);
            return conflict(
                "idempotency.key_reused",
                "Idempotency-Key was already used with a different request",
                false,
            );
        }
        Ok(Reservation::InProgress) => {
            return conflict(
                "idempotency.in_progress",
                "a request with this Idempotency-Key is still running",
                true,
            );
        }
        Err(e) => return ApiError::from(e).into_response(),
    }

    let key_ref = KeyRef {
        db: &db,
        scope,
        principal,
        key: &key,
        hash: &hash,
        deps,
    };
    let tx = match db.tenant_tx(scope).await {
        Ok(tx) => tx,
        Err(e) => {
            key_ref.release("tx_open_failed").await;
            return ApiError::from(e).into_response();
        }
    };
    let shared = IdempotentTx(Arc::new(Mutex::new(Some(tx))));
    let mut req = Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(shared.clone());
    let outcome = tokio::time::timeout(
        HANDLER_TIMEOUT,
        AssertUnwindSafe(next.run(req)).catch_unwind(),
    )
    .await;
    let tx = shared.0.lock().await.take();
    let res = match outcome {
        Ok(Ok(res)) if !res.status().is_server_error() => res,
        other => {
            if let Some(tx) = tx {
                tx.rollback().await;
            }
            let (reason, res) = match other {
                Ok(Ok(res)) => ("server_error", res),
                Ok(Err(_panic)) => (
                    "panic",
                    ApiError::misconfigured("idempotent handler panicked").into_response(),
                ),
                Err(_elapsed) => (
                    "timeout",
                    ApiError::new(
                        AppErrorKind::Unavailable {
                            retry_after_s: RETRY_AFTER_S,
                        },
                        "service.timeout",
                        "request timed out, retry later",
                    )
                    .into_response(),
                ),
            };
            key_ref.release(reason).await;
            return res;
        }
    };
    let Some(tx) = tx else {
        key_ref.release("tx_taken").await;
        return ApiError::misconfigured("idempotent tx taken by handler").into_response();
    };
    record(tx, &key_ref, res).await
}

/// Everything needed to release / complete the key.
struct KeyRef<'a> {
    db: &'a db::Db,
    scope: &'a domain::rbac::TenantScope,
    principal: uuid::Uuid,
    key: &'a str,
    hash: &'a [u8; 32],
    deps: &'a GateDeps,
}

impl KeyRef<'_> {
    /// Free the key for a retry (same key + same body). Failure = stale takeover after 60 s.
    async fn release(&self, reason: &'static str) {
        metrics::counter!("idempotency_released_total", "reason" => reason).increment(1);
        let r = idempotency::release(
            self.db,
            self.scope,
            self.principal,
            self.key,
            self.hash,
            self.deps.clock.now(),
        )
        .await;
        if let Err(e) = r {
            tracing::warn!(error = %e, "idempotency key release failed (stale takeover applies)");
        }
    }
}

/// Capture (bounded), `complete` in the business tx, COMMIT both.
async fn record(mut tx: TenantTx, k: &KeyRef<'_>, res: Response) -> Response {
    let (parts, body) = res.into_parts();
    let capturable = body
        .size_hint()
        .upper()
        .is_some_and(|n| n <= MAX_CAPTURE_BYTES as u64);
    let (captured, out_body) = if capturable {
        match axum::body::to_bytes(body, MAX_CAPTURE_BYTES).await {
            Ok(b) => (Some(b.clone()), Body::from(b)),
            Err(_) => {
                tx.rollback().await;
                k.release("body_failed").await;
                return ApiError::misconfigured("idempotent response body failed").into_response();
            }
        }
    } else {
        (None, body)
    };
    let rec = encode(&parts.headers, captured.as_deref());
    let done = idempotency::complete(
        &mut tx,
        k.principal,
        k.key,
        parts.status.as_u16(),
        Some(rec.as_slice()),
        None,
    )
    .await;
    if let Err(e) = done {
        tx.rollback().await;
        k.release("complete_failed").await;
        return ApiError::from(e).into_response();
    }
    if let Err(e) = tx.commit().await {
        // Rolled back with the business write: free the key for a retry. Unknown commit outcome:
        // keep the key (a retry could double-execute); stale takeover after 60 s.
        if !matches!(e, db::DbError::CommitUnknown) {
            k.release("commit_failed").await;
        }
        return ApiError::from(e).into_response();
    }
    metrics::counter!("idempotency_total", "outcome" => "fresh").increment(1);
    Response::from_parts(parts, out_body)
}

#[cfg(test)]
mod tests {
    use super::{encode, replay, request_hash};
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header};

    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        h.insert(header::LOCATION, HeaderValue::from_static("/api/v1/x/1"));
        h.insert("x-request-id", HeaderValue::from_static("not-replayed"));
        h
    }

    #[tokio::test]
    async fn replay_restores_content_type_location_and_body() {
        let r = replay(201, Some(encode(&headers(), Some(b"{\"id\":1}"))));
        assert_eq!(r.status(), StatusCode::CREATED);
        assert_eq!(r.headers()[header::LOCATION], "/api/v1/x/1");
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/json");
        assert!(!r.headers().contains_key("x-request-id"));
        let b = axum::body::to_bytes(r.into_body(), 1024).await.expect("b");
        assert_eq!(&b[..], b"{\"id\":1}");
    }

    #[tokio::test]
    async fn oversized_or_uncaptured_body_replays_409_unavailable() {
        for rec in [
            encode(&headers(), Some(&vec![b'x'; 20_000])),
            encode(&headers(), None),
        ] {
            assert!(rec.len() <= db::idempotency::MAX_RESPONSE_BYTES);
            let r = replay(201, Some(rec));
            assert_eq!(r.status(), StatusCode::CONFLICT);
            let b = axum::body::to_bytes(r.into_body(), 1 << 16)
                .await
                .expect("b");
            let v: serde_json::Value = serde_json::from_slice(&b).expect("json");
            assert_eq!(v["code"], "idempotency.replay_unavailable");
        }
    }

    #[test]
    fn hash_binds_method_path_and_body() {
        let a = request_hash("POST", "/x", b"{}");
        assert_eq!(a, request_hash("POST", "/x", b"{}"));
        assert_ne!(a, request_hash("POST", "/x", b"{ }"));
        assert_ne!(a, request_hash("PUT", "/x", b"{}"));
        assert_ne!(a, request_hash("POST", "/y", b"{}"));
        // separator: no ambiguity between path and body bytes
        assert_ne!(
            request_hash("POST", "/ab", b"c"),
            request_hash("POST", "/a", b"bc")
        );
    }
}
