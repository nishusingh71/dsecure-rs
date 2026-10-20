//! `AppError` -> RFC 9457 `application/problem+json` (ARCHITECTURE.md §7).
//!
//! Rules:
//! - Body sirf stable `code`, safe `detail`, `status`, `request_id`, `errors[]`. Kabhi value, SQL,
//!   token, email ya source error client ko nahi jaata (`source` sirf log mein).
//! - 5xx (Unavailable ke alawa) ka detail hamesha generic "internal error".
//! - Auth failures generic: har 401 = `auth.unauthenticated` + `WWW-Authenticate: Bearer`.
//! - Busy (storage upload limiter, login hash queue) = 503 + `Retry-After`.

use std::borrow::Cow;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use common::{AppError, AppErrorKind, FieldError};
use serde::Serialize;

use crate::middleware::request_id;

pub const PROBLEM_JSON: &str = "application/problem+json";
/// The single credential-failure code (login, refresh, step-up).
pub const LOGIN_FAILED: &str = "auth.invalid_credentials";
pub const MFA_REQUIRED: &str = "auth.mfa_required";
/// Retry hint for load shed / busy / transient DB (seconds).
pub const RETRY_AFTER_S: u32 = 1;

/// Handler error type. `common::AppError` + `IntoResponse` (orphan rule ki wajah se newtype).
#[derive(Debug)]
pub struct ApiError(pub AppError);

impl ApiError {
    #[must_use]
    pub fn new(
        kind: AppErrorKind,
        code: &'static str,
        detail: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self(AppError::new(kind, code, detail))
    }

    /// The ONE generic 401.
    #[must_use]
    pub fn unauthenticated() -> Self {
        Self::new(
            AppErrorKind::Unauthenticated,
            "auth.unauthenticated",
            "authentication required",
        )
    }

    /// 503 + `Retry-After: 1`.
    #[must_use]
    pub fn unavailable(code: &'static str) -> Self {
        Self::new(
            AppErrorKind::Unavailable {
                retry_after_s: RETRY_AFTER_S,
            },
            code,
            "service temporarily unavailable, retry later",
        )
    }

    #[must_use]
    pub fn payload_too_large() -> Self {
        Self::new(
            AppErrorKind::PayloadTooLarge,
            "request.too_large",
            "request body exceeds the allowed size",
        )
    }

    #[must_use]
    pub fn not_found() -> Self {
        Self::new(AppErrorKind::NotFound, "not_found", "resource not found")
    }

    /// Server-side wiring bug (fail closed, 500).
    #[must_use]
    pub fn misconfigured(what: &'static str) -> Self {
        Self(AppError::internal(Misconfigured(what)))
    }

    #[must_use]
    pub const fn kind(&self) -> AppErrorKind {
        self.0.kind
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.0.code
    }

    #[must_use]
    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.0.kind.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("server misconfiguration: {0}")]
struct Misconfigured(&'static str);

impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        Self(e)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Serialize)]
struct Problem<'a> {
    #[serde(rename = "type")]
    type_: String,
    title: &'static str,
    status: u16,
    code: &'a str,
    detail: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    errors: &'a [FieldError],
}

/// Serialise a problem document (also used by the panic handler, which has no task-local id).
#[must_use]
pub fn problem_body(
    status: StatusCode,
    code: &str,
    detail: &str,
    request_id: Option<String>,
    fields: &[FieldError],
) -> Vec<u8> {
    let p = Problem {
        type_: format!("urn:dsecure:problem:{code}"),
        title: status.canonical_reason().unwrap_or("Error"),
        status: status.as_u16(),
        code,
        detail,
        request_id,
        errors: fields,
    };
    serde_json::to_vec(&p).unwrap_or_else(|_| b"{\"code\":\"internal\"}".to_vec())
}

fn log(e: &AppError, status: StatusCode) {
    // Source sirf log mein (value-free error types; RedactingLayer masks anything that looks
    // sensitive). Client ko nahi.
    let source = e.source.as_ref().map(|s| format!("{s:#}"));
    if status.is_server_error() {
        tracing::error!(code = e.code, status = status.as_u16(), source = ?source, "request failed");
    } else {
        tracing::debug!(code = e.code, status = status.as_u16(), "request rejected");
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let e = self.0;
        let status =
            StatusCode::from_u16(e.kind.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        log(&e, status);
        let (code, detail): (&str, &str) = match e.kind {
            // Credential failures: the ONE generic login failure.
            AppErrorKind::Unauthenticated if e.code == LOGIN_FAILED => {
                (LOGIN_FAILED, "invalid credentials")
            }
            // Password was correct, second factor missing (not an enumeration oracle: it needs
            // the right password first).
            AppErrorKind::Unauthenticated if e.code == MFA_REQUIRED => {
                (MFA_REQUIRED, "a second factor is required")
            }
            // Every other 401: generic, whatever the caller built.
            AppErrorKind::Unauthenticated => ("auth.unauthenticated", "authentication required"),
            AppErrorKind::Internal | AppErrorKind::NotPersisted => (e.code, "internal error"),
            _ => (e.code, &e.detail),
        };
        let fields: &[FieldError] = if status.is_server_error() {
            &[]
        } else {
            &e.fields
        };
        let body = problem_body(status, code, detail, request_id::current(), fields);
        let mut res = (status, body).into_response();
        let h = res.headers_mut();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        match e.kind {
            AppErrorKind::RateLimited { retry_after_s }
            | AppErrorKind::Unavailable { retry_after_s } => {
                h.insert(header::RETRY_AFTER, HeaderValue::from(retry_after_s.max(1)));
            }
            AppErrorKind::Unauthenticated => {
                h.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            }
            _ => {}
        }
        res
    }
}

// ---- conversions from the other crates (value-free; source kept for the log only) ----

impl From<db::DbError> for ApiError {
    fn from(e: db::DbError) -> Self {
        use AppErrorKind as K;
        use db::DbError as D;
        let (kind, code, detail): (AppErrorKind, &'static str, &'static str) = match &e {
            D::NotFound(_) => (K::NotFound, "not_found", "resource not found"),
            D::NotPersisted { .. } => (K::NotPersisted, "write.not_persisted", "internal error"),
            D::Conflict(c) => (K::Conflict, *c, "conflict with the current state"),
            D::LastOwner => (
                K::Conflict,
                "members.last_owner",
                "the last owner cannot be removed or demoted",
            ),
            D::QuotaExceeded { .. } => (K::QuotaExceeded, "quota.exceeded", "quota exceeded"),
            D::Invalid(_) => (K::BadRequest, "request.invalid", "invalid request"),
            D::Forbidden(_) | D::ReadOnly => (K::Forbidden, "authz.forbidden", "forbidden"),
            D::Duplicate { .. } => (K::Conflict, "conflict.duplicate", "resource already exists"),
            D::Transient { .. } | D::Timeout | D::Unavailable => (
                K::Unavailable {
                    retry_after_s: RETRY_AFTER_S,
                },
                "service.unavailable",
                "service temporarily unavailable, retry later",
            ),
            D::TenantMismatch => {
                // L6 row-tenant assert: never data, always an alert.
                metrics::counter!("tenant_row_mismatch_total").increment(1);
                tracing::error!(alert = "db.tenant_mismatch", "row tenant mismatch");
                (K::Internal, "internal", "internal error")
            }
            _ => (K::Internal, "internal", "internal error"),
        };
        Self(AppError::new(kind, code, detail).with_source(e))
    }
}

impl From<storage::StorageError> for ApiError {
    fn from(e: storage::StorageError) -> Self {
        use storage::StorageError as S;
        match &e {
            S::Busy => Self(Self::unavailable("storage.busy").0.with_source(e)),
            S::TooLarge { .. } => Self(Self::payload_too_large().0.with_source(e)),
            S::NotFound => Self(Self::not_found().0.with_source(e)),
            _ => Self(AppError::internal(e)),
        }
    }
}

impl From<crypto::CryptoError> for ApiError {
    fn from(e: crypto::CryptoError) -> Self {
        match &e {
            // Login hash queue full (LOGIN_HASH_CONCURRENCY): 503, never a queue.
            crypto::CryptoError::Busy => Self(Self::unavailable("service.busy").0.with_source(e)),
            _ => Self(AppError::internal(e)),
        }
    }
}

impl From<auth::AuthError> for ApiError {
    fn from(e: auth::AuthError) -> Self {
        match &e {
            auth::AuthError::Unauthenticated(r) => {
                metrics::counter!("auth_rejections_total", "reason" => r.label()).increment(1);
                Self::unauthenticated()
            }
            auth::AuthError::Unavailable => {
                Self(Self::unavailable("service.unavailable").0.with_source(e))
            }
            auth::AuthError::Forbidden(_) => {
                Self::new(AppErrorKind::Forbidden, "authz.forbidden", "forbidden")
            }
            auth::AuthError::Internal(_) => Self(AppError::internal(e)),
        }
    }
}

impl From<auth::LoginError> for ApiError {
    fn from(e: auth::LoginError) -> Self {
        match e {
            auth::LoginError::Busy => Self::unavailable("auth.busy"),
            auth::LoginError::Unavailable => Self::unavailable("service.unavailable"),
            auth::LoginError::MfaRequired => {
                Self::new(AppErrorKind::Unauthenticated, MFA_REQUIRED, "")
            }
            // Failed (and TenantChoiceRequired, which the login route answers itself): the
            // generic failure (no tenant ids, no reason).
            _ => Self::new(AppErrorKind::Unauthenticated, LOGIN_FAILED, ""),
        }
    }
}

impl From<auth::Denied> for ApiError {
    fn from(d: auth::Denied) -> Self {
        use auth::DenyCode;
        metrics::counter!("authz_denials_total", "code" => d.code_str()).increment(1);
        match d.status() {
            401 => Self::unauthenticated(),
            // Cross-tenant / out of scope look exactly like a missing row.
            404 => Self::not_found(),
            500 => Self::misconfigured("route policy"),
            503 => Self::unavailable("service.unavailable"),
            _ => match d.code {
                DenyCode::Forbidden => {
                    Self::new(AppErrorKind::Forbidden, "authz.forbidden", "forbidden")
                }
                DenyCode::FeatureDisabled(_) => Self::new(
                    AppErrorKind::FeatureDisabled,
                    "feature.disabled",
                    "this feature is not enabled for the tenant",
                ),
                DenyCode::StepUpRequired => Self::new(
                    AppErrorKind::StepUpRequired,
                    "auth.step_up_required",
                    "re-authentication required for this action",
                ),
                _ => Self::new(AppErrorKind::Forbidden, d.code_str(), "forbidden"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body(r: Response) -> serde_json::Value {
        let b = to_bytes(r.into_body(), 1 << 16).await.expect("body");
        serde_json::from_slice(&b).expect("json")
    }

    #[tokio::test]
    async fn internal_never_leaks_source_or_detail() {
        let e = ApiError(
            AppError::new(AppErrorKind::Internal, "internal", "db password=hunter2")
                .with_source(std::io::Error::other("secret path C:/x")),
        );
        let r = e.into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(r.headers()[header::CONTENT_TYPE], PROBLEM_JSON);
        let v = body(r).await;
        let s = v.to_string();
        assert!(!s.contains("hunter2") && !s.contains("C:/x"), "{s}");
        assert_eq!(v["detail"], "internal error");
        assert_eq!(v["status"], 500);
        assert_eq!(v["type"], "urn:dsecure:problem:internal");
    }

    #[tokio::test]
    async fn busy_maps_to_503_with_retry_after() {
        for e in [
            ApiError::from(storage::StorageError::Busy),
            ApiError::from(crypto::CryptoError::Busy),
            ApiError::from(auth::LoginError::Busy),
            ApiError::from(db::DbError::Unavailable),
        ] {
            let r = e.into_response();
            assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(r.headers()[header::RETRY_AFTER], "1");
        }
    }

    #[tokio::test]
    async fn auth_failures_are_generic() {
        let a = ApiError::from(auth::AuthError::Unauthenticated(
            auth::Rejection::BadSignature,
        ))
        .into_response();
        let b = ApiError::from(auth::AuthError::Unauthenticated(auth::Rejection::Expired))
            .into_response();
        assert_eq!(a.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(a.headers()[header::WWW_AUTHENTICATE], "Bearer");
        assert_eq!(body(a).await, body(b).await);
    }

    #[tokio::test]
    async fn db_mapping() {
        let r = ApiError::from(db::DbError::NotFound("membership")).into_response();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let v = body(r).await;
        assert!(!v.to_string().contains("membership"));
        let r = ApiError::from(db::DbError::NotPersisted {
            expected: 1,
            actual: 0,
        })
        .into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let r = ApiError::from(db::DbError::Conflict("users.email_taken")).into_response();
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(body(r).await["code"], "users.email_taken");
        assert_eq!(
            ApiError::from(storage::StorageError::TooLarge { max: 1 })
                .into_response()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn field_errors_are_listed_for_4xx() {
        let e = ApiError(
            AppError::bad_request("request.invalid", "invalid request")
                .with_field(FieldError::new("limit", "range", "must be 1..=200")),
        );
        let v = body(e.into_response()).await;
        assert_eq!(v["errors"][0]["field"], "limit");
    }
}
