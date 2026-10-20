//! Layers 8-9: CORS (config allowlist) + security headers (SECURITY.md §11: HSTS, nosniff, frame deny,
//! `Cache-Control: no-store`). JSON-only API: strict CSP, no referrer.

use std::time::Duration;

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::Response;
use tower_http::cors::{AllowOrigin, CorsLayer};

const STATIC_HEADERS: &[(HeaderName, &str)] = &[
    (
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=63072000; includeSubDomains",
    ),
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (header::X_FRAME_OPTIONS, "DENY"),
    (header::REFERRER_POLICY, "no-referrer"),
    (
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; frame-ancestors 'none'",
    ),
];

pub async fn headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    for (name, value) in STATIC_HEADERS {
        if !h.contains_key(name) {
            h.insert(name.clone(), HeaderValue::from_static(value));
        }
    }
    // API responses (tenant data) are never cacheable; a handler may opt in explicitly later.
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

/// `CORS_ALLOWED_ORIGINS` allowlist. Empty = no CORS headers at all (same-origin only). `*` is only
/// accepted outside production (config validation refuses it in prod). Invalid entries are skipped
/// and counted (never logged by value).
pub fn cors(origins: &[String]) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::IF_MATCH,
            HeaderName::from_static("idempotency-key"),
            HeaderName::from_static(crate::authz::STEP_UP_HEADER),
            HeaderName::from_static(crate::middleware::request_id::HEADER),
        ])
        .expose_headers([
            HeaderName::from_static(crate::middleware::request_id::HEADER),
            header::RETRY_AFTER,
            header::ETAG,
        ])
        .max_age(Duration::from_secs(600));
    if origins.iter().any(|o| o == "*") {
        return base.allow_origin(AllowOrigin::any());
    }
    let mut list = Vec::with_capacity(origins.len());
    for o in origins {
        match HeaderValue::from_str(o.trim()) {
            Ok(v) => list.push(v),
            Err(_) => tracing::warn!("CORS_ALLOWED_ORIGINS entry skipped (invalid)"),
        }
    }
    base.allow_origin(AllowOrigin::list(list))
}
