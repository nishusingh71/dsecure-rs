//! Request span helper. Raw path (ids), query string aur client IP kabhi span/metric mein nahi jaate:
//! sirf request id, route TEMPLATE, method, status, latency.

use std::time::Duration;

use tracing::Span;

use crate::meters::{method_label, record_request, sanitize_route};

const MAX_REQUEST_ID_LEN: usize = 64;

/// Request id sirf `[A-Za-z0-9_-]` aur <= 64 chars ho; warna `invalid` (client-supplied header se injection nahi).
pub fn sanitize_request_id(id: &str) -> &str {
    if !id.is_empty()
        && id.len() <= MAX_REQUEST_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        id
    } else {
        "invalid"
    }
}

/// `request` span with fields `request_id`, `route`, `method`, `status`, `latency_ms`.
pub fn request_span(
    request_id: &str,
    route_template: &str,
    method: &str,
    status: u16,
    latency: Duration,
) -> Span {
    let route = sanitize_route(route_template);
    tracing::info_span!(
        "request",
        request_id = sanitize_request_id(request_id),
        route = %route,
        method = method_label(method),
        status = status,
        latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX),
    )
}

/// Request complete hone par: span banao, ek log event emit karo (5xx = error) aur RED metrics record karo.
pub fn log_request_completed(
    request_id: &str,
    route_template: &str,
    method: &str,
    status: u16,
    latency: Duration,
) {
    record_request(method, route_template, status, latency);
    request_span(request_id, route_template, method, status, latency).in_scope(|| {
        if status >= 500 {
            tracing::error!("request completed");
        } else {
            tracing::info!("request completed");
        }
    });
}
