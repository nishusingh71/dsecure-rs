//! Layer 2: `X-Request-Id` (ARCHITECTURE.md §5). Client id sirf tab accept hota hai jab woh
//! 1..=64 chars `[A-Za-z0-9_-]` ho (UUID fit hota hai); warna naya UUIDv7. Id response header mein
//! wapas jaata hai aur task-local se problem+json `request_id` mein.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

pub const HEADER: &str = "x-request-id";
const MAX_LEN: usize = 64;

tokio::task_local! {
    static REQUEST_ID: Arc<str>;
}

/// Request extension with the accepted/generated id.
#[derive(Clone, Debug)]
pub struct RequestId(pub Arc<str>);

/// Id of the request being handled on this task (None outside a request).
#[must_use]
pub fn current() -> Option<String> {
    REQUEST_ID.try_with(|r| r.to_string()).ok()
}

/// Client-supplied id if it is safe to echo and log.
#[must_use]
pub fn accept(raw: &str) -> Option<&str> {
    let ok = !raw.is_empty()
        && raw.len() <= MAX_LEN
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ok.then_some(raw)
}

pub async fn layer(mut req: Request, next: Next) -> Response {
    let id: Arc<str> = req
        .headers()
        .get(HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(accept)
        .map_or_else(|| Arc::from(uuid::Uuid::now_v7().to_string()), Arc::from);
    req.extensions_mut().insert(RequestId(Arc::clone(&id)));
    let mut res = REQUEST_ID.scope(Arc::clone(&id), next.run(req)).await;
    if let Ok(v) = HeaderValue::from_str(&id) {
        res.headers_mut().insert(HEADER, v);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::accept;

    #[test]
    fn accepts_only_safe_ids() {
        assert_eq!(accept("abc-123_X"), Some("abc-123_X"));
        assert!(accept("").is_none());
        assert!(accept("a b").is_none());
        assert!(accept("x\r\ny").is_none());
        assert!(accept(&"a".repeat(65)).is_none());
        assert!(accept("0192f3c4-7a1b-7c3d-8e9f-0123456789ab").is_some());
    }
}
