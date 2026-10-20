//! Layer 4: request span + RED metrics (`telemetry::log_request_completed`). Sirf route TEMPLATE
//! (`MatchedPath`), method, status, latency, request id. Raw path, query string, client IP aur
//! headers kabhi log/metric mein nahi (T-O1).

use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;

use crate::middleware::request_id::RequestId;

/// Label for requests that matched no route (never the raw path: cardinality + PII).
pub const UNMATCHED: &str = "unmatched";

pub async fn layer(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| UNMATCHED.to_owned(), |m| m.as_str().to_owned());
    let rid = req
        .extensions()
        .get::<RequestId>()
        .map_or_else(String::new, |r| r.0.to_string());
    let res = next.run(req).await;
    telemetry::log_request_completed(
        &rid,
        &route,
        method.as_str(),
        res.status().as_u16(),
        start.elapsed(),
    );
    res
}
