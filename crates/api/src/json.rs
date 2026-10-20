//! `JsonBody<T>`: JSON request extractor with problem+json rejections (413 over the body limit,
//! 415 wrong content type, 400 bad JSON). The body is already wrapped in `Limited` by the body-limit
//! layer, so reading never buffers more than `MAX_JSON_BODY_BYTES`.

use axum::extract::{FromRequest, Request};
use axum::http::header;
use common::{AppErrorKind, FieldError};
use serde::de::DeserializeOwned;

use crate::errors::ApiError;
use crate::middleware::limits::read_body;

#[derive(Debug)]
pub struct JsonBody<T>(pub T);

fn is_json(req: &Request) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| {
            let m = m.trim();
            m.eq_ignore_ascii_case("application/json")
                || (m.starts_with("application/") && m.ends_with("+json"))
        })
}

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for JsonBody<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, ApiError> {
        if !is_json(&req) {
            return Err(ApiError::new(
                AppErrorKind::BadRequest,
                "request.unsupported_media_type",
                "Content-Type must be application/json",
            ));
        }
        let bytes = read_body(req.into_body()).await?;
        serde_json::from_slice(&bytes).map(JsonBody).map_err(|e| {
            // Position only: serde messages can echo input values.
            let mut err = ApiError::new(
                AppErrorKind::BadRequest,
                "request.json_invalid",
                "request body is not valid JSON for this endpoint",
            );
            err.0 = err.0.with_field(FieldError::new(
                "body",
                "invalid",
                format!("line {} column {}", e.line(), e.column()),
            ));
            err
        })
    }
}
