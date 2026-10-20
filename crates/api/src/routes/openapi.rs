//! `GET /api/v1/openapi.json`: generated from the PolicyRouter table, so the spec can never list a
//! route that has no policy (or miss one). Public only outside production with `OPENAPI_PUBLIC`;
//! otherwise a staff policy (`platform.health.detailed`). Phase 0: paths + security only; request
//! and response schemas arrive with the endpoints (P0-11+).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Extension;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::authz::public_reason;
use crate::router::RouteEntry;

/// The generated document (request extension, inserted by `app::assemble`).
#[derive(Clone, Debug)]
pub struct OpenApiDoc(pub Arc<Vec<u8>>);

#[must_use]
pub fn document(table: &[RouteEntry]) -> Value {
    let mut paths: BTreeMap<&str, serde_json::Map<String, Value>> = BTreeMap::new();
    for r in table {
        let public = public_reason(&r.policy);
        let mut op = serde_json::Map::new();
        op.insert(
            "operationId".into(),
            json!(format!(
                "{}{}",
                r.method.as_str().to_ascii_lowercase(),
                r.path.replace(['/', '{', '}', '-', '.'], "_")
            )),
        );
        op.insert(
            "security".into(),
            if public.is_some() {
                json!([])
            } else {
                json!([{ "bearer": [] }])
            },
        );
        if let Some(reason) = public {
            op.insert("x-public-reason".into(), json!(reason));
        }
        if let Some(p) = r.policy.permission_of() {
            op.insert("x-permission".into(), json!(p.name()));
        }
        if r.policy.is_idempotent() {
            op.insert(
                "parameters".into(),
                json!([{ "name": "Idempotency-Key", "in": "header", "required": true,
                         "schema": { "type": "string", "maxLength": 128 } }]),
            );
        }
        op.insert(
            "responses".into(),
            json!({
                "default": {
                    "description": "RFC 9457 problem document on error",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } }
                }
            }),
        );
        paths
            .entry(r.path)
            .or_default()
            .insert(r.method.as_str().to_ascii_lowercase(), Value::Object(op));
    }
    json!({
        "openapi": "3.1.0",
        "info": { "title": "DSecure API", "version": "v1" },
        "paths": paths,
        "components": {
            "securitySchemes": { "bearer": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" } },
            "schemas": {
                "Problem": {
                    "type": "object",
                    "required": ["type", "title", "status", "code", "detail"],
                    "properties": {
                        "type": { "type": "string" },
                        "title": { "type": "string" },
                        "status": { "type": "integer" },
                        "code": { "type": "string" },
                        "detail": { "type": "string" },
                        "request_id": { "type": "string" },
                        "errors": { "type": "array", "items": { "type": "object",
                            "properties": { "field": { "type": "string" }, "code": { "type": "string" }, "message": { "type": "string" } } } }
                    }
                }
            }
        }
    })
}

pub async fn serve(Extension(doc): Extension<OpenApiDoc>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        doc.0.as_ref().clone(),
    )
        .into_response()
}
