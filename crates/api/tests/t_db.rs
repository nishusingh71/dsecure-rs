//! End-to-end on the LOCAL MySQL 8.4 scratch DB: T-H1 (readiness), authz
//! (401/403), idempotency (replay / 409), cross-tenant (`/me` shows only the caller).

// Test-only crate: helpers outside #[test] fns are not covered by clippy.toml allow-*-in-tests.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use std::sync::atomic::{AtomicU64, Ordering};

use api::json::JsonBody;
use api::{AppState, Authz, PolicyRouter, RouteOptions};
use auth::{Audience, Policy, PrincipalKind};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use config::Environment;
use domain::rbac::Feature;
use support::{World, with_scratch};
use tower::ServiceExt as _;

async fn json(r: axum::response::Response) -> serde_json::Value {
    let b = axum::body::to_bytes(r.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&b).expect("json")
}

fn get(path: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::get(path);
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::empty()).expect("req")
}

async fn call(app: &Router, req: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(req).await.expect("resp")
}

// ---------------------------------------------------------------- authz + cross-tenant

async fn feature_route(_a: Authz) -> &'static str {
    "on"
}

#[tokio::test]
async fn authz_and_cross_tenant() {
    with_scratch("authz_and_cross_tenant", |db, fx| async move {
        let w = World::new(db, fx).await;
        let (ea, eb) = (World::email("alice"), World::email("bob"));
        let (ua, ta, ma) = w.owner(&ea).await;
        let (ub, tb, _) = w.owner(&eb).await;
        let tok_a = w.login(&ea).await;
        let tok_b1 = w.login(&eb).await;
        let tok_b2 = w.login(&eb).await;
        let app = w
            .app_with(|r| {
                r.get(
                    "/t/private-cloud",
                    Policy::member().feature(Feature::PrivateCloud),
                    feature_route,
                )
            })
            .await;

        // no token -> 401 problem
        let r = call(&app, get("/api/v1/me", None)).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json(r).await["code"], "auth.unauthenticated");

        // correctly signed token, audience not accepted by the API (cleaner) -> 401
        let cleaner = w.token_for(Audience::Cleaner, PrincipalKind::Cleaner).await;
        let r = call(&app, get("/api/v1/me", Some(&cleaner))).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let generic = json(r).await;
        assert_eq!(generic["code"], "auth.unauthenticated");
        // staff token on a member route -> 401 (wrong principal), same body shape
        let staff = w.token_for(Audience::Platform, PrincipalKind::Staff).await;
        let r = call(&app, get("/api/v1/me", Some(&staff))).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json(r).await["detail"], generic["detail"]);
        // tampered member token -> 401
        let mut bad = tok_a.clone();
        bad.pop();
        bad.push(if tok_a.ends_with('A') { 'B' } else { 'A' });
        let r = call(&app, get("/api/v1/me", Some(&bad))).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

        // feature off -> 403 problem+json
        let r = call(&app, get("/t/private-cloud", Some(&tok_a))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            r.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        assert_eq!(json(r).await["code"], "feature.disabled");

        // /me: each caller sees only itself
        let a = json(call(&app, get("/api/v1/me", Some(&tok_a))).await).await;
        assert_eq!(a["user_id"], ua.0.to_string());
        assert_eq!(a["tenant_id"], ta.0.to_string());
        assert_eq!(a["membership_id"], ma.0.to_string());
        assert_eq!(a["role"], "owner");
        let b = json(call(&app, get("/api/v1/me", Some(&tok_b1))).await).await;
        assert_eq!(b["user_id"], ub.0.to_string());
        assert_eq!(b["tenant_id"], tb.0.to_string());
        assert_ne!(a["tenant_id"], b["tenant_id"]);
        // query parameters cannot redirect /me to another user
        let r = call(
            &app,
            get(&format!("/api/v1/me?user_id={}", ub.0), Some(&tok_a)),
        )
        .await;
        assert_eq!(json(r).await["user_id"], ua.0.to_string());

        // /me/sessions: only own sessions; keyset pagination
        let sa = json(call(&app, get("/api/v1/me/sessions", Some(&tok_a))).await).await;
        assert_eq!(sa["data"].as_array().expect("arr").len(), 1);
        assert_eq!(sa["data"][0]["current"], true);
        let sb = json(call(&app, get("/api/v1/me/sessions", Some(&tok_b2))).await).await;
        let ids_b: Vec<String> = sb["data"]
            .as_array()
            .expect("arr")
            .iter()
            .map(|s| s["id"].as_str().expect("id").to_owned())
            .collect();
        assert_eq!(ids_b.len(), 2);
        assert!(!ids_b.contains(&sa["data"][0]["id"].as_str().expect("id").to_owned()));
        let p1 = json(call(&app, get("/api/v1/me/sessions?limit=1", Some(&tok_b2))).await).await;
        assert_eq!(p1["data"].as_array().expect("arr").len(), 1);
        let cursor = p1["next_cursor"].as_str().expect("cursor").to_owned();
        let p2 = json(
            call(
                &app,
                get(
                    &format!("/api/v1/me/sessions?limit=1&cursor={cursor}"),
                    Some(&tok_b2),
                ),
            )
            .await,
        )
        .await;
        assert_eq!(p2["data"].as_array().expect("arr").len(), 1);
        assert_ne!(p1["data"][0]["id"], p2["data"][0]["id"]);
        assert!(p2["next_cursor"].is_null());
        // tampered cursor -> 400; unknown query key -> 400
        let r = call(
            &app,
            get("/api/v1/me/sessions?cursor=AAAAtampered", Some(&tok_b2)),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let r = call(&app, get("/api/v1/me/sessions?tenant_id=x", Some(&tok_b2))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);

        // openapi is generated from the route table (public in test env)
        let spec = json(call(&app, get("/api/v1/openapi.json", None)).await).await;
        assert_eq!(spec["openapi"], "3.1.0");
        assert!(spec["paths"]["/api/v1/me"]["get"]["security"][0]["bearer"].is_array());
        assert_eq!(
            spec["paths"]["/health/live"]["get"]["security"],
            serde_json::json!([])
        );
    })
    .await;
}

// ---------------------------------------------------------------- idempotency

static HITS: AtomicU64 = AtomicU64::new(0);

async fn idem_handler(
    JsonBody(v): JsonBody<serde_json::Value>,
) -> (
    StatusCode,
    [(header::HeaderName, &'static str); 1],
    axum::Json<serde_json::Value>,
) {
    let n = HITS.fetch_add(1, Ordering::SeqCst) + 1;
    (
        StatusCode::CREATED,
        [(header::LOCATION, "/t/idem/created")],
        axum::Json(serde_json::json!({ "n": n, "echo": v })),
    )
}

/// Gate for the concurrency test: the handler signals `entered`, then waits for `release`.
static SLOW: std::sync::OnceLock<(tokio::sync::Notify, tokio::sync::Notify)> =
    std::sync::OnceLock::new();

fn slow_gate() -> &'static (tokio::sync::Notify, tokio::sync::Notify) {
    SLOW.get_or_init(|| (tokio::sync::Notify::new(), tokio::sync::Notify::new()))
}

async fn slow_handler(JsonBody(_v): JsonBody<serde_json::Value>) -> StatusCode {
    let (entered, release) = slow_gate();
    entered.notify_one();
    release.notified().await;
    StatusCode::CREATED
}

static FLAKY: AtomicU64 = AtomicU64::new(0);

/// First call fails with 500 (after using the business tx), later calls succeed.
async fn flaky_handler(
    tx: api::middleware::idempotency::IdempotentTx,
    JsonBody(_v): JsonBody<serde_json::Value>,
) -> StatusCode {
    assert!(tx.lock().await.is_some(), "business tx available");
    if FLAKY.fetch_add(1, Ordering::SeqCst) == 0 {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::CREATED
    }
}

async fn big_handler(JsonBody(_v): JsonBody<serde_json::Value>) -> String {
    "x".repeat(40_000)
}

fn post(path: &str, token: &str, key: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(k) = key {
        b = b.header("idempotency-key", k);
    }
    b.body(Body::from(body.to_owned())).expect("req")
}

#[tokio::test]
async fn idempotency_replay_mismatch_in_progress_and_oversized() {
    with_scratch("idempotency", |db, fx| async move {
        let w = World::new(db, fx).await;
        let e = World::email("idem");
        w.owner(&e).await;
        let tok = w.login(&e).await;
        let app = w
            .app_with(|r: PolicyRouter<AppState>| {
                r.post("/t/idem", Policy::member().idempotent(), idem_handler)
                    .post("/t/slow", Policy::member().idempotent(), slow_handler)
                    .post("/t/big", Policy::member().idempotent(), big_handler)
                    .post("/t/flaky", Policy::member().idempotent(), flaky_handler)
            })
            .await;
        let before = HITS.load(Ordering::SeqCst);

        let r = call(&app, post("/t/idem", &tok, None, "{\"a\":1}")).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(r).await["code"], "idempotency.key_required");

        let r1 = call(&app, post("/t/idem", &tok, Some("k-1"), "{\"a\":1}")).await;
        assert_eq!(r1.status(), StatusCode::CREATED);
        assert!(!r1.headers().contains_key("idempotent-replayed"));
        let b1 = json(r1).await;

        let r2 = call(&app, post("/t/idem", &tok, Some("k-1"), "{\"a\":1}")).await;
        assert_eq!(r2.status(), StatusCode::CREATED);
        assert_eq!(r2.headers()["idempotent-replayed"], "true");
        assert_eq!(r2.headers()[header::LOCATION], "/t/idem/created");
        assert_eq!(json(r2).await, b1, "replay returns the stored response");
        assert_eq!(HITS.load(Ordering::SeqCst), before + 1, "handler ran once");

        let r3 = call(&app, post("/t/idem", &tok, Some("k-1"), "{\"a\":2}")).await;
        assert_eq!(r3.status(), StatusCode::CONFLICT);
        assert_eq!(json(r3).await["code"], "idempotency.key_reused");

        // a different key runs fresh
        let r4 = call(&app, post("/t/idem", &tok, Some("k-2"), "{\"a\":2}")).await;
        assert_eq!(r4.status(), StatusCode::CREATED);
        assert_eq!(HITS.load(Ordering::SeqCst), before + 2);

        // Concurrent duplicate: 409 in_progress at once (reservation already committed).
        let (entered, release) = slow_gate();
        let first = call(&app, post("/t/slow", &tok, Some("k-slow"), "{}"));
        let second = async {
            entered.notified().await;
            let r = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                call(&app, post("/t/slow", &tok, Some("k-slow"), "{}")),
            )
            .await
            .expect("duplicate must not block");
            release.notify_one();
            r
        };
        let (a, b) = tokio::join!(first, second);
        assert_eq!(a.status(), StatusCode::CREATED);
        assert_eq!(b.status(), StatusCode::CONFLICT);
        assert_eq!(b.headers()[header::RETRY_AFTER], "1");
        assert_eq!(json(b).await["code"], "idempotency.in_progress");

        // Handler error -> key released -> retry with the same key + body runs and succeeds.
        let r = call(&app, post("/t/flaky", &tok, Some("k-flaky"), "{\"z\":1}")).await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let r = call(&app, post("/t/flaky", &tok, Some("k-flaky"), "{\"z\":1}")).await;
        assert_eq!(r.status(), StatusCode::CREATED, "released key is reusable");
        assert!(!r.headers().contains_key("idempotent-replayed"));
        let r = call(&app, post("/t/flaky", &tok, Some("k-flaky"), "{\"z\":1}")).await;
        assert_eq!(r.status(), StatusCode::CREATED);
        assert_eq!(
            r.headers()["idempotent-replayed"],
            "true",
            "success is stored"
        );
        assert_eq!(FLAKY.load(Ordering::SeqCst), 2);

        // Response too big to store: first call fine, replay 409 replay_unavailable.
        let r = call(&app, post("/t/big", &tok, Some("k-big"), "{}")).await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = axum::body::to_bytes(r.into_body(), 1 << 20)
            .await
            .expect("b");
        assert_eq!(body.len(), 40_000);
        let r = call(&app, post("/t/big", &tok, Some("k-big"), "{}")).await;
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(json(r).await["code"], "idempotency.replay_unavailable");
    })
    .await;
}

// ---------------------------------------------------------------- T-H1

#[tokio::test]
async fn ready_reports_db_and_keys() {
    with_scratch("ready_reports_db_and_keys", |db, fx| async move {
        let w = World::new(db.clone(), fx).await;
        let build = |state: AppState| {
            let routes = api::build_routes(&RouteOptions {
                environment: Environment::Test,
                openapi_public: false,
            });
            let http = api::HttpSettings {
                max_inflight: 8,
                max_json_body: 1024,
                timeout: std::time::Duration::from_secs(10),
                cors_origins: Vec::new(),
                proxies: api::middleware::client_ip::TrustedProxies::none(),
            };
            api::assemble(routes, state, w.gate(), &http)
                .expect("router")
                .0
        };

        let ok = build(w.state(true).await);
        let r = call(&ok, get("/health/ready", None)).await;
        assert_eq!(r.status(), StatusCode::OK);
        let v = json(r).await;
        assert_eq!(
            v,
            serde_json::json!({"status":"ok","checks":{"db":"ok","keys":"ok","migrations":"ok"}})
        );

        let no_keys = build(w.state(false).await);
        let r = call(&no_keys, get("/health/ready", None)).await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let v = json(r).await;
        assert_eq!(v["status"], "degraded");
        assert_eq!(v["checks"]["keys"], "fail");
        assert_eq!(v["checks"]["db"], "ok");

        // DB down: pool closed.
        db.close().await;
        // Within the 5 s cache the old (ok) probe result is reused: no DB round trip.
        let r = call(&ok, get("/health/ready", None)).await;
        assert_eq!(r.status(), StatusCode::OK, "cached readiness");
        // A fresh state (empty cache) probes and sees the closed pool.
        let down = build(w.state(true).await);
        let r = call(&down, get("/health/ready", None)).await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let v = json(r).await;
        assert_eq!(v["checks"]["db"], "fail");
        // status words only: no versions / hosts / error text
        assert_eq!(v.as_object().expect("obj").len(), 2);
        assert_eq!(v["checks"].as_object().expect("obj").len(), 3);
        // liveness stays up
        let r = call(&down, get("/health/live", None)).await;
        assert_eq!(r.status(), StatusCode::OK);
    })
    .await;
}
