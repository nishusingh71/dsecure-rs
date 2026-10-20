//! T-R1 (router policy rules), T-L1 (body / in-flight limits), DB-free authz basics.
//! No database: the gate uses `DenyAllAuthenticator`; routes are test routes or the real table.
// Test-only crate: helpers outside #[test] fns are not covered by clippy.toml allow-*-in-tests.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use api::authn::DenyAllAuthenticator;
use api::json::JsonBody;
use api::middleware::client_ip::TrustedProxies;
use api::{GateDeps, HttpSettings, PolicyRouter, RouteOptions, RouterError, assemble};
use auth::{Policy, PolicyError};
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use common::SystemClock;
use config::Environment;
use domain::rbac::Perm;
use tokio::sync::Notify;
use tower::ServiceExt as _;

fn http(max_inflight: usize, max_body: usize) -> HttpSettings {
    HttpSettings {
        max_inflight,
        max_json_body: max_body,
        timeout: Duration::from_secs(5),
        cors_origins: vec!["https://dashboard.dsecure.test".into()],
        proxies: TrustedProxies::none(),
    }
}

fn gate() -> GateDeps {
    GateDeps {
        authn: Arc::new(DenyAllAuthenticator),
        clock: Arc::new(SystemClock),
        db: None,
        auth: None,
    }
}

#[derive(Clone, Default)]
struct Slow {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

async fn ok() -> &'static str {
    "ok"
}

async fn echo(JsonBody(v): JsonBody<serde_json::Value>) -> axum::Json<serde_json::Value> {
    axum::Json(v)
}

async fn slow(State(s): State<Slow>) -> &'static str {
    s.entered.notify_one();
    s.release.notified().await;
    "slow"
}

fn test_app(max_inflight: usize, max_body: usize) -> (Router, Slow) {
    let s = Slow::default();
    let routes = PolicyRouter::new()
        .get("/t/ok", Policy::public("test"), ok)
        .post("/t/echo", Policy::public("test"), echo)
        .get("/t/slow", Policy::public("test"), slow)
        .get("/health/live", Policy::public("test liveness"), ok)
        .get(
            "/t/member",
            Policy::member().permission(Perm::ProfileReadSelf),
            ok,
        );
    let (app, _) =
        assemble(routes, s.clone(), gate(), &http(max_inflight, max_body)).expect("router");
    (app, s)
}

async fn json(r: axum::response::Response) -> serde_json::Value {
    let b = axum::body::to_bytes(r.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&b).expect("problem json")
}

fn get(path: &str) -> Request<Body> {
    Request::get(path).body(Body::empty()).expect("req")
}

// ---------------------------------------------------------------- T-R1

#[test]
fn route_with_invalid_policy_fails_the_build() {
    let r = PolicyRouter::<()>::new()
        .get("/a", Policy::public(""), ok)
        .get("/b", Policy::staff(), ok)
        .get("/c", Policy::device(), ok);
    let errs = r.into_router().expect_err("must fail");
    assert!(errs.contains(&RouterError::InvalidPolicy {
        method: "GET".into(),
        path: "/a",
        err: PolicyError::PublicWithoutReason,
    }));
    assert!(errs.contains(&RouterError::InvalidPolicy {
        method: "GET".into(),
        path: "/b",
        err: PolicyError::StaffWithoutPlatformPermission,
    }));
    assert!(errs.contains(&RouterError::InvalidPolicy {
        method: "GET".into(),
        path: "/c",
        err: PolicyError::DeviceWithoutPermission,
    }));
}

#[test]
fn duplicate_and_bad_paths_fail_the_build() {
    let errs = PolicyRouter::<()>::new()
        .get("/a", Policy::public("x"), ok)
        .get("/a", Policy::member(), ok)
        .get("no-slash", Policy::public("x"), ok)
        .into_router()
        .expect_err("must fail");
    assert!(errs.contains(&RouterError::Duplicate {
        method: "GET".into(),
        path: "/a",
    }));
    assert!(errs.contains(&RouterError::BadPath { path: "no-slash" }));
}

fn reviewed(include: &[&str]) -> BTreeSet<String> {
    include_str!("../reviewed_public_routes.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (when, method, path) = (it.next()?, it.next()?, it.next()?);
            include.contains(&when).then(|| format!("{method} {path}"))
        })
        .collect()
}

fn public_of(opts: &RouteOptions) -> BTreeSet<String> {
    api::route_policies(opts)
        .expect("table")
        .into_iter()
        .filter(|r| r.public_reason.is_some())
        .map(|r| format!("{} {}", r.method, r.path))
        .collect()
}

const DEV_FIXTURES: bool = cfg!(all(feature = "dev-fixtures", debug_assertions));

#[test]
fn public_routes_equal_the_reviewed_list() {
    let prod = RouteOptions {
        environment: Environment::Production,
        openapi_public: true, // ignored in prod
    };
    assert_eq!(public_of(&prod), reviewed(&["always"]));

    let staging = RouteOptions {
        environment: Environment::Staging,
        openapi_public: false,
    };
    assert_eq!(public_of(&staging), reviewed(&["always"]));

    let dev = RouteOptions {
        environment: Environment::Dev,
        openapi_public: true,
    };
    let mut tags = vec!["always", "non-prod"];
    if DEV_FIXTURES {
        tags.push("dev-fixtures");
    }
    assert_eq!(public_of(&dev), reviewed(&tags));
}

#[test]
fn every_route_has_a_valid_policy_and_report_is_complete() {
    let opts = RouteOptions {
        environment: Environment::Production,
        openapi_public: false,
    };
    let rep = api::route_policies(&opts).expect("table");
    let paths: Vec<_> = rep
        .iter()
        .map(|r| format!("{} {}", r.method, r.path))
        .collect();
    for want in [
        "GET /health/live",
        "GET /health/ready",
        "GET /api/v1/me",
        "GET /api/v1/me/sessions",
        "GET /api/v1/openapi.json",
    ] {
        assert!(paths.iter().any(|p| p == want), "missing {want}");
    }
    let me = rep.iter().find(|r| r.path == "/api/v1/me").expect("me");
    assert_eq!(me.permission, Some("profile.read_self"));
    assert!(me.public_reason.is_none());
    // openapi in prod: staff only
    let spec = rep
        .iter()
        .find(|r| r.path == "/api/v1/openapi.json")
        .expect("spec");
    assert!(spec.public_reason.is_none());
    assert!(rep.iter().all(|r| !r.policy.is_empty()));
}

#[tokio::test]
async fn unknown_route_is_404_problem_json() {
    let (app, _) = test_app(8, 1024);
    let r = app.oneshot(get("/nope?email=a@b.c")).await.expect("resp");
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        r.headers()[header::CONTENT_TYPE],
        "application/problem+json"
    );
    assert!(r.headers().contains_key("x-request-id"));
    let v = json(r).await;
    assert_eq!(v["code"], "not_found");
    assert!(v["request_id"].is_string());
}

// ---------------------------------------------------------------- authz basics (no DB)

#[tokio::test]
async fn no_token_on_member_route_is_401_problem() {
    let (app, _) = test_app(8, 1024);
    let r = app.oneshot(get("/t/member")).await.expect("resp");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(r.headers()[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(json(r).await["code"], "auth.unauthenticated");
}

#[tokio::test]
async fn bad_token_and_missing_token_look_identical() {
    let (app, _) = test_app(8, 1024);
    let a = app.clone().oneshot(get("/t/member")).await.expect("resp");
    let mut req = get("/t/member");
    req.headers_mut().insert(
        header::AUTHORIZATION,
        "Bearer abc.def.ghi".parse().expect("hv"),
    );
    let b = app.oneshot(req).await.expect("resp");
    assert_eq!(a.status(), b.status());
    let (mut va, mut vb) = (json(a).await, json(b).await);
    va["request_id"] = serde_json::Value::Null;
    vb["request_id"] = serde_json::Value::Null;
    assert_eq!(va, vb);
}

#[tokio::test]
async fn public_route_ignores_tokens_and_sets_security_headers() {
    let (app, _) = test_app(8, 1024);
    let mut req = get("/t/ok");
    req.headers_mut()
        .insert(header::AUTHORIZATION, "Bearer junk".parse().expect("hv"));
    let r = app.oneshot(req).await.expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    let h = r.headers();
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
    assert!(h.contains_key(header::STRICT_TRANSPORT_SECURITY));
}

#[tokio::test]
async fn request_id_is_echoed_only_when_safe() {
    let (app, _) = test_app(8, 1024);
    let mut req = get("/t/ok");
    req.headers_mut()
        .insert("x-request-id", "abc-123".parse().expect("hv"));
    let r = app.clone().oneshot(req).await.expect("resp");
    assert_eq!(r.headers()["x-request-id"], "abc-123");
    let mut req = get("/t/ok");
    req.headers_mut()
        .insert("x-request-id", "bad id with spaces".parse().expect("hv"));
    let r = app.oneshot(req).await.expect("resp");
    assert_ne!(r.headers()["x-request-id"], "bad id with spaces");
}

#[tokio::test]
async fn cors_allowlist() {
    let (app, _) = test_app(8, 1024);
    let mut req = get("/t/ok");
    req.headers_mut().insert(
        header::ORIGIN,
        "https://dashboard.dsecure.test".parse().expect("hv"),
    );
    let r = app.clone().oneshot(req).await.expect("resp");
    assert_eq!(
        r.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://dashboard.dsecure.test"
    );
    let mut req = get("/t/ok");
    req.headers_mut()
        .insert(header::ORIGIN, "https://evil.test".parse().expect("hv"));
    let r = app.oneshot(req).await.expect("resp");
    assert!(
        !r.headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
}

// ---------------------------------------------------------------- T-L1

#[tokio::test]
async fn body_over_limit_is_413_declared_and_chunked() {
    let (app, _) = test_app(8, 64);
    let big = format!("{{\"a\":\"{}\"}}", "x".repeat(200));
    // Content-Length declared
    let req = Request::post("/t/echo")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, big.len())
        .body(Body::from(big.clone()))
        .expect("req");
    let r = app.clone().oneshot(req).await.expect("resp");
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        r.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff",
        "headers on 413"
    );
    assert_eq!(json(r).await["code"], "request.too_large");
    // No Content-Length (streamed body)
    let stream = futures_stream(big.into_bytes());
    let req = Request::post("/t/echo")
        .header(header::CONTENT_TYPE, "application/json")
        .body(stream)
        .expect("req");
    let r = app.clone().oneshot(req).await.expect("resp");
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json(r).await["code"], "request.too_large");
    // under the limit passes
    let req = Request::post("/t/echo")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{\"a\":1}"))
        .expect("req");
    let r = app.oneshot(req).await.expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
}

/// Body without a size hint (like a chunked upload), split in small frames.
fn futures_stream(bytes: Vec<u8>) -> Body {
    let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = bytes
        .chunks(16)
        .map(|c| Ok(bytes::Bytes::copy_from_slice(c)))
        .collect();
    Body::from_stream(futures_util::stream::iter(chunks))
}

#[tokio::test]
async fn inflight_over_limit_is_503_with_retry_after() {
    let (app, s) = test_app(1, 1024);
    let first = app.clone().oneshot(get("/t/slow"));
    let second = async {
        s.entered.notified().await;
        let r = app.clone().oneshot(get("/t/ok")).await.expect("resp");
        // liveness is exempt from load shed
        let live = app
            .clone()
            .oneshot(get("/health/live"))
            .await
            .expect("resp");
        s.release.notify_one();
        (r, live)
    };
    let (a, (b, live)) = tokio::join!(first, second);
    assert_eq!(a.expect("resp").status(), StatusCode::OK);
    assert_eq!(b.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        b.headers()[header::X_FRAME_OPTIONS],
        "DENY",
        "headers on load-shed 503"
    );
    assert_eq!(b.headers()[header::RETRY_AFTER], "1");
    assert_eq!(json(b).await["code"], "service.overloaded");
    assert_eq!(live.status(), StatusCode::OK);
    // permit released: next request passes
    let c = app.oneshot(get("/t/ok")).await.expect("resp");
    assert_eq!(c.status(), StatusCode::OK);
}

#[tokio::test]
async fn timeout_is_503_problem() {
    let s = Slow::default();
    let routes = PolicyRouter::new().get("/t/slow", Policy::public("test"), slow);
    let mut h = http(8, 1024);
    h.timeout = Duration::from_millis(50);
    let (app, _) = assemble(routes, s, gate(), &h).expect("router");
    let r = app.oneshot(get("/t/slow")).await.expect("resp");
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json(r).await["code"], "service.timeout");
}

#[tokio::test]
async fn wrong_content_type_and_bad_json_are_400() {
    let (app, _) = test_app(8, 1024);
    let req = Request::post("/t/echo")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("{}"))
        .expect("req");
    let r = app.clone().oneshot(req).await.expect("resp");
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let req = Request::post("/t/echo")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{\"secret\": \"hunter2\""))
        .expect("req");
    let r = app.oneshot(req).await.expect("resp");
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let v = json(r).await;
    assert!(!v.to_string().contains("hunter2"));
}
