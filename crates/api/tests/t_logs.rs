//! T-O1 end-to-end: the request log line of a real authenticated request (and of a 401) contains
//! no email, token or IP. Own test binary: a thread-local subscriber must not race with other
//! tests' callsite-interest caching.

// Test-only crate: helpers outside #[test] fns are not covered by clippy.toml allow-*-in-tests.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use support::{World, with_scratch};
use tower::ServiceExt as _;
use tracing_subscriber::layer::SubscriberExt as _;

async fn call(app: &Router, req: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(req).await.expect("resp")
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("cap").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn request_log_has_no_email_token_or_ip() {
    with_scratch(
        "request_log_has_no_email_token_or_ip",
        |db, fx| async move {
            let w = World::new(db, fx).await;
            let email = World::email("log.alice");
            w.owner(&email).await;
            let token = w.login(&email).await;
            let app = w.app_with(|r| r).await;

            let cap = Capture::default();
            let writer = cap.clone();
            let subscriber = tracing_subscriber::registry().with(telemetry::RedactingLayer::new(
                move || writer.clone(),
                telemetry::LogStyle::Json,
            ));
            let client_ip = "198.51.100.77";
            let proxy_peer: SocketAddr = "10.0.0.9:4444".parse().expect("addr");
            let status = {
                let _guard = tracing::subscriber::set_default(subscriber);
                // Callsites first hit before this subscriber existed keep a cached interest.
                tracing::callsite::rebuild_interest_cache();
                let mut req = Request::get(format!("/api/v1/me?email={email}&ip={client_ip}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header("x-forwarded-for", client_ip)
                    .body(Body::empty())
                    .expect("req");
                req.extensions_mut().insert(ConnectInfo(proxy_peer));
                let r = call(&app, req).await;
                // and an error path (401) with the same sensitive inputs
                let mut req2 = Request::get(format!("/api/v1/me/sessions?email={email}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}x"))
                    .header("x-forwarded-for", client_ip)
                    .body(Body::empty())
                    .expect("req");
                req2.extensions_mut().insert(ConnectInfo(proxy_peer));
                let r2 = call(&app, req2).await;
                (r.status(), r2.status())
            };
            assert_eq!(status, (StatusCode::OK, StatusCode::UNAUTHORIZED));
            let out = cap.0.lock().expect("cap").clone();
            let text = String::from_utf8(out).expect("utf8");
            assert!(text.contains("request completed"), "log captured: {text}");
            assert!(text.contains("/api/v1/me"), "route template logged");
            let local = email.split('@').next().expect("local").to_owned();
            for secret in [
                email.as_str(),
                local.as_str(),
                token.as_str(),
                &token[..24],
                client_ip,
                "10.0.0.9",
            ] {
                assert!(!text.contains(secret), "log leaked a sensitive value");
            }
        },
    )
    .await;
}
