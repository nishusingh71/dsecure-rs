//! Log scan for the auth endpoints: login (wrong + right password), refresh, step-up, logout. The
//! captured logs must contain no password, email, access token, refresh token or step-up token.
//! Own test binary (thread-local subscriber, see t_logs.rs).

// Test-only crate: helpers outside #[test] fns are not covered by clippy.toml allow-*-in-tests.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use serde_json::json;
use support::{PW, World, call, json, post_json, with_scratch};
use tracing_subscriber::layer::SubscriberExt as _;

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
async fn auth_logs_contain_no_secrets() {
    with_scratch("auth_logs", |db, fx| async move {
        let w = World::new(db, fx).await;
        let email = World::email("log.carol");
        w.owner(&email).await;
        let app = w.app_with(|r| r).await;

        let cap = Capture::default();
        let writer = cap.clone();
        let subscriber = tracing_subscriber::registry().with(telemetry::RedactingLayer::new(
            move || writer.clone(),
            telemetry::LogStyle::Json,
        ));
        let mut secrets: Vec<String> = vec![email.clone(), PW.to_owned()];
        {
            let _guard = tracing::subscriber::set_default(subscriber);
            tracing::callsite::rebuild_interest_cache();
            let r = call(
                &app,
                post_json(
                    "/api/v1/auth/login",
                    None,
                    &json!({ "email": email, "password": "wrong-pass-123" }),
                ),
            )
            .await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
            secrets.push("wrong-pass-123".into());
            let r = call(
                &app,
                post_json(
                    "/api/v1/auth/login",
                    None,
                    &json!({ "email": email, "password": PW }),
                ),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK);
            let t = json(r).await;
            let refresh = t["refresh_token"].as_str().expect("rt").to_owned();
            let r = call(
                &app,
                post_json(
                    "/api/v1/auth/refresh",
                    None,
                    &json!({ "refresh_token": refresh }),
                ),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK);
            let t2 = json(r).await;
            let access = t2["access_token"].as_str().expect("at").to_owned();
            let r = call(
                &app,
                post_json(
                    "/api/v1/auth/step-up",
                    Some(&access),
                    &json!({ "password": PW, "action": "mfa.totp.enrol" }),
                ),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK);
            let su = json(r).await["step_up_token"]
                .as_str()
                .expect("su")
                .to_owned();
            let r = call(
                &app,
                post_json("/api/v1/auth/logout", Some(&access), &json!({})),
            )
            .await;
            assert_eq!(r.status(), StatusCode::NO_CONTENT);
            for v in [&t["access_token"], &t2["refresh_token"]] {
                secrets.push(v.as_str().expect("tok").to_owned());
            }
            secrets.extend([refresh, access, su]);
        }
        let text = String::from_utf8(cap.0.lock().expect("cap").clone()).expect("utf8");
        assert!(text.contains("request completed"), "logs captured");
        assert!(text.contains("/api/v1/auth/login"), "route template logged");
        let local = email.split('@').next().expect("local").to_owned();
        secrets.push(local);
        for (i, sec) in secrets.iter().enumerate() {
            assert!(
                !text.contains(sec.as_str()),
                "log leaked sensitive value #{i}"
            );
            // token prefixes too (a truncated token is still a leak)
            if sec.len() > 40 {
                assert!(
                    !text.contains(&sec[..24]),
                    "log leaked prefix of value #{i}"
                );
            }
        }
    })
    .await;
}
