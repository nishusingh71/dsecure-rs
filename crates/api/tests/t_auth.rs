//! P0-11 over HTTP on the LOCAL MySQL scratch DB: T-A2 login/state matrix, T-A3 refresh rotation +
//! reuse, pre-auth rate limits (incl. X-Forwarded-For spoofing), step-up end to end, TOTP enrolment,
//! logout, staff login refusal, JWT keys from `signing_keys` + JWKS.

// Test-only crate: helpers outside #[test] fns are not covered by clippy.toml allow-*-in-tests.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use std::net::SocketAddr;
use std::time::Duration;

use api::Authz;
use api::ratelimit::Rule;
use auth::Policy;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use db::repo::memberships::MembershipStatus;
use db::repo::users::UserStatus;
use serde_json::{Value, json};
use support::{
    PW, World, call, get, json, post_json, relaxed_rules, with_scratch, without_request_id,
};

const LOGIN: &str = "/api/v1/auth/login";
const REFRESH: &str = "/api/v1/auth/refresh";
const LOGOUT: &str = "/api/v1/auth/logout";
const STEP_UP: &str = "/api/v1/auth/step-up";

fn creds(email: &str, pw: &str) -> Value {
    json!({ "email": email, "password": pw })
}

async fn login(app: &axum::Router, email: &str, pw: &str) -> (StatusCode, Value) {
    let r = call(app, post_json(LOGIN, None, &creds(email, pw))).await;
    (r.status(), json(r).await)
}

async fn login_ok(app: &axum::Router, email: &str) -> Value {
    let (st, v) = login(app, email, PW).await;
    assert_eq!(st, StatusCode::OK, "login should succeed");
    v
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().expect("string field").to_owned()
}

// ---------------------------------------------------------------- T-A2

#[tokio::test]
async fn t_a2_login_and_state_matrix_is_generic() {
    with_scratch("t_a2", |db, fx| async move {
        let w = World::new(db, fx).await;
        let app = w.app_with(|r| r).await;

        let ok = World::email("ok");
        w.owner(&ok).await;
        let (st, wrong_pw) = login(&app, &ok, "wrong password").await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let generic = without_request_id(wrong_pw);
        assert_eq!(generic["code"], "auth.invalid_credentials");

        let (st, v) = login(&app, &World::email("nobody"), PW).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert_eq!(without_request_id(v), generic, "unknown user");

        for (name, status) in [
            ("suspended", UserStatus::Suspended),
            ("disabled", UserStatus::Disabled),
        ] {
            let e = World::email(name);
            let (u, _, _) = w.owner(&e).await;
            w.set_user_status(u, status).await;
            let (st, v) = login(&app, &e, PW).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "{name}");
            assert_eq!(without_request_id(v), generic, "{name}");
        }

        let unv = World::email("unverified");
        let u = w.user(&unv, false).await;
        w.tenant(u).await;
        let (st, v) = login(&app, &unv, PW).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert_eq!(without_request_id(v), generic, "unverified");

        // Locked after 10 failures: the correct password then looks exactly like a wrong one.
        let locked = World::email("locked");
        w.owner(&locked).await;
        for _ in 0..10 {
            let (st, _) = login(&app, &locked, "nope").await;
            assert_eq!(st, StatusCode::UNAUTHORIZED);
        }
        let (st, v) = login(&app, &locked, PW).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert_eq!(without_request_id(v), generic, "locked");

        // Membership disabled (member of someone else's tenant) and tenant suspended.
        let owner = World::email("owner");
        let (_, t, om) = w.owner(&owner).await;
        let mem = World::email("member");
        let mu = w.user(&mem, true).await;
        let m = w.member(t, om, mu).await;
        let member_tokens = login_ok(&app, &mem).await;
        let owner_tokens = login_ok(&app, &owner).await;
        w.set_member_status(t, om, m, MembershipStatus::Disabled)
            .await;
        let (st, v) = login(&app, &mem, PW).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert_eq!(without_request_id(v), generic, "membership disabled");
        // ... and at request + refresh time
        let r = call(
            &app,
            get("/api/v1/me", Some(&s(&member_tokens, "access_token"))),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "request after disable"
        );
        let r = call(
            &app,
            post_json(
                REFRESH,
                None,
                &json!({ "refresh_token": s(&member_tokens, "refresh_token") }),
            ),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "refresh after disable"
        );
        assert_eq!(without_request_id(json(r).await), generic);

        w.suspend_tenant(t).await;
        let (st, v) = login(&app, &owner, PW).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert_eq!(without_request_id(v), generic, "tenant suspended");
        let r = call(
            &app,
            get("/api/v1/me", Some(&s(&owner_tokens, "access_token"))),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "request after suspend"
        );
        let r = call(
            &app,
            post_json(
                REFRESH,
                None,
                &json!({ "refresh_token": s(&owner_tokens, "refresh_token") }),
            ),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "refresh after suspend"
        );

        // Platform audience is not accepted on the member route; malformed body is 400.
        let r = call(
            &app,
            post_json(
                LOGIN,
                None,
                &json!({ "email": ok, "password": PW, "audience": "platform" }),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(without_request_id(json(r).await), generic);
        let r = call(&app, post_json(LOGIN, None, &json!({ "email": ok }))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);

        // Staff login with a member account: same generic failure.
        let r = call(
            &app,
            post_json("/api/v1/platform/auth/login", None, &creds(&ok, PW)),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    })
    .await;
}

// ---------------------------------------------------------------- T-A3

#[tokio::test]
async fn t_a3_refresh_rotation_and_reuse() {
    with_scratch("t_a3", |db, fx| async move {
        let w = World::new(db, fx).await;
        let app = w.app_with(|r| r).await;
        let e = World::email("rot");
        w.owner(&e).await;
        let first = login_ok(&app, &e).await;
        assert_eq!(first["token_type"], "Bearer");
        let r1 = s(&first, "refresh_token");

        let r = call(
            &app,
            post_json(REFRESH, None, &json!({ "refresh_token": r1 })),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let second = json(r).await;
        let r2 = s(&second, "refresh_token");
        assert_ne!(r1, r2, "rotated");
        assert_eq!(second["session_id"], first["session_id"]);
        let r = call(&app, get("/api/v1/me", Some(&s(&second, "access_token")))).await;
        assert_eq!(r.status(), StatusCode::OK);

        // Reuse of the old token: generic 401, family + session revoked.
        let r = call(
            &app,
            post_json(REFRESH, None, &json!({ "refresh_token": r1 })),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let r = call(
            &app,
            post_json(REFRESH, None, &json!({ "refresh_token": r2 })),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "family revoked");
        let r = call(&app, get("/api/v1/me", Some(&s(&second, "access_token")))).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "session revoked");

        // garbage token
        let r = call(
            &app,
            post_json(REFRESH, None, &json!({ "refresh_token": "x" })),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    })
    .await;
}

// ---------------------------------------------------------------- rate limits

fn from_peer(mut req: Request<Body>, peer: &str, xff: Option<&str>) -> Request<Body> {
    let addr: SocketAddr = peer.parse().expect("addr");
    req.extensions_mut().insert(ConnectInfo(addr));
    if let Some(x) = xff {
        req.headers_mut()
            .insert("x-forwarded-for", x.parse().expect("hv"));
    }
    req
}

#[tokio::test]
async fn rate_limits_use_trusted_ip_only() {
    with_scratch("rate_limits", |db, fx| async move {
        let w = World::new(db, fx).await;
        let e = World::email("rl");
        w.owner(&e).await;
        let mut rules = relaxed_rules();
        rules.login_ip = Rule::new("login_ip", 3, Duration::from_secs(60));
        let app = w.app_full(|r| r, rules).await;
        let body = creds(&e, "wrong");

        // Untrusted peer rotating X-Forwarded-For: still ONE bucket (the peer).
        for i in 0..3 {
            let xff = format!("198.51.100.{i}");
            let r = call(
                &app,
                from_peer(
                    post_json(LOGIN, None, &body),
                    "203.0.113.5:1000",
                    Some(&xff),
                ),
            )
            .await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "attempt {i}");
        }
        let r = call(
            &app,
            from_peer(
                post_json(LOGIN, None, &body),
                "203.0.113.5:1000",
                Some("192.0.2.77"),
            ),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "spoofed XFF ignored"
        );
        let ra: u64 = r.headers()[header::RETRY_AFTER]
            .to_str()
            .expect("ra")
            .parse()
            .expect("secs");
        assert!((1..=61).contains(&ra));
        assert_eq!(json(r).await["code"], "rate_limited");
        // Even the right password is not tried while limited.
        let r = call(
            &app,
            from_peer(
                post_json(LOGIN, None, &creds(&e, PW)),
                "203.0.113.5:1000",
                None,
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);

        // Trusted proxy: the forwarded client IP is the bucket.
        for _ in 0..3 {
            let r = call(
                &app,
                from_peer(
                    post_json(LOGIN, None, &body),
                    "10.0.0.9:443",
                    Some("198.51.100.20"),
                ),
            )
            .await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        }
        let r = call(
            &app,
            from_peer(
                post_json(LOGIN, None, &body),
                "10.0.0.9:443",
                Some("198.51.100.20"),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        let r = call(
            &app,
            from_peer(
                post_json(LOGIN, None, &creds(&e, PW)),
                "10.0.0.9:443",
                Some("198.51.100.21"),
            ),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "other client behind the proxy unaffected"
        );

        // Per IP + email bucket (existing and unknown emails behave the same).
        let mut rules = relaxed_rules();
        rules.login_ip_email = Rule::new("login_ip_email", 2, Duration::from_secs(60));
        let app = w.app_full(|r| r, rules).await;
        for email in [e.clone(), World::email("ghost")] {
            for _ in 0..2 {
                let r = call(
                    &app,
                    from_peer(
                        post_json(LOGIN, None, &creds(&email, "x")),
                        "203.0.113.9:1",
                        None,
                    ),
                )
                .await;
                assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
            }
            let r = call(
                &app,
                from_peer(
                    post_json(LOGIN, None, &creds(&email, "x")),
                    "203.0.113.9:1",
                    None,
                ),
            )
            .await;
            assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    })
    .await;
}

// ---------------------------------------------------------------- step-up, MFA, logout

async fn danger(_a: Authz) -> &'static str {
    "done"
}

fn with_step_up(mut req: Request<Body>, token: &str) -> Request<Body> {
    req.headers_mut()
        .insert("x-step-up-token", token.parse().expect("hv"));
    req
}

async fn step_up(app: &axum::Router, access: &str, body: Value) -> (StatusCode, Value) {
    let r = call(app, post_json(STEP_UP, Some(access), &body)).await;
    (r.status(), json(r).await)
}

fn base32_decode(s: &str) -> Vec<u8> {
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("base32"),
        };
        bits = (bits << 5) | u32::from(v);
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push(u8::try_from((bits >> n) & 0xff).expect("byte"));
        }
    }
    out
}

#[tokio::test]
async fn step_up_mfa_and_logout_end_to_end() {
    with_scratch("step_up_flow", |db, fx| async move {
        let w = World::new(db, fx).await;
        let app = w
            .app_with(|r| r.get("/t/danger", Policy::member().step_up("test.danger"), danger))
            .await;
        let e = World::email("su");
        w.owner(&e).await;
        let t = login_ok(&app, &e).await;
        let access = s(&t, "access_token");

        let r = call(&app, get("/t/danger", Some(&access))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(json(r).await["code"], "auth.step_up_required");

        let (st, v) = step_up(
            &app,
            &access,
            json!({ "password": "nope", "action": "test.danger" }),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert_eq!(v["code"], "auth.invalid_credentials");
        let (st, v) = step_up(
            &app,
            &access,
            json!({ "password": PW, "action": "made.up" }),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(v["code"], "auth.step_up_action_unknown");
        let r = call(
            &app,
            post_json(
                STEP_UP,
                None,
                &json!({ "password": PW, "action": "test.danger" }),
            ),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "step-up needs a session"
        );

        let (st, v) = step_up(
            &app,
            &access,
            json!({ "password": PW, "action": "test.danger" }),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let su = s(&v, "step_up_token");
        assert!(v["expires_in"].as_i64().is_some_and(|x| x > 0));
        let r = call(&app, with_step_up(get("/t/danger", Some(&access)), &su)).await;
        assert_eq!(r.status(), StatusCode::OK);
        let r = call(&app, with_step_up(get("/t/danger", Some(&access)), &su)).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "single use");
        // A token for another action does not unlock this one.
        let (_, v) = step_up(
            &app,
            &access,
            json!({ "password": PW, "action": "mfa.totp.enrol" }),
        )
        .await;
        let enrol_token = s(&v, "step_up_token");
        let r = call(
            &app,
            with_step_up(get("/t/danger", Some(&access)), &enrol_token),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "action bound");

        // TOTP enrolment: step-up required.
        let r = call(
            &app,
            post_json("/api/v1/me/mfa/totp", Some(&access), &json!({})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let (_, v) = step_up(
            &app,
            &access,
            json!({ "password": PW, "action": "mfa.totp.enrol" }),
        )
        .await;
        let r = call(
            &app,
            with_step_up(
                post_json("/api/v1/me/mfa/totp", Some(&access), &json!({})),
                &s(&v, "step_up_token"),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CREATED);
        let enrol = json(r).await;
        let factor = s(&enrol, "factor_id");
        let secret = base32_decode(&s(&enrol, "secret_base32"));
        let r = call(
            &app,
            post_json(
                "/api/v1/me/mfa/totp/confirm",
                Some(&access),
                &json!({ "factor_id": factor, "code": "000000x" }),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(r).await["code"], "mfa.code_invalid");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let code = format!("{:06}", auth::totp::totp_at(&secret, now, 6));
        let r = call(
            &app,
            post_json(
                "/api/v1/me/mfa/totp/confirm",
                Some(&access),
                &json!({ "factor_id": factor, "code": code }),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let codes: Vec<String> = json(r).await["recovery_codes"]
            .as_array()
            .expect("codes")
            .iter()
            .map(|c| c.as_str().expect("code").to_owned())
            .collect();
        assert_eq!(codes.len(), 10);

        // MFA now required at login; recovery code works once.
        let (st, v) = login(&app, &e, PW).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert_eq!(v["code"], "auth.mfa_required");
        let (st, v) = login(&app, &e, "wrong").await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert_eq!(
            v["code"], "auth.invalid_credentials",
            "wrong password stays generic"
        );
        let with_rc = json!({ "email": e, "password": PW, "recovery_code": codes[0] });
        let r = call(&app, post_json(LOGIN, None, &with_rc)).await;
        assert_eq!(r.status(), StatusCode::OK);
        let mfa_tokens = json(r).await;
        let r = call(&app, post_json(LOGIN, None, &with_rc)).await;
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "recovery code single use"
        );

        // Logout revokes the session (access + refresh).
        let mfa_access = s(&mfa_tokens, "access_token");
        let r = call(&app, post_json(LOGOUT, Some(&mfa_access), &json!({}))).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        let r = call(&app, get("/api/v1/me", Some(&mfa_access))).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let r = call(
            &app,
            post_json(
                REFRESH,
                None,
                &json!({ "refresh_token": s(&mfa_tokens, "refresh_token") }),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let r = call(&app, post_json(LOGOUT, None, &json!({}))).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        // the first session is still alive
        let r = call(&app, get("/api/v1/me", Some(&access))).await;
        assert_eq!(r.status(), StatusCode::OK);
    })
    .await;
}

// ---------------------------------------------------------------- signing keys + JWKS

#[tokio::test]
async fn signing_keys_from_db_and_jwks() {
    with_scratch("signing_keys", |db, fx| async move {
        let w = World::new(db.clone(), fx.clone()).await;
        let enc = crypto::AesGcmFieldEncryptor::new(w.keys.clone());
        let n =
            api::keys::dev_bootstrap(&fx, config::Environment::Test, &enc, "m-test-1", "s-test-1")
                .await
                .expect("bootstrap");
        assert_eq!(n, 2);
        let again =
            api::keys::dev_bootstrap(&fx, config::Environment::Test, &enc, "m-test-1", "s-test-1")
                .await
                .expect("bootstrap 2");
        assert_eq!(again, 0, "idempotent");
        assert!(
            api::keys::dev_bootstrap(&fx, config::Environment::Production, &enc, "m", "s")
                .await
                .is_err(),
            "refused outside dev/test"
        );
        // App user (SELECT only) loads signer + verify set.
        let (_issuer, set) = api::keys::load_jwt(&db, &enc, "m-test-1", "s-test-1")
            .await
            .expect("load");
        assert_eq!(set.len(), 2);
        assert!(
            api::keys::load_jwt(&db, &enc, "missing", "s-test-1")
                .await
                .is_err()
        );
        assert!(
            api::keys::load_jwt(&db, &enc, "s-test-1", "m-test-1")
                .await
                .is_err(),
            "realm swap refused"
        );

        let app = w.app_with(|r| r).await;
        let r = call(&app, get("/.well-known/jwks.json", None)).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers()[header::CONTENT_TYPE],
            "application/jwk-set+json"
        );
        let v = json(r).await;
        let kids: Vec<&str> = v["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .map(|k| k["kid"].as_str().expect("kid"))
            .collect();
        assert!(kids.contains(&"m-test-1") && kids.contains(&"s-test-1"));
        assert!(
            v["keys"]
                .as_array()
                .expect("k")
                .iter()
                .all(|k| k.get("d").is_none())
        );
    })
    .await;
}

// ---------------------------------------------------------------- staff sessions

async fn staff_ok() -> &'static str {
    "staff"
}

fn code_at(secret: &[u8], offset_s: i64) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    format!("{:06}", auth::totp::totp_at(secret, now + offset_s, 6))
}

#[tokio::test]
async fn staff_login_step_up_and_logout() {
    with_scratch("staff_sessions", |db, fx| async move {
        let w = World::new(db, fx).await;
        let e = World::email("staff");
        let u = w.user(&e, true).await;
        let mut tx = w.fixtures_db.system_tx().await.expect("tx");
        db::repo::auth_state::testing_insert_staff(
            &mut tx,
            u,
            domain::rbac::StaffRole::Superadmin,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .expect("staff");
        tx.commit().await.expect("commit");
        // TOTP enrolment through the auth service (ops path for staff); confirm on step n-1.
        let enrol = w.svc.begin_totp_enrolment(u, "staff").await.expect("begin");
        let secret = base32_decode(enrol.secret_base32());
        w.svc
            .confirm_totp_enrolment(u, enrol.factor_id, &code_at(&secret, -30))
            .await
            .expect("confirm");

        let app = w
            .app_with(|r| {
                r.get(
                    "/t/staff-danger",
                    api::app::staff_session_policy().step_up("test.staff"),
                    staff_ok,
                )
            })
            .await;
        const STAFF_LOGIN: &str = "/api/v1/platform/auth/login";
        // Password only: second factor required.
        let r = call(&app, post_json(STAFF_LOGIN, None, &creds(&e, PW))).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json(r).await["code"], "auth.mfa_required");
        let r = call(
            &app,
            post_json(
                STAFF_LOGIN,
                None,
                &json!({ "email": e, "password": PW, "totp": code_at(&secret, 0) }),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let t = json(r).await;
        let access = s(&t, "access_token");

        // Staff token is refused on member routes (audience gate) ...
        let r = call(&app, get("/api/v1/me", Some(&access))).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        // ... and a member token on staff routes.
        let m = World::email("not.staff");
        w.owner(&m).await;
        let member = login_ok(&app, &m).await;
        let r = call(
            &app,
            post_json(
                "/api/v1/platform/auth/logout",
                Some(&s(&member, "access_token")),
                &json!({}),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

        // Staff step-up: TOTP required.
        let su_path = "/api/v1/platform/auth/step-up";
        let r = call(
            &app,
            post_json(
                su_path,
                Some(&access),
                &json!({ "password": PW, "action": "test.staff" }),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "no TOTP");
        let r = call(
            &app,
            post_json(
                su_path,
                Some(&access),
                &json!({ "password": PW, "action": "test.staff", "totp": code_at(&secret, 30) }),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let su = s(&json(r).await, "step_up_token");
        let r = call(&app, get("/t/staff-danger", Some(&access))).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let r = call(
            &app,
            with_step_up(get("/t/staff-danger", Some(&access)), &su),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);

        // Staff logout revokes the session.
        let r = call(
            &app,
            post_json("/api/v1/platform/auth/logout", Some(&access), &json!({})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        let r = call(
            &app,
            post_json(
                su_path,
                Some(&access),
                &json!({ "password": PW, "action": "test.staff" }),
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "session revoked");
        let r = call(
            &app,
            post_json("/api/v1/platform/auth/logout", Some(&access), &json!({})),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    })
    .await;
}
