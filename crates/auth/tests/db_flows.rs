//! auth integration tests on the LOCAL MySQL 8.4 only (T-A2, T-A3 core, T-A4, T-DB10, constant work,
//! lockout incl. parallel load, bcrypt rehash, device principal, step-up (E19), staff realm, refresh
//! races, suspend/reactivate, logout).

#[cfg(test)]
mod support;

use std::sync::atomic::Ordering;

use auth::{
    AccessClaims, Amr, Audience, AuthEventKind, Authorized, DenyCode, EvalContext, Freshness,
    LoginError, Policy, Principal, PrincipalKind, RefreshHasher, Rejection, StaffGrantVerifier,
    TokenIssuer, TokenVerifier,
};
use common::{DeviceId, GrantId, TenantId};
use db::repo::auth_devices::{self, NewDeviceCredential};
use db::repo::memberships::MembershipStatus;
use db::repo::sessions;
use db::repo::users::UserStatus;
use domain::rbac::{Perm, Subject, Target, TenantRole};
use support::{PW, REFRESH_KEY, World, role_of, with_db};
use time::Duration;

#[tokio::test]
async fn login_then_request_happy_path() {
    with_db("login_happy", |db, url| async move {
        let w = World::new(db, url).await;
        let u = w.user("Owner@Example.com", None, true).await;
        let (t, _) = w.tenant(u).await;
        let pair = w
            .login("  owner@example.COM ", PW, Audience::Web)
            .await
            .expect("login");
        assert_eq!(pair.tenant, Some(t));
        let c = w.claims(&pair.access_token);
        assert_eq!(
            (c.audience(), c.kind(), c.tenant()),
            (Audience::Web, PrincipalKind::Member, Some(t))
        );
        let p = w
            .request(&pair.access_token, Freshness::Live)
            .await
            .expect("principal");
        assert_eq!(role_of(&p), TenantRole::Owner);
        let a = Policy::member()
            .permission(Perm::ProfileReadSelf)
            .evaluate(&p, &EvalContext::at(w.now()))
            .expect("allowed");
        assert!(matches!(a, Authorized::Tenant { .. }));
        let app = w
            .login("owner@example.com", PW, Audience::App)
            .await
            .expect("app login");
        assert_ne!(app.session, pair.session);
        assert!(app.refresh_expires_at - pair.refresh_expires_at > Duration::days(59));
        assert!(w.sink.kinds().contains(&AuthEventKind::LoginSucceeded));
    })
    .await;
}

#[tokio::test]
async fn account_states_at_login() {
    with_db("states_login", |db, url| async move {
        let w = World::new(db, url).await;
        for (email, st) in [
            ("susp@x.test", UserStatus::Suspended),
            ("dis@x.test", UserStatus::Disabled),
        ] {
            let u = w.user(email, None, true).await;
            w.tenant(u).await;
            w.set_user_status(u, st).await;
            assert!(matches!(
                w.login(email, PW, Audience::Web).await,
                Err(LoginError::Failed)
            ));
            assert_eq!(
                w.sink.last_login_failure(),
                Some("user_inactive"),
                "{email}"
            );
        }
        let u = w.user("unv@x.test", None, false).await;
        w.tenant(u).await;
        assert!(matches!(
            w.login("unv@x.test", PW, Audience::Web).await,
            Err(LoginError::Failed)
        ));
        assert_eq!(w.sink.last_login_failure(), Some("email_unverified"));
        let u = w.user("lock@x.test", None, true).await;
        w.tenant(u).await;
        for _ in 0..10 {
            assert!(w.login("lock@x.test", "nope", Audience::Web).await.is_err());
        }
        assert!(matches!(
            w.login("lock@x.test", PW, Audience::Web).await,
            Err(LoginError::Failed)
        ));
        assert_eq!(w.sink.last_login_failure(), Some("locked"));
        let o = w.user("own@x.test", None, true).await;
        let (t, om) = w.tenant(o).await;
        let mu = w.user("mem@x.test", None, true).await;
        let m = w.member(t, om, mu, TenantRole::Member).await;
        assert!(w.login("mem@x.test", PW, Audience::Web).await.is_ok());
        w.set_member_status(t, om, m, MembershipStatus::Disabled)
            .await;
        assert!(matches!(
            w.login("mem@x.test", PW, Audience::Web).await,
            Err(LoginError::Failed)
        ));
        assert_eq!(w.sink.last_login_failure(), Some("no_membership"));
        w.suspend_tenant(t).await;
        assert!(matches!(
            w.login("own@x.test", PW, Audience::Web).await,
            Err(LoginError::Failed)
        ));
        assert_eq!(w.sink.last_login_failure(), Some("tenant_inactive"));
        assert_eq!(LoginError::Failed.code(), "auth.invalid_credentials");
    })
    .await;
}

/// Login OK, then the state changes: refresh and request (cached and live) must fail.
#[tokio::test]
async fn account_states_at_refresh_and_request() {
    with_db("states_refresh", |db, url| async move {
        let w = World::new(db, url).await;
        #[derive(Clone, Copy, Debug)]
        enum Change {
            Suspend,
            Disable,
            MemberDisabled,
            TenantSuspended,
        }
        for (i, ch) in [
            Change::Suspend,
            Change::Disable,
            Change::MemberDisabled,
            Change::TenantSuspended,
        ]
        .into_iter()
        .enumerate()
        {
            let o = w.user(&format!("o{i}@x.test"), None, true).await;
            let (t, om) = w.tenant(o).await;
            let mu = w.user(&format!("m{i}@x.test"), None, true).await;
            let m = w.member(t, om, mu, TenantRole::Member).await;
            let pair = w
                .login(&format!("m{i}@x.test"), PW, Audience::Web)
                .await
                .expect("login");
            assert!(
                w.request(&pair.access_token, Freshness::Cached)
                    .await
                    .is_ok()
            );
            w.poll().await;
            assert!(
                w.request(&pair.access_token, Freshness::Cached)
                    .await
                    .is_ok(),
                "warm cache"
            );
            match ch {
                Change::Suspend => w.set_user_status(mu, UserStatus::Suspended).await,
                Change::Disable => w.set_user_status(mu, UserStatus::Disabled).await,
                Change::MemberDisabled => {
                    w.set_member_status(t, om, m, MembershipStatus::Disabled)
                        .await;
                }
                Change::TenantSuspended => w.suspend_tenant(t).await,
            }
            w.poll().await;
            assert!(
                w.request(&pair.access_token, Freshness::Cached)
                    .await
                    .is_err(),
                "{ch:?} cached"
            );
            assert!(
                w.request(&pair.access_token, Freshness::Live)
                    .await
                    .is_err(),
                "{ch:?} live"
            );
            assert!(
                matches!(
                    w.refresh(&pair, Audience::Web).await,
                    Err(LoginError::Failed)
                ),
                "{ch:?} refresh"
            );
        }
        // locked: refresh denied, request still allowed (lock is a login-time state, RBAC.md §6.3)
        let u = w.user("lk@x.test", None, true).await;
        w.tenant(u).await;
        let pair = w
            .login("lk@x.test", PW, Audience::Web)
            .await
            .expect("login");
        for _ in 0..10 {
            let _ = w.login("lk@x.test", "bad", Audience::Web).await;
        }
        assert!(matches!(
            w.refresh(&pair, Audience::Web).await,
            Err(LoginError::Failed)
        ));
        assert_eq!(w.sink.last_refresh_failure(), Some("locked"));
        assert!(w.request(&pair.access_token, Freshness::Live).await.is_ok());
    })
    .await;
}

/// F3: suspend revokes sessions + refresh families in the same tx; reactivation never revives them.
#[tokio::test]
async fn suspend_then_reactivate_old_tokens_stay_dead() {
    with_db("suspend_reactivate", |db, url| async move {
        let w = World::new(db, url).await;
        let u = w.user("sr@x.test", None, true).await;
        w.tenant(u).await;
        let pair = w
            .login("sr@x.test", PW, Audience::Web)
            .await
            .expect("login");
        let rotated = w.refresh(&pair, Audience::Web).await.expect("rotate");
        w.set_user_status(u, UserStatus::Suspended).await;
        w.set_user_status(u, UserStatus::Active).await;
        w.poll().await;
        assert!(matches!(
            w.refresh(&rotated, Audience::Web).await,
            Err(LoginError::Failed)
        ));
        assert_eq!(w.sink.last_refresh_failure(), Some("revoked"));
        let e = w
            .request(&rotated.access_token, Freshness::Cached)
            .await
            .expect_err("old access token");
        assert!(matches!(
            e.rejection(),
            Some(Rejection::SessionRevoked | Rejection::TokensRevoked)
        ));
        // a new login after reactivation works
        w.advance(Duration::seconds(2));
        let fresh = w
            .login("sr@x.test", PW, Audience::Web)
            .await
            .expect("login");
        assert!(
            w.request(&fresh.access_token, Freshness::Live)
                .await
                .is_ok()
        );
        assert!(w.refresh(&fresh, Audience::Web).await.is_ok());
    })
    .await;
}

#[tokio::test]
async fn refresh_rotation_and_reuse_revokes_family() {
    with_db("refresh_reuse", |db, url| async move {
        let w = World::new(db, url).await;
        let u = w.user("r@x.test", None, true).await;
        w.tenant(u).await;
        let p1 = w.login("r@x.test", PW, Audience::Web).await.expect("login");
        let p2 = w.refresh(&p1, Audience::Web).await.expect("rotate 1");
        assert_ne!(p1.refresh_token.expose(), p2.refresh_token.expose());
        assert_eq!(p1.session, p2.session);
        assert_eq!(p2.refresh_expires_at, p1.refresh_expires_at);
        assert!(w.refresh(&p2, Audience::App).await.is_err());
        let p3 = w.refresh(&p2, Audience::Web).await.expect("rotate 2");
        assert!(matches!(
            w.refresh(&p1, Audience::Web).await,
            Err(LoginError::Failed)
        ));
        assert!(
            w.sink
                .kinds()
                .contains(&AuthEventKind::RefreshReuseDetected)
        );
        assert!(w.refresh(&p3, Audience::Web).await.is_err());
        let e = w
            .request(&p3.access_token, Freshness::Live)
            .await
            .expect_err("revoked");
        assert_eq!(e.rejection(), Some(Rejection::SessionRevoked));
        assert!(w.svc.refresh("rt1_garbage", Audience::Web).await.is_err());
    })
    .await;
}

/// The `mark_used` Conflict path (lost race on the row lock) revokes the family — deterministic:
/// another tx holds the token row's lock and marks it used while the refresh is in flight.
#[tokio::test]
async fn refresh_race_conflict_path_revokes_family() {
    with_db("refresh_race", |db, url| async move {
        let w = World::new(db, url).await;
        let u = w.user("race@x.test", None, true).await;
        w.tenant(u).await;
        let p1 = w
            .login("race@x.test", PW, Audience::Web)
            .await
            .expect("login");
        let hash = RefreshHasher::new(&REFRESH_KEY)
            .hash(p1.refresh_token.expose())
            .expect("hash");
        let mut holder = w.db.identity_tx().await.expect("tx");
        let row = sessions::find_refresh_by_hash(&mut holder, &hash)
            .await
            .expect("find")
            .expect("row");
        sessions::mark_refresh_used(&mut holder, row.id, uuid::Uuid::now_v7(), w.now())
            .await
            .expect("mark");
        let release = async {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            holder.commit().await.expect("commit");
        };
        let (r, ()) = tokio::join!(w.refresh(&p1, Audience::Web), release);
        assert!(matches!(r, Err(LoginError::Failed)));
        assert!(
            w.sink
                .kinds()
                .contains(&AuthEventKind::RefreshReuseDetected)
        );
        let e = w
            .request(&p1.access_token, Freshness::Live)
            .await
            .expect_err("session revoked");
        assert_eq!(e.rejection(), Some(Rejection::SessionRevoked));

        // two real concurrent refreshes of one token: at most one wins, the family ends revoked
        let p2 = w
            .login("race@x.test", PW, Audience::Web)
            .await
            .expect("login");
        let (a, b) = tokio::join!(
            w.svc.refresh(p2.refresh_token.expose(), Audience::Web),
            w.svc.refresh(p2.refresh_token.expose(), Audience::Web)
        );
        let winners: Vec<_> = [a, b].into_iter().filter_map(Result::ok).collect();
        assert!(winners.len() <= 1);
        for t in &winners {
            assert!(w.refresh(t, Audience::Web).await.is_err(), "family revoked");
        }
    })
    .await;
}

/// T-A4: an `authz_version` change / epoch bump makes the next evaluation use the new role.
#[tokio::test]
async fn role_change_is_seen_by_next_evaluation() {
    with_db("authz_version", |db, url| async move {
        let w = World::new(db, url).await;
        let o = w.user("o@x.test", None, true).await;
        let (t, om) = w.tenant(o).await;
        let mu = w.user("m@x.test", None, true).await;
        let m = w.member(t, om, mu, TenantRole::Member).await;
        let pair = w.login("m@x.test", PW, Audience::Web).await.expect("login");
        let policy = Policy::member().permission(Perm::MembersCreate);
        w.poll().await;
        let p = w
            .request(&pair.access_token, Freshness::Cached)
            .await
            .expect("load");
        assert_eq!(role_of(&p), TenantRole::Member);
        assert!(policy.evaluate(&p, &EvalContext::at(w.now())).is_err());
        let hits = w.loader.stats().cache_hits.load(Ordering::SeqCst);
        let p = w
            .request(&pair.access_token, Freshness::Cached)
            .await
            .expect("load");
        assert_eq!(role_of(&p), TenantRole::Member);
        assert_eq!(
            w.loader.stats().cache_hits.load(Ordering::SeqCst),
            hits + 1,
            "cache used"
        );
        w.set_role(t, om, m, TenantRole::Admin).await;
        w.poll().await;
        let p = w
            .request(&pair.access_token, Freshness::Cached)
            .await
            .expect("load");
        assert_eq!(
            role_of(&p),
            TenantRole::Admin,
            "same old token, new live role"
        );
        let Principal::Member(mp) = &p else { panic!() };
        assert!(mp.authz_version() > w.claims(&pair.access_token).authz_version());
        let d = policy
            .evaluate(&p, &EvalContext::at(w.now()))
            .expect_err("feature off");
        assert!(matches!(
            d.code,
            DenyCode::Rbac(domain::rbac::DenyReason::FeatureDisabled(_))
        ));
        let p2 = w.refresh(&pair, Audience::Web).await.expect("refresh");
        assert_eq!(
            w.claims(&p2.access_token).authz_version(),
            mp.authz_version()
        );
    })
    .await;
}

/// T-DB10: change on pool A, loader on pool B; high-risk live read; poller outage = bypass.
#[tokio::test]
async fn epoch_cross_pool_high_risk_and_poller_outage() {
    // pool B = app pool (loader + poller), pool A = migrator pool (the "other instance").
    with_db("epochs", |db_b, db_a| async move {
        let w = World::new(db_b, db_a.clone()).await;
        let o = w.user("o@x.test", None, true).await;
        let (t, om) = w.tenant(o).await;
        let mu = w.user("m@x.test", None, true).await;
        let m = w.member(t, om, mu, TenantRole::Member).await;
        let pair = w.login("m@x.test", PW, Audience::Web).await.expect("login");
        w.poll().await;
        assert_eq!(
            role_of(
                &w.request(&pair.access_token, Freshness::Cached)
                    .await
                    .expect("l")
            ),
            TenantRole::Member
        );
        w.tick();
        let mut tx = db_a
            .tenant_tx(&World::owner_scope(t, om))
            .await
            .expect("tx");
        db::repo::memberships::set_role(&mut tx, m, TenantRole::Admin, w.now())
            .await
            .expect("role");
        tx.commit().await.expect("commit");
        let cached = w
            .request(&pair.access_token, Freshness::Cached)
            .await
            .expect("l");
        assert_eq!(role_of(&cached), TenantRole::Member);
        let hr = Policy::member().permission(Perm::MembersAssignRole);
        assert_eq!(hr.freshness(), Freshness::Live);
        let live = w
            .request(&pair.access_token, hr.freshness())
            .await
            .expect("l");
        assert_eq!(role_of(&live), TenantRole::Admin);
        w.poll().await;
        assert_eq!(
            role_of(
                &w.request(&pair.access_token, Freshness::Cached)
                    .await
                    .expect("l")
            ),
            TenantRole::Admin
        );
        w.advance(Duration::seconds(11));
        let before = w.loader.stats().live_loads.load(Ordering::SeqCst);
        w.request(&pair.access_token, Freshness::Cached)
            .await
            .expect("l");
        w.request(&pair.access_token, Freshness::Cached)
            .await
            .expect("l");
        assert_eq!(
            w.loader.stats().live_loads.load(Ordering::SeqCst),
            before + 2
        );
    })
    .await;
}

#[tokio::test]
async fn constant_work_unknown_user_and_wrong_password() {
    with_db("constant_work", |db, url| async move {
        let w = World::new(db, url).await;
        let u = w.user("known@x.test", None, true).await;
        w.tenant(u).await;
        for (email, pw) in [
            ("nobody@x.test", PW),
            ("known@x.test", "wrong"),
            ("not-an-email", PW),
        ] {
            let before = w.verifies();
            let r = w.login(email, pw, Audience::Web).await;
            assert!(matches!(r, Err(LoginError::Failed)), "{email}");
            assert_eq!(w.verifies() - before, 1, "exactly one verify for {email}");
        }
        for _ in 0..9 {
            let _ = w.login("known@x.test", "wrong", Audience::Web).await;
        }
        let real = w.stored_hash(u).await.password_hash;
        let (before, before_real) = (w.verifies(), w.verifies_against(&real));
        assert!(w.login("known@x.test", PW, Audience::Web).await.is_err());
        assert_eq!(w.verifies() - before, 1);
        assert_eq!(
            w.verifies_against(&real),
            before_real,
            "locked: real hash untouched"
        );
        for aud in [Audience::Device, Audience::Platform] {
            let before = w.verifies();
            assert!(w.login("known@x.test", PW, aud).await.is_err());
            assert_eq!(w.verifies() - before, 1, "{aud:?}");
        }
    })
    .await;
}

#[tokio::test]
async fn lockout_progression_decay_then_reset() {
    with_db("lockout", |db, url| async move {
        let w = World::new(db, url).await;
        let u = w.user("l@x.test", None, true).await;
        w.tenant(u).await;
        // decay: old failures do not count
        for _ in 0..5 {
            let _ = w.login("l@x.test", "bad", Audience::Web).await;
        }
        w.advance(Duration::minutes(16));
        let _ = w.login("l@x.test", "bad", Audience::Web).await;
        assert_eq!(w.stored_hash(u).await.failed_attempts, 1, "decayed");
        for _ in 0..9 {
            let _ = w.login("l@x.test", "bad", Audience::Web).await;
        }
        let c = w.stored_hash(u).await;
        assert_eq!(c.failed_attempts, 10);
        assert_eq!(
            c.locked_until.map(|l| l - w.now() <= Duration::minutes(15)),
            Some(true)
        );
        assert!(w.sink.kinds().contains(&AuthEventKind::LockedOut));
        assert!(
            w.login("l@x.test", PW, Audience::Web).await.is_err(),
            "locked"
        );
        w.advance(Duration::minutes(16));
        let _ = w.login("l@x.test", "bad", Audience::Web).await;
        let c = w.stored_hash(u).await;
        assert_eq!(c.failed_attempts, 11);
        let lock = c.locked_until.expect("locked") - w.now();
        assert!(
            lock > Duration::minutes(29) && lock <= Duration::minutes(30),
            "{lock}"
        );
        w.advance(Duration::minutes(31));
        assert!(w.login("l@x.test", PW, Audience::Web).await.is_ok());
        let c = w.stored_hash(u).await;
        assert_eq!((c.failed_attempts, c.locked_until), (0, None), "reset");
    })
    .await;
}

/// F4: 20 parallel wrong logins never get more than 10 real verifies (reserve-before-verify).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lockout_under_parallel_load() {
    with_db("lockout_parallel", |db, url| async move {
        let w = World::new(db, url).await;
        let u = w.user("par@x.test", None, true).await;
        w.tenant(u).await;
        let real = w.stored_hash(u).await.password_hash;
        let attempts = (0..20).map(|_| {
            w.svc.authenticate(auth::LoginRequest {
                email: "par@x.test",
                password: World::secret("wrong"),
                audience: Audience::Web,
                tenant: None,
                product_code: None,
                device_label: None,
                mfa: None,
            })
        });
        let results = futures_util::future::join_all(attempts).await;
        assert!(results.iter().all(Result::is_err));
        assert!(
            w.verifies_against(&real) <= 10,
            "{}",
            w.verifies_against(&real)
        );
        let c = w.stored_hash(u).await;
        assert_eq!(c.failed_attempts, 10);
        assert!(c.locked_until.is_some());
    })
    .await;
}

#[tokio::test]
async fn legacy_bcrypt_user_is_rehashed_to_argon2id() {
    with_db("bcrypt", |db, url| async move {
        let w = World::new(db, url).await;
        let legacy = bcrypt::hash(PW, 4).expect("bcrypt");
        let u = w.user("legacy@x.test", Some(&legacy), true).await;
        w.tenant(u).await;
        w.login("legacy@x.test", PW, Audience::Web)
            .await
            .expect("login");
        let c = w.stored_hash(u).await;
        assert!(c.password_hash.starts_with("$argon2id$"));
        assert_eq!(c.hash_scheme, "argon2id");
        assert!(w.sink.kinds().contains(&AuthEventKind::PasswordRehashed));
        w.login("legacy@x.test", PW, Audience::Web)
            .await
            .expect("login again");
        let v = w
            .user(
                "broken@x.test",
                Some("$2b$99$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
                true,
            )
            .await;
        w.tenant(v).await;
        assert!(matches!(
            w.login("broken@x.test", PW, Audience::Web).await,
            Err(LoginError::Failed)
        ));
        assert_eq!(w.sink.last_login_failure(), Some("bad_stored_hash"));
    })
    .await;
}

#[tokio::test]
async fn device_principal_is_live_and_bound() {
    with_db("device", |db, url| async move {
        let w = World::new(db, url).await;
        let o = w.user("o@x.test", None, true).await;
        let (t, om) = w.tenant(o).await;
        let cred = uuid::Uuid::now_v7();
        let device = DeviceId::new();
        let mut tx =
            w.db.tenant_tx(&World::owner_scope(t, om))
                .await
                .expect("tx");
        auth_devices::insert(
            &mut tx,
            &NewDeviceCredential {
                id: cred,
                device,
                operator: om,
                product_code: "drive".to_owned(),
                scopes: "device:reports.upload device:bogus".to_owned(),
                secret_hash: Some([1u8; 32]),
            },
            w.now(),
        )
        .await
        .expect("insert");
        tx.commit().await.expect("commit");
        let now = w.now().unix_timestamp();
        let token = w
            .issuer
            .issue_access(&AccessClaims {
                iss: support::ISS.to_owned(),
                sub: device.0,
                aud: Audience::Device,
                exp: now + 900,
                nbf: now,
                iat: now,
                jti: uuid::Uuid::now_v7(),
                typ: PrincipalKind::Device,
                tid: Some(t),
                mid: Some(om),
                sid: None,
                dcid: Some(cred),
                av: 1,
                amr: vec![Amr::Dev],
                auth_time: now,
            })
            .await
            .expect("issue");
        assert!(
            w.verifier
                .verify(&token, &[Audience::Web, Audience::App])
                .is_err()
        );
        let p = w.request(&token, Freshness::Cached).await.expect("device");
        let Principal::Device(d) = &p else {
            panic!("device")
        };
        assert_eq!((d.device(), d.owner(), d.tenant()), (device, om, t));
        let own = Target::of(t, Subject::Device(device));
        let other = Target::of(t, Subject::Device(DeviceId::new()));
        let pol = Policy::device().permission(Perm::ReportsDriveCreate);
        assert!(
            pol.evaluate_on(&p, Some(&own), &EvalContext::at(w.now()))
                .is_ok()
        );
        assert!(
            pol.evaluate_on(&p, Some(&other), &EvalContext::at(w.now()))
                .is_err()
        );
        w.tick();
        let mut tx =
            w.db.tenant_tx(&World::owner_scope(t, om))
                .await
                .expect("tx");
        auth_devices::revoke(&mut tx, cred, w.now())
            .await
            .expect("revoke");
        tx.commit().await.expect("commit");
        let e = w
            .request(&token, Freshness::Live)
            .await
            .expect_err("revoked");
        assert_eq!(e.rejection(), Some(Rejection::CredentialRevoked));
    })
    .await;
}

/// F1 / E19: step-up is a separate single-use token bound to session + action + target.
#[tokio::test]
async fn step_up_single_use_bound_to_session_action_target() {
    with_db("step_up", |db, url| async move {
        let w = World::new(db, url).await;
        let u = w.user("s@x.test", None, true).await;
        let (t, _) = w.tenant(u).await;
        let pair = w.login("s@x.test", PW, Audience::Web).await.expect("login");
        let other_session = w
            .login("s@x.test", PW, Audience::Web)
            .await
            .expect("login 2");
        let claims = w.claims(&pair.access_token);
        let claims2 = w.claims(&other_session.access_token);
        let wipe = Policy::member().permission(Perm::DevicesRemoteWipe);
        let act = wipe.required_step_up().expect("step-up action");
        let dev_a = DeviceId::new();
        let dev_b = DeviceId::new();
        let target_a = Target::of(t, Subject::Device(dev_a));
        let p = w
            .request(&pair.access_token, wipe.freshness())
            .await
            .expect("p");
        let d = wipe
            .evaluate_on(&p, Some(&target_a), &EvalContext::at(w.now()))
            .expect_err("no step-up");
        assert_eq!(d.code, DenyCode::StepUpRequired);
        assert_eq!(d.status(), 403);
        // wrong password: no token
        assert!(
            w.svc
                .step_up(&claims, World::secret("bad"), None, act, Some(dev_a.0))
                .await
                .is_err()
        );
        let su = w
            .svc
            .step_up(&claims, World::secret(PW), None, act, Some(dev_a.0))
            .await
            .expect("step-up");
        // other target / other action / other session: nothing consumed
        assert!(
            w.svc
                .consume_step_up(&claims, su.expose(), act, Some(dev_b.0))
                .await
                .expect("db")
                .is_none()
        );
        assert!(
            w.svc
                .consume_step_up(&claims, su.expose(), "members.delete", Some(dev_a.0))
                .await
                .expect("db")
                .is_none()
        );
        assert!(
            w.svc
                .consume_step_up(&claims2, su.expose(), act, Some(dev_a.0))
                .await
                .expect("db")
                .is_none()
        );
        // a refresh token string is not a step-up token
        assert!(
            w.svc
                .consume_step_up(&claims, pair.refresh_token.expose(), act, Some(dev_a.0))
                .await
                .expect("db")
                .is_none()
        );
        // exact match: consumed once, policy allows
        let proof = w
            .svc
            .consume_step_up(&claims, su.expose(), act, Some(dev_a.0))
            .await
            .expect("db")
            .expect("proof");
        assert!(
            wipe.evaluate_on(
                &p,
                Some(&target_a),
                &EvalContext::at(w.now()).with_step_up(&proof)
            )
            .is_ok()
        );
        // the proof does not open another target
        let target_b = Target::of(t, Subject::Device(dev_b));
        assert_eq!(
            wipe.evaluate_on(
                &p,
                Some(&target_b),
                &EvalContext::at(w.now()).with_step_up(&proof)
            )
            .expect_err("other target")
            .status(),
            403
        );
        // replay
        assert!(
            w.svc
                .consume_step_up(&claims, su.expose(), act, Some(dev_a.0))
                .await
                .expect("db")
                .is_none()
        );
        // expiry: a new token unused for 6 minutes is gone
        let su2 = w
            .svc
            .step_up(&claims, World::secret(PW), None, act, Some(dev_a.0))
            .await
            .expect("step-up 2");
        w.advance(Duration::minutes(6));
        assert!(
            w.svc
                .consume_step_up(&claims, su2.expose(), act, Some(dev_a.0))
                .await
                .expect("db")
                .is_none()
        );
        // logout: session + refresh dead, access token dead on next request
        w.svc.logout(&claims).await.expect("logout");
        assert!(
            w.request(&pair.access_token, Freshness::Cached)
                .await
                .is_err()
        );
        assert!(w.refresh(&pair, Audience::Web).await.is_err());
        assert!(w.sink.kinds().contains(&AuthEventKind::Logout));
    })
    .await;
}

/// F2: staff password login refused until MFA; staff sessions need MFA, 30 min idle, 8 h max.
#[tokio::test]
async fn staff_realm_mfa_idle_and_absolute_limits() {
    with_db("staff", |db, url| async move {
        let w = World::new(db, url).await;
        let (u, s) = w.staff_session("staff@x.test").await;
        assert!(matches!(
            w.login("staff@x.test", PW, Audience::Platform).await,
            Err(LoginError::Failed)
        ));
        assert_eq!(w.sink.last_login_failure(), Some("mfa_not_enrolled"));
        // no MFA on the session: rejected
        let tok = w.staff_token(u, s).await;
        let e = w.request(&tok, Freshness::Live).await.expect_err("no mfa");
        assert_eq!(e.rejection(), Some(Rejection::MfaRequired));
        w.mark_mfa(s).await;
        let p = w.request(&tok, Freshness::Live).await.expect("staff");
        assert!(matches!(p, Principal::Staff(_)));
        // idle > 30 min
        w.advance(Duration::minutes(31));
        let tok = w.staff_token(u, s).await;
        let e = w.request(&tok, Freshness::Live).await.expect_err("idle");
        assert_eq!(e.rejection(), Some(Rejection::SessionIdle));
        // active use keeps it alive, but never past 8 h
        let (u2, s2) = w.staff_session("staff2@x.test").await;
        w.mark_mfa(s2).await;
        for _ in 0..23 {
            w.advance(Duration::minutes(20));
            let tok = w.staff_token(u2, s2).await;
            w.request(&tok, Freshness::Live)
                .await
                .expect("active staff");
        }
        w.advance(Duration::minutes(21));
        let tok = w.staff_token(u2, s2).await;
        let e = w.request(&tok, Freshness::Live).await.expect_err("8h");
        assert!(matches!(e.rejection(), Some(Rejection::SessionExpired)));
        // grant verifier: unknown grant = 403 (mapping checked on the migrator pool) and always a
        // deny on the app pool. NOTE for db: on the least-privilege app pool `staff_grant::verify`
        // fails with 1142 (its `SELECT ... FOR UPDATE` needs UPDATE, App has SELECT only), which
        // surfaces as `internal`; still fail closed.
        let v = auth::DbStaffGrantVerifier::new(w.admin.clone());
        let e = v
            .verify(u2, GrantId::new(), TenantId::new(), w.now())
            .await
            .expect_err("no grant");
        assert_eq!(e.code(), "authz.forbidden");
        let app = auth::DbStaffGrantVerifier::new(w.db.clone());
        assert!(
            app.verify(u2, GrantId::new(), TenantId::new(), w.now())
                .await
                .is_err()
        );
    })
    .await;
}

/// Staff: password-only refused; password + TOTP gives a staff session with `mfa_at`; replayed code
/// refused; recovery codes single use; staff step-up needs TOTP.
#[tokio::test]
async fn staff_login_requires_totp() {
    with_db("staff_mfa", |db, admin| async move {
        let w = World::new(db, admin).await;
        let (u, _) = w.staff_session("ops@x.test").await;
        // not enrolled: refused even with the right password
        assert!(matches!(
            w.login("ops@x.test", PW, Audience::Platform).await,
            Err(LoginError::Failed)
        ));
        assert_eq!(w.sink.last_login_failure(), Some("mfa_not_enrolled"));
        let (secret, recovery) = w.enrol_totp(u).await;
        assert_eq!(recovery.len(), 10);
        // enrolled, no code: MFA required (password was right)
        assert!(matches!(
            w.login("ops@x.test", PW, Audience::Platform).await,
            Err(LoginError::MfaRequired)
        ));
        // wrong code
        assert!(matches!(
            w.login_mfa(
                "ops@x.test",
                PW,
                Audience::Platform,
                auth::MfaInput::Totp("000000".into())
            )
            .await,
            Err(LoginError::Failed)
        ));
        let code = w.code(&secret);
        let pair = w
            .login_mfa(
                "ops@x.test",
                PW,
                Audience::Platform,
                auth::MfaInput::Totp(code.clone()),
            )
            .await
            .expect("staff login");
        let c = w.claims(&pair.access_token);
        assert_eq!(
            (c.audience(), c.kind()),
            (Audience::Platform, PrincipalKind::Staff)
        );
        assert!(c.amr().contains(&Amr::Mfa));
        let p = w
            .request(&pair.access_token, Freshness::Live)
            .await
            .expect("staff");
        let Principal::Staff(sp) = &p else {
            panic!("staff")
        };
        assert!(sp.mfa_at().is_some());
        // replay of the same code (same step) refused
        assert!(matches!(
            w.login_mfa(
                "ops@x.test",
                PW,
                Audience::Platform,
                auth::MfaInput::Totp(code)
            )
            .await,
            Err(LoginError::Failed)
        ));
        assert_eq!(w.sink.last_login_failure(), Some("mfa_invalid"));
        // recovery code: works once
        let rc = recovery[0].clone();
        assert!(
            w.login_mfa(
                "ops@x.test",
                PW,
                Audience::Platform,
                auth::MfaInput::Recovery(rc.clone())
            )
            .await
            .is_ok()
        );
        assert!(matches!(
            w.login_mfa(
                "ops@x.test",
                PW,
                Audience::Platform,
                auth::MfaInput::Recovery(rc)
            )
            .await,
            Err(LoginError::Failed)
        ));
        // a refreshed staff session keeps working (mfa_at stays on the session)
        assert!(w.refresh(&pair, Audience::Platform).await.is_ok());
        // staff step-up: TOTP mandatory, recovery codes not accepted
        assert!(matches!(
            w.svc
                .step_up(&c, World::secret(PW), None, "tenants.suspend", None)
                .await,
            Err(LoginError::MfaRequired)
        ));
        assert!(
            w.svc
                .step_up(
                    &c,
                    World::secret(PW),
                    Some(auth::MfaInput::Recovery(recovery[1].clone())),
                    "tenants.suspend",
                    None
                )
                .await
                .is_err()
        );
        w.advance(Duration::seconds(30));
        let su = w
            .svc
            .step_up(
                &c,
                World::secret(PW),
                Some(auth::MfaInput::Totp(w.code(&secret))),
                "tenants.suspend",
                None,
            )
            .await
            .expect("staff step-up");
        assert!(su.expose().starts_with("su1_"));
    })
    .await;
}

/// Members: MFA optional; once enrolled login asks for a code; replay refused; pending enrolment
/// (not confirmed) changes nothing; wrong confirm code refused.
#[tokio::test]
async fn member_mfa_opt_in() {
    with_db("member_mfa", |db, admin| async move {
        let w = World::new(db, admin).await;
        let u = w.user("mm@x.test", None, true).await;
        w.tenant(u).await;
        // pending enrolment does not change login; bad confirm code is refused
        let pending = w.svc.begin_totp_enrolment(u, "mm").await.expect("begin");
        assert!(
            w.svc
                .confirm_totp_enrolment(u, pending.factor_id, "123456")
                .await
                .is_err()
        );
        assert!(w.login("mm@x.test", PW, Audience::Web).await.is_ok());
        let (secret, _) = w.enrol_totp(u).await;
        assert!(w.svc.has_mfa(u).await.expect("db"));
        assert!(matches!(
            w.login("mm@x.test", PW, Audience::Web).await,
            Err(LoginError::MfaRequired)
        ));
        let code = w.code(&secret);
        let pair = w
            .login_mfa(
                "mm@x.test",
                PW,
                Audience::Web,
                auth::MfaInput::Totp(code.clone()),
            )
            .await
            .expect("login with code");
        assert!(w.claims(&pair.access_token).amr().contains(&Amr::Mfa));
        assert!(
            w.login_mfa("mm@x.test", PW, Audience::Web, auth::MfaInput::Totp(code))
                .await
                .is_err(),
            "replay"
        );
        // wrong TOTP codes count towards the lockout
        let before = w.stored_hash(u).await.failed_attempts;
        let _ = w
            .login_mfa(
                "mm@x.test",
                PW,
                Audience::Web,
                auth::MfaInput::Totp("999999".into()),
            )
            .await;
        assert_eq!(w.stored_hash(u).await.failed_attempts, before + 1);
    })
    .await;
}
