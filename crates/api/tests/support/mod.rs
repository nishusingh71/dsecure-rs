//! End-to-end harness: LOCAL MySQL scratch DB (`db::testing::ScratchDb`, `.dev/dev.env`), real
//! `AuthService`, real `LiveAuthenticator` and the real route table + middleware stack. Never prints
//! URLs or credentials; never touches anything but `dsecure_t_*` scratch databases.

#![allow(dead_code)]

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use api::authn::LiveAuthenticator;
use api::middleware::client_ip::TrustedProxies;
use api::ratelimit::{PreAuthLimiter, Rule, Rules};
use api::{AppState, AuthHttp, GateDeps, HttpSettings, PolicyRouter, RouteOptions, assemble};
use auth::{
    AccessClaims, Amr, Audience, AuthDeps, AuthService, AuthSettings, DbPrincipalLoader,
    Es256Issuer, Es256Verifier, KeySet, LoginRequest, NoopSink, PrincipalKind, Realm,
    RefreshHasher, TokenIssuer as _,
};
use aws_lc_rs::hmac;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, header};
use common::{Clock, MembershipId, SessionId, SystemClock, TenantId, UserId};
use config::Environment;
use crypto::{
    AesGcmFieldEncryptor, Argon2Params, Argon2idHasher, BlindIndexer, BlindKind, BlindScope,
    CryptoError, EnvKeyProvider, Es256Signer, InMemoryDekStore, KeyRing, ParamPolicy,
    PasswordHasher,
};
use db::Db;
use db::repo::auth_account::{self, TenantStatus};
use db::repo::memberships::{self, MembershipKind, MembershipStatus, NewMember};
use db::repo::tenants::{self, NewOwner, NewTenant, TenantKind};
use db::repo::users::{self, HashScheme, NewUser, UserStatus};
use db::testing::{ScratchDb, TestEnv};
use domain::rbac::{TenantRole, TenantScope, Visibility};
use futures_util::FutureExt as _;
use secrecy::SecretString;
use tower::ServiceExt as _;

pub const ISS: &str = "https://api.dsecure.test";
pub const PW: &str = "correct horse battery staple 42";

/// Run `f` against a fresh scratch DB; always dropped afterwards (also on panic).
pub async fn with_scratch<F, Fut>(test: &str, f: F)
where
    F: FnOnce(Db, Db) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let env: TestEnv = match db::testing::load_env() {
        Ok(e) => e,
        Err(reason) if db::testing::skip_allowed() => {
            eprintln!("SKIP {test}: {reason} (DSECURE_DB_TESTS=skip)");
            return;
        }
        Err(reason) => panic!("{test}: local test DB env unavailable: {reason}"),
    };
    let scratch = match ScratchDb::create(&env).await {
        Ok(s) => s,
        Err(e) if db::testing::skip_allowed() => {
            eprintln!("SKIP {test}: scratch DB failed ({e})");
            return;
        }
        Err(e) => panic!("{test}: scratch DB failed: {e}"),
    };
    let migrator = scratch.migrator().clone();
    let app = scratch.app().cloned().unwrap_or_else(|| migrator.clone());
    let r = AssertUnwindSafe(f(app, migrator)).catch_unwind().await;
    let _ = scratch.drop_db(&env).await;
    if let Err(p) = r {
        std::panic::resume_unwind(p);
    }
}

/// HMAC email blind index with a fixed test key (production normalisation).
pub struct TestIndexer(hmac::Key);

impl BlindIndexer for TestIndexer {
    fn index(&self, kind: BlindKind, _s: BlindScope, raw: &str) -> Result<[u8; 32], CryptoError> {
        let n = crypto::blind_index::normalise(kind, raw)?;
        let tag = hmac::sign(&self.0, n.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }
}

fn es256(kid: &str) -> Arc<Es256Signer> {
    let pk = Es256Signer::generate_pkcs8().expect("gen");
    Arc::new(Es256Signer::from_pkcs8(kid, &pk).expect("load"))
}

pub async fn test_keyring() -> Arc<KeyRing> {
    let kek = crypto::devkeys::generate_kek_b64().expect("kek");
    let provider = Arc::new(EnvKeyProvider::new("t1", [("t1", (*kek).clone())]).expect("kek"));
    let store = Arc::new(InMemoryDekStore::new());
    KeyRing::ensure_platform_keys(provider.as_ref(), store.as_ref())
        .await
        .expect("bootstrap");
    Arc::new(KeyRing::load_platform(provider, store).await.expect("ring"))
}

/// Limits high enough that only the rate-limit tests ever hit them.
pub fn relaxed_rules() -> Rules {
    let r = |name| Rule::new(name, 10_000, std::time::Duration::from_secs(60));
    Rules {
        login_ip: r("login_ip"),
        login_ip_email: r("login_ip_email"),
        login_net: r("login_net"),
        refresh_ip: r("refresh_ip"),
        step_up_ip: r("step_up_ip"),
    }
}

static SEQ: AtomicUsize = AtomicUsize::new(0);

pub struct World {
    pub db: Db,
    pub fixtures_db: Db,
    pub svc: Arc<AuthService>,
    pub verifier: Arc<Es256Verifier>,
    pub loader: Arc<DbPrincipalLoader>,
    pub issuer: Arc<Es256Issuer>,
    pub hasher: Arc<Argon2idHasher>,
    pub indexer: Arc<TestIndexer>,
    pub keys: Arc<KeyRing>,
    pub clock: Arc<dyn Clock>,
}

impl World {
    pub async fn new(db: Db, fixtures_db: Db) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let hasher = Arc::new(
            Argon2idHasher::new(
                Argon2Params {
                    m_kib: 1024,
                    t: 1,
                    p: 1,
                },
                2,
                std::time::Duration::from_secs(10),
                ParamPolicy::Relaxed,
            )
            .expect("hasher"),
        );
        let indexer = Arc::new(TestIndexer(hmac::Key::new(hmac::HMAC_SHA256, &[42u8; 32])));
        let member = es256("member-test-1");
        let staff = es256("staff-test-1");
        let cleaner = es256("cleaner-test-1");
        let issuer = Arc::new(
            Es256Issuer::new(member.clone(), staff.clone(), Some(cleaner.clone())).expect("iss"),
        );
        let mut keys = KeySet::new();
        keys.insert_signer(member.as_ref(), Realm::Member)
            .expect("k");
        keys.insert_signer(staff.as_ref(), Realm::Staff).expect("k");
        keys.insert_signer(cleaner.as_ref(), Realm::Cleaner)
            .expect("k");
        let verifier = Arc::new(Es256Verifier::new(keys, ISS, clock.clone(), 30));
        let settings = AuthSettings::defaults(ISS);
        let loader = Arc::new(DbPrincipalLoader::new(db.clone(), clock.clone(), &settings));
        let ring = test_keyring().await;
        let svc = AuthService::new(AuthDeps {
            db: db.clone(),
            hasher: hasher.clone(),
            indexer: indexer.clone(),
            issuer: issuer.clone(),
            refresh: RefreshHasher::new(&[9u8; 32]),
            fields: Arc::new(AesGcmFieldEncryptor::new(ring.clone())),
            sink: Arc::new(NoopSink),
            clock: clock.clone(),
            loader: loader.clone(),
            settings,
        })
        .await
        .expect("auth service");
        Self {
            db,
            fixtures_db,
            svc: Arc::new(svc),
            verifier,
            loader,
            issuer,
            hasher,
            indexer,
            keys: ring,
            clock,
        }
    }

    /// Unique test email.
    pub fn email(prefix: &str) -> String {
        format!(
            "{prefix}.{}@example.com",
            SEQ.fetch_add(1, Ordering::SeqCst)
        )
    }

    /// User with password [`PW`] (no tenant).
    pub async fn user(&self, email: &str, verified: bool) -> UserId {
        let now = self.clock.now();
        let bidx = self
            .indexer
            .index(BlindKind::Email, BlindScope::Global, email)
            .expect("bidx");
        let mut tx = self.fixtures_db.identity_tx().await.expect("tx");
        let id = users::insert(
            &mut tx,
            &NewUser {
                id: UserId::new(),
                email_bidx: bidx,
                email_enc: vec![1, 2, 3],
                name_enc: None,
                status: UserStatus::Active,
            },
            now,
        )
        .await
        .expect("user");
        let phc = self
            .hasher
            .hash(SecretString::from(PW.to_owned()))
            .await
            .expect("hash");
        users::set_password(&mut tx, id, &phc, HashScheme::Argon2id, now)
            .await
            .expect("pw");
        if verified {
            auth_account::mark_email_verified(&mut tx, id, "staff", now)
                .await
                .expect("verify");
        }
        tx.commit().await.expect("commit");
        id
    }

    /// Fresh tenant owned by `owner`.
    pub async fn tenant(&self, owner: UserId) -> (TenantId, MembershipId) {
        let mut tx = self.fixtures_db.system_tx().await.expect("tx");
        let c = tenants::create(
            &mut tx,
            &NewTenant {
                id: TenantId::new(),
                kind: TenantKind::Organization,
                display_name_enc: vec![9],
            },
            &NewOwner {
                membership_id: MembershipId::new(),
                user_id: owner,
                display_name_enc: None,
            },
            self.clock.now(),
        )
        .await
        .expect("tenant");
        tx.commit().await.expect("commit");
        (c.tenant, c.owner)
    }

    /// Verified user with password [`PW`] owning a fresh tenant.
    pub async fn owner(&self, email: &str) -> (UserId, TenantId, MembershipId) {
        let u = self.user(email, true).await;
        let (t, m) = self.tenant(u).await;
        (u, t, m)
    }

    fn owner_scope(tenant: TenantId, owner: MembershipId) -> TenantScope {
        TenantScope::for_tests(tenant, owner, Visibility::Tenant, None)
    }

    /// `user` joins `tenant` as a plain member.
    pub async fn member(
        &self,
        tenant: TenantId,
        owner: MembershipId,
        user: UserId,
    ) -> MembershipId {
        let mut tx = self
            .fixtures_db
            .tenant_tx(&Self::owner_scope(tenant, owner))
            .await
            .expect("tx");
        let id = memberships::insert(
            &mut tx,
            &NewMember {
                id: MembershipId::new(),
                user_id: user,
                role: TenantRole::Member,
                kind: MembershipKind::Primary,
                status: MembershipStatus::Active,
                parent_membership_id: None,
                department_id: None,
                display_name_enc: None,
            },
            self.clock.now(),
        )
        .await
        .expect("member");
        tx.commit().await.expect("commit");
        id
    }

    pub async fn set_member_status(
        &self,
        tenant: TenantId,
        owner: MembershipId,
        m: MembershipId,
        s: MembershipStatus,
    ) {
        let mut tx = self
            .fixtures_db
            .tenant_tx(&Self::owner_scope(tenant, owner))
            .await
            .expect("tx");
        memberships::set_status(&mut tx, m, s, self.clock.now())
            .await
            .expect("status");
        tx.commit().await.expect("commit");
    }

    pub async fn set_user_status(&self, u: UserId, s: UserStatus) {
        let mut tx = self.fixtures_db.identity_tx().await.expect("tx");
        auth_account::set_user_status(&mut tx, u, s, self.clock.now())
            .await
            .expect("status");
        tx.commit().await.expect("commit");
    }

    pub async fn suspend_tenant(&self, t: TenantId) {
        let mut tx = self.fixtures_db.system_tx().await.expect("tx");
        auth_account::set_tenant_status(&mut tx, t, TenantStatus::Suspended, self.clock.now())
            .await
            .expect("suspend");
        tx.commit().await.expect("commit");
    }

    /// Direct (non-HTTP) login -> access token.
    pub async fn login(&self, email: &str) -> String {
        self.svc
            .authenticate(LoginRequest {
                email,
                password: SecretString::from(PW.to_owned()),
                audience: Audience::Web,
                tenant: None,
                product_code: None,
                device_label: None,
                mfa: None,
            })
            .await
            .expect("login")
            .access_token
    }

    /// Correctly signed token for another audience (shape-valid for that kind).
    pub async fn token_for(&self, aud: Audience, kind: PrincipalKind) -> String {
        let now = self.clock.now().unix_timestamp();
        let c = AccessClaims {
            iss: ISS.into(),
            sub: uuid::Uuid::now_v7(),
            aud,
            exp: now + 300,
            nbf: now - 1,
            iat: now - 1,
            jti: uuid::Uuid::now_v7(),
            typ: kind,
            tid: None,
            mid: None,
            sid: Some(SessionId::new()),
            dcid: None,
            av: 0,
            amr: vec![Amr::Pwd],
            auth_time: now - 1,
        };
        self.issuer.issue_access(&c).await.expect("issue")
    }

    pub fn gate(&self) -> GateDeps {
        GateDeps {
            authn: Arc::new(LiveAuthenticator::new(
                self.verifier.clone(),
                self.loader.clone(),
            )),
            clock: self.clock.clone(),
            db: Some(self.db.clone()),
            auth: Some(self.svc.clone()),
        }
    }

    pub async fn state(&self, keys: bool) -> AppState {
        self.state_with(keys, relaxed_rules()).await
    }

    pub async fn state_with(&self, keys: bool, rules: Rules) -> AppState {
        let ring = keys.then(|| self.keys.clone());
        let cursor = api::state::cursor_key_from(&self.keys)
            .await
            .expect("cursor");
        AppState::new(Environment::Test, self.db.clone(), ring, cursor).with_auth(AuthHttp {
            service: self.svc.clone(),
            limiter: Arc::new(PreAuthLimiter::in_memory(rules).expect("limiter")),
            indexer: self.indexer.clone(),
        })
    }

    pub fn http() -> HttpSettings {
        HttpSettings {
            max_inflight: 32,
            max_json_body: 65_536,
            timeout: std::time::Duration::from_secs(15),
            cors_origins: Vec::new(),
            proxies: TrustedProxies::new(1, &["10.0.0.0/8".into()]).expect("tp"),
        }
    }

    /// Real route table (+ optional extra test routes), full middleware stack.
    pub async fn app_with(
        &self,
        extra: impl FnOnce(PolicyRouter<AppState>) -> PolicyRouter<AppState>,
    ) -> Router {
        self.app_full(extra, relaxed_rules()).await
    }

    pub async fn app_full(
        &self,
        extra: impl FnOnce(PolicyRouter<AppState>) -> PolicyRouter<AppState>,
        rules: Rules,
    ) -> Router {
        let routes = extra(api::build_routes(&RouteOptions {
            environment: Environment::Test,
            openapi_public: true,
        }));
        assemble(
            routes,
            self.state_with(true, rules).await,
            self.gate(),
            &Self::http(),
        )
        .expect("router")
        .0
    }
}

// ---- HTTP helpers ----

pub async fn json(r: axum::response::Response) -> serde_json::Value {
    let b = axum::body::to_bytes(r.into_body(), 1 << 20)
        .await
        .expect("body");
    if b.is_empty() {
        return serde_json::Value::Null;
    }
    serde_json::from_slice(&b).expect("json")
}

pub async fn call(app: &Router, req: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(req).await.expect("resp")
}

pub fn post_json(path: &str, token: Option<&str>, body: &serde_json::Value) -> Request<Body> {
    let mut b = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).expect("req")
}

pub fn get(path: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::get(path);
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::empty()).expect("req")
}

/// Problem body without the per-request id (for "indistinguishable" comparisons).
pub fn without_request_id(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(o) = v.as_object_mut() {
        o.remove("request_id");
    }
    v
}
