//! Local MySQL 8.4 harness for auth integration tests, on `db::testing::ScratchDb`.
//!
//! - Only the LOCAL dev server from `.dev/dev.env` is used; URLs and credentials are never printed.
//! - Every test gets its own scratch database (+ its own least-privilege app user), created,
//!   migrated and dropped by `ScratchDb`. Business paths (`AuthService`, loader, poller) run on the
//!   scratch **app** pool (real App grants); fixtures run on the migrator pool.
//! - A global semaphore caps concurrent DB tests at 3.
//! - No env file / no server = the test FAILS. Skips only with `DSECURE_DB_TESTS=skip` (same rule as db).

#![allow(dead_code)]

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use auth::{
    AccessClaims, Amr, Audience, AuthDeps, AuthError, AuthEvent, AuthEventKind, AuthEventSink,
    AuthService, AuthSettings, DbPrincipalLoader, Es256Issuer, Es256Verifier, Freshness, KeySet,
    LoginError, LoginRequest, Principal, PrincipalKind, PrincipalStateLoader, Realm, RefreshHasher,
    TokenIssuer, TokenPair, TokenVerifier, VerifiedClaims,
};
use aws_lc_rs::hmac;
use common::{Clock, FixedClock, MembershipId, SessionId, TenantId, UserId};
use crypto::{
    Argon2Params, Argon2idHasher, BlindIndexer, BlindKind, BlindScope, CryptoError, Es256Signer,
    ParamPolicy, PasswordHasher, VerifyOutcome,
};
use db::Db;
use db::repo::memberships::{self, MembershipKind, MembershipStatus, NewMember};
use db::repo::sessions::{self, ClientKind, NewSession, PrincipalKind as DbKind};
use db::repo::tenants::{self, NewOwner, NewTenant, TenantKind};
use db::repo::users::{self, HashScheme, NewUser, UserStatus};
use db::testing::ScratchDb;
use domain::rbac::{StaffRole, TenantRole, TenantScope, Visibility};
use futures_util::FutureExt as _;
use secrecy::SecretString;
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;

pub const ISS: &str = "https://api.dsecure.test";
pub const PW: &str = "correct horse battery staple 42";
/// Refresh / step-up HMAC key used by every test world.
pub const REFRESH_KEY: [u8; 32] = [9u8; 32];

static DB_SLOTS: Semaphore = Semaphore::const_new(3);

fn unavailable(test: &str, reason: &str) -> bool {
    if db::testing::skip_allowed() {
        eprintln!("SKIP {test}: {reason} (DSECURE_DB_TESTS=skip)");
        true
    } else {
        panic!("{test}: local test DB required ({reason}); set DSECURE_DB_TESTS=skip to skip");
    }
}

/// Run `f(app, migrator)` against a fresh `ScratchDb`; always dropped afterwards.
pub async fn with_db<F, Fut>(test: &str, f: F)
where
    F: FnOnce(Db, Db) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _slot = DB_SLOTS.acquire().await.expect("db test semaphore");
    let env = match db::testing::load_env() {
        Ok(e) => e,
        Err(r) => {
            if unavailable(test, r) {
                return;
            }
            unreachable!();
        }
    };
    let scratch = match ScratchDb::create(&env).await {
        Ok(s) => s,
        Err(e) => {
            if unavailable(test, &format!("scratch db: {e}")) {
                return;
            }
            unreachable!();
        }
    };
    let migrator = scratch.migrator().clone();
    let Some(app) = scratch.app().cloned() else {
        let _ = scratch.drop_db(&env).await;
        if unavailable(test, "scratch app user needs LOCAL_MYSQL_ROOT_PASSWORD") {
            return;
        }
        unreachable!();
    };
    let result = AssertUnwindSafe(f(app, migrator)).catch_unwind().await;
    let _ = scratch.drop_db(&env).await;
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

/// Counts hasher calls (constant-work assertions use counts, never wall-clock timing) and records
/// which stored hash every verify ran against.
pub struct CountingHasher {
    inner: Argon2idHasher,
    pub verifies: AtomicUsize,
    pub hashes: AtomicUsize,
    pub verified: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl PasswordHasher for CountingHasher {
    async fn hash(&self, pw: SecretString) -> Result<String, CryptoError> {
        self.hashes.fetch_add(1, Ordering::SeqCst);
        self.inner.hash(pw).await
    }
    async fn verify(&self, pw: SecretString, h: &str) -> Result<VerifyOutcome, CryptoError> {
        self.verifies.fetch_add(1, Ordering::SeqCst);
        self.verified.lock().expect("lock").push(h.to_owned());
        self.inner.verify(pw, h).await
    }
}

/// HMAC email blind index with a fixed test key (same normalisation as production).
pub struct TestIndexer(hmac::Key);

impl BlindIndexer for TestIndexer {
    fn index(
        &self,
        kind: BlindKind,
        _scope: BlindScope,
        raw: &str,
    ) -> Result<[u8; 32], CryptoError> {
        let n = crypto::blind_index::normalise(kind, raw)?;
        let tag = hmac::sign(&self.0, n.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }
}

#[derive(Default)]
pub struct RecordingSink(pub Mutex<Vec<AuthEvent>>);

impl AuthEventSink for RecordingSink {
    fn record(&self, ev: AuthEvent) {
        self.0.lock().expect("sink").push(ev);
    }
}

impl RecordingSink {
    pub fn kinds(&self) -> Vec<AuthEventKind> {
        self.0
            .lock()
            .expect("sink")
            .iter()
            .map(|e| e.kind)
            .collect()
    }
    pub fn last_login_failure(&self) -> Option<&'static str> {
        self.kinds().into_iter().rev().find_map(|k| match k {
            AuthEventKind::LoginFailed(r) => Some(r),
            _ => None,
        })
    }
    pub fn last_refresh_failure(&self) -> Option<&'static str> {
        self.kinds().into_iter().rev().find_map(|k| match k {
            AuthEventKind::RefreshFailed(r) => Some(r),
            _ => None,
        })
    }
}

pub fn micros(t: OffsetDateTime) -> OffsetDateTime {
    t.replace_nanosecond(t.nanosecond() / 1000 * 1000)
        .unwrap_or(t)
}

pub struct World {
    /// Scratch app pool (least privilege): every business path.
    pub db: Db,
    /// Migrator pool: fixtures only.
    pub admin: Db,
    pub svc: AuthService,
    pub loader: Arc<DbPrincipalLoader>,
    pub verifier: Es256Verifier,
    pub issuer: Arc<Es256Issuer>,
    pub hasher: Arc<CountingHasher>,
    pub indexer: Arc<TestIndexer>,
    pub clock: Arc<FixedClock>,
    pub sink: Arc<RecordingSink>,
    pub settings: AuthSettings,
}

fn es256(kid: &str) -> Arc<Es256Signer> {
    let pk = Es256Signer::generate_pkcs8().expect("gen");
    Arc::new(Es256Signer::from_pkcs8(kid, &pk).expect("load"))
}

impl World {
    pub async fn new(db: Db, admin: Db) -> Self {
        let clock = Arc::new(FixedClock::new(micros(OffsetDateTime::now_utc())));
        let hasher = Arc::new(CountingHasher {
            inner: Argon2idHasher::new(
                Argon2Params {
                    m_kib: 1024,
                    t: 1,
                    p: 1,
                },
                4,
                std::time::Duration::from_secs(30),
                ParamPolicy::Relaxed,
            )
            .expect("hasher"),
            verifies: AtomicUsize::new(0),
            hashes: AtomicUsize::new(0),
            verified: Mutex::new(Vec::new()),
        });
        let indexer = Arc::new(TestIndexer(hmac::Key::new(hmac::HMAC_SHA256, &[42u8; 32])));
        let member_signer = es256("member-test-1");
        let staff_signer = es256("staff-test-1");
        let issuer = Arc::new(
            Es256Issuer::new(member_signer.clone(), staff_signer.clone(), None).expect("issuer"),
        );
        let mut keys = KeySet::new();
        keys.insert_signer(member_signer.as_ref(), Realm::Member)
            .expect("k");
        keys.insert_signer(staff_signer.as_ref(), Realm::Staff)
            .expect("k");
        let verifier = Es256Verifier::new(keys, ISS, clock.clone(), 30);
        let settings = AuthSettings::defaults(ISS);
        let fields = field_encryptor().await;
        let loader = Arc::new(DbPrincipalLoader::new(db.clone(), clock.clone(), &settings));
        let sink = Arc::new(RecordingSink::default());
        let svc = AuthService::new(AuthDeps {
            db: db.clone(),
            hasher: hasher.clone(),
            indexer: indexer.clone(),
            issuer: issuer.clone(),
            refresh: RefreshHasher::new(&REFRESH_KEY),
            fields,
            sink: sink.clone(),
            clock: clock.clone(),
            loader: loader.clone(),
            settings: settings.clone(),
        })
        .await
        .expect("service");
        Self {
            db,
            admin,
            svc,
            loader,
            verifier,
            issuer,
            hasher,
            indexer,
            clock,
            sink,
            settings,
        }
    }

    pub fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    /// Advance the fixed clock (keeps every DB timestamp strictly increasing).
    pub fn tick(&self) {
        self.clock.advance(Duration::milliseconds(5));
    }

    pub fn advance(&self, d: Duration) {
        self.clock.advance(d);
    }

    pub fn verifies(&self) -> usize {
        self.hasher.verifies.load(Ordering::SeqCst)
    }

    /// Verifies that ran against this exact stored hash.
    pub fn verifies_against(&self, hash: &str) -> usize {
        self.hasher
            .verified
            .lock()
            .expect("lock")
            .iter()
            .filter(|h| h.as_str() == hash)
            .count()
    }

    /// New user with an Argon2id password (or a given legacy hash).
    pub async fn user(&self, email: &str, legacy_hash: Option<&str>, verified: bool) -> UserId {
        self.tick();
        let bidx = self
            .indexer
            .index(BlindKind::Email, BlindScope::Global, email)
            .expect("bidx");
        let phc = match legacy_hash {
            Some(h) => h.to_owned(),
            None => self
                .hasher
                .inner
                .hash(SecretString::from(PW.to_owned()))
                .await
                .expect("hash"),
        };
        let scheme = if legacy_hash.is_some() {
            HashScheme::BcryptLegacy
        } else {
            HashScheme::Argon2id
        };
        let mut tx = self.admin.identity_tx().await.expect("tx");
        let id = users::insert(
            &mut tx,
            &NewUser {
                id: UserId::new(),
                email_bidx: bidx,
                email_enc: vec![1, 2, 3],
                name_enc: None,
                status: UserStatus::Active,
            },
            self.now(),
        )
        .await
        .expect("insert user");
        users::set_password(&mut tx, id, &phc, scheme, self.now())
            .await
            .expect("password");
        if verified {
            db::repo::auth_account::mark_email_verified(&mut tx, id, "staff", self.now())
                .await
                .expect("verify");
        }
        tx.commit().await.expect("commit");
        id
    }

    pub async fn stored_hash(&self, u: UserId) -> users::CredentialRow {
        let mut tx = self.admin.identity_tx().await.expect("tx");
        let c = users::credentials(&mut tx, u)
            .await
            .expect("c")
            .expect("row");
        tx.rollback().await;
        c
    }

    pub async fn tenant(&self, owner: UserId) -> (TenantId, MembershipId) {
        self.tick();
        let mut tx = self.admin.system_tx().await.expect("tx");
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
            self.now(),
        )
        .await
        .expect("tenant");
        tx.commit().await.expect("commit");
        (c.tenant, c.owner)
    }

    pub fn owner_scope(tenant: TenantId, owner: MembershipId) -> TenantScope {
        TenantScope::for_tests(tenant, owner, Visibility::Tenant, None)
    }

    pub async fn member(
        &self,
        tenant: TenantId,
        owner: MembershipId,
        user: UserId,
        role: TenantRole,
    ) -> MembershipId {
        self.tick();
        let mut tx = self
            .db
            .tenant_tx(&Self::owner_scope(tenant, owner))
            .await
            .expect("tx");
        let id = memberships::insert(
            &mut tx,
            &NewMember {
                id: MembershipId::new(),
                user_id: user,
                role,
                kind: MembershipKind::Primary,
                status: MembershipStatus::Active,
                parent_membership_id: None,
                department_id: None,
                display_name_enc: None,
            },
            self.now(),
        )
        .await
        .expect("member");
        tx.commit().await.expect("commit");
        id
    }

    pub async fn set_role(
        &self,
        tenant: TenantId,
        owner: MembershipId,
        m: MembershipId,
        role: TenantRole,
    ) {
        self.tick();
        let mut tx = self
            .db
            .tenant_tx(&Self::owner_scope(tenant, owner))
            .await
            .expect("tx");
        memberships::set_role(&mut tx, m, role, self.now())
            .await
            .expect("set role");
        tx.commit().await.expect("commit");
    }

    pub async fn set_member_status(
        &self,
        tenant: TenantId,
        owner: MembershipId,
        m: MembershipId,
        s: MembershipStatus,
    ) {
        self.tick();
        let mut tx = self
            .db
            .tenant_tx(&Self::owner_scope(tenant, owner))
            .await
            .expect("tx");
        memberships::set_status(&mut tx, m, s, self.now())
            .await
            .expect("set status");
        tx.commit().await.expect("commit");
    }

    pub async fn set_user_status(&self, u: UserId, s: UserStatus) {
        self.tick();
        let mut tx = self.admin.identity_tx().await.expect("tx");
        db::repo::auth_account::set_user_status(&mut tx, u, s, self.now())
            .await
            .expect("status");
        tx.commit().await.expect("commit");
    }

    pub async fn suspend_tenant(&self, t: TenantId) {
        self.tick();
        let mut tx = self.admin.system_tx().await.expect("tx");
        db::repo::auth_account::set_tenant_status(
            &mut tx,
            t,
            db::repo::auth_account::TenantStatus::Suspended,
            self.now(),
        )
        .await
        .expect("suspend");
        tx.commit().await.expect("commit");
    }

    pub async fn login(
        &self,
        email: &str,
        pw: &str,
        aud: Audience,
    ) -> Result<TokenPair, LoginError> {
        self.tick();
        self.svc
            .authenticate(LoginRequest {
                email,
                password: SecretString::from(pw.to_owned()),
                audience: aud,
                tenant: None,
                product_code: None,
                device_label: None,
                mfa: None,
            })
            .await
    }

    pub async fn login_mfa(
        &self,
        email: &str,
        pw: &str,
        aud: Audience,
        mfa: auth::MfaInput,
    ) -> Result<TokenPair, LoginError> {
        self.tick();
        self.svc
            .authenticate(LoginRequest {
                email,
                password: SecretString::from(pw.to_owned()),
                audience: aud,
                tenant: None,
                product_code: None,
                device_label: None,
                mfa: Some(mfa),
            })
            .await
    }

    /// Enrol + confirm TOTP for `u`; returns (raw secret, recovery codes).
    pub async fn enrol_totp(&self, u: UserId) -> (Vec<u8>, Vec<String>) {
        let e = self
            .svc
            .begin_totp_enrolment(u, "user@x.test")
            .await
            .expect("begin");
        assert!(e.otpauth_uri().starts_with("otpauth://totp/DSecure:"));
        let secret = base32_decode(e.secret_base32());
        let rc = self
            .svc
            .confirm_totp_enrolment(u, e.factor_id, &self.code(&secret))
            .await
            .expect("confirm");
        let codes = rc.codes().into_iter().map(str::to_owned).collect();
        // the confirming step is used up: move to the next step for the next code
        self.advance(Duration::seconds(30));
        (secret, codes)
    }

    /// Current TOTP code at the fixed clock.
    pub fn code(&self, secret: &[u8]) -> String {
        format!(
            "{:06}",
            auth::totp::totp_at(secret, self.now().unix_timestamp(), auth::totp::DIGITS)
        )
    }

    pub async fn refresh(&self, pair: &TokenPair, aud: Audience) -> Result<TokenPair, LoginError> {
        self.tick();
        self.svc.refresh(pair.refresh_token.expose(), aud).await
    }

    pub fn claims(&self, token: &str) -> VerifiedClaims {
        self.verifier
            .verify(
                token,
                &[
                    Audience::Web,
                    Audience::App,
                    Audience::Device,
                    Audience::Platform,
                ],
            )
            .expect("verify")
    }

    /// Request path: verify + live/cached principal load.
    pub async fn request(&self, token: &str, fresh: Freshness) -> Result<Principal, AuthError> {
        let c = self.verifier.verify(
            token,
            &[
                Audience::Web,
                Audience::App,
                Audience::Device,
                Audience::Platform,
            ],
        )?;
        self.loader.load(&c, fresh).await
    }

    pub async fn poll(&self) {
        self.tick();
        auth::poll_epochs_once(&self.db, self.clock.as_ref())
            .await
            .expect("poll");
    }

    pub fn secret(pw: &str) -> SecretString {
        SecretString::from(pw.to_owned())
    }

    /// Staff user + staff session created directly (password login for staff is refused until MFA).
    pub async fn staff_session(&self, email: &str) -> (UserId, SessionId) {
        let u = self.user(email, None, true).await;
        self.tick();
        let mut tx = self.admin.system_tx().await.expect("tx");
        db::repo::auth_state::testing_insert_staff(&mut tx, u, StaffRole::Support, self.now())
            .await
            .expect("staff");
        tx.commit().await.expect("commit");
        let s = SessionId::new();
        let mut tx = self.admin.identity_tx().await.expect("tx");
        sessions::insert(
            &mut tx,
            &NewSession {
                id: s,
                user_id: u,
                tenant: None,
                principal_kind: DbKind::Staff,
                client_kind: ClientKind::PlatformConsole,
                product_code: None,
                device_label: None,
                expires_at: self.now() + self.settings.refresh_ttl_platform,
            },
            self.now(),
        )
        .await
        .expect("session");
        tx.commit().await.expect("commit");
        (u, s)
    }

    pub async fn mark_mfa(&self, s: SessionId) {
        let mut tx = self.admin.identity_tx().await.expect("tx");
        db::repo::auth_state::mark_session_mfa(&mut tx, s, self.now())
            .await
            .expect("mfa");
        tx.commit().await.expect("commit");
    }

    /// Fresh staff access token at the current clock time.
    pub async fn staff_token(&self, u: UserId, s: SessionId) -> String {
        let now = self.now().unix_timestamp();
        self.issuer
            .issue_access(&AccessClaims {
                iss: ISS.to_owned(),
                sub: u.0,
                aud: Audience::Platform,
                exp: now + 900,
                nbf: now,
                iat: now,
                jti: uuid::Uuid::now_v7(),
                typ: PrincipalKind::Staff,
                tid: None,
                mid: None,
                sid: Some(s),
                dcid: None,
                av: 1,
                amr: vec![Amr::Pwd, Amr::Mfa],
                auth_time: now,
            })
            .await
            .expect("issue")
    }
}

pub fn role_of(p: &Principal) -> TenantRole {
    match p {
        Principal::Member(m) => m.role(),
        other => panic!("member expected, got {other:?}"),
    }
}

/// Platform-key field encryptor over an in-memory DEK store (test KEK, never a real key).
pub async fn field_encryptor() -> Arc<dyn crypto::FieldEncryptor> {
    use base64::Engine as _;
    let p: Arc<dyn crypto::KeyProvider> = Arc::new(
        crypto::EnvKeyProvider::new(
            "testkek1",
            [(
                "testkek1",
                base64::engine::general_purpose::STANDARD.encode([5u8; 32]),
            )],
        )
        .expect("provider"),
    );
    let store = Arc::new(crypto::InMemoryDekStore::new());
    crypto::KeyRing::ensure_platform_keys(&*p, &*store)
        .await
        .expect("platform keys");
    let ring = Arc::new(
        crypto::KeyRing::load_platform(p, store)
            .await
            .expect("ring"),
    );
    Arc::new(crypto::AesGcmFieldEncryptor::new(ring))
}

/// RFC 4648 base32 decode (test helper for the enrolment secret).
pub fn base32_decode(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let mut buf: u64 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = A.iter().position(|x| *x == c).expect("base32 char") as u64;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    out
}
