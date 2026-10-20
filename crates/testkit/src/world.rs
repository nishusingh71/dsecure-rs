//! `World`: the real auth stack on a scratch DB plus the standard fixture population.
//!
//! Standard population (see [`World::standard`]):
//! - tenant A (features subusers + groups + user_activity ON, private_cloud OFF): owner, admin,
//!   member, viewer, group admin (member + group `ops` + group-admin grant), a member whose user is
//!   suspended after login, a member whose membership is disabled after login, an enrolled device
//!   (operator = A member);
//! - tenant B (all features OFF): owner, member;
//! - tenant C (suspended after login): owner;
//! - platform staff (support) with MFA, and one without MFA;
//! - anonymous, garbage and expired-token callers.
//!
//! Tokens come from `AuthService::authenticate` (members) or the real `Es256Issuer` (device, staff,
//! expired). Gaps: staff is `Support` only (no staff-only tenant routes exist yet); a staff user
//! created through the 4-eyes `PlatformAdminTx` path and a staff access grant (`VerifiedGrant`) are
//! not exercised; fixture writes for features / group-admin grants are raw inserts on the migrator
//! pool because Phase 0 has no repo function for them.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use api::authn::LiveAuthenticator;
use api::middleware::client_ip::TrustedProxies;
use api::ratelimit::{PreAuthLimiter, Rule, Rules};
use api::{AppState, AuthHttp, GateDeps, HttpSettings, PolicyRouter, RouteOptions, assemble};
use auth::{
    AccessClaims, Amr, Audience, AuthDeps, AuthService, AuthSettings, DbPrincipalLoader,
    Es256Issuer, Es256Verifier, KeySet, LoginRequest, PrincipalKind, Realm, RefreshHasher,
    TokenIssuer as _,
};
use aws_lc_rs::hmac;
use axum::Router;
use common::{Clock, DeviceId, GroupId, MembershipId, SessionId, SystemClock, TenantId, UserId};
use config::Environment;
use crypto::{
    AesGcmFieldEncryptor, Argon2Params, Argon2idHasher, BlindIndexer, BlindKind, BlindScope,
    CryptoError, EnvKeyProvider, Es256Signer, InMemoryDekStore, KeyRing, ParamPolicy,
    PasswordHasher,
};
use db::Db;
use db::repo::auth_devices::{self, NewDeviceCredential};
use db::repo::memberships::{self, MembershipKind, MembershipStatus, NewMember};
use db::repo::sessions::{self, ClientKind, NewSession, PrincipalKind as DbKind};
use db::repo::tenants::{self, NewOwner, NewTenant, TenantKind};
use db::repo::users::{self, HashScheme, NewUser, UserStatus};
use db::repo::{auth_account, groups};
use db::testing::{RawBind, raw_exec};
use domain::rbac::{Feature, StaffRole, TenantRole, TenantScope, Visibility};
use secrecy::SecretString;

use crate::principals::{Persona, PersonaKind, names};

pub const ISS: &str = "https://api.dsecure.test";
pub const PW: &str = "correct horse battery staple 42";

static SEQ: AtomicUsize = AtomicUsize::new(0);

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

async fn test_keyring() -> Arc<KeyRing> {
    let kek = crypto::devkeys::generate_kek_b64().expect("kek");
    let provider = Arc::new(EnvKeyProvider::new("t1", [("t1", (*kek).clone())]).expect("kek"));
    let store = Arc::new(InMemoryDekStore::new());
    KeyRing::ensure_platform_keys(provider.as_ref(), store.as_ref())
        .await
        .expect("bootstrap");
    Arc::new(KeyRing::load_platform(provider, store).await.expect("ring"))
}

/// Limits high enough that the matrix never trips a rate limit.
#[must_use]
pub fn relaxed_rules() -> Rules {
    let r = |name| Rule::new(name, 100_000, std::time::Duration::from_secs(60));
    Rules {
        login_ip: r("login_ip"),
        login_ip_email: r("login_ip_email"),
        login_net: r("login_net"),
        refresh_ip: r("refresh_ip"),
        step_up_ip: r("step_up_ip"),
    }
}

/// A tenant of the standard population.
#[derive(Clone, Debug)]
pub struct TenantFx {
    pub id: TenantId,
    pub owner_membership: MembershipId,
    /// Group `ops` (tenant A only).
    pub group: Option<GroupId>,
    pub features: Vec<Feature>,
}

pub struct World {
    /// App-role pool (least privilege when the local root password exists).
    pub db: Db,
    /// Migrator pool, used for fixture writes the app role may not do.
    pub fixtures_db: Db,
    pub svc: Arc<AuthService>,
    pub verifier: Arc<Es256Verifier>,
    pub loader: Arc<DbPrincipalLoader>,
    pub issuer: Arc<Es256Issuer>,
    pub hasher: Arc<Argon2idHasher>,
    pub indexer: Arc<TestIndexer>,
    pub keys: Arc<KeyRing>,
    pub clock: Arc<dyn Clock>,
    pub a: Option<TenantFx>,
    pub b: Option<TenantFx>,
    pub personas: Vec<Persona>,
    /// Platform staff user that owns the feature toggles.
    staff_admin: Option<UserId>,
}

impl World {
    /// Empty world: services only, no data (use the builder methods or [`World::standard`]).
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
            sink: Arc::new(auth::NoopSink),
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
            a: None,
            b: None,
            personas: Vec::new(),
            staff_admin: None,
        }
    }

    // ---------------------------------------------------------------- low-level builders

    /// Unique test email.
    #[must_use]
    pub fn email(prefix: &str) -> String {
        format!(
            "{prefix}.{}@example.com",
            SEQ.fetch_add(1, Ordering::SeqCst)
        )
    }

    /// Verified user with password [`PW`] (no tenant).
    pub async fn user(&self, email: &str) -> UserId {
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
        auth_account::mark_email_verified(&mut tx, id, "staff", now)
            .await
            .expect("verify");
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

    #[must_use]
    pub const fn owner_scope(tenant: TenantId, owner: MembershipId) -> TenantScope {
        TenantScope::for_tests(tenant, owner, Visibility::Tenant, None)
    }

    /// `user` joins `tenant` with `role`.
    pub async fn add_member(
        &self,
        tenant: TenantId,
        owner: MembershipId,
        user: UserId,
        role: TenantRole,
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
                role,
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

    /// Group in `tenant` (created by the owner).
    pub async fn group(&self, tenant: TenantId, owner: MembershipId, name: &str) -> GroupId {
        let mut tx = self
            .fixtures_db
            .tenant_tx(&Self::owner_scope(tenant, owner))
            .await
            .expect("tx");
        let id = groups::create(&mut tx, GroupId::new(), name, None, self.clock.now())
            .await
            .expect("group");
        tx.commit().await.expect("commit");
        id
    }

    pub async fn add_to_group(
        &self,
        tenant: TenantId,
        owner: MembershipId,
        group: GroupId,
        member: MembershipId,
    ) {
        let mut tx = self
            .fixtures_db
            .tenant_tx(&Self::owner_scope(tenant, owner))
            .await
            .expect("tx");
        groups::add_member(&mut tx, group, member, self.clock.now())
            .await
            .expect("group member");
        tx.commit().await.expect("commit");
    }

    /// Group-admin grant (no repo fn in Phase 0: raw insert on the migrator pool).
    pub async fn grant_group_admin(
        &self,
        tenant: TenantId,
        group: GroupId,
        member: MembershipId,
        granted_by: MembershipId,
    ) {
        raw_exec(
            &self.fixtures_db,
            "INSERT INTO group_admin_grants \
             (tenant_id, group_id, membership_id, can_remote_wipe, granted_by, granted_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
            &[
                RawBind::Uuid(tenant.0),
                RawBind::Uuid(group.0),
                RawBind::Uuid(member.0),
                RawBind::I64(0),
                RawBind::Uuid(granted_by.0),
                RawBind::Time(self.clock.now()),
            ],
        )
        .await
        .expect("group admin grant");
    }

    /// Platform staff user inserted without the 4-eyes path (fixture only).
    pub async fn staff_user(&self, email: &str, role: StaffRole) -> UserId {
        let u = self.user(email).await;
        let mut tx = self.fixtures_db.system_tx().await.expect("tx");
        db::repo::auth_state::testing_insert_staff(&mut tx, u, role, self.clock.now())
            .await
            .expect("staff");
        tx.commit().await.expect("commit");
        u
    }

    /// Feature toggle for a tenant (staff-owned table; fixture write on the migrator pool).
    pub async fn set_feature(&mut self, tenant: TenantId, feature: Feature, enabled: bool) {
        let by = if let Some(u) = self.staff_admin {
            u
        } else {
            let u = self
                .staff_user(&Self::email("features-staff"), StaffRole::Superadmin)
                .await;
            self.staff_admin = Some(u);
            u
        };
        raw_exec(
            &self.fixtures_db,
            "INSERT INTO tenant_features (tenant_id, feature, enabled, changed_by_staff, changed_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE enabled = VALUES(enabled), changed_at = VALUES(changed_at)",
            &[
                RawBind::Uuid(tenant.0),
                RawBind::Str(feature.as_str().to_owned()),
                RawBind::I64(i64::from(enabled)),
                RawBind::Uuid(by.0),
                RawBind::Time(self.clock.now()),
            ],
        )
        .await
        .expect("feature toggle");
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
        auth_account::set_tenant_status(
            &mut tx,
            t,
            auth_account::TenantStatus::Suspended,
            self.clock.now(),
        )
        .await
        .expect("suspend");
        tx.commit().await.expect("commit");
    }

    // ---------------------------------------------------------------- tokens

    /// Real password login (web audience) -> access token + session.
    pub async fn login(&self, email: &str) -> (String, SessionId) {
        let pair = self
            .svc
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
            .expect("login");
        (pair.access_token, pair.session)
    }

    async fn issue(&self, c: &AccessClaims) -> String {
        self.issuer.issue_access(c).await.expect("issue")
    }

    fn claims(
        &self,
        sub: uuid::Uuid,
        aud: Audience,
        typ: PrincipalKind,
        exp_offset: i64,
    ) -> AccessClaims {
        let now = self.clock.now().unix_timestamp();
        AccessClaims {
            iss: ISS.to_owned(),
            sub,
            aud,
            exp: now + exp_offset,
            nbf: now - 1000,
            iat: now - 1000,
            jti: uuid::Uuid::now_v7(),
            typ,
            tid: None,
            mid: None,
            sid: None,
            dcid: None,
            av: 1,
            amr: vec![Amr::Pwd],
            auth_time: now - 1000,
        }
    }

    async fn device_token(
        &self,
        tenant: TenantId,
        owner: MembershipId,
        operator: MembershipId,
    ) -> String {
        let cred = uuid::Uuid::now_v7();
        let device = DeviceId::new();
        let mut tx = self
            .fixtures_db
            .tenant_tx(&Self::owner_scope(tenant, owner))
            .await
            .expect("tx");
        auth_devices::insert(
            &mut tx,
            &NewDeviceCredential {
                id: cred,
                device,
                operator,
                product_code: "drive".to_owned(),
                scopes: "device:reports.upload".to_owned(),
                secret_hash: Some([1u8; 32]),
            },
            self.clock.now(),
        )
        .await
        .expect("device credential");
        tx.commit().await.expect("commit");
        let mut c = self.claims(device.0, Audience::Device, PrincipalKind::Device, 900);
        c.tid = Some(tenant);
        c.mid = Some(operator);
        c.dcid = Some(cred);
        c.amr = vec![Amr::Dev];
        self.issue(&c).await
    }

    async fn staff_token(&self, mfa: bool, email: &str) -> (UserId, String) {
        let u = self.staff_user(email, StaffRole::Support).await;
        let s = SessionId::new();
        let mut tx = self.fixtures_db.identity_tx().await.expect("tx");
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
                expires_at: self.clock.now() + time::Duration::hours(8),
            },
            self.clock.now(),
        )
        .await
        .expect("session");
        tx.commit().await.expect("commit");
        if mfa {
            let mut tx = self.fixtures_db.identity_tx().await.expect("tx");
            db::repo::auth_state::mark_session_mfa(&mut tx, s, self.clock.now())
                .await
                .expect("mfa");
            tx.commit().await.expect("commit");
        }
        let mut c = self.claims(u.0, Audience::Platform, PrincipalKind::Staff, 900);
        c.sid = Some(s);
        c.amr = if mfa {
            vec![Amr::Pwd, Amr::Mfa]
        } else {
            vec![Amr::Pwd]
        };
        (u, self.issue(&c).await)
    }

    // ---------------------------------------------------------------- the standard population

    #[allow(clippy::too_many_arguments)]
    async fn member_persona(
        &mut self,
        name: &'static str,
        note: &'static str,
        user: UserId,
        email: &str,
        tenant: TenantId,
        membership: MembershipId,
        role: TenantRole,
    ) {
        let (token, _) = self.login(email).await;
        self.personas.push(Persona {
            name,
            kind: PersonaKind::Member,
            tenant: Some(tenant),
            membership: Some(membership),
            user: Some(user),
            role: Some(role),
            token: Some(token),
            note,
        });
    }

    fn bare(
        name: &'static str,
        kind: PersonaKind,
        token: Option<String>,
        note: &'static str,
    ) -> Persona {
        Persona {
            name,
            kind,
            tenant: None,
            membership: None,
            user: None,
            role: None,
            token,
            note,
        }
    }

    /// Build the standard population (module docs). Panics on any fixture failure.
    #[allow(clippy::too_many_lines)]
    pub async fn standard(db: Db, fixtures_db: Db) -> Self {
        let mut w = Self::new(db, fixtures_db).await;

        // --- tenant A
        let e = Self::email("a-owner");
        let a_owner = w.user(&e).await;
        let (ta, a_om) = w.tenant(a_owner).await;
        let group = w.group(ta, a_om, "ops").await;
        for f in [Feature::Subusers, Feature::Groups, Feature::UserActivity] {
            w.set_feature(ta, f, true).await;
        }
        w.set_feature(ta, Feature::PrivateCloud, false).await;
        w.member_persona(
            names::A_OWNER,
            "owner of tenant A",
            a_owner,
            &e,
            ta,
            a_om,
            TenantRole::Owner,
        )
        .await;

        let mut a_member_mid = a_om;
        for (name, note, role) in [
            (names::A_ADMIN, "admin of tenant A", TenantRole::Admin),
            (names::A_MEMBER, "member of tenant A", TenantRole::Member),
            (names::A_VIEWER, "viewer of tenant A", TenantRole::Viewer),
        ] {
            let e = Self::email(name);
            let u = w.user(&e).await;
            let m = w.add_member(ta, a_om, u, role).await;
            if name == names::A_MEMBER {
                a_member_mid = m;
            }
            w.member_persona(name, note, u, &e, ta, m, role).await;
        }

        let e = Self::email("a-ga");
        let u = w.user(&e).await;
        let m = w.add_member(ta, a_om, u, TenantRole::Member).await;
        w.add_to_group(ta, a_om, group, m).await;
        w.grant_group_admin(ta, group, m, a_om).await;
        w.member_persona(
            names::A_GROUP_ADMIN,
            "member with a group-admin grant on group ops",
            u,
            &e,
            ta,
            m,
            TenantRole::Member,
        )
        .await;

        // --- state changes AFTER login (token stays valid cryptographically, live state denies)
        let e = Self::email("a-susp");
        let u = w.user(&e).await;
        let m = w.add_member(ta, a_om, u, TenantRole::Member).await;
        w.member_persona(
            names::A_SUSPENDED_USER,
            "user suspended after login: must be refused everywhere",
            u,
            &e,
            ta,
            m,
            TenantRole::Member,
        )
        .await;
        w.set_user_status(u, UserStatus::Suspended).await;

        let e = Self::email("a-dis");
        let u = w.user(&e).await;
        let m = w.add_member(ta, a_om, u, TenantRole::Member).await;
        w.member_persona(
            names::A_DISABLED_MEMBER,
            "membership disabled after login: must be refused everywhere",
            u,
            &e,
            ta,
            m,
            TenantRole::Member,
        )
        .await;
        w.set_member_status(ta, a_om, m, MembershipStatus::Disabled)
            .await;

        // --- device principal of tenant A (operator = A member)
        let token = w.device_token(ta, a_om, a_member_mid).await;
        w.personas.push(Persona {
            tenant: Some(ta),
            membership: Some(a_member_mid),
            ..Self::bare(
                names::A_DEVICE,
                PersonaKind::Device,
                Some(token),
                "enrolled desktop device (scope device:reports.upload)",
            )
        });

        // --- tenant B (all features OFF = single-buyer default)
        let e = Self::email("b-owner");
        let b_owner = w.user(&e).await;
        let (tb, b_om) = w.tenant(b_owner).await;
        w.member_persona(
            names::B_OWNER,
            "owner of the OTHER tenant",
            b_owner,
            &e,
            tb,
            b_om,
            TenantRole::Owner,
        )
        .await;
        let e = Self::email("b-member");
        let u = w.user(&e).await;
        let m = w.add_member(tb, b_om, u, TenantRole::Member).await;
        w.member_persona(
            names::B_MEMBER,
            "member of the OTHER tenant",
            u,
            &e,
            tb,
            m,
            TenantRole::Member,
        )
        .await;

        // --- tenant C (suspended after login)
        let e = Self::email("c-owner");
        let c_owner = w.user(&e).await;
        let (tc, c_om) = w.tenant(c_owner).await;
        w.member_persona(
            names::C_SUSPENDED_TENANT_OWNER,
            "owner of a tenant suspended after login",
            c_owner,
            &e,
            tc,
            c_om,
            TenantRole::Owner,
        )
        .await;
        w.suspend_tenant(tc).await;

        // --- staff
        let (su, token) = w.staff_token(true, &Self::email("staff-mfa")).await;
        w.personas.push(Persona {
            user: Some(su),
            ..Self::bare(
                names::STAFF_MFA,
                PersonaKind::Staff,
                Some(token),
                "platform support staff, session with MFA",
            )
        });
        let (su, token) = w.staff_token(false, &Self::email("staff-nomfa")).await;
        w.personas.push(Persona {
            user: Some(su),
            ..Self::bare(
                names::STAFF_NO_MFA,
                PersonaKind::Staff,
                Some(token),
                "platform staff WITHOUT MFA: staff realm must refuse",
            )
        });

        // --- unauthenticated callers
        w.personas.push(Self::bare(
            names::ANONYMOUS,
            PersonaKind::Anonymous,
            None,
            "no Authorization header",
        ));
        w.personas.push(Self::bare(
            names::GARBAGE,
            PersonaKind::Garbage,
            Some("not.a.jwt".to_owned()),
            "bearer value that is not a JWT",
        ));
        let mut c = w.claims(a_owner.0, Audience::Web, PrincipalKind::Member, -300);
        c.tid = Some(ta);
        c.mid = Some(a_om);
        c.sid = Some(SessionId::new());
        let token = w.issue(&c).await;
        w.personas.push(Persona {
            tenant: Some(ta),
            membership: Some(a_om),
            user: Some(a_owner),
            role: Some(TenantRole::Owner),
            ..Self::bare(
                names::EXPIRED,
                PersonaKind::Expired,
                Some(token),
                "validly signed, but expired",
            )
        });

        w.a = Some(TenantFx {
            id: ta,
            owner_membership: a_om,
            group: Some(group),
            features: vec![Feature::Subusers, Feature::Groups, Feature::UserActivity],
        });
        w.b = Some(TenantFx {
            id: tb,
            owner_membership: b_om,
            group: None,
            features: Vec::new(),
        });
        w
    }

    /// Persona by stable name (see `principals::names`).
    ///
    /// # Panics
    /// Unknown name (a typo in a test).
    #[must_use]
    pub fn persona(&self, name: &str) -> &Persona {
        self.personas
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("unknown persona {name}"))
    }

    #[must_use]
    pub fn tenant_a(&self) -> &TenantFx {
        self.a.as_ref().expect("standard world")
    }

    #[must_use]
    pub fn tenant_b(&self) -> &TenantFx {
        self.b.as_ref().expect("standard world")
    }

    // ---------------------------------------------------------------- the app

    #[must_use]
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

    pub async fn state(&self) -> AppState {
        let cursor = api::state::cursor_key_from(&self.keys)
            .await
            .expect("cursor");
        AppState::new(
            Environment::Test,
            self.db.clone(),
            Some(self.keys.clone()),
            cursor,
        )
        .with_auth(AuthHttp {
            service: self.svc.clone(),
            limiter: Arc::new(PreAuthLimiter::in_memory(relaxed_rules()).expect("limiter")),
            indexer: self.indexer.clone(),
        })
    }

    #[must_use]
    pub fn http() -> HttpSettings {
        HttpSettings {
            max_inflight: 64,
            max_json_body: 65_536,
            timeout: std::time::Duration::from_secs(15),
            cors_origins: Vec::new(),
            proxies: TrustedProxies::new(1, &["10.0.0.0/8".into()]).expect("tp"),
        }
    }

    /// Route options used by the matrix (`openapi_public` ON, non-production).
    #[must_use]
    pub const fn route_options() -> RouteOptions {
        RouteOptions {
            environment: Environment::Test,
            openapi_public: true,
        }
    }

    /// The real route table (+ optional extra routes) behind the full middleware stack.
    pub async fn app_with(
        &self,
        extra: impl FnOnce(PolicyRouter<AppState>) -> PolicyRouter<AppState>,
    ) -> Router {
        let routes = extra(api::build_routes(&Self::route_options()));
        assemble(routes, self.state().await, self.gate(), &Self::http())
            .expect("router")
            .0
    }

    pub async fn app(&self) -> Router {
        self.app_with(|r| r).await
    }
}
