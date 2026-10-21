//! Operator subcommands (B1 `migrate`, B2 `staff-bootstrap`) against a LOCAL MySQL scratch DB
//! (`db::testing::ScratchDb`, `.dev/dev.env`). The bootstrap runs with the NARROW grants: the
//! scratch app user (`DbRole::App`) and a scratch platform-admin user (`DbRole::PlatformAdmin`).
//! Never prints URLs, passwords or secrets; drops only its own scratch DB and scratch users.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use api::ops::staff_bootstrap::{
    BootstrapDeps, BootstrapError, BootstrapInput, FirstStaffCommit, Terminal, bootstrap,
};
use api::ops::{EXIT_CONFIG, EXIT_OK};
use auth::{
    AuthDeps, AuthService, AuthSettings, DbPrincipalLoader, Es256Issuer, LoginRequest, MfaInput,
    NoopSink, RefreshHasher,
};
use common::config_util::Env;
use common::{Clock, SystemClock};
use config::{AppConfig, Environment};
use crypto::{
    AesGcmFieldEncryptor, Argon2Params, Argon2idHasher, EnvKeyProvider, Es256Signer,
    HmacBlindIndexer, KeyProvider, KeyPurpose, KeyRing, ParamPolicy,
};
use db::platform_admin::PlatformAdminDb;
use db::testing::{RawBind, ScratchDb, TestEnv, raw_fetch};
use db::{Db, DbDekStore};
use futures_util::FutureExt as _;
use secrecy::{ExposeSecret as _, SecretString};

const ISS: &str = "https://api.dsecure.test";
const PW: &str = "bootstrap horse battery 42";

async fn scratch(test: &str) -> Option<(TestEnv, ScratchDb)> {
    let env = match db::testing::load_env() {
        Ok(e) => e,
        Err(reason) if db::testing::skip_allowed() => {
            eprintln!("SKIP {test}: {reason} (DSECURE_DB_TESTS=skip)");
            return None;
        }
        Err(reason) => panic!("{test}: local test DB env unavailable: {reason}"),
    };
    if db::testing::test_engine() == db::testing::TestEngine::TiDb {
        eprintln!("SKIP (tidb): {test}: needs scratch users");
        return None;
    }
    match ScratchDb::create(&env).await {
        Ok(s) => Some((env, s)),
        Err(e) if db::testing::skip_allowed() => {
            eprintln!("SKIP {test}: scratch DB failed ({e})");
            None
        }
        Err(e) => panic!("{test}: scratch DB failed: {e}"),
    }
}

fn app_config(app_url: &SecretString, migrator_url: Option<&SecretString>) -> AppConfig {
    let kek = crypto::devkeys::generate_kek_b64().expect("kek");
    let mut p: Vec<(String, String)> = [
        ("DSECURE_ENV", "test"),
        ("KEK_PROVIDER", "env"),
        ("KEK_ENV_ACTIVE_ID", "t1"),
        ("JWT_ISSUER", ISS),
        ("JWT_SIGNING_KID_MEMBER", "member-t1"),
        ("JWT_SIGNING_KID_STAFF", "staff-t1"),
        ("BLOB_BACKEND", "fs"),
        ("BLOB_FS_ROOT", "./target/t_ops_blobs"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    p.push(("KEK_ENV_t1".into(), (*kek).clone()));
    p.push(("DATABASE_URL".into(), app_url.expose_secret().to_owned()));
    if let Some(m) = migrator_url {
        p.push(("MIGRATOR_DATABASE_URL".into(), m.expose_secret().to_owned()));
    }
    AppConfig::load(&Env::from_pairs(p)).expect("test config")
}

#[tokio::test]
async fn migrate_command_status_and_apply_on_scratch() {
    let Some((env, s)) = scratch("ops_migrate").await else {
        return;
    };
    let mig = s.migrator_url(&env);
    let r = AssertUnwindSafe(async {
        let cfg = app_config(&mig, Some(&mig));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        // ScratchDb is already migrated: status 0 pending, apply 0 applied, both exit 0.
        assert_eq!(
            api::ops::migrate::run(&cfg, true, &mut out, &mut err).await,
            EXIT_OK
        );
        assert_eq!(
            api::ops::migrate::run(&cfg, false, &mut out, &mut err).await,
            EXIT_OK
        );
        let text = String::from_utf8(out).expect("utf8");
        assert!(
            text.contains("0 pending") && text.contains("0 applied"),
            "{text}"
        );
        assert!(!text.contains("mysql://") && !text.contains('@'));
        assert!(err.is_empty());

        // No MIGRATOR_DATABASE_URL: refused (78) before any connection, no fallback to the app URL.
        let cfg = app_config(&mig, None);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            api::ops::migrate::run(&cfg, false, &mut out, &mut err).await,
            EXIT_CONFIG
        );
        let e = String::from_utf8(err).expect("utf8");
        assert!(e.contains("MIGRATOR_DATABASE_URL") && !e.contains("mysql://"));
    })
    .catch_unwind()
    .await;
    let _ = s.drop_db(&env).await;
    if let Err(p) = r {
        std::panic::resume_unwind(p);
    }
}

/// Scripted operator: reads the printed TOTP secret and answers with valid (or wrong) codes.
struct Operator {
    lines: Vec<String>,
    wrong_codes: usize,
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

impl Operator {
    fn secret(&self) -> Vec<u8> {
        let l = self
            .lines
            .iter()
            .find_map(|l| l.trim().strip_prefix("secret      : "))
            .expect("secret shown");
        base32_decode(l.trim())
    }

    fn recovery_codes(&self) -> Vec<String> {
        let start = self
            .lines
            .iter()
            .position(|l| l.contains("recovery codes"))
            .expect("codes block");
        self.lines[start + 2..]
            .iter()
            .take_while(|l| l.starts_with("  "))
            .map(|l| l.trim().to_owned())
            .collect()
    }
}

impl Terminal for Operator {
    fn line(&mut self, s: &str) -> std::io::Result<()> {
        self.lines.push(s.to_owned());
        Ok(())
    }

    fn ask(&mut self, _prompt: &str) -> std::io::Result<Option<String>> {
        if self.wrong_codes > 0 {
            self.wrong_codes -= 1;
            return Ok(Some("000000".into()));
        }
        // Previous step: never collides with a later login code, always inside the window.
        let now = time::OffsetDateTime::now_utc().unix_timestamp() - 30;
        Ok(Some(format!(
            "{:06}",
            auth::totp::totp_at(&self.secret(), now, 6)
        )))
    }
}

fn provider() -> Arc<dyn KeyProvider> {
    let kek = crypto::devkeys::generate_kek_b64().expect("kek");
    Arc::new(EnvKeyProvider::new("t1", [("t1", (*kek).clone())]).expect("kek"))
}

fn hasher() -> Arc<Argon2idHasher> {
    Arc::new(
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
    )
}

fn deps(app: &Db, admin: &PlatformAdminDb, provider: &Arc<dyn KeyProvider>) -> BootstrapDeps {
    BootstrapDeps {
        app: app.clone(),
        admin: admin.clone(),
        provider: Arc::clone(provider),
        hasher: hasher(),
        settings: AuthSettings::defaults(ISS),
        max_tenant_deks_cached: 100,
        clock: Arc::new(SystemClock),
        staff_commit: None,
    }
}

/// Number of rows of `SELECT 1 FROM ...` (no sqlx dependency in this crate's tests).
async fn count(db: &Db, sql_text: &str, binds: &[RawBind]) -> usize {
    raw_fetch(db, sql_text, binds).await.expect("count").len()
}

fn es256(kid: &str) -> Arc<Es256Signer> {
    let pk = Es256Signer::generate_pkcs8().expect("gen");
    Arc::new(Es256Signer::from_pkcs8(kid, &pk).expect("load"))
}

/// Login as the bootstrapped staff user through the real `AuthService` (same KeyRing + refresh
/// subkey as the api would use), second factor = one recovery code.
async fn staff_login(app: &Db, provider: &Arc<dyn KeyProvider>, email: &str, code: &str) -> bool {
    let ring = Arc::new(
        KeyRing::load_platform(Arc::clone(provider), Arc::new(DbDekStore::new(app.clone())))
            .await
            .expect("ring"),
    );
    let key = ring
        .derive_subkey(KeyPurpose::Secrets, None, api::startup::REFRESH_KEY_LABEL)
        .await
        .expect("subkey");
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let settings = AuthSettings::defaults(ISS);
    let svc = AuthService::new(AuthDeps {
        db: app.clone(),
        hasher: hasher(),
        indexer: Arc::new(HmacBlindIndexer::new(Arc::clone(&ring))),
        issuer: Arc::new(Es256Issuer::new(es256("m1"), es256("s1"), None).expect("iss")),
        refresh: RefreshHasher::new(&key),
        fields: Arc::new(AesGcmFieldEncryptor::new(Arc::clone(&ring))),
        sink: Arc::new(NoopSink),
        clock: Arc::clone(&clock),
        loader: Arc::new(DbPrincipalLoader::new(app.clone(), clock, &settings)),
        settings,
    })
    .await
    .expect("svc");
    svc.authenticate(LoginRequest {
        email,
        password: SecretString::from(PW),
        audience: auth::Audience::Platform,
        tenant: None,
        product_code: None,
        device_label: None,
        mfa: Some(MfaInput::Recovery(code.to_owned())),
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn staff_bootstrap_with_narrow_grants_once() {
    let Some((env, mut s)) = scratch("ops_staff_bootstrap").await else {
        return;
    };
    let r = AssertUnwindSafe(async {
        let Some(app) = s.app().cloned() else {
            panic!("staff bootstrap test needs LOCAL_MYSQL_ROOT_PASSWORD (narrow app user)");
        };
        let padm_url = s.platform_admin_url(&env).await.expect("padm user");
        // Normal connect path of the platform-admin pool (CURRENT_USER check only outside dev/test).
        let admin = PlatformAdminDb::connect(
            &db::testing::test_config_with(&padm_url, 2),
            Environment::Test,
        )
        .await
        .expect("padm connect");
        let mig = s.migrator().clone();
        let provider = provider();
        let d = deps(&app, &admin, &provider);

        // 0) Review N1: one platform DEK exists under KEK A; a bootstrap with KEK B is refused by the
        //    shared plan/guard BEFORE any write (no DEK, no user).
        premake_dek(&mig, &provider, KeyPurpose::Identity).await;
        let other = self::provider();
        let e = bootstrap(
            &deps(&app, &admin, &other),
            &BootstrapInput {
                email: "wrong.kek@dsecure.test".into(),
                password: SecretString::from(PW),
            },
            &mut Operator {
                lines: Vec::new(),
                wrong_codes: 0,
            },
        )
        .await
        .expect_err("other KEK");
        assert!(matches!(e, BootstrapError::KeysPlan(_)), "{e:?}");
        assert_eq!(count(&mig, "SELECT 1 FROM data_keys", &[]).await, 1);
        assert_eq!(count(&mig, "SELECT 1 FROM users", &[]).await, 0);

        // 1) Wrong codes only: refused, no staff row, the new user stays disabled.
        let mut op = Operator {
            lines: Vec::new(),
            wrong_codes: 3,
        };
        let e = bootstrap(
            &d,
            &BootstrapInput {
                email: "first.try@dsecure.test".into(),
                password: SecretString::from(PW),
            },
            &mut op,
        )
        .await
        .expect_err("wrong codes");
        assert!(matches!(e, BootstrapError::TotpNotConfirmed), "{e:?}");
        assert_eq!(count(&mig, "SELECT 1 FROM platform_staff", &[]).await, 0);
        assert_eq!(
            count(&mig, "SELECT 1 FROM users WHERE status = 'disabled'", &[]).await,
            1
        );
        assert!(op.lines.iter().any(|l| l.contains("otpauth://totp/")));

        // 2) Success with the narrow grants.
        let email = "ops.root@dsecure.test";
        let mut op = Operator {
            lines: Vec::new(),
            wrong_codes: 1,
        };
        let out = bootstrap(
            &d,
            &BootstrapInput {
                email: email.into(),
                password: SecretString::from(PW),
            },
            &mut op,
        )
        .await
        .expect("bootstrap");
        let u = RawBind::Uuid(out.user_id.0);
        // The aborted run committed no DEK (N1: DEKs only commit with the staff row).
        assert_eq!(
            out.platform_deks_created,
            KeyPurpose::PLATFORM.len() - 1,
            "all but the pre-made one"
        );
        assert_eq!(
            count(&mig, "SELECT 1 FROM data_keys", &[]).await,
            KeyPurpose::PLATFORM.len()
        );
        assert_eq!(
            count(
                &mig,
                "SELECT 1 FROM platform_staff WHERE user_id = ? AND role = 'platform_superadmin' AND revoked_at IS NULL AND granted_by IS NULL",
                std::slice::from_ref(&u),
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &mig,
                "SELECT 1 FROM users WHERE id = ? AND status = 'active' AND verification_source = 'staff'",
                std::slice::from_ref(&u),
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &mig,
                "SELECT 1 FROM mfa_factors WHERE user_id = ? AND disabled_at IS NULL AND last_used_at IS NOT NULL",
                std::slice::from_ref(&u),
            )
            .await,
            1,
            "factor active only after the confirmed code"
        );
        assert_eq!(
            count(
                &mig,
                "SELECT 1 FROM mfa_recovery_codes WHERE user_id = ?",
                std::slice::from_ref(&u),
            )
            .await,
            10
        );
        assert_eq!(
            count(
                &mig,
                "SELECT 1 FROM audit_events WHERE action = 'staff.bootstrap' AND actor_kind = 'system' AND actor_id = ?",
                std::slice::from_ref(&u),
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &mig,
                "SELECT 1 FROM user_credentials WHERE user_id = ? AND hash_scheme = 'argon2id' AND password_hash LIKE '$argon2id$%'",
                std::slice::from_ref(&u),
            )
            .await,
            1
        );
        let codes = op.recovery_codes();
        assert_eq!(codes.len(), 10);
        assert!(
            op.lines.iter().all(|l| !l.contains(PW)),
            "password never shown"
        );

        // 3) The account really works for staff login (password + recovery code).
        assert!(staff_login(&app, &provider, email, &codes[0]).await);

        // 4) Exactly once: a second run (any email) is refused and writes nothing.
        let users_before = count(&mig, "SELECT 1 FROM users", &[]).await;
        let mut op = Operator {
            lines: Vec::new(),
            wrong_codes: 0,
        };
        let e = bootstrap(
            &d,
            &BootstrapInput {
                email: "second@dsecure.test".into(),
                password: SecretString::from(PW),
            },
            &mut op,
        )
        .await
        .expect_err("second run");
        assert!(matches!(e, BootstrapError::AlreadyBootstrapped), "{e:?}");
        assert_eq!(count(&mig, "SELECT 1 FROM users", &[]).await, users_before);
        assert!(op.lines.is_empty(), "nothing shown when refused");

        // 5) Input checks before any write.
        let e = bootstrap(
            &d,
            &BootstrapInput {
                email: "not-an-email".into(),
                password: SecretString::from(PW),
            },
            &mut op,
        )
        .await
        .expect_err("email");
        assert!(matches!(e, BootstrapError::Invalid(_)));
        admin.db().close().await;
    })
    .catch_unwind()
    .await;
    let _ = s.drop_db(&env).await;
    if let Err(p) = r {
        std::panic::resume_unwind(p);
    }
}

/// One active platform DEK of `p`, wrapped by `provider`, written directly (test setup only).
async fn premake_dek(mig: &Db, provider: &Arc<dyn KeyProvider>, p: KeyPurpose) {
    use crypto::DekStore as _;
    let kid = crypto::Kid::generate(p, None).expect("kid");
    let dek = crypto::Dek::generate().expect("dek");
    let w = provider
        .wrap(
            &dek,
            &crypto::WrapContext {
                kid: &kid,
                purpose: p,
                tenant: None,
            },
        )
        .await
        .expect("wrap");
    DbDekStore::new(mig.clone())
        .insert(&kid, p, None, &w)
        .await
        .expect("insert dek");
}

async fn narrow_pools(s: &mut ScratchDb, env: &TestEnv) -> (Db, PlatformAdminDb, Db) {
    let Some(app) = s.app().cloned() else {
        panic!("staff bootstrap tests need LOCAL_MYSQL_ROOT_PASSWORD (narrow app user)");
    };
    let padm_url = s.platform_admin_url(env).await.expect("padm user");
    let admin = PlatformAdminDb::connect(
        &db::testing::test_config_with(&padm_url, 4),
        Environment::Test,
    )
    .await
    .expect("padm connect");
    (app, admin, s.migrator().clone())
}

/// Review N3: the platform-admin tx fails AFTER the user was activated (here: the singleton marker of
/// another, in-flight bootstrap already exists while platform_staff is still empty) -> the user is
/// set back to disabled, no staff row, no DEK committed.
#[tokio::test]
async fn staff_bootstrap_failure_after_activation_disables_user() {
    let Some((env, mut s)) = scratch("ops_staff_bootstrap_revert").await else {
        return;
    };
    let r = AssertUnwindSafe(async {
        let (app, admin, mig) = narrow_pools(&mut s, &env).await;
        db::testing::raw_exec(
            &mig,
            "INSERT INTO platform_bootstrap (id, user_id, created_at) VALUES (1, ?, ?)",
            &[
                RawBind::Uuid(uuid::Uuid::now_v7()),
                RawBind::Time(time::OffsetDateTime::now_utc()),
            ],
        )
        .await
        .expect("marker");
        let provider = provider();
        let e = bootstrap(
            &deps(&app, &admin, &provider),
            &BootstrapInput {
                email: "late@dsecure.test".into(),
                password: SecretString::from(PW),
            },
            &mut Operator {
                lines: Vec::new(),
                wrong_codes: 0,
            },
        )
        .await
        .expect_err("marker taken");
        assert!(matches!(e, BootstrapError::AlreadyBootstrapped), "{e:?}");
        assert_eq!(count(&mig, "SELECT 1 FROM platform_staff", &[]).await, 0);
        assert_eq!(
            count(&mig, "SELECT 1 FROM users WHERE status = 'disabled'", &[]).await,
            1,
            "activated user set back to disabled"
        );
        assert_eq!(
            count(&mig, "SELECT 1 FROM users WHERE status = 'active'", &[]).await,
            0
        );
        assert_eq!(count(&mig, "SELECT 1 FROM data_keys", &[]).await, 0);
        admin.db().close().await;
    })
    .catch_unwind()
    .await;
    let _ = s.drop_db(&env).await;
    if let Err(p) = r {
        std::panic::resume_unwind(p);
    }
}

/// Review N2: two concurrent bootstraps (narrow grants) -> exactly one platform_staff row, one marker,
/// one set of platform DEKs; the loser's user ends disabled.
#[tokio::test]
async fn concurrent_staff_bootstraps_create_exactly_one_superadmin() {
    let Some((env, mut s)) = scratch("ops_staff_bootstrap_race").await else {
        return;
    };
    let r = AssertUnwindSafe(async {
        let (app, admin, mig) = narrow_pools(&mut s, &env).await;
        let provider = provider();
        let (d1, d2) = (deps(&app, &admin, &provider), deps(&app, &admin, &provider));
        // Two different users enrolling TOTP at the same moment can hit a transient MySQL lock error
        // in the MFA tables (auth `service.unavailable`, a retry for the operator). That is not the
        // property under test, so a round where BOTH runs fail that way is repeated (new emails);
        // the singleton guarantee is checked after every round.
        let mut wins = 0;
        for round in 0..5 {
            let mut o1 = Operator {
                lines: Vec::new(),
                wrong_codes: 0,
            };
            let mut o2 = Operator {
                lines: Vec::new(),
                wrong_codes: 0,
            };
            let i1 = BootstrapInput {
                email: format!("race.one.{round}@dsecure.test"),
                password: SecretString::from(PW),
            };
            let i2 = BootstrapInput {
                email: format!("race.two.{round}@dsecure.test"),
                password: SecretString::from(PW),
            };
            let (r1, r2) = tokio::join!(bootstrap(&d1, &i1, &mut o1), bootstrap(&d2, &i2, &mut o2));
            wins += usize::from(r1.is_ok()) + usize::from(r2.is_ok());
            for r in [&r1, &r2] {
                if let Err(e) = r {
                    assert!(
                        matches!(
                            e,
                            BootstrapError::AlreadyBootstrapped
                                | BootstrapError::Auth("service.unavailable")
                        ),
                        "{e:?}"
                    );
                }
            }
            assert!(wins <= 1, "two bootstraps succeeded: {r1:?} / {r2:?}");
            assert_eq!(count(&mig, "SELECT 1 FROM platform_staff", &[]).await, wins);
            if wins == 1 {
                eprintln!(
                    "concurrent bootstrap test: winner found in round {}",
                    round + 1
                );
                break;
            }
            eprintln!(
                "concurrent bootstrap test: round {} had no winner (transient), retrying",
                round + 1
            );
        }
        assert_eq!(wins, 1, "no round produced a winner");
        assert_eq!(count(&mig, "SELECT 1 FROM platform_staff", &[]).await, 1);
        assert_eq!(
            count(&mig, "SELECT 1 FROM platform_bootstrap", &[]).await,
            1
        );
        assert_eq!(
            count(&mig, "SELECT 1 FROM data_keys", &[]).await,
            KeyPurpose::PLATFORM.len()
        );
        assert_eq!(
            count(&mig, "SELECT 1 FROM users WHERE status = 'active'", &[]).await,
            1
        );
        admin.db().close().await;
    })
    .catch_unwind()
    .await;
    let _ = s.drop_db(&env).await;
    if let Err(p) = r {
        std::panic::resume_unwind(p);
    }
}

/// Fault injection (review M1): the REAL commit happens, then the call reports `CommitUnknown`
/// (connection dropped after COMMIT was sent).
struct CommitThenUnknown(PlatformAdminDb);

#[async_trait::async_trait]
impl FirstStaffCommit for CommitThenUnknown {
    async fn commit_first_superadmin(
        &self,
        user: common::UserId,
        deks: &[db::repo::keys::PlatformDekPlan],
        audit: &db::repo::audit::AuditRowRecord,
        now: time::OffsetDateTime,
    ) -> Result<(), db::DbError> {
        self.0
            .bootstrap_first_superadmin_with_deks(user, deks, audit, now)
            .await
            .expect("real commit");
        Err(db::DbError::CommitUnknown)
    }
}

/// Review M1: COMMIT applied but reported `CommitUnknown` -> the tool checks on a fresh connection,
/// keeps the superadmin ACTIVE, says so, and still shows the recovery codes.
#[tokio::test]
async fn commit_unknown_but_applied_keeps_superadmin_active() {
    let Some((env, mut s)) = scratch("ops_staff_bootstrap_commit_unknown").await else {
        return;
    };
    let r = AssertUnwindSafe(async {
        let (app, admin, mig) = narrow_pools(&mut s, &env).await;
        let provider = provider();
        let mut d = deps(&app, &admin, &provider);
        d.staff_commit = Some(Arc::new(CommitThenUnknown(admin.clone())));
        let mut op = Operator {
            lines: Vec::new(),
            wrong_codes: 0,
        };
        let out = bootstrap(
            &d,
            &BootstrapInput {
                email: "unknown.commit@dsecure.test".into(),
                password: SecretString::from(PW),
            },
            &mut op,
        )
        .await
        .expect("committed bootstrap is a success");
        let u = RawBind::Uuid(out.user_id.0);
        assert_eq!(count(&mig, "SELECT 1 FROM platform_staff", &[]).await, 1);
        assert_eq!(
            count(
                &mig,
                "SELECT 1 FROM users WHERE id = ? AND status = 'active'",
                std::slice::from_ref(&u),
            )
            .await,
            1,
            "never disable a committed superadmin"
        );
        assert!(op.lines.iter().any(|l| l.contains("IS committed")));
        assert_eq!(op.recovery_codes().len(), 10, "codes path ran");
        assert!(admin.bootstrap_committed_for(out.user_id).await.expect("q"));
        admin.db().close().await;
    })
    .catch_unwind()
    .await;
    let _ = s.drop_db(&env).await;
    if let Err(p) = r {
        std::panic::resume_unwind(p);
    }
}

#[test]
fn admin_url_rules() {
    let pw = SecretString::from(String::from("mysql://a:b@127.0.0.1:3307/dsecure_test"));
    let cfg = app_config(&pw, None);
    let e = |pairs: &[(&str, &str)]| {
        Env::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    };
    use api::ops::staff_bootstrap::admin_db_config;
    assert!(admin_db_config(&cfg, &e(&[])).is_err());
    assert!(
        admin_db_config(
            &cfg,
            &e(&[(
                "PLATFORM_ADMIN_DATABASE_URL",
                "mysql://a:b@127.0.0.1:3307/Cloud_Erase__App"
            )])
        )
        .is_err()
    );
    let c = admin_db_config(
        &cfg,
        &e(&[(
            "PLATFORM_ADMIN_DATABASE_URL",
            "mysql://a:b@127.0.0.1:3307/dsecure_test",
        )]),
    )
    .expect("ok in test env");
    assert_eq!(c.max_connections, 2);
    assert!(c.migrator_url.is_none());
}
