//! `dsecure-api staff-bootstrap` (B2, PHASE0_PROGRESS carry-forward 23): create the FIRST platform
//! superadmin exactly once, on an empty `platform_staff` table.
//!
//! Least privilege: two pools with the EXISTING DB users (grant change: only S/I on the new marker
//! table `platform_bootstrap` for rs_padm, migration 0880_0001).
//! - App user (`DATABASE_URL`): `users`, `user_credentials`, `mfa_factors`, `mfa_recovery_codes`
//!   (it already holds S/I/U there; the platform-admin user has no grant on `users`).
//! - Platform-admin user (`PLATFORM_ADMIN_DATABASE_URL`, `CURRENT_USER()` checked outside dev/test):
//!   ONE transaction `PlatformAdminDb::bootstrap_first_superadmin_with_deks`: singleton marker row
//!   (two concurrent bootstraps: exactly one wins, review N2) + locked staff count + the missing
//!   PLATFORM DEKs + `platform_staff` row + audit row. Creating platform DEKs here is the same
//!   first-run exception as the bootstrap itself and is atomic with it (review N1): the DEK plan
//!   (`db::repo::keys::plan_platform_deks`, shared with `provision-keys seed-db`) guards every
//!   existing platform DEK against this KEK BEFORE anything is written, and new DEKs commit only
//!   together with the staff row. `provision-keys seed-db` then finds them and creates only the
//!   signing keys.
//!
//! Order: pre-check no staff -> DEK plan + KEK guard (read-only) -> KeyRing in memory from the plan ->
//! user row with status `disabled` + Argon2id password (app user) -> TOTP enrolment
//! (`AuthService::begin_totp_enrolment`; URI + secret ONLY on the operator terminal) -> the operator
//! confirms a code (`confirm_totp_enrolment`, 3 attempts; issues the recovery codes) -> user
//! `active` -> the platform-admin tx above -> recovery codes on the terminal. If the platform-admin
//! tx fails, the user is set back to `disabled` (review N3).
//!
//! Leftovers of an aborted run: a DISABLED user without staff row or membership (inert; no DELETE
//! anywhere). Whether its email is "taken" depends on the email blind-index DEK (`BidxEmail`): on a
//! fresh database that DEK was only planned and never committed, so a re-run plans a NEW DEK, the
//! leftover row's `email_bidx` no longer matches, and the SAME email can be used again (review L1). If
//! the platform DEKs already existed before the run, the bidx is the same and the email is taken:
//! use another email.
//! A COMMIT that applied but reported an error (`CommitUnknown`) is detected by re-reading the
//! singleton marker on a fresh connection: the superadmin stays active and the codes are shown
//! (review M1). Only if the platform-admin tx fails AND the revert fails, the user stays `active`
//! without staff row or membership (no login path accepts it): `RevertFailed` names the user id; the
//! owner disables it (SQL in `docs/ops/RENDER_SETUP.md` step 6). If even the commit check fails,
//! `OutcomeUnknown` leaves the user active and explains how to check.
//!
//! Never printed or logged: password, URLs, KEK. The TOTP secret / otpauth URI and the recovery codes
//! go only to the interactive terminal (`run_cli` refuses when stdin or stdout is not a terminal, so
//! they cannot end up in a log file or a CI log).

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::sync::Arc;

use auth::{
    AccessClaims, AuthDeps, AuthError, AuthService, AuthSettings, DbPrincipalLoader, RefreshHasher,
    TokenIssuer, TracingSink,
};
use common::config_util::Env;
use common::{Clock, SystemClock, UserId};
use config::AppConfig;
use crypto::{
    AesGcmFieldEncryptor, BlindIndexer as _, BlindKind, BlindScope, DekStore as _, FieldContext,
    FieldEncryptor as _, HmacBlindIndexer, InMemoryDekStore, KeyProvider, KeyPurpose, KeyRing,
    PasswordHasher,
};
use db::platform_admin::PlatformAdminDb;
use db::repo::audit::AuditRowRecord;
use db::repo::auth_account;
use db::repo::keys::{PlatformDekPlan, plan_platform_deks};
use db::repo::users::{self, HashScheme, NewUser, UserStatus};
use db::{Db, DbDekStore, DbError};
use secrecy::{ExposeSecret as _, SecretString};
use time::OffsetDateTime;

use super::{
    BootstrapArgs, EXIT_ALREADY_BOOTSTRAPPED, EXIT_CONFIG, EXIT_DATAERR, EXIT_FAILURE, EXIT_OK,
    EXIT_USAGE,
};
use crate::startup::REFRESH_KEY_LABEL;

/// Env key of the platform-admin DB URL (never on the command line, never printed).
pub const PLATFORM_ADMIN_URL_KEY: &str = "PLATFORM_ADMIN_DATABASE_URL";
/// Staff password length (characters / bytes). Staff also need TOTP, so 12 is the floor.
pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Wrong TOTP codes allowed before the run aborts.
pub const TOTP_ATTEMPTS: usize = 3;
/// `audit_events.action` of the bootstrap row.
pub const AUDIT_ACTION: &str = "staff.bootstrap";

/// Operator terminal. Secrets are written only through this.
pub trait Terminal {
    /// Write one line.
    ///
    /// # Errors
    /// I/O.
    fn line(&mut self, s: &str) -> std::io::Result<()>;
    /// Prompt and read one line (`None` = end of input).
    ///
    /// # Errors
    /// I/O.
    fn ask(&mut self, prompt: &str) -> std::io::Result<Option<String>>;
}

/// stdin/stdout, only when BOTH are interactive terminals.
#[derive(Debug)]
pub struct StdTerminal(());

impl StdTerminal {
    #[must_use]
    pub fn open() -> Option<Self> {
        (std::io::stdin().is_terminal() && std::io::stdout().is_terminal()).then_some(Self(()))
    }
}

impl Terminal for StdTerminal {
    fn line(&mut self, s: &str) -> std::io::Result<()> {
        let mut o = std::io::stdout().lock();
        writeln!(o, "{s}")?;
        o.flush()
    }

    fn ask(&mut self, prompt: &str) -> std::io::Result<Option<String>> {
        {
            let mut o = std::io::stdout().lock();
            write!(o, "{prompt}")?;
            o.flush()?;
        }
        let mut buf = String::new();
        let n = std::io::stdin().lock().read_line(&mut buf)?;
        Ok((n > 0).then(|| buf.trim().to_owned()))
    }
}

/// Everything the bootstrap needs (pools already connected and checked).
pub struct BootstrapDeps {
    /// App-user pool (`DATABASE_URL`).
    pub app: Db,
    /// Platform-admin pool.
    pub admin: PlatformAdminDb,
    pub provider: Arc<dyn KeyProvider>,
    pub hasher: Arc<dyn PasswordHasher>,
    pub settings: AuthSettings,
    pub max_tenant_deks_cached: u64,
    pub clock: Arc<dyn Clock>,
    /// Step 7 committer. `None` = `admin` (production). Tests inject faults here (review M1: a commit
    /// that applied but reported `CommitUnknown`).
    pub staff_commit: Option<Arc<dyn FirstStaffCommit>>,
}

/// The final platform-admin transaction of the bootstrap (marker + DEKs + staff row + audit).
#[async_trait::async_trait]
pub trait FirstStaffCommit: Send + Sync {
    /// # Errors
    /// See `PlatformAdminDb::bootstrap_first_superadmin_with_deks`.
    async fn commit_first_superadmin(
        &self,
        user: UserId,
        deks: &[PlatformDekPlan],
        audit: &AuditRowRecord,
        now: OffsetDateTime,
    ) -> Result<(), DbError>;
}

#[async_trait::async_trait]
impl FirstStaffCommit for PlatformAdminDb {
    async fn commit_first_superadmin(
        &self,
        user: UserId,
        deks: &[PlatformDekPlan],
        audit: &AuditRowRecord,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        self.bootstrap_first_superadmin_with_deks(user, deks, audit, now)
            .await
    }
}

impl std::fmt::Debug for BootstrapDeps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BootstrapDeps")
    }
}

/// Operator input. `Debug` never shows the password.
pub struct BootstrapInput {
    pub email: String,
    pub password: SecretString,
}

impl std::fmt::Debug for BootstrapInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BootstrapInput([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapOutcome {
    pub user_id: UserId,
    pub platform_deks_created: usize,
}

/// Value-free failure reasons.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error(
        "refused: platform staff already exists (bootstrap only runs on an empty platform_staff)"
    )]
    AlreadyBootstrapped,
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    #[error(
        "refused: a user with this email already exists (platform DEKs existed before); use another email"
    )]
    EmailTaken,
    #[error(
        "TOTP code not confirmed after {TOTP_ATTEMPTS} attempts; nothing was granted (the new user \
         stays disabled); run again (on a fresh database the same email works again)"
    )]
    TotpNotConfirmed,
    #[error("platform keys refused: {0}")]
    Keys(&'static str),
    /// KEK guard of the shared DEK plan (kids and KEK ids only, never key bytes).
    #[error("platform keys refused: {0}")]
    KeysPlan(String),
    #[error("database: {0}")]
    Db(DbError),
    #[error("auth: {0}")]
    Auth(&'static str),
    #[error("terminal I/O failed")]
    Terminal,
    /// The final platform-admin tx failed AND setting the user back to `disabled` failed too.
    #[error(
        "{cause}; ALSO could not set user {user} back to disabled ({revert}); it has no staff row \
         and no membership, so it cannot log in, but disable it manually"
    )]
    RevertFailed {
        cause: Box<BootstrapError>,
        user: uuid::Uuid,
        revert: DbError,
    },
    /// The final tx reported an error AND the follow-up check (fresh connection) failed too: it is
    /// unknown whether the bootstrap committed. The user is left ACTIVE (never disable a superadmin
    /// that may exist); the recovery codes were shown.
    #[error(
        "{cause}; ALSO could not check whether the bootstrap of user {user} committed ({check}). The \
         user was left active and the recovery codes were shown. Check with \
         `SELECT HEX(user_id) FROM platform_bootstrap WHERE id = 1`: if it is this user, the bootstrap \
         is done; if there is no row, run again"
    )]
    OutcomeUnknown {
        cause: Box<BootstrapError>,
        user: uuid::Uuid,
        check: DbError,
    },
}

impl BootstrapError {
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::AlreadyBootstrapped => EXIT_ALREADY_BOOTSTRAPPED,
            Self::Invalid(_) | Self::EmailTaken | Self::TotpNotConfirmed => EXIT_DATAERR,
            Self::Keys(_) | Self::KeysPlan(_) => EXIT_CONFIG,
            Self::Db(DbError::Config(_) | DbError::EngineMismatch { .. }) => EXIT_CONFIG,
            Self::Db(_)
            | Self::Auth(_)
            | Self::Terminal
            | Self::RevertFailed { .. }
            | Self::OutcomeUnknown { .. } => EXIT_FAILURE,
        }
    }
}

impl From<DbError> for BootstrapError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::Conflict("users.email_taken") => Self::EmailTaken,
            DbError::Conflict("staff.bootstrap_done") => Self::AlreadyBootstrapped,
            DbError::Conflict("data_keys.changed") => {
                Self::Keys("data_keys changed during the bootstrap (another run?); nothing granted")
            }
            other => Self::Db(other),
        }
    }
}

fn term_err(_: std::io::Error) -> BootstrapError {
    BootstrapError::Terminal
}

/// The bootstrap never issues tokens (it needs no JWT signing keys, which do not exist yet on a
/// fresh database: `seed-db` creates them with this superadmin as approver).
struct NoTokens;

#[async_trait::async_trait]
impl TokenIssuer for NoTokens {
    async fn issue_access(&self, _c: &AccessClaims) -> Result<String, AuthError> {
        Err(AuthError::Internal("staff-bootstrap issues no tokens"))
    }
}

/// Review N3: the staff tx failed after activation: the user goes back to `disabled` (this also
/// revokes any session, `set_user_status` semantics).
async fn revert_to_disabled(app: &Db, user: UserId, now: OffsetDateTime) -> Result<(), DbError> {
    let mut tx = app.identity_tx().await?;
    match auth_account::set_user_status(&mut tx, user, UserStatus::Disabled, micros(now)).await {
        Ok(()) => tx.commit().await,
        Err(e) => {
            tx.rollback().await;
            Err(e)
        }
    }
}

/// DB `DATETIME(6)` precision, so the audit row hash matches the stored row.
fn micros(t: OffsetDateTime) -> OffsetDateTime {
    t.replace_nanosecond(t.nanosecond() / 1000 * 1000)
        .unwrap_or(t)
}

fn check_password(pw: &SecretString) -> Result<(), BootstrapError> {
    let s = pw.expose_secret();
    if s.len() > MAX_PASSWORD_BYTES {
        return Err(BootstrapError::Invalid("password longer than 1024 bytes"));
    }
    if s.chars().count() < MIN_PASSWORD_CHARS || s.trim().is_empty() {
        return Err(BootstrapError::Invalid(
            "password shorter than 12 characters",
        ));
    }
    Ok(())
}

fn audit_row(
    user: UserId,
    kek_ref: &str,
    dek_kids_created: &[String],
    now: OffsetDateTime,
) -> Result<AuditRowRecord, BootstrapError> {
    let mut a = AuditRowRecord {
        id: uuid::Uuid::now_v7(),
        occurred_at: now,
        tenant_id: None,
        actor_kind: "system".into(),
        actor_id: Some(user.0),
        staff_grant_id: None,
        action: AUDIT_ACTION.into(),
        outcome: "success".into(),
        target_type: Some("platform_staff".into()),
        target_id: Some(user.0),
        request_id: None,
        ip_hmac: None,
        metadata: Some(serde_json::json!({
            "actor": "ops_bootstrap",
            "tool": "dsecure-api staff-bootstrap",
            "role": domain::rbac::StaffRole::Superadmin.as_str(),
            "mfa": "totp",
            "kek_ref": kek_ref,
            "dek_kids_created": dek_kids_created,
        })),
        row_hash: Vec::new(),
    };
    a.row_hash = audit::chain::compute_row_hash(&a)
        .map_err(|_| BootstrapError::Auth("audit row hash"))?
        .to_vec();
    Ok(a)
}

/// Create the first platform superadmin (module docs for the order and the guarantees).
///
/// # Errors
/// [`BootstrapError`] (value-free).
#[allow(clippy::too_many_lines)]
pub async fn bootstrap(
    deps: &BootstrapDeps,
    input: &BootstrapInput,
    term: &mut dyn Terminal,
) -> Result<BootstrapOutcome, BootstrapError> {
    let email =
        common::Email::parse(&input.email).map_err(|_| BootstrapError::Invalid("email address"))?;
    check_password(&input.password)?;

    // 1) Cheap pre-check (the locked count in step 7 is authoritative).
    if deps.admin.has_any_staff().await? {
        return Err(BootstrapError::AlreadyBootstrapped);
    }

    // 2) DEK plan + KEK guard BEFORE any write (shared with seed-db). New DEKs are only planned
    //    (wrapped in memory); they commit in step 7 together with the staff row.
    let plan = plan_platform_deks(
        deps.provider.as_ref(),
        &DbDekStore::new(deps.admin.db().clone()),
    )
    .await
    .map_err(|e| BootstrapError::KeysPlan(e.to_string()))?;
    let dek_kids_created: Vec<String> = plan
        .iter()
        .filter(|d| !d.existing)
        .map(|d| d.kid.to_string())
        .collect();
    // 3) KeyRing from the plan (in memory: the new DEKs are not committed yet).
    let mem = Arc::new(InMemoryDekStore::new());
    for d in &plan {
        mem.insert(&d.kid, d.purpose, None, &d.wrapped)
            .await
            .map_err(|_| BootstrapError::Keys("in-memory DEK store"))?;
    }
    let ring =
        KeyRing::load_platform_with(Arc::clone(&deps.provider), mem, deps.max_tenant_deks_cached)
            .await
            .map(Arc::new)
            .map_err(|_| BootstrapError::Keys("platform DEKs could not be loaded with this KEK"))?;
    let indexer = Arc::new(HmacBlindIndexer::new(Arc::clone(&ring)));
    let fields = Arc::new(AesGcmFieldEncryptor::new(Arc::clone(&ring)));
    let refresh_key = ring
        .derive_subkey(KeyPurpose::Secrets, None, REFRESH_KEY_LABEL)
        .await
        .map_err(|_| BootstrapError::Keys("refresh subkey"))?;

    // 4) User row (disabled until TOTP is confirmed) + Argon2id password, app user.
    let user = UserId::new();
    let bidx = indexer
        .index(BlindKind::Email, BlindScope::Global, email.as_str())
        .map_err(|_| BootstrapError::Invalid("email address"))?;
    let email_enc = fields
        .encrypt(
            email.as_str().as_bytes(),
            &FieldContext::new("users", "email_enc", None, user.0, KeyPurpose::Identity),
        )
        .await
        .map_err(|_| BootstrapError::Keys("email encryption"))?;
    let phc = deps
        .hasher
        .hash(input.password.clone())
        .await
        .map_err(|_| BootstrapError::Auth("password hashing"))?;
    let now = micros(deps.clock.now());
    let mut tx = deps.app.identity_tx().await?;
    let r = async {
        users::insert(
            &mut tx,
            &NewUser {
                id: user,
                email_bidx: bidx,
                email_enc,
                name_enc: None,
                status: UserStatus::Disabled,
            },
            now,
        )
        .await?;
        users::set_password(&mut tx, user, &phc, HashScheme::Argon2id, now).await?;
        auth_account::mark_email_verified(&mut tx, user, "staff", now).await
    }
    .await;
    match r {
        Ok(()) => tx.commit().await?,
        Err(e) => {
            tx.rollback().await;
            return Err(e.into());
        }
    }

    // 5) TOTP enrolment through the auth service (same secret handling as the API).
    let settings = deps.settings.clone();
    let svc = AuthService::new(AuthDeps {
        db: deps.app.clone(),
        hasher: Arc::clone(&deps.hasher),
        indexer,
        issuer: Arc::new(NoTokens),
        refresh: RefreshHasher::new(&refresh_key),
        fields,
        sink: Arc::new(TracingSink),
        clock: Arc::clone(&deps.clock),
        loader: Arc::new(DbPrincipalLoader::new(
            deps.app.clone(),
            Arc::clone(&deps.clock),
            &settings,
        )),
        settings,
    })
    .await
    .map_err(|e| BootstrapError::Auth(e.code()))?;
    let enrol = svc
        .begin_totp_enrolment(user, email.as_str())
        .await
        .map_err(|e| BootstrapError::Auth(e.code()))?;
    for l in [
        "",
        "==== SECRET (shown once): TOTP for the first platform superadmin ====================",
        "Add it to your authenticator app: scan the otpauth URI as a QR code or type the secret.",
        "Never paste it into chat, tickets, logs or files.",
    ] {
        term.line(l).map_err(term_err)?;
    }
    term.line(&format!("  otpauth URI : {}", enrol.otpauth_uri()))
        .map_err(term_err)?;
    term.line(&format!("  secret      : {}", enrol.secret_base32()))
        .map_err(term_err)?;
    term.line(
        "=====================================================================================",
    )
    .map_err(term_err)?;

    // 6) Confirm a code; this activates the factor and issues the recovery codes.
    let mut codes = None;
    for attempt in 1..=TOTP_ATTEMPTS {
        let Some(code) = term
            .ask(&format!(
                "Enter the current 6-digit code from the app ({attempt}/{TOTP_ATTEMPTS}): "
            ))
            .map_err(term_err)?
        else {
            break;
        };
        match svc
            .confirm_totp_enrolment(user, enrol.factor_id, code.trim())
            .await
        {
            Ok(c) => {
                codes = Some(c);
                break;
            }
            Err(AuthError::Unauthenticated(_)) => {
                term.line("  code not accepted (wait for the next code and try again)")
                    .map_err(term_err)?;
            }
            Err(e) => return Err(BootstrapError::Auth(e.code())),
        }
    }
    let Some(codes) = codes else {
        return Err(BootstrapError::TotpNotConfirmed);
    };

    // 7) Activate, then ONE platform-admin tx: marker + staff count + new DEKs + staff row + audit.
    //    On ANY error the outcome is checked on a fresh connection first (review M1: a COMMIT can
    //    apply and still report `CommitUnknown`): committed -> keep going; not committed -> the user
    //    goes back to disabled (review N3); check failed -> user stays active, codes shown, error.
    let now = micros(deps.clock.now());
    let mut tx = deps.app.identity_tx().await?;
    match auth_account::set_user_status(&mut tx, user, UserStatus::Active, now).await {
        Ok(()) => tx.commit().await?,
        Err(e) => {
            tx.rollback().await;
            return Err(e.into());
        }
    }
    let staff = async {
        let audit = audit_row(user, deps.provider.active_kek_ref(), &dek_kids_created, now)?;
        let committer: &dyn FirstStaffCommit = match &deps.staff_commit {
            Some(c) => c.as_ref(),
            None => &deps.admin,
        };
        committer
            .commit_first_superadmin(user, &plan, &audit, now)
            .await
            .map_err(BootstrapError::from)
    }
    .await;
    if let Err(cause) = staff {
        match deps.admin.bootstrap_committed_for(user).await {
            Ok(true) => {
                tracing::warn!(error = %cause, "staff-bootstrap: error reported, but the bootstrap is committed");
                term.line(&format!(
                    "NOTE: the database reported an error ({cause}), but a check on a fresh \
                     connection shows the bootstrap IS committed for this user. Continuing."
                ))
                .map_err(term_err)?;
            }
            Ok(false) => {
                return Err(
                    match revert_to_disabled(&deps.app, user, deps.clock.now()).await {
                        Ok(()) => cause,
                        Err(revert) => BootstrapError::RevertFailed {
                            cause: Box::new(cause),
                            user: user.0,
                            revert,
                        },
                    },
                );
            }
            Err(check) => {
                show_recovery_codes(term, &codes)?;
                return Err(BootstrapError::OutcomeUnknown {
                    cause: Box::new(cause),
                    user: user.0,
                    check,
                });
            }
        }
    }
    let created = dek_kids_created.len();
    tracing::info!(
        platform_deks_created = created,
        "first platform superadmin bootstrapped"
    );

    // 8) Recovery codes, once, terminal only.
    show_recovery_codes(term, &codes)?;
    term.line(&format!(
        "staff-bootstrap: done. platform_superadmin user id: {} (use it as --approver for \
         `cargo xtask provision-keys seed-db`). platform DEKs created: {created}",
        user.0
    ))
    .map_err(term_err)?;
    Ok(BootstrapOutcome {
        user_id: user,
        platform_deks_created: created,
    })
}

fn show_recovery_codes(
    term: &mut dyn Terminal,
    codes: &auth::RecoveryCodes,
) -> Result<(), BootstrapError> {
    for l in [
        "",
        "==== SECRET (shown once): recovery codes, each works once for login =================",
        "Store them offline (password manager / paper). They are not shown again.",
    ] {
        term.line(l).map_err(term_err)?;
    }
    for c in codes.codes() {
        term.line(&format!("  {c}")).map_err(term_err)?;
    }
    term.line(
        "=====================================================================================",
    )
    .map_err(term_err)?;
    Ok(())
}

/// Platform-admin `DbConfig`: the URL from [`PLATFORM_ADMIN_URL_KEY`], everything else (CA, engine,
/// timeouts) from the validated app config. URL rules as for `DATABASE_URL`.
///
/// # Errors
/// Value-free reason (key name only).
pub fn admin_db_config(cfg: &AppConfig, env: &Env) -> Result<config::DbConfig, &'static str> {
    let url = env
        .optional(PLATFORM_ADMIN_URL_KEY)
        .map_err(|_| "PLATFORM_ADMIN_DATABASE_URL is not valid unicode")?
        .filter(|u| !u.trim().is_empty())
        .ok_or("PLATFORM_ADMIN_DATABASE_URL is not set")?;
    if !config::dburl::is_mysql_url(&url) {
        return Err("PLATFORM_ADMIN_DATABASE_URL must be a valid mysql:// URL");
    }
    if config::dburl::targets_legacy_db(&url) {
        return Err("PLATFORM_ADMIN_DATABASE_URL must not point at the legacy database");
    }
    if !cfg.environment.is_local()
        && config::dburl::tls_check(&url) != config::dburl::TlsCheck::Verified
    {
        return Err("PLATFORM_ADMIN_DATABASE_URL needs exactly one ssl-mode=VERIFY_IDENTITY");
    }
    let d = &cfg.db;
    Ok(config::DbConfig {
        url: SecretString::from(url),
        tls_ca: d.tls_ca.clone(),
        expect_engine: d.expect_engine,
        // Bootstrap tx + DEK store; never more.
        max_connections: 2,
        acquire_timeout_ms: d.acquire_timeout_ms,
        tx_timeout_ms: d.tx_timeout_ms,
        max_execution_ms: d.max_execution_ms,
        lock_wait_timeout_s: d.lock_wait_timeout_s,
        retry_max_attempts: d.retry_max_attempts,
        retry_base_delay_ms: d.retry_base_delay_ms,
        statement_cache_capacity: 0,
        migrator_url: None,
    })
}

/// Read the password from the env variable named by `--password-env`.
///
/// # Errors
/// Value-free reason.
pub fn password_from_env(env: &Env, name: &str) -> Result<SecretString, &'static str> {
    env.optional(name)
        .map_err(|_| "the password variable is not valid unicode")?
        .filter(|p| !p.is_empty())
        .map(SecretString::from)
        .ok_or("the variable named by --password-env is not set or empty")
}

/// CLI wrapper: terminal check, env, pools, then [`bootstrap`]. Returns the exit code.
#[allow(clippy::print_stderr)]
pub async fn run_cli(cfg: &AppConfig, env: &Env, args: &BootstrapArgs) -> u8 {
    let Some(mut term) = StdTerminal::open() else {
        eprintln!(
            "staff-bootstrap refused: stdin and stdout must be an interactive terminal (it shows a \
             TOTP secret and recovery codes only there; never pipe or log its output)"
        );
        return EXIT_USAGE;
    };
    let password = match password_from_env(env, &args.password_env) {
        Ok(p) => p,
        Err(m) => {
            eprintln!("staff-bootstrap refused: {m}");
            return EXIT_USAGE;
        }
    };
    let admin_cfg = match admin_db_config(cfg, env) {
        Ok(c) => c,
        Err(m) => {
            eprintln!("staff-bootstrap refused: {m}");
            return EXIT_CONFIG;
        }
    };
    let provider = match crate::startup::kek_provider(cfg) {
        Ok(p) => p,
        Err(code) => {
            eprintln!("staff-bootstrap refused: KEK configuration (see log)");
            return code;
        }
    };
    let hasher = match crate::startup::hasher(cfg) {
        Ok(h) => h,
        Err(code) => {
            eprintln!("staff-bootstrap refused: Argon2 parameters (see log)");
            return code;
        }
    };
    let app = match Db::connect(&cfg.db, cfg.environment).await {
        Ok(db) => db,
        Err(e) => {
            eprintln!("staff-bootstrap: app database (DATABASE_URL) connect refused: {e}");
            return BootstrapError::Db(e).exit_code();
        }
    };
    let admin = match PlatformAdminDb::connect(&admin_cfg, cfg.environment).await {
        Ok(a) => a,
        Err(e) => {
            app.close().await;
            eprintln!("staff-bootstrap: platform-admin database connect refused: {e}");
            return BootstrapError::Db(e).exit_code();
        }
    };
    let deps = BootstrapDeps {
        app: app.clone(),
        admin,
        provider,
        hasher: Arc::new(hasher),
        settings: AuthSettings::from_config(cfg),
        max_tenant_deks_cached: cfg.limits.max_tenant_deks_cached,
        clock: Arc::new(SystemClock),
        staff_commit: None,
    };
    let input = BootstrapInput {
        email: args.email.clone(),
        password,
    };
    let r = bootstrap(&deps, &input, &mut term).await;
    deps.admin.db().close().await;
    app.close().await;
    match r {
        Ok(_) => EXIT_OK,
        Err(e) => {
            eprintln!("staff-bootstrap failed: {e}");
            e.exit_code()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_rules() {
        assert!(check_password(&SecretString::from("short")).is_err());
        assert!(check_password(&SecretString::from("            ")).is_err());
        assert!(check_password(&SecretString::from("a".repeat(1025))).is_err());
        assert!(check_password(&SecretString::from("correct horse battery")).is_ok());
    }

    #[test]
    fn exit_codes() {
        assert_eq!(
            BootstrapError::AlreadyBootstrapped.exit_code(),
            EXIT_ALREADY_BOOTSTRAPPED
        );
        assert_eq!(BootstrapError::EmailTaken.exit_code(), EXIT_DATAERR);
        assert_eq!(BootstrapError::TotpNotConfirmed.exit_code(), EXIT_DATAERR);
        assert_eq!(
            BootstrapError::Db(DbError::Config("x")).exit_code(),
            EXIT_CONFIG
        );
        assert!(matches!(
            BootstrapError::from(DbError::Conflict("staff.bootstrap_done")),
            BootstrapError::AlreadyBootstrapped
        ));
        assert!(matches!(
            BootstrapError::from(DbError::Conflict("users.email_taken")),
            BootstrapError::EmailTaken
        ));
    }

    #[test]
    fn audit_row_is_system_bootstrap_and_hashed() {
        let u = UserId::new();
        let a = audit_row(
            u,
            "kek-1",
            &["k1".to_owned()],
            micros(OffsetDateTime::now_utc()),
        )
        .expect("row");
        assert_eq!(a.actor_kind, "system");
        assert_eq!(a.actor_id, Some(u.0));
        assert_eq!(a.action, AUDIT_ACTION);
        assert_eq!(a.row_hash.len(), 32);
        assert_eq!(
            a.metadata.as_ref().and_then(|m| m.get("actor")),
            Some(&serde_json::json!("ops_bootstrap"))
        );
    }

    fn env_with(pairs: &[(&str, &str)]) -> Env {
        Env::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    }

    #[test]
    fn password_only_from_named_env_var() {
        let e = env_with(&[("BOOT_PW", "correct horse battery")]);
        assert!(password_from_env(&e, "BOOT_PW").is_ok());
        assert!(password_from_env(&e, "OTHER").is_err());
        let e = env_with(&[("BOOT_PW", "")]);
        assert!(password_from_env(&e, "BOOT_PW").is_err());
    }
}
