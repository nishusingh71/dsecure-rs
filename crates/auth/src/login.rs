//! Login core without HTTP (P0-09): `authenticate`, `refresh`, `step_up` / `consume_step_up`,
//! `logout`.
//!
//! - Email lookup via the global email blind index.
//! - Unknown user / bad email / locked account: ONE dummy Argon2id verify with the same params, so
//!   every path runs exactly one hash verification (constant HASH work; test asserts the call count).
//!   DB work still differs (a known user's attempt writes the lockout row). That user-enumeration
//!   timing channel is mitigated by the per-IP + per-email pre-auth limiter (P0-11, SECURITY.md §9),
//!   tracked as review item F5.
//! - Lockout: every attempt is RESERVED under `SELECT ... FOR UPDATE` before the real verify
//!   (locked = refused, no verify), reset on success, decaying counter (see [`crate::lockout`]).
//!   A verify that fails with `Busy` stays counted (fail closed).
//! - Legacy bcrypt (or old Argon2 params) → rehash to current Argon2id after a successful verify.
//! - `HashCostExceeded` / `MalformedHash` = failed login (never a 500).
//! - Staff realm (`Audience::Platform`): password + TOTP (or a recovery code) is mandatory; the
//!   session gets `mfa_at`. Staff sessions also need `mfa_at` on every request, max 8 h absolute and
//!   30 min idle (loader). Staff step-up needs a TOTP code.
//! - Members: MFA opt-in (D-23); once enrolled, login and step-up ask for a code
//!   (`LoginError::MfaRequired`). Wrong codes count towards the lockout like wrong passwords.
//! - Callers get ONE generic `LoginError::Failed`; reasons go to the [`AuthEventSink`] only.

use std::sync::Arc;

use common::{Clock, Email, MembershipId, SessionId, TenantId, UserId};
use crypto::{
    BlindIndexer, BlindKind, BlindScope, CryptoError, FieldEncryptor, PasswordHasher, VerifyOutcome,
};
use db::Db;
use db::repo::sessions::{self, ClientKind, NewRefreshToken, NewSession, PrincipalKind as DbKind};
use db::repo::users::{self, HashScheme, UserRow};
use db::repo::{auth_credentials, auth_state, auth_step_up};
use db::{DbError, IdentityTx};
use secrecy::{ExposeSecret, SecretString};
use time::{Duration, OffsetDateTime};

use crate::claims::{AccessClaims, Amr, Audience, PrincipalKind, VerifiedClaims};
use crate::error::{AuthError, LoginError, Rejection};
use crate::loader::{self, DbPrincipalLoader, Freshness, PrincipalStateLoader, StaffLimits};
use crate::lockout;
use crate::mfa::{MfaCheck, MfaInput};
use crate::refresh::{self, RefreshHasher, RefreshSecret};
use crate::settings::AuthSettings;
use crate::sink::{AuthEvent, AuthEventKind, AuthEventSink};
use crate::stepup::{STEP_UP_PREFIX, StepUpProof, StepUpSecret};
use crate::tokens::TokenIssuer;

/// TiDB optimistic write conflict (only possible if a session ever runs optimistic).
const TIDB_WRITE_CONFLICT: u16 = 9007;

/// Login input. `password` is never logged or echoed.
pub struct LoginRequest<'a> {
    pub email: &'a str,
    pub password: SecretString,
    pub audience: Audience,
    pub tenant: Option<TenantId>,
    pub product_code: Option<String>,
    pub device_label: Option<String>,
    /// Second factor. Mandatory for `Audience::Platform` (staff); required for members who enrolled
    /// (otherwise `LoginError::MfaRequired` after a correct password).
    pub mfa: Option<MfaInput>,
}

impl std::fmt::Debug for LoginRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest")
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

/// Issued tokens. `Debug` hides both tokens.
pub struct TokenPair {
    pub access_token: String,
    pub access_expires_at: OffsetDateTime,
    pub refresh_token: RefreshSecret,
    pub refresh_expires_at: OffsetDateTime,
    pub session: SessionId,
    pub tenant: Option<TenantId>,
}

impl std::fmt::Debug for TokenPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPair")
            .field("session", &self.session)
            .field("access_expires_at", &self.access_expires_at)
            .finish_non_exhaustive()
    }
}

/// Live identity of the session being created / refreshed.
struct Issued {
    user: UserId,
    tenant: Option<(TenantId, MembershipId)>,
    av: u64,
    mfa: bool,
}

/// Outcome of reserving a login attempt under the credential row lock.
enum Reservation {
    Locked,
    Reserved { hash: String, newly_locked: bool },
}

pub struct AuthService {
    pub(crate) db: Db,
    hasher: Arc<dyn PasswordHasher>,
    indexer: Arc<dyn BlindIndexer>,
    issuer: Arc<dyn TokenIssuer>,
    pub(crate) refresh: RefreshHasher,
    pub(crate) fields: Arc<dyn FieldEncryptor>,
    pub(crate) sink: Arc<dyn AuthEventSink>,
    pub(crate) clock: Arc<dyn Clock>,
    loader: Arc<DbPrincipalLoader>,
    settings: AuthSettings,
    /// Argon2id hash of a random password with the configured params (unknown-user path).
    dummy_hash: String,
}

/// Second-factor requirement of one password check.
#[derive(Clone, Copy, Debug)]
struct SecondFactor<'a> {
    input: Option<&'a MfaInput>,
    /// Staff: an enrolled, valid factor is mandatory.
    required: bool,
    allow_recovery: bool,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService").finish_non_exhaustive()
    }
}

/// Constructor inputs.
pub struct AuthDeps {
    pub db: Db,
    pub hasher: Arc<dyn PasswordHasher>,
    pub indexer: Arc<dyn BlindIndexer>,
    pub issuer: Arc<dyn TokenIssuer>,
    /// Keyed hash for refresh AND step-up tokens and recovery codes (domain-separated).
    pub refresh: RefreshHasher,
    /// Field encryption for TOTP secrets (purpose `Secrets`, platform scope).
    pub fields: Arc<dyn FieldEncryptor>,
    pub sink: Arc<dyn AuthEventSink>,
    pub clock: Arc<dyn Clock>,
    pub loader: Arc<DbPrincipalLoader>,
    pub settings: AuthSettings,
}

fn db_err(e: &DbError) -> LoginError {
    match AuthError::from_db(e) {
        AuthError::Unavailable => LoginError::Unavailable,
        _ => LoginError::Failed,
    }
}

const fn client_kind(aud: Audience) -> Option<ClientKind> {
    match aud {
        Audience::Web => Some(ClientKind::Web),
        Audience::App => Some(ClientKind::DesktopApp),
        Audience::Platform => Some(ClientKind::PlatformConsole),
        Audience::Device | Audience::Cleaner => None,
    }
}

fn audience_of(client_kind: &str) -> Option<Audience> {
    match client_kind {
        "web" => Some(Audience::Web),
        "desktop_app" => Some(Audience::App),
        "platform_console" => Some(Audience::Platform),
        _ => None,
    }
}

fn copy_secret(pw: &SecretString) -> SecretString {
    SecretString::from(pw.expose_secret().to_owned())
}

impl AuthService {
    /// Builds the dummy hash with the configured hasher (one `hash` call).
    ///
    /// # Errors
    /// `Internal` if hashing or the RNG fails.
    pub async fn new(deps: AuthDeps) -> Result<Self, AuthError> {
        let random = refresh::generate()?;
        let dummy_hash = deps
            .hasher
            .hash(SecretString::from(random.expose().to_owned()))
            .await
            .map_err(|_| AuthError::Internal("dummy hash"))?;
        Ok(Self {
            db: deps.db,
            hasher: deps.hasher,
            indexer: deps.indexer,
            issuer: deps.issuer,
            refresh: deps.refresh,
            fields: deps.fields,
            sink: deps.sink,
            clock: deps.clock,
            loader: deps.loader,
            settings: deps.settings,
            dummy_hash,
        })
    }

    fn event(
        &self,
        kind: AuthEventKind,
        user: Option<UserId>,
        tenant: Option<TenantId>,
        session: Option<SessionId>,
    ) {
        self.sink.record(AuthEvent {
            kind,
            user,
            tenant,
            session,
            at: self.clock.now(),
        });
    }

    fn fail(&self, reason: &'static str, user: Option<UserId>) -> LoginError {
        self.event(AuthEventKind::LoginFailed(reason), user, None, None);
        LoginError::Failed
    }

    /// Same Argon2 work as a real verify; result ignored.
    async fn dummy_verify(&self, pw: SecretString) -> Result<(), LoginError> {
        match self.hasher.verify(pw, &self.dummy_hash).await {
            Err(CryptoError::Busy) => Err(LoginError::Busy),
            _ => Ok(()),
        }
    }

    const fn refresh_ttl(&self, aud: Audience) -> Duration {
        match aud {
            Audience::App => self.settings.refresh_ttl_app,
            Audience::Platform => self.settings.refresh_ttl_platform,
            _ => self.settings.refresh_ttl_web,
        }
    }

    async fn find_user(&self, email: &str) -> Result<Option<UserRow>, LoginError> {
        let Ok(email) = Email::parse(email) else {
            return Ok(None);
        };
        let Ok(bidx) = self
            .indexer
            .index(BlindKind::Email, BlindScope::Global, email.as_str())
        else {
            return Ok(None);
        };
        let mut tx = self.db.identity_tx().await.map_err(|e| db_err(&e))?;
        let user = users::find_by_email_bidx(&mut tx, &bidx).await;
        tx.rollback().await;
        user.map_err(|e| db_err(&e))
    }

    /// Lock the credential row; refuse if locked, else count this attempt NOW (before the verify).
    async fn reserve_attempt(&self, user: UserId) -> Result<Option<Reservation>, LoginError> {
        let now = self.clock.now();
        let mut tx = self.db.identity_tx().await.map_err(|e| db_err(&e))?;
        let row = match auth_credentials::lockout_for_update(&mut tx, user).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                tx.rollback().await;
                return Ok(None);
            }
            Err(e) => {
                tx.rollback().await;
                return Err(db_err(&e));
            }
        };
        if lockout::is_locked(row.locked_until, now) {
            tx.rollback().await;
            return Ok(Some(Reservation::Locked));
        }
        let (attempts, locked_until) = lockout::after_failure(
            row.failed_attempts,
            row.last_failed_at,
            row.locked_until,
            now,
        );
        auth_credentials::record_failure(&mut tx, user, attempts, now, locked_until)
            .await
            .map_err(|e| db_err(&e))?;
        tx.commit().await.map_err(|e| db_err(&e))?;
        Ok(Some(Reservation::Reserved {
            hash: row.password_hash,
            newly_locked: lockout::is_locked(locked_until, now),
        }))
    }

    /// Verify a password for a known user (reservation + lockout + rehash). Exactly one hasher
    /// verify call on every path.
    /// Returns whether a second factor was verified. The reserved attempt is cleared only after
    /// BOTH factors passed, so wrong TOTP codes count towards the lockout like wrong passwords.
    async fn check_password(
        &self,
        user: UserId,
        pw: SecretString,
        second: SecondFactor<'_>,
    ) -> Result<bool, (&'static str, LoginError)> {
        let (hash, newly_locked) = match self.reserve_attempt(user).await {
            Ok(Some(Reservation::Reserved { hash, newly_locked })) => (hash, newly_locked),
            Ok(Some(Reservation::Locked)) => {
                self.dummy_verify(pw).await.map_err(|e| ("busy", e))?;
                return Err(("locked", LoginError::Failed));
            }
            Ok(None) => {
                self.dummy_verify(pw).await.map_err(|e| ("busy", e))?;
                return Err(("no_credentials", LoginError::Failed));
            }
            Err(e) => {
                self.dummy_verify(pw).await.map_err(|e| ("busy", e))?;
                return Err(("db", e));
            }
        };
        let keep = copy_secret(&pw);
        let needs_rehash = match self.hasher.verify(pw, &hash).await {
            Ok(VerifyOutcome::Valid { needs_rehash }) => needs_rehash,
            Err(CryptoError::Busy) => return Err(("busy", LoginError::Busy)),
            Ok(VerifyOutcome::Invalid) => {
                if newly_locked {
                    self.event(AuthEventKind::LockedOut, Some(user), None, None);
                }
                return Err(("wrong_password", LoginError::Failed));
            }
            // HashCostExceeded / MalformedHash / anything else: a failed login, never a 500.
            Err(_) => {
                if newly_locked {
                    self.event(AuthEventKind::LockedOut, Some(user), None, None);
                }
                return Err(("bad_stored_hash", LoginError::Failed));
            }
        };
        let mfa = match self
            .check_mfa(user, second.input, second.allow_recovery)
            .await
        {
            Ok(MfaCheck::Ok) => {
                self.event(AuthEventKind::MfaVerified, Some(user), None, None);
                true
            }
            Ok(MfaCheck::NotEnrolled) if second.required => {
                return Err(("mfa_not_enrolled", LoginError::Failed));
            }
            Ok(MfaCheck::NotEnrolled) => false,
            Ok(MfaCheck::Missing) => return Err(("mfa_required", LoginError::MfaRequired)),
            Ok(MfaCheck::Invalid) => return Err(("mfa_invalid", LoginError::Failed)),
            Err(AuthError::Unavailable) => return Err(("db", LoginError::Unavailable)),
            Err(_) => return Err(("mfa_error", LoginError::Failed)),
        };
        // Success: the reserved attempt (and any older ones) are cleared.
        let mut tx = self
            .db
            .identity_tx()
            .await
            .map_err(|e| ("db", db_err(&e)))?;
        auth_credentials::reset_failures(&mut tx, user)
            .await
            .map_err(|e| ("db", db_err(&e)))?;
        tx.commit().await.map_err(|e| ("db", db_err(&e)))?;
        if needs_rehash {
            self.rehash(user, &hash, keep).await;
        }
        Ok(mfa)
    }

    /// Best effort: a failed rehash never fails the login (next login retries).
    async fn rehash(&self, user: UserId, old: &str, pw: SecretString) {
        let Ok(new_hash) = self.hasher.hash(pw).await else {
            return;
        };
        let Ok(mut tx) = self.db.identity_tx().await else {
            return;
        };
        match auth_credentials::rehash(&mut tx, user, old, &new_hash, HashScheme::Argon2id).await {
            Ok(true) => {
                if tx.commit().await.is_ok() {
                    self.event(AuthEventKind::PasswordRehashed, Some(user), None, None);
                }
            }
            _ => tx.rollback().await,
        }
    }

    /// Password login.
    ///
    /// # Errors
    /// `Failed` (generic), `TenantChoiceRequired`, `Busy`, `Unavailable`.
    pub async fn authenticate(&self, req: LoginRequest<'_>) -> Result<TokenPair, LoginError> {
        let LoginRequest {
            email,
            password,
            audience,
            tenant,
            product_code,
            device_label,
            mfa,
        } = req;
        let found = match self.find_user(email).await {
            Ok(f) => f,
            Err(e) => {
                self.dummy_verify(password).await?;
                return Err(e);
            }
        };
        // Staff realm: password + TOTP (or recovery code) mandatory; no password-only staff session.
        let staff = audience == Audience::Platform;
        let Some(kind) = client_kind(audience) else {
            self.dummy_verify(password).await?;
            return Err(self.fail("unsupported_audience", None));
        };
        let Some(user) = found else {
            self.dummy_verify(password).await?;
            return Err(self.fail("unknown_user", None));
        };
        let second = SecondFactor {
            input: mfa.as_ref(),
            required: staff,
            allow_recovery: true,
        };
        let mfa_ok = match self.check_password(user.id, password, second).await {
            Ok(m) => m,
            Err((reason, e)) => {
                if matches!(e, LoginError::Failed | LoginError::MfaRequired) {
                    self.event(
                        AuthEventKind::LoginFailed(reason),
                        Some(user.id),
                        None,
                        None,
                    );
                }
                return Err(e);
            }
        };
        if staff && !mfa_ok {
            return Err(self.fail("staff_mfa_required", Some(user.id)));
        }
        // Password correct: account state (generic failure, reason to the sink).
        if user.status != users::UserStatus::Active {
            return Err(self.fail("user_inactive", Some(user.id)));
        }
        if user.email_verified_at.is_none() {
            return Err(self.fail("email_unverified", Some(user.id)));
        }
        let now = self.clock.now();
        let expires = now + self.refresh_ttl(audience);
        let mut tx = self.db.identity_tx().await.map_err(|e| db_err(&e))?;
        let pick = if staff {
            None
        } else {
            match self.choose_tenant(&mut tx, user.id, tenant).await {
                Ok(p) => Some(p),
                Err(e) => {
                    tx.rollback().await;
                    return Err(match e {
                        LoginError::Failed => self.fail("no_membership", Some(user.id)),
                        other => other,
                    });
                }
            }
        };
        let session = SessionId::new();
        let new = NewSession {
            id: session,
            user_id: user.id,
            tenant: pick,
            principal_kind: if staff { DbKind::Staff } else { DbKind::Member },
            client_kind: kind,
            product_code,
            device_label,
            expires_at: expires,
        };
        if let Err(e) = sessions::insert(&mut tx, &new, now).await {
            tx.rollback().await;
            return Err(match e {
                DbError::NotFound(_) => self.fail("no_membership", Some(user.id)),
                other => db_err(&other),
            });
        }
        if mfa_ok && let Err(e) = auth_state::mark_session_mfa(&mut tx, session, now).await {
            tx.rollback().await;
            return Err(db_err(&e));
        }
        let issued = match self
            .live_issue(&mut tx, session, user.id, pick, audience, None)
            .await
        {
            Ok(i) => i,
            Err(e) => {
                tx.rollback().await;
                return Err(match e {
                    AuthError::Unauthenticated(r) => self.fail(r.label(), Some(user.id)),
                    AuthError::Unavailable => LoginError::Unavailable,
                    AuthError::Internal(_) | AuthError::Forbidden(_) => LoginError::Failed,
                });
            }
        };
        let secret = refresh::generate().map_err(|_| LoginError::Unavailable)?;
        let hash = self
            .refresh
            .hash(secret.expose())
            .map_err(|_| LoginError::Unavailable)?;
        let rt = NewRefreshToken {
            id: uuid::Uuid::now_v7(),
            session,
            family_id: uuid::Uuid::now_v7(),
            token_hash: hash,
            expires_at: expires,
        };
        sessions::insert_refresh(&mut tx, &rt, now)
            .await
            .map_err(|e| db_err(&e))?;
        tx.commit().await.map_err(|e| db_err(&e))?;
        let access = self.access_claims(&issued, session, audience, now, now.unix_timestamp());
        let (access_token, access_expires_at) = self.sign(&access).await?;
        self.event(
            AuthEventKind::LoginSucceeded,
            Some(user.id),
            issued.tenant.map(|(t, _)| t),
            Some(session),
        );
        Ok(TokenPair {
            access_token,
            access_expires_at,
            refresh_token: secret,
            refresh_expires_at: expires,
            session,
            tenant: issued.tenant.map(|(t, _)| t),
        })
    }

    async fn choose_tenant(
        &self,
        tx: &mut IdentityTx,
        user: UserId,
        choice: Option<TenantId>,
    ) -> Result<(TenantId, MembershipId), LoginError> {
        let dir = users::memberships_of(tx, user)
            .await
            .map_err(|e| db_err(&e))?;
        let active: Vec<_> = dir
            .into_iter()
            .filter(|d| d.status == db::repo::memberships::MembershipStatus::Active)
            .collect();
        match choice {
            Some(t) => active
                .iter()
                .find(|d| d.tenant == t)
                .map(|d| (d.tenant, d.membership))
                .ok_or(LoginError::Failed),
            None => match active.as_slice() {
                [] => Err(LoginError::Failed),
                [one] => Ok((one.tenant, one.membership)),
                many => Err(LoginError::TenantChoiceRequired(
                    many.iter().map(|d| d.tenant).collect(),
                )),
            },
        }
    }

    /// Live state check of a session (inside `tx`) + what goes into the access token.
    /// `issued_at`: issue time of the presented refresh token (checked against
    /// `tokens_valid_after`); `None` at login.
    async fn live_issue(
        &self,
        tx: &mut IdentityTx,
        session: SessionId,
        user: UserId,
        tenant: Option<(TenantId, MembershipId)>,
        audience: Audience,
        issued_at: Option<OffsetDateTime>,
    ) -> Result<Issued, AuthError> {
        let now = self.clock.now();
        if let Some((t, m)) = tenant {
            let row = auth_state::member_live(tx, session, user, t, m)
                .await
                .map_err(|e| AuthError::from_db(&e))?
                .ok_or(AuthError::Unauthenticated(Rejection::SessionMissing))?;
            loader::check_member_row(&row, audience, issued_at, now)?;
            Ok(Issued {
                user,
                tenant: Some((t, m)),
                av: row.membership_authz_version,
                mfa: row.session.mfa_at.is_some(),
            })
        } else {
            if audience != Audience::Platform {
                return Err(AuthError::Unauthenticated(Rejection::KindMismatch));
            }
            let row = auth_state::staff_live(tx, session, user)
                .await
                .map_err(|e| AuthError::from_db(&e))?
                .ok_or(AuthError::Unauthenticated(Rejection::StaffRevoked))?;
            loader::check_staff_row(
                &row,
                issued_at,
                now,
                StaffLimits::from_settings(&self.settings),
            )?;
            Ok(Issued {
                user,
                tenant: None,
                av: row.user.authz_version,
                mfa: row.session.mfa_at.is_some(),
            })
        }
    }

    fn access_claims(
        &self,
        i: &Issued,
        session: SessionId,
        audience: Audience,
        now: OffsetDateTime,
        auth_time: i64,
    ) -> AccessClaims {
        let iat = now.unix_timestamp();
        let mut amr = vec![Amr::Pwd];
        if i.mfa {
            amr.push(Amr::Mfa);
        }
        AccessClaims {
            iss: self.settings.issuer.clone(),
            sub: i.user.0,
            aud: audience,
            exp: iat + self.settings.access_ttl.whole_seconds(),
            nbf: iat,
            iat,
            jti: uuid::Uuid::now_v7(),
            typ: audience.kind(),
            tid: i.tenant.map(|(t, _)| t),
            mid: i.tenant.map(|(_, m)| m),
            sid: Some(session),
            dcid: None,
            av: i.av,
            amr,
            auth_time,
        }
    }

    async fn sign(&self, c: &AccessClaims) -> Result<(String, OffsetDateTime), LoginError> {
        let token = self
            .issuer
            .issue_access(c)
            .await
            .map_err(|_| LoginError::Unavailable)?;
        let exp =
            OffsetDateTime::from_unix_timestamp(c.exp).map_err(|_| LoginError::Unavailable)?;
        Ok((token, exp))
    }

    fn refresh_fail(&self, reason: &'static str, session: Option<SessionId>) -> LoginError {
        self.event(AuthEventKind::RefreshFailed(reason), None, None, session);
        LoginError::Failed
    }

    /// Reuse of a used token (or a lost rotation race): roll back the current tx, then in a FRESH tx
    /// revoke the family AND the session (+ its other tokens, + epoch). The reuse event is emitted
    /// only after that commit succeeded.
    async fn reuse_detected(
        &self,
        old: IdentityTx,
        family: uuid::Uuid,
        session: SessionId,
    ) -> LoginError {
        old.rollback().await;
        let now = self.clock.now();
        let committed = match self.db.identity_tx().await {
            Ok(mut tx) => {
                let ok = sessions::revoke_family(&mut tx, family, now).await.is_ok()
                    && auth_state::revoke_session(&mut tx, session, "refresh_reuse", now)
                        .await
                        .is_ok();
                if ok {
                    tx.commit().await.is_ok()
                } else {
                    tx.rollback().await;
                    false
                }
            }
            Err(_) => false,
        };
        if committed {
            self.loader.invalidate_session(session);
            self.event(
                AuthEventKind::RefreshReuseDetected,
                None,
                None,
                Some(session),
            );
        } else {
            self.event(
                AuthEventKind::RefreshFailed("reuse_revoke_failed"),
                None,
                None,
                Some(session),
            );
        }
        LoginError::Failed
    }

    /// Rotate a refresh token: full live state re-check, new access + refresh token, old one used.
    ///
    /// # Errors
    /// `Failed` (generic), `Unavailable`.
    pub async fn refresh(&self, token: &str, audience: Audience) -> Result<TokenPair, LoginError> {
        let Ok(hash) = self.refresh.hash(token) else {
            return Err(self.refresh_fail("malformed", None));
        };
        let now = self.clock.now();
        let mut tx = self.db.identity_tx().await.map_err(|e| db_err(&e))?;
        let row = match sessions::find_refresh_by_hash(&mut tx, &hash).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                tx.rollback().await;
                return Err(self.refresh_fail("unknown", None));
            }
            Err(e) => {
                tx.rollback().await;
                return Err(db_err(&e));
            }
        };
        if row.revoked_at.is_some() {
            tx.rollback().await;
            return Err(self.refresh_fail("revoked", Some(row.session)));
        }
        if row.used_at.is_some() {
            return Err(self.reuse_detected(tx, row.family_id, row.session).await);
        }
        if row.expires_at <= now {
            tx.rollback().await;
            return Err(self.refresh_fail("expired", Some(row.session)));
        }
        let session = match sessions::get(&mut tx, row.session).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                tx.rollback().await;
                return Err(self.refresh_fail("session_missing", Some(row.session)));
            }
            Err(e) => {
                tx.rollback().await;
                return Err(db_err(&e));
            }
        };
        // Bound to the session's client: a web refresh token never mints an app/platform token.
        if audience_of(&session.client_kind) != Some(audience) {
            tx.rollback().await;
            return Err(self.refresh_fail("audience_mismatch", Some(session.id)));
        }
        let tenant = match (session.tenant, session.membership) {
            (Some(t), Some(m)) => Some((t, m)),
            (None, None) => None,
            _ => {
                tx.rollback().await;
                return Err(self.refresh_fail("state_mismatch", Some(session.id)));
            }
        };
        // Full live re-check; the refresh token must be newer than `tokens_valid_after`.
        let issued = match self
            .live_issue(
                &mut tx,
                session.id,
                session.user_id,
                tenant,
                audience,
                Some(row.issued_at),
            )
            .await
        {
            Ok(i) => i,
            Err(e) => {
                tx.rollback().await;
                return Err(match e {
                    AuthError::Unauthenticated(r) => self.refresh_fail(r.label(), Some(session.id)),
                    AuthError::Unavailable => LoginError::Unavailable,
                    AuthError::Internal(_) | AuthError::Forbidden(_) => LoginError::Failed,
                });
            }
        };
        // Lockout applies at refresh too (RBAC.md §6.3).
        match users::credentials(&mut tx, session.user_id).await {
            Ok(Some(c)) if !lockout::is_locked(c.locked_until, now) => {}
            Ok(_) => {
                tx.rollback().await;
                return Err(self.refresh_fail("locked", Some(session.id)));
            }
            Err(e) => {
                tx.rollback().await;
                return Err(db_err(&e));
            }
        }
        let secret = refresh::generate().map_err(|_| LoginError::Unavailable)?;
        let new_hash = self
            .refresh
            .hash(secret.expose())
            .map_err(|_| LoginError::Unavailable)?;
        let new_id = uuid::Uuid::now_v7();
        match sessions::mark_refresh_used(&mut tx, row.id, new_id, now).await {
            Ok(()) => {}
            // Lost a race with a concurrent use of the same token = reuse (TiDB optimistic conflict
            // 9007 is the same race; sessions run pessimistic, this is defence in depth).
            Err(
                DbError::Conflict(_)
                | DbError::Transient {
                    code: TIDB_WRITE_CONFLICT,
                },
            ) => {
                return Err(self.reuse_detected(tx, row.family_id, session.id).await);
            }
            Err(e) => {
                tx.rollback().await;
                return Err(db_err(&e));
            }
        }
        let rt = NewRefreshToken {
            id: new_id,
            session: session.id,
            family_id: row.family_id,
            token_hash: new_hash,
            // Absolute session lifetime: rotation never extends it.
            expires_at: session.expires_at,
        };
        sessions::insert_refresh(&mut tx, &rt, now)
            .await
            .map_err(|e| db_err(&e))?;
        match tx.commit().await {
            Ok(()) => {}
            Err(DbError::Transient {
                code: TIDB_WRITE_CONFLICT,
            }) => {
                // Commit-time conflict: the tx is gone, revoke in a fresh one.
                let fresh = self.db.identity_tx().await.map_err(|e| db_err(&e))?;
                return Err(self.reuse_detected(fresh, row.family_id, session.id).await);
            }
            Err(e) => return Err(db_err(&e)),
        }
        let auth_time = session.created_at.unix_timestamp();
        let access = self.access_claims(&issued, session.id, audience, now, auth_time);
        let (access_token, access_expires_at) = self.sign(&access).await?;
        self.event(
            AuthEventKind::RefreshRotated,
            Some(session.user_id),
            tenant.map(|(t, _)| t),
            Some(session.id),
        );
        Ok(TokenPair {
            access_token,
            access_expires_at,
            refresh_token: secret,
            refresh_expires_at: session.expires_at,
            session: session.id,
            tenant: tenant.map(|(t, _)| t),
        })
    }

    /// Step-up: password re-entry → separate single-use token bound to this session + `action` +
    /// `target` (5 min). Returned once; only its HMAC is stored.
    ///
    /// # Errors
    /// `Failed` (generic), `Busy`, `Unavailable`.
    /// Staff: a TOTP code is mandatory (`mfa`), recovery codes are not accepted. Members who enrolled
    /// MFA must also send a TOTP code.
    pub async fn step_up(
        &self,
        claims: &VerifiedClaims,
        password: SecretString,
        mfa: Option<MfaInput>,
        action: &str,
        target: Option<uuid::Uuid>,
    ) -> Result<StepUpSecret, LoginError> {
        let valid_action =
            !action.is_empty() && action.len() <= auth_step_up::MAX_ACTION_LEN && action.is_ascii();
        let Some(session) = claims.session().filter(|_| valid_action) else {
            self.dummy_verify(password).await?;
            return Err(self.step_fail("bad_request", claims));
        };
        if !matches!(claims.kind(), PrincipalKind::Member | PrincipalKind::Staff) {
            self.dummy_verify(password).await?;
            return Err(self.step_fail("kind", claims));
        }
        // Session and account must be live right now.
        if self.loader.load(claims, Freshness::Live).await.is_err() {
            self.dummy_verify(password).await?;
            return Err(self.step_fail("state", claims));
        }
        let second = SecondFactor {
            input: mfa.as_ref(),
            required: claims.kind() == PrincipalKind::Staff,
            allow_recovery: false,
        };
        match self.check_password(claims.user(), password, second).await {
            Ok(_) => {}
            Err((reason, e)) => {
                if matches!(e, LoginError::Failed | LoginError::MfaRequired) {
                    self.event(
                        AuthEventKind::StepUpFailed(reason),
                        Some(claims.user()),
                        claims.tenant(),
                        claims.session(),
                    );
                }
                return Err(e);
            }
        }
        let secret =
            refresh::generate_opaque(STEP_UP_PREFIX).map_err(|_| LoginError::Unavailable)?;
        let hash = self
            .refresh
            .hash_opaque(STEP_UP_PREFIX, &secret)
            .map_err(|_| LoginError::Unavailable)?;
        let now = self.clock.now();
        let mut tx = self.db.identity_tx().await.map_err(|e| db_err(&e))?;
        auth_step_up::insert(
            &mut tx,
            &auth_step_up::NewStepUp {
                id: uuid::Uuid::now_v7(),
                session,
                action,
                target,
                token_hash: hash,
                expires_at: now + self.settings.step_up_ttl,
            },
        )
        .await
        .map_err(|e| db_err(&e))?;
        tx.commit().await.map_err(|e| db_err(&e))?;
        self.event(
            AuthEventKind::StepUpGranted,
            Some(claims.user()),
            claims.tenant(),
            Some(session),
        );
        Ok(StepUpSecret(secret))
    }

    /// Consume a step-up token for exactly this request (session from the verified access token,
    /// `action` from the route policy, `target` from the loaded row). Single use: one atomic UPDATE.
    /// Call BEFORE the protected action; if the action then fails the proof is burned (fail closed).
    /// `Ok(None)` = no valid proof (replay, other session/action/target, expired, malformed): the
    /// policy then answers 403 `auth.step_up_required`.
    ///
    /// # Errors
    /// `Unavailable` / `Internal` (DB).
    pub async fn consume_step_up(
        &self,
        claims: &VerifiedClaims,
        token: &str,
        action: &str,
        target: Option<uuid::Uuid>,
    ) -> Result<Option<StepUpProof>, AuthError> {
        let Some(session) = claims.session() else {
            return Ok(None);
        };
        let Ok(hash) = self.refresh.hash_opaque(STEP_UP_PREFIX, token) else {
            self.event(
                AuthEventKind::StepUpFailed("malformed"),
                Some(claims.user()),
                claims.tenant(),
                Some(session),
            );
            return Ok(None);
        };
        let now = self.clock.now();
        let mut tx = self
            .db
            .identity_tx()
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        let ok = auth_step_up::consume(&mut tx, &hash, session, action, target, now)
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        tx.commit().await.map_err(|e| AuthError::from_db(&e))?;
        if ok {
            Ok(Some(StepUpProof::new(session, action.to_owned(), target)))
        } else {
            self.event(
                AuthEventKind::StepUpFailed("not_consumable"),
                Some(claims.user()),
                claims.tenant(),
                Some(session),
            );
            Ok(None)
        }
    }

    fn step_fail(&self, reason: &'static str, claims: &VerifiedClaims) -> LoginError {
        self.event(
            AuthEventKind::StepUpFailed(reason),
            Some(claims.user()),
            claims.tenant(),
            claims.session(),
        );
        LoginError::Failed
    }

    /// Logout: revoke the session + its refresh tokens, bump the tenant epoch, drop local cache.
    ///
    /// # Errors
    /// `Unauthenticated` (no session claim), `Unavailable` / `Internal`.
    pub async fn logout(&self, claims: &VerifiedClaims) -> Result<(), AuthError> {
        let Some(session) = claims.session() else {
            return Err(AuthError::Unauthenticated(Rejection::MissingClaim));
        };
        let now = self.clock.now();
        let mut tx = self
            .db
            .identity_tx()
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        auth_state::revoke_session(&mut tx, session, "logout", now)
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        tx.commit().await.map_err(|e| AuthError::from_db(&e))?;
        self.loader.invalidate_session(session);
        self.event(
            AuthEventKind::Logout,
            Some(claims.user()),
            claims.tenant(),
            Some(session),
        );
        Ok(())
    }
}
