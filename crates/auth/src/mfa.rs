//! MFA service (TOTP + recovery codes) on `AuthService`. SECURITY.md §5: TOTP day one, staff
//! mandatory, members opt-in (D-23).
//!
//! - Secret: 20 random bytes, stored encrypted with `FieldEncryptor` (purpose `Secrets`, platform
//!   scope, AAD = `mfa_factors.secret_enc` + factor id). Never logged; shown to the user once as an
//!   otpauth URI.
//! - Enrolment: [`AuthService::begin_totp_enrolment`] stores a PENDING factor; it becomes active only
//!   after [`AuthService::confirm_totp_enrolment`] with a valid code, which also disables older
//!   factors and issues 10 fresh recovery codes (older unused ones burned).
//! - Replay: the start of the last accepted step is stored; a code is accepted only for a strictly
//!   later step, atomically (`db::repo::auth_mfa::use_step`).
//! - Recovery codes: `HMAC(key, "rc1:" || normalised code)`, single use (atomic UPDATE). Allowed for
//!   login, never for step-up.

use common::UserId;
use crypto::{FieldContext, KeyPurpose};
use db::repo::auth_mfa;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::error::{AuthError, Rejection};
use crate::login::AuthService;
use crate::sink::AuthEventKind;
use crate::totp;

/// Issuer label in authenticator apps.
pub const TOTP_ISSUER: &str = "DSecure";
const RECOVERY_DOMAIN: &[u8] = b"rc1:";

/// Second factor sent with login / step-up. `Debug` never shows the code.
#[derive(Clone)]
pub enum MfaInput {
    Totp(String),
    Recovery(String),
}

impl std::fmt::Debug for MfaInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Totp(_) => "MfaInput::Totp([redacted])",
            Self::Recovery(_) => "MfaInput::Recovery([redacted])",
        })
    }
}

/// Result of `begin_totp_enrolment`: show `otpauth_uri` (QR) / `secret_base32` once.
pub struct TotpEnrolment {
    pub factor_id: uuid::Uuid,
    otpauth_uri: Zeroizing<String>,
    secret_base32: Zeroizing<String>,
}

impl TotpEnrolment {
    #[must_use]
    pub fn otpauth_uri(&self) -> &str {
        &self.otpauth_uri
    }
    #[must_use]
    pub fn secret_base32(&self) -> &str {
        &self.secret_base32
    }
}

impl std::fmt::Debug for TotpEnrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpEnrolment")
            .field("factor_id", &self.factor_id)
            .finish_non_exhaustive()
    }
}

/// Fresh recovery codes, shown to the user once.
pub struct RecoveryCodes(Vec<Zeroizing<String>>);

impl RecoveryCodes {
    #[must_use]
    pub fn codes(&self) -> Vec<&str> {
        self.0.iter().map(|c| c.as_str()).collect()
    }
}

impl std::fmt::Debug for RecoveryCodes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecoveryCodes([{} redacted])", self.0.len())
    }
}

/// Outcome of a second-factor check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MfaCheck {
    NotEnrolled,
    Missing,
    Invalid,
    Ok,
}

fn factor_ctx(id: uuid::Uuid) -> FieldContext<'static> {
    FieldContext::new("mfa_factors", "secret_enc", None, id, KeyPurpose::Secrets)
}

fn invalid() -> AuthError {
    AuthError::Unauthenticated(Rejection::MfaInvalid)
}

impl AuthService {
    /// Start TOTP enrolment for `user` (api: from the caller's VerifiedClaims; staff bootstrap: ops
    /// tool). `account_label` is shown in the authenticator app (e.g. the email, never logged).
    ///
    /// # Errors
    /// `Internal` (RNG / encryption), `Unavailable`.
    pub async fn begin_totp_enrolment(
        &self,
        user: UserId,
        account_label: &str,
    ) -> Result<TotpEnrolment, AuthError> {
        let secret = totp::generate_secret()?;
        let id = uuid::Uuid::now_v7();
        let enc = self
            .fields
            .encrypt(&secret, &factor_ctx(id))
            .await
            .map_err(|_| AuthError::Internal("mfa secret encryption"))?;
        let now = self.clock.now();
        let mut tx = self
            .db
            .identity_tx()
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        auth_mfa::insert_factor(&mut tx, user, id, &enc, Some("authenticator"), now)
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        tx.commit().await.map_err(|e| AuthError::from_db(&e))?;
        Ok(TotpEnrolment {
            factor_id: id,
            otpauth_uri: Zeroizing::new(totp::otpauth_uri(TOTP_ISSUER, account_label, &secret)),
            secret_base32: Zeroizing::new(totp::base32(&secret)),
        })
    }

    /// Activate a pending factor with a valid code; returns 10 new recovery codes (once).
    ///
    /// # Errors
    /// `Unauthenticated(MfaInvalid)` (wrong code, unknown / already active / disabled factor),
    /// `Internal`, `Unavailable`.
    pub async fn confirm_totp_enrolment(
        &self,
        user: UserId,
        factor_id: uuid::Uuid,
        code: &str,
    ) -> Result<RecoveryCodes, AuthError> {
        let now = self.clock.now();
        let mut tx = self
            .db
            .identity_tx()
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        let factor = match auth_mfa::get_factor(&mut tx, user, factor_id).await {
            Ok(Some(f)) if f.last_step_at.is_none() && f.disabled_at.is_none() => f,
            Ok(_) => {
                tx.rollback().await;
                return Err(invalid());
            }
            Err(e) => {
                tx.rollback().await;
                return Err(AuthError::from_db(&e));
            }
        };
        let secret = self
            .fields
            .decrypt(&factor.secret_enc, &factor_ctx(factor.id))
            .await
            .map_err(|_| AuthError::Internal("mfa secret decryption"))?;
        let Some(step) = totp::verify_code(&secret, code, now.unix_timestamp(), None) else {
            tx.rollback().await;
            self.mfa_event(user, "enrol_code_invalid");
            return Err(invalid());
        };
        let step_at = step_time(step)?;
        let used = auth_mfa::use_step(&mut tx, user, factor.id, step_at)
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        if !used {
            tx.rollback().await;
            return Err(invalid());
        }
        auth_mfa::disable_others(&mut tx, user, factor.id, now)
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        let mut codes = Vec::with_capacity(totp::RECOVERY_CODES);
        let mut macs = Vec::with_capacity(totp::RECOVERY_CODES);
        for _ in 0..totp::RECOVERY_CODES {
            let c = totp::generate_recovery_code()?;
            let n = totp::normalise_recovery(&c).ok_or(AuthError::Internal("recovery code"))?;
            macs.push(self.refresh.mac(RECOVERY_DOMAIN, n.as_bytes()));
            codes.push(c);
        }
        auth_mfa::replace_recovery(&mut tx, user, &macs, now)
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        tx.commit().await.map_err(|e| AuthError::from_db(&e))?;
        Ok(RecoveryCodes(codes))
    }

    /// Does `user` have an active TOTP factor?
    ///
    /// # Errors
    /// `Unavailable` / `Internal`.
    pub async fn has_mfa(&self, user: UserId) -> Result<bool, AuthError> {
        let mut tx = self
            .db
            .identity_tx()
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        let f = auth_mfa::active_factor(&mut tx, user).await;
        tx.rollback().await;
        Ok(f.map_err(|e| AuthError::from_db(&e))?.is_some())
    }

    fn mfa_event(&self, user: UserId, reason: &'static str) {
        self.sink.record(crate::sink::AuthEvent {
            kind: AuthEventKind::MfaFailed(reason),
            user: Some(user),
            tenant: None,
            session: None,
            at: self.clock.now(),
        });
    }

    /// Check (and consume) a second factor for `user`. Recovery codes only if `allow_recovery`.
    pub(crate) async fn check_mfa(
        &self,
        user: UserId,
        input: Option<&MfaInput>,
        allow_recovery: bool,
    ) -> Result<MfaCheck, AuthError> {
        let now = self.clock.now();
        let mut tx = self
            .db
            .identity_tx()
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        let factor = match auth_mfa::active_factor(&mut tx, user).await {
            Ok(Some(f)) => f,
            Ok(None) => {
                tx.rollback().await;
                return Ok(MfaCheck::NotEnrolled);
            }
            Err(e) => {
                tx.rollback().await;
                return Err(AuthError::from_db(&e));
            }
        };
        let ok = match input {
            None => {
                tx.rollback().await;
                return Ok(MfaCheck::Missing);
            }
            Some(MfaInput::Totp(code)) => {
                let secret = self
                    .fields
                    .decrypt(&factor.secret_enc, &factor_ctx(factor.id))
                    .await
                    .map_err(|_| AuthError::Internal("mfa secret decryption"))?;
                let after = factor
                    .last_step_at
                    .map(|t| totp::step_of(t.unix_timestamp()));
                match totp::verify_code(&secret, code, now.unix_timestamp(), after) {
                    Some(step) => auth_mfa::use_step(&mut tx, user, factor.id, step_time(step)?)
                        .await
                        .map_err(|e| AuthError::from_db(&e))?,
                    None => false,
                }
            }
            Some(MfaInput::Recovery(code)) if allow_recovery => {
                match totp::normalise_recovery(code) {
                    Some(n) => {
                        let mac = self.refresh.mac(RECOVERY_DOMAIN, n.as_bytes());
                        auth_mfa::use_recovery(&mut tx, user, &mac, now)
                            .await
                            .map_err(|e| AuthError::from_db(&e))?
                    }
                    None => false,
                }
            }
            Some(MfaInput::Recovery(_)) => false,
        };
        if ok {
            tx.commit().await.map_err(|e| AuthError::from_db(&e))?;
            Ok(MfaCheck::Ok)
        } else {
            tx.rollback().await;
            self.mfa_event(user, "code_invalid");
            Ok(MfaCheck::Invalid)
        }
    }
}

fn step_time(step: i64) -> Result<OffsetDateTime, AuthError> {
    OffsetDateTime::from_unix_timestamp(totp::step_start(step))
        .map_err(|_| AuthError::Internal("totp step"))
}
