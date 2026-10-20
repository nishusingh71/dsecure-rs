//! `POST /api/v1/auth/{login,refresh,logout,step-up}` over `auth::AuthService`.
//!
//! - Every credential failure is the SAME problem: 401 `auth.invalid_credentials` (wrong email,
//!   wrong password, locked, suspended, disabled, unverified, no membership, tenant suspended,
//!   reused/expired refresh token, unsupported audience). Lockout is indistinguishable from a wrong
//!   password at the HTTP level.
//! - Pre-auth rate limits run BEFORE any DB or hash work (`ratelimit`), keyed by the trusted client
//!   IP and the email blind index.
//! - Staff (`/platform/auth/login`) need password + TOTP or a recovery code; without a second factor
//!   a correct password gets 401 `auth.mfa_required`. Staff logout / step-up use the same handlers
//!   behind `app::staff_session_policy` (step-up requires TOTP for staff, enforced by auth).
//! - Request bodies are never logged; the structs have no `Debug`.

use std::collections::BTreeSet;
use std::sync::Arc;

use auth::{Audience, LoginError, LoginRequest, MfaInput, TokenPair};
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use common::{AppErrorKind, TenantId};
use crypto::{BlindKind, BlindScope};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;

use crate::authz::AuthnClaims;
use crate::errors::{ApiError, PROBLEM_JSON, problem_body};
use crate::json::JsonBody;
use crate::middleware::client_ip::ClientIp;
use crate::middleware::request_id;
use crate::state::{AppState, AuthHttp};

/// Hard input caps (bigger = generic failure, no hashing).
const MAX_EMAIL_LEN: usize = 320;
const MAX_PASSWORD_LEN: usize = 1024;
const MAX_LABEL_LEN: usize = 128;

/// Step-up actions that some registered route requires (request extension from `app::assemble`).
/// A step-up for any other action is refused (400): no junk rows, no guessing game.
#[derive(Clone, Debug, Default)]
pub struct StepUpActions(pub Arc<BTreeSet<&'static str>>);

fn generic_failure() -> ApiError {
    ApiError::from(LoginError::Failed)
}

fn deps(s: &AppState) -> Result<&AuthHttp, ApiError> {
    s.auth()
        .ok_or_else(|| ApiError::unavailable("service.unavailable"))
}

fn ip(c: Option<Extension<ClientIp>>) -> Option<std::net::IpAddr> {
    c.and_then(|Extension(ClientIp(ip))| ip)
}

/// Member audiences only (staff = later, after MFA).
fn audience(raw: Option<&str>) -> Option<Audience> {
    match raw.unwrap_or("web") {
        "web" => Some(Audience::Web),
        "app" => Some(Audience::App),
        _ => None,
    }
}

#[derive(Serialize)]
pub struct TokensOut {
    pub token_type: &'static str,
    pub access_token: String,
    pub access_expires_at: String,
    pub refresh_token: String,
    pub refresh_expires_at: String,
    pub session_id: uuid::Uuid,
    pub tenant_id: Option<uuid::Uuid>,
}

fn tokens(p: &TokenPair) -> Result<Response, ApiError> {
    let fmt = |t: time::OffsetDateTime| {
        t.format(&Rfc3339)
            .map_err(|e| ApiError(common::AppError::internal(e)))
    };
    let body = TokensOut {
        token_type: "Bearer",
        access_token: p.access_token.clone(),
        access_expires_at: fmt(p.access_expires_at)?,
        refresh_token: p.refresh_token.expose().to_owned(),
        refresh_expires_at: fmt(p.refresh_expires_at)?,
        session_id: p.session.0,
        tenant_id: p.tenant.map(|t| t.0),
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// 409 for "password correct, several tenants: pick one" (only after a correct password, so the
/// tenant ids are the caller's own).
fn tenant_choice(tenants: &[TenantId]) -> Response {
    let status = StatusCode::CONFLICT;
    let base = problem_body(
        status,
        "auth.tenant_choice_required",
        "choose a tenant and repeat the login with tenant_id",
        request_id::current(),
        &[],
    );
    let mut v: serde_json::Value = serde_json::from_slice(&base).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.insert(
            "tenant_ids".into(),
            serde_json::json!(tenants.iter().map(|t| t.0).collect::<Vec<_>>()),
        );
    }
    let mut r = (status, serde_json::to_vec(&v).unwrap_or(base)).into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON));
    r
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginIn {
    pub email: String,
    pub password: String,
    /// `web` (default) or `app`.
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub product_code: Option<String>,
    #[serde(default)]
    pub device_label: Option<String>,
    /// Second factor (members who enrolled TOTP): 6-digit code ...
    #[serde(default)]
    pub totp: Option<String>,
    /// ... or a one-time recovery code.
    #[serde(default)]
    pub recovery_code: Option<String>,
}

/// `totp` wins if both are sent; over-long values are refused like a wrong code.
fn mfa(totp: Option<String>, recovery: Option<String>) -> Result<Option<MfaInput>, ApiError> {
    let too_long = |v: &Option<String>| v.as_ref().is_some_and(|c| c.len() > MAX_LABEL_LEN);
    if too_long(&totp) || too_long(&recovery) {
        return Err(generic_failure());
    }
    Ok(totp
        .map(MfaInput::Totp)
        .or(recovery.map(MfaInput::Recovery)))
}

pub async fn login(
    State(s): State<AppState>,
    client: Option<Extension<ClientIp>>,
    JsonBody(input): JsonBody<LoginIn>,
) -> Result<Response, ApiError> {
    // Member audiences only on this route; staff use `/platform/auth/login`.
    let aud = audience(input.audience.as_deref());
    login_as(&s, ip(client), input, aud).await
}

/// Staff login body: password + TOTP or recovery code (MFA mandatory for staff).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffLoginIn {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub recovery_code: Option<String>,
}

/// `POST /api/v1/platform/auth/login`: audience `dsecure-platform`. Same limiter, same generic
/// failure; without a second factor the answer is 401 `auth.mfa_required` only after a correct
/// password (auth crate decides).
pub async fn staff_login(
    State(s): State<AppState>,
    client: Option<Extension<ClientIp>>,
    JsonBody(input): JsonBody<StaffLoginIn>,
) -> Result<Response, ApiError> {
    let input = LoginIn {
        email: input.email,
        password: input.password,
        audience: None,
        tenant_id: None,
        product_code: None,
        device_label: None,
        totp: input.totp,
        recovery_code: input.recovery_code,
    };
    login_as(&s, ip(client), input, Some(Audience::Platform)).await
}

async fn login_as(
    s: &AppState,
    ip: Option<std::net::IpAddr>,
    input: LoginIn,
    aud: Option<Audience>,
) -> Result<Response, ApiError> {
    let d = deps(s)?;
    let bidx = common::Email::parse(&input.email).ok().and_then(|e| {
        d.indexer
            .index(BlindKind::Email, BlindScope::Global, e.as_str())
            .ok()
    });
    // Before any DB or hash work.
    d.limiter.login(ip, bidx.as_ref()).await?;
    let password = SecretString::from(input.password);
    let Some(aud) = aud else {
        return Err(generic_failure());
    };
    let too_long = |v: &Option<String>| v.as_ref().is_some_and(|v| v.len() > MAX_LABEL_LEN);
    if input.email.len() > MAX_EMAIL_LEN
        || secrecy::ExposeSecret::expose_secret(&password).len() > MAX_PASSWORD_LEN
        || too_long(&input.product_code)
        || too_long(&input.device_label)
    {
        return Err(generic_failure());
    }
    let r = d
        .service
        .authenticate(LoginRequest {
            email: &input.email,
            password,
            audience: aud,
            tenant: input.tenant_id.map(TenantId),
            product_code: input.product_code,
            device_label: input.device_label,
            mfa: mfa(input.totp, input.recovery_code)?,
        })
        .await;
    match r {
        Ok(pair) => tokens(&pair),
        Err(LoginError::TenantChoiceRequired(t)) => Ok(tenant_choice(&t)),
        Err(e) => Err(e.into()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshIn {
    pub refresh_token: String,
    #[serde(default)]
    pub audience: Option<String>,
}

pub async fn refresh(
    State(s): State<AppState>,
    client: Option<Extension<ClientIp>>,
    JsonBody(input): JsonBody<RefreshIn>,
) -> Result<Response, ApiError> {
    let d = deps(&s)?;
    d.limiter.refresh(ip(client)).await?;
    let Some(aud) = audience(input.audience.as_deref()) else {
        return Err(generic_failure());
    };
    if input.refresh_token.len() > MAX_PASSWORD_LEN {
        return Err(generic_failure());
    }
    let pair = d.service.refresh(&input.refresh_token, aud).await?;
    tokens(&pair)
}

pub async fn logout(State(s): State<AppState>, claims: AuthnClaims) -> Result<Response, ApiError> {
    let d = deps(&s)?;
    d.service.logout(claims.claims()).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpIn {
    pub password: String,
    pub action: String,
    #[serde(default)]
    pub target_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub recovery_code: Option<String>,
}

#[derive(Serialize)]
pub struct StepUpOut {
    pub step_up_token: String,
    pub action: String,
    pub expires_in: i64,
}

pub async fn step_up(
    State(s): State<AppState>,
    client: Option<Extension<ClientIp>>,
    actions: Option<Extension<StepUpActions>>,
    claims: AuthnClaims,
    JsonBody(input): JsonBody<StepUpIn>,
) -> Result<Response, ApiError> {
    let d = deps(&s)?;
    d.limiter.step_up(ip(client)).await?;
    let known = actions.is_some_and(|Extension(a)| a.0.contains(input.action.as_str()));
    if !known {
        return Err(ApiError::new(
            AppErrorKind::BadRequest,
            "auth.step_up_action_unknown",
            "no route requires a step-up for this action",
        ));
    }
    let password = SecretString::from(input.password);
    if secrecy::ExposeSecret::expose_secret(&password).len() > MAX_PASSWORD_LEN {
        return Err(generic_failure());
    }
    let secret = d
        .service
        .step_up(
            claims.claims(),
            password,
            mfa(input.totp, input.recovery_code)?,
            &input.action,
            input.target_id,
        )
        .await?;
    let out = StepUpOut {
        step_up_token: secret.expose().to_owned(),
        action: input.action,
        expires_in: auth::settings::STEP_UP_TTL.whole_seconds(),
    };
    Ok((StatusCode::OK, Json(out)).into_response())
}

// ---------------------------------------------------------------- MFA (TOTP) management

/// Step-up action guarding TOTP enrolment (a stolen access token alone cannot add a factor).
pub const MFA_ENROL_ACTION: &str = "mfa.totp.enrol";

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TotpBeginIn {
    /// Label shown in the authenticator app (default "DSecure"); never logged.
    #[serde(default)]
    pub account_label: Option<String>,
}

#[derive(Serialize)]
pub struct TotpBeginOut {
    pub factor_id: uuid::Uuid,
    pub otpauth_uri: String,
    pub secret_base32: String,
}

/// `POST /api/v1/me/mfa/totp` (member + step-up `mfa.totp.enrol`): new pending factor. The secret
/// is returned once (QR / manual entry); responses are `no-store` and never logged.
pub async fn totp_begin(
    State(s): State<AppState>,
    claims: AuthnClaims,
    JsonBody(input): JsonBody<TotpBeginIn>,
) -> Result<Response, ApiError> {
    let d = deps(&s)?;
    let label = input.account_label.unwrap_or_else(|| "DSecure".to_owned());
    if label.is_empty() || label.len() > MAX_LABEL_LEN {
        return Err(ApiError::new(
            AppErrorKind::BadRequest,
            "mfa.label_invalid",
            "account_label must be 1..=128 characters",
        ));
    }
    let e = d
        .service
        .begin_totp_enrolment(claims.claims().user(), &label)
        .await?;
    let out = TotpBeginOut {
        factor_id: e.factor_id,
        otpauth_uri: e.otpauth_uri().to_owned(),
        secret_base32: e.secret_base32().to_owned(),
    };
    Ok((StatusCode::CREATED, Json(out)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpConfirmIn {
    pub factor_id: uuid::Uuid,
    pub code: String,
}

#[derive(Serialize)]
pub struct TotpConfirmOut {
    /// Shown exactly once; only MACs are stored.
    pub recovery_codes: Vec<String>,
}

/// `POST /api/v1/me/mfa/totp/confirm`: activate the pending factor with a valid code; returns the
/// recovery codes exactly once. A wrong code is 400 `mfa.code_invalid` (not 401: the session is
/// fine).
pub async fn totp_confirm(
    State(s): State<AppState>,
    claims: AuthnClaims,
    JsonBody(input): JsonBody<TotpConfirmIn>,
) -> Result<Response, ApiError> {
    let d = deps(&s)?;
    if input.code.len() > MAX_LABEL_LEN {
        return Err(code_invalid());
    }
    match d
        .service
        .confirm_totp_enrolment(claims.claims().user(), input.factor_id, &input.code)
        .await
    {
        Ok(codes) => {
            let out = TotpConfirmOut {
                recovery_codes: codes.codes().into_iter().map(str::to_owned).collect(),
            };
            Ok((StatusCode::OK, Json(out)).into_response())
        }
        Err(auth::AuthError::Unauthenticated(_)) => Err(code_invalid()),
        Err(e) => Err(e.into()),
    }
}

fn code_invalid() -> ApiError {
    ApiError::new(
        AppErrorKind::BadRequest,
        "mfa.code_invalid",
        "the code is not valid for this factor",
    )
}
