//! One request-authorisation entry point for the api middleware (api gap 4):
//! policy check → token verify with ONLY the policy's audiences → live/cached principal load (with
//! the policy's freshness) → `Policy::evaluate_on`. A token of the wrong audience or principal kind
//! is refused at the verify step, before any DB access.

use domain::rbac::Target;

use crate::claims::VerifiedClaims;
use crate::error::AuthError;
use crate::loader::PrincipalStateLoader;
use crate::policy::{Authorized, Denied, DenyCode, EvalContext, Policy};
use crate::principal::Principal;
use crate::tokens::TokenVerifier;

/// Successful authorisation: decision + the loaded principal (+ claims for step-up / logout).
#[derive(Debug)]
pub struct Authorization {
    pub authorized: Authorized,
    pub principal: Principal,
    pub claims: Option<VerifiedClaims>,
}

const fn deny_for(e: &AuthError) -> DenyCode {
    match e {
        AuthError::Unauthenticated(_) => DenyCode::Unauthenticated,
        AuthError::Unavailable => DenyCode::Unavailable,
        AuthError::Forbidden(_) => DenyCode::Forbidden,
        AuthError::Internal(_) => DenyCode::Internal,
    }
}

/// Authorise one request. `bearer` = raw access token (without `Bearer `), `None` if absent.
///
/// # Errors
/// `Denied` (fail closed): 401 for missing/invalid/wrong-audience tokens and dead state, 403/404
/// from the policy, 503 when live state cannot be read.
pub async fn authorize(
    policy: &Policy,
    verifier: &dyn TokenVerifier,
    loader: &dyn PrincipalStateLoader,
    bearer: Option<&str>,
    target: Option<&Target>,
    ctx: &EvalContext<'_>,
) -> Result<Authorization, Denied> {
    if let Err(e) = policy.validate() {
        return Err(Denied::new(DenyCode::Misconfigured(e)));
    }
    if policy.is_public() {
        let authorized = policy.evaluate_on(&Principal::Anonymous, target, ctx)?;
        return Ok(Authorization {
            authorized,
            principal: Principal::Anonymous,
            claims: None,
        });
    }
    let Some(token) = bearer else {
        return Err(Denied::new(DenyCode::Unauthenticated));
    };
    // Audience / kind gate BEFORE any DB access.
    let claims = verifier
        .verify(token, &policy.audiences())
        .map_err(|e| Denied::new(deny_for(&e)))?;
    let principal = loader
        .load(&claims, policy.freshness())
        .await
        .map_err(|e| Denied::new(deny_for(&e)))?;
    let authorized = match target {
        Some(t) => policy.evaluate_on(&principal, Some(t), ctx)?,
        None => policy.evaluate(&principal, ctx)?,
    };
    Ok(Authorization {
        authorized,
        principal,
        claims: Some(claims),
    })
}
