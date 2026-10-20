//! Layers 11-12 entry: `auth::authorize` (policy check -> token verify with ONLY the policy's
//! audiences, before any DB access -> live/cached principal load -> `Policy::evaluate`). This file
//! (and `authz.rs`) are the only callers of the auth token/loader APIs, so auth signature changes
//! stay a small fix here.
//!
//! Every token/state failure is the same generic 401 (`errors::ApiError::unauthenticated`); the
//! detailed reason never reaches the client.

use std::sync::Arc;

use auth::{
    Authorization, Authorized, EvalContext, Policy, Principal, PrincipalStateLoader, TokenVerifier,
    VerifiedClaims,
};
use axum::http::{HeaderMap, header};

use crate::errors::ApiError;

/// Hard cap on the Authorization header (ES256 JWTs are ~600 bytes).
const MAX_TOKEN_LEN: usize = 4096;

#[async_trait::async_trait]
pub trait Authenticator: Send + Sync {
    /// Full decision for one request (public policies need no token).
    async fn authorize(
        &self,
        policy: &Policy,
        bearer: Option<&str>,
        ctx: &EvalContext<'_>,
    ) -> Result<Authorization, ApiError>;

    /// Token verify only (policy audiences): needed BEFORE `authorize` to consume a step-up token.
    fn verify(&self, policy: &Policy, token: &str) -> Result<VerifiedClaims, ApiError>;
}

/// Production authenticator: ES256 verifier + DB live-state loader (bounded epoch cache).
pub struct LiveAuthenticator {
    verifier: Arc<dyn TokenVerifier>,
    loader: Arc<dyn PrincipalStateLoader>,
}

impl LiveAuthenticator {
    #[must_use]
    pub fn new(verifier: Arc<dyn TokenVerifier>, loader: Arc<dyn PrincipalStateLoader>) -> Self {
        Self { verifier, loader }
    }
}

#[async_trait::async_trait]
impl Authenticator for LiveAuthenticator {
    async fn authorize(
        &self,
        policy: &Policy,
        bearer: Option<&str>,
        ctx: &EvalContext<'_>,
    ) -> Result<Authorization, ApiError> {
        auth::authorize(
            policy,
            self.verifier.as_ref(),
            self.loader.as_ref(),
            bearer,
            None,
            ctx,
        )
        .await
        .map_err(ApiError::from)
    }

    fn verify(&self, policy: &Policy, token: &str) -> Result<VerifiedClaims, ApiError> {
        Ok(self.verifier.verify(token, &policy.audiences())?)
    }
}

/// Allows public policies, refuses every token (route-table reports, DB-free tests).
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllAuthenticator;

#[async_trait::async_trait]
impl Authenticator for DenyAllAuthenticator {
    async fn authorize(
        &self,
        policy: &Policy,
        _bearer: Option<&str>,
        _ctx: &EvalContext<'_>,
    ) -> Result<Authorization, ApiError> {
        match crate::authz::public_reason(policy) {
            Some(reason) => Ok(Authorization {
                authorized: Authorized::Public { reason },
                principal: Principal::Anonymous,
                claims: None,
            }),
            None => Err(ApiError::unauthenticated()),
        }
    }

    fn verify(&self, _policy: &Policy, _token: &str) -> Result<VerifiedClaims, ApiError> {
        Err(ApiError::unauthenticated())
    }
}

/// `Authorization: Bearer <token>`. `None` = header absent or not a usable bearer token.
#[must_use]
pub fn bearer(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let v = values.next()?;
    if values.next().is_some() {
        return None; // two Authorization headers: ambiguous, refuse
    }
    let s = v.to_str().ok()?;
    let (scheme, token) = s.split_once(' ')?;
    let token = token.trim();
    let ok = scheme.eq_ignore_ascii_case("bearer")
        && !token.is_empty()
        && token.len() <= MAX_TOKEN_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'='));
    ok.then(|| token.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn h(v: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert(header::AUTHORIZATION, HeaderValue::from_str(v).expect("hv"));
        m
    }

    #[test]
    fn bearer_parsing() {
        assert_eq!(
            bearer(&h("Bearer abc.def-ghi_")),
            Some("abc.def-ghi_".into())
        );
        assert_eq!(bearer(&h("bearer abc")), Some("abc".into()));
        assert_eq!(bearer(&h("Basic abc")), None);
        assert_eq!(bearer(&h("Bearer ")), None);
        assert_eq!(bearer(&h("Bearer a b")), None);
        assert_eq!(bearer(&HeaderMap::new()), None);
        let mut two = h("Bearer a");
        two.append(header::AUTHORIZATION, HeaderValue::from_static("Bearer b"));
        assert_eq!(bearer(&two), None);
        assert_eq!(bearer(&h(&format!("Bearer {}", "a".repeat(5000)))), None);
    }
}
