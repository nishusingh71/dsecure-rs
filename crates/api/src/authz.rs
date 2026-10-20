//! Layer 12 (+14): per-route policy gate. Every route registered through `router::PolicyRouter` gets
//! this gate with its own `auth::Policy`:
//!
//! 1. public policy -> `Principal::Anonymous` (a sent token is ignored);
//!    otherwise bearer -> [`crate::authn::Authenticator`] (generic 401 on any failure);
//! 2. `Policy::evaluate` -> `Authorized` (fail closed: any deny = problem+json 401/403/404);
//! 3. the result goes into request extensions as a crate-private [`Granted`]; the [`Authz`] extractor
//!    can ONLY be built from it, so a handler that asks for `Authz` cannot run without the gate;
//! 4. step-up policies: the `X-Step-Up-Token` header is consumed (single use, bound to session +
//!    action + target) BEFORE `evaluate`, and the proof goes into `EvalContext`;
//! 5. `Policy::idempotent()` routes continue in `middleware::idempotency`.

use std::sync::Arc;

use auth::{AuthService, Authorized, EvalContext, Policy, Principal, VerifiedClaims};
use axum::extract::{FromRequestParts, Request};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use common::{Clock, MembershipId, SessionId, TenantId, UserId};
use domain::rbac::{TenantRole, TenantScope};

use crate::authn::{Authenticator, bearer};
use crate::errors::ApiError;
use crate::middleware::idempotency;

/// Runtime dependencies of the gate. Inserted once as a request extension by `app::assemble`; a
/// route whose gate finds no `GateDeps` fails closed (500).
#[derive(Clone)]
pub struct GateDeps {
    pub authn: Arc<dyn Authenticator>,
    pub clock: Arc<dyn Clock>,
    /// Needed by `idempotent()` routes only (`None` -> those routes answer 503).
    pub db: Option<db::Db>,
    /// Step-up consumption (`None` -> step-up routes always 403 `auth.step_up_required`).
    pub auth: Option<Arc<AuthService>>,
}

/// Header carrying the single-use step-up token.
pub const STEP_UP_HEADER: &str = "x-step-up-token";
const MAX_STEP_UP_LEN: usize = 256;

/// Who is calling (ids only, from the LIVE principal; never from the body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    Member {
        user: UserId,
        tenant: TenantId,
        membership: MembershipId,
        session: SessionId,
        role: TenantRole,
        audience: &'static str,
    },
    Device {
        device: uuid::Uuid,
        tenant: TenantId,
        owner: MembershipId,
    },
    Staff {
        user: UserId,
        session: SessionId,
    },
    Anonymous,
}

impl Caller {
    fn of(p: &Principal) -> Self {
        match p {
            Principal::Member(m) => Self::Member {
                user: m.user(),
                tenant: m.tenant(),
                membership: m.membership(),
                session: m.session(),
                role: m.role(),
                audience: m.audience().as_str(),
            },
            Principal::Device(d) => Self::Device {
                device: d.device().0,
                tenant: d.tenant(),
                owner: d.owner(),
            },
            Principal::Staff(s) => Self::Staff {
                user: s.user(),
                session: s.session(),
            },
            Principal::Cleaner(_) | Principal::Anonymous => Self::Anonymous,
        }
    }
}

/// Gate result. Crate-private type: nothing outside this crate can name or insert it.
#[derive(Clone, Debug)]
pub(crate) struct Granted {
    pub(crate) authorized: Authorized,
    pub(crate) caller: Caller,
    /// Verified access token claims (`None` on public routes).
    pub(crate) claims: Option<Arc<VerifiedClaims>>,
}

/// Public reason of a policy (`None` = not public). Uses `evaluate` on an anonymous principal, so
/// it is exactly what the gate would do.
#[must_use]
pub fn public_reason(p: &Policy) -> Option<&'static str> {
    if !p.is_public() {
        return None;
    }
    match p.evaluate(
        &Principal::Anonymous,
        &EvalContext::at(time::OffsetDateTime::now_utc()),
    ) {
        Ok(Authorized::Public { reason }) => Some(reason),
        _ => None,
    }
}

/// The per-route gate (installed by `PolicyRouter` with `route_layer`).
pub(crate) async fn gate(policy: Arc<Policy>, mut req: Request, next: Next) -> Response {
    let Some(deps) = req.extensions().get::<GateDeps>().cloned() else {
        return ApiError::misconfigured("gate deps missing").into_response();
    };
    let token = if policy.is_public() {
        None
    } else {
        let t = bearer(req.headers());
        if t.is_none() {
            metrics::counter!("auth_rejections_total", "reason" => "missing_bearer").increment(1);
            return ApiError::unauthenticated().into_response();
        }
        t
    };
    // Step-up: verify (policy audiences) -> consume the single-use token -> proof into the ctx.
    let proof = match (policy.required_step_up(), token.as_deref()) {
        (Some(action), Some(t)) => {
            let claims = match deps.authn.verify(&policy, t) {
                Ok(c) => c,
                Err(e) => return e.into_response(),
            };
            match consume_step_up(&deps, step_up_token(&req), &claims, action).await {
                Ok(p) => p,
                Err(e) => return e.into_response(),
            }
        }
        _ => None,
    };
    let base = EvalContext::at(deps.clock.now());
    let ctx = match &proof {
        Some(p) => base.with_step_up(p),
        None => base,
    };
    let a = match deps.authn.authorize(&policy, token.as_deref(), &ctx).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let (authorized, principal, claims) = (a.authorized, a.principal, a.claims.map(Arc::new));
    let granted = Granted {
        authorized,
        caller: Caller::of(&principal),
        claims,
    };
    req.extensions_mut().insert(granted.clone());
    if policy.is_idempotent() {
        return idempotency::run(&deps, &granted, req, next).await;
    }
    next.run(req).await
}

/// Consume the request's step-up token for `action` (collection-level target: `None`). The token is
/// burned even if a later check denies (fail closed). No/invalid token -> `None` -> 403 from evaluate.
fn step_up_token(req: &Request) -> Option<String> {
    req.headers()
        .get(STEP_UP_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.len() <= MAX_STEP_UP_LEN)
        .map(str::to_owned)
}

async fn consume_step_up(
    deps: &GateDeps,
    token: Option<String>,
    claims: &VerifiedClaims,
    action: &'static str,
) -> Result<Option<auth::StepUpProof>, ApiError> {
    let (Some(token), Some(svc)) = (token, deps.auth.as_ref()) else {
        return Ok(None);
    };
    Ok(svc.consume_step_up(claims, &token, action, None).await?)
}

/// Verified access-token claims of the caller (logout, step-up). Only constructible from the gate.
#[derive(Clone, Debug)]
pub struct AuthnClaims(Arc<VerifiedClaims>);

impl AuthnClaims {
    #[must_use]
    pub fn claims(&self) -> &VerifiedClaims {
        &self.0
    }
}

impl<S: Send + Sync> FromRequestParts<S> for AuthnClaims {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        parts
            .extensions
            .get::<Granted>()
            .and_then(|g| g.claims.clone())
            .map(Self)
            .ok_or_else(|| ApiError::misconfigured("AuthnClaims on a public route"))
    }
}

/// Handler extractor for tenant routes: the `TenantScope` the gate computed + the caller ids.
/// Only constructible from the gate's [`Granted`] (no public constructor).
#[derive(Clone, Debug)]
pub struct Authz {
    scope: TenantScope,
    caller: Caller,
}

impl Authz {
    /// Scope for `Db::tenant_tx` (tenant from the live principal, never the request).
    #[must_use]
    pub const fn scope(&self) -> &TenantScope {
        &self.scope
    }

    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.scope.tenant()
    }

    #[must_use]
    pub const fn caller(&self) -> &Caller {
        &self.caller
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Authz {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        let g = parts
            .extensions
            .get::<Granted>()
            .ok_or_else(|| ApiError::misconfigured("Authz without policy gate"))?;
        match &g.authorized {
            Authorized::Tenant { scope, .. } => Ok(Self {
                scope: scope.clone(),
                caller: g.caller.clone(),
            }),
            _ => Err(ApiError::misconfigured("Authz on a non-tenant policy")),
        }
    }
}
