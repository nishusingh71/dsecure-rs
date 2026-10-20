//! Route table + middleware stack assembly (ARCHITECTURE.md §5 order).

use std::sync::Arc;
use std::time::Duration;

use auth::Policy;
use axum::Router;
use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Response, StatusCode, header};
use axum::response::IntoResponse;
use config::Environment;
use domain::rbac::{Perm, PlatformPerm};
use tokio::sync::Semaphore;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;

use crate::authz::GateDeps;
use crate::errors::{ApiError, PROBLEM_JSON, problem_body};
use crate::middleware::client_ip::TrustedProxies;
use crate::middleware::{client_ip, limits, request_id, security, trace};
use crate::router::{PolicyRouter, RouteEntry, RoutePolicyReport, RouterError, report};
use crate::routes::auth::StepUpActions;
use crate::routes::openapi::{OpenApiDoc, document};
use crate::routes::{auth as auth_routes, health, jwks, me, openapi};
use crate::state::AppState;

/// What decides the route table (no runtime values needed: `xtask route-policies` uses it too).
#[derive(Clone, Copy, Debug)]
pub struct RouteOptions {
    pub environment: Environment,
    /// `OPENAPI_PUBLIC`; ignored (forced off) in production.
    pub openapi_public: bool,
}

impl RouteOptions {
    #[must_use]
    pub const fn from_config(cfg: &config::AppConfig) -> Self {
        Self {
            environment: cfg.environment,
            openapi_public: cfg.http.openapi_public,
        }
    }
}

/// Staff session routes (logout, step-up): any staff principal with a live MFA session.
///
/// `auth::Policy` has no "staff, no platform permission" constructor yet (`validate` refuses
/// `Policy::staff()` alone). `platform.tenants.read` is granted to ALL four staff roles
/// (Superadmin/Support: Y, Billing/Auditor: restricted view), so it acts as "any staff" here
/// (pinned by a unit test). MFA: the staff state loader refuses sessions without a completed second
/// factor (fail closed). Follow-up for auth: `Policy::staff_session()`.
#[must_use]
pub fn staff_session_policy() -> Policy {
    Policy::staff().platform(PlatformPerm::TenantsRead)
}

/// THE route table. Every route = method + path + policy.
#[must_use]
pub fn build_routes(opts: &RouteOptions) -> PolicyRouter<AppState> {
    let openapi_policy = if opts.openapi_public && !opts.environment.is_production() {
        Policy::public("api spec (non-production only)")
    } else {
        Policy::staff().platform(PlatformPerm::HealthDetailed)
    };
    let r = PolicyRouter::new()
        .get(
            "/health/live",
            Policy::public("liveness probe"),
            health::live,
        )
        .get(
            "/health/ready",
            Policy::public("readiness probe (status words only)"),
            health::ready,
        )
        .get(
            "/api/v1/me",
            Policy::member().permission(Perm::ProfileReadSelf),
            me::me,
        )
        .get(
            "/api/v1/me/sessions",
            Policy::member().permission(Perm::SessionsReadSelf),
            me::sessions,
        )
        .get(
            "/.well-known/jwks.json",
            Policy::public("jwks (public JWT verification keys)"),
            jwks::serve,
        )
        .post(
            "/api/v1/auth/login",
            Policy::public("login (pre-auth rate limited, generic failures)"),
            auth_routes::login,
        )
        .post(
            "/api/v1/auth/refresh",
            Policy::public("refresh token rotation (rate limited, generic failures)"),
            auth_routes::refresh,
        )
        .post("/api/v1/auth/logout", Policy::member(), auth_routes::logout)
        .post(
            "/api/v1/auth/step-up",
            Policy::member(),
            auth_routes::step_up,
        )
        .post(
            "/api/v1/platform/auth/login",
            Policy::public("staff login (password + TOTP; rate limited, generic failures)"),
            auth_routes::staff_login,
        )
        .post(
            "/api/v1/platform/auth/logout",
            staff_session_policy(),
            auth_routes::logout,
        )
        .post(
            "/api/v1/platform/auth/step-up",
            staff_session_policy(),
            auth_routes::step_up,
        )
        .post(
            "/api/v1/me/mfa/totp",
            Policy::member().step_up(auth_routes::MFA_ENROL_ACTION),
            auth_routes::totp_begin,
        )
        .post(
            "/api/v1/me/mfa/totp/confirm",
            Policy::member(),
            auth_routes::totp_confirm,
        )
        .get("/api/v1/openapi.json", openapi_policy, openapi::serve);
    with_dev_fixtures(r, opts)
}

#[cfg(all(feature = "dev-fixtures", debug_assertions))]
fn with_dev_fixtures(r: PolicyRouter<AppState>, opts: &RouteOptions) -> PolicyRouter<AppState> {
    if opts.environment.is_local() {
        r.post(
            "/api/v1/dev/fixtures",
            Policy::public("dev fixtures (debug build + feature dev-fixtures + dev/test env)"),
            crate::routes::dev_fixtures::seed,
        )
    } else {
        r
    }
}

#[cfg(not(all(feature = "dev-fixtures", debug_assertions)))]
const fn with_dev_fixtures(
    r: PolicyRouter<AppState>,
    _opts: &RouteOptions,
) -> PolicyRouter<AppState> {
    r
}

/// Route -> policy report for `xtask route-policies` (no DB, no keys).
///
/// # Errors
/// Router build problems (invalid policy, duplicate).
pub fn route_policies(opts: &RouteOptions) -> Result<Vec<RoutePolicyReport>, Vec<RouterError>> {
    build_routes(opts).into_router().map(|(_, t)| report(&t))
}

/// HTTP limits (config-derived).
#[derive(Clone, Debug)]
pub struct HttpSettings {
    pub max_inflight: usize,
    pub max_json_body: usize,
    pub timeout: Duration,
    pub cors_origins: Vec<String>,
    pub proxies: TrustedProxies,
}

impl HttpSettings {
    /// # Errors
    /// Invalid `TRUSTED_PROXY_CIDRS` entry (index only).
    pub fn from_config(cfg: &config::AppConfig) -> Result<Self, client_ip::BadCidr> {
        Ok(Self {
            max_inflight: usize::try_from(cfg.limits.max_inflight_requests)
                .unwrap_or(128)
                .max(1),
            max_json_body: cfg.limits.max_json_body_bytes.max(1),
            timeout: limits::DEFAULT_TIMEOUT,
            cors_origins: cfg.http.cors_allowed_origins.clone(),
            proxies: TrustedProxies::new(
                cfg.http.trusted_proxy_hops,
                &cfg.http.trusted_proxy_cidrs,
            )?,
        })
    }
}

/// 500 problem for a caught panic (debug/test builds; release uses `panic = "abort"`).
fn panic_response(_: Box<dyn std::any::Any + Send + 'static>) -> Response<Body> {
    metrics::counter!("http_panics_total").increment(1);
    tracing::error!(alert = "http.panic", "handler panicked");
    let body = problem_body(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal error",
        None,
        &[],
    );
    let mut res = Response::new(Body::from(body));
    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    res.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON));
    res
}

async fn not_found() -> axum::response::Response {
    ApiError::not_found().into_response()
}

async fn method_not_allowed() -> axum::response::Response {
    let mut r = ApiError::new(
        common::AppErrorKind::BadRequest,
        "request.method_not_allowed",
        "method not allowed for this route",
    )
    .into_response();
    *r.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
    r
}

/// Assemble the full app: routes (each with its policy gate) + global stack.
///
/// # Errors
/// Router build problems.
pub fn assemble<S>(
    routes: PolicyRouter<S>,
    state: S,
    gate: GateDeps,
    http: &HttpSettings,
) -> Result<(Router, Vec<RouteEntry>), Vec<RouterError>>
where
    S: Clone + Send + Sync + 'static,
{
    let (router, table) = routes.into_router()?;
    let doc = OpenApiDoc(Arc::new(
        serde_json::to_vec(&document(&table)).unwrap_or_default(),
    ));
    let step_up_actions = StepUpActions(Arc::new(
        table
            .iter()
            .filter_map(|r| r.policy.required_step_up())
            .collect(),
    ));
    let stack = ServiceBuilder::new()
        .layer(CatchPanicLayer::custom(panic_response)) // 1
        // 9 (moved outward): response-only, so every response gets the headers, including the
        // 413 / 503 load-shed / timeout answers produced by layers 5-7.
        .layer(axum::middleware::from_fn(security::headers))
        .layer(axum::middleware::from_fn(request_id::layer)) // 2
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(http.proxies.clone()),
            client_ip::layer,
        )) // 3
        .layer(axum::middleware::from_fn(trace::layer)) // 4
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(Semaphore::new(http.max_inflight)),
            limits::inflight,
        )) // 5
        .layer(axum::middleware::from_fn_with_state(
            http.timeout,
            limits::timeout,
        )) // 6
        .layer(axum::middleware::from_fn_with_state(
            http.max_json_body,
            limits::body_limit,
        )) // 7
        .layer(DefaultBodyLimit::max(http.max_json_body))
        .layer(security::cors(&http.cors_origins)) // 8
        .layer(axum::Extension(gate)) // 11-14 deps (per-route gates)
        .layer(axum::Extension(doc))
        .layer(axum::Extension(step_up_actions));
    let app = router
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(stack)
        .with_state(state);
    Ok((app, table))
}

#[cfg(test)]
mod tests {
    use domain::rbac::{PlatformPerm, StaffRole, platform_grants};

    #[test]
    fn staff_session_policy_admits_every_staff_role() {
        for role in [
            StaffRole::Superadmin,
            StaffRole::Support,
            StaffRole::Billing,
            StaffRole::Auditor,
        ] {
            assert!(
                platform_grants(role, PlatformPerm::TenantsRead).is_some(),
                "{role:?}"
            );
        }
        assert!(super::staff_session_policy().validate().is_ok());
    }
}
