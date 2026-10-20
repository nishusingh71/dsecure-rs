//! `PolicyRouter`: the ONLY way to add a route (PHASE0_SPEC §3.4, T-R1).
//!
//! - Every registration takes an `auth::Policy` argument, so a route without a policy does not
//!   compile; `axum::Router::route` is a clippy `disallowed_methods` everywhere except the two
//!   `#[allow]`s in this module.
//! - Policies are validated (`Policy::validate`) and duplicates refused when the router is built:
//!   a bad table is a startup error (exit), never a silently open route.
//! - The route table (method, path, policy) is kept for `xtask route-policies` and the OpenAPI doc.
//!
//! ```compile_fail
//! // T-R1: no policy -> no route.
//! async fn h() -> &'static str { "x" }
//! let _ = api::router::PolicyRouter::<()>::new().get("/x", h);
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use auth::{Policy, PolicyError};
use axum::Router;
use axum::handler::Handler;
use axum::http::Method;
use axum::routing::{MethodRouter, get};
use serde::Serialize;

use crate::authz::{gate, public_reason};

/// One registered route.
#[derive(Clone, Debug)]
pub struct RouteEntry {
    pub method: Method,
    pub path: &'static str,
    pub policy: Policy,
}

/// Router build problems (values are route templates and static reasons only).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RouterError {
    #[error("{method} {path}: invalid policy: {err}")]
    InvalidPolicy {
        method: String,
        path: &'static str,
        err: PolicyError,
    },
    #[error("{method} {path}: registered twice")]
    Duplicate { method: String, path: &'static str },
    #[error("{path}: route path must start with '/' and contain no empty segment")]
    BadPath { path: &'static str },
}

pub struct PolicyRouter<S> {
    routes: BTreeMap<&'static str, MethodRouter<S>>,
    table: Vec<RouteEntry>,
    problems: Vec<RouterError>,
}

impl<S> Default for PolicyRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S> PolicyRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: BTreeMap::new(),
            table: Vec::new(),
            problems: Vec::new(),
        }
    }

    #[must_use]
    pub fn get<H, T>(self, path: &'static str, policy: Policy, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.add(Method::GET, path, policy, axum::routing::get(handler))
    }

    #[must_use]
    pub fn post<H, T>(self, path: &'static str, policy: Policy, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.add(Method::POST, path, policy, axum::routing::post(handler))
    }

    #[must_use]
    pub fn put<H, T>(self, path: &'static str, policy: Policy, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.add(Method::PUT, path, policy, axum::routing::put(handler))
    }

    #[must_use]
    pub fn patch<H, T>(self, path: &'static str, policy: Policy, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.add(Method::PATCH, path, policy, axum::routing::patch(handler))
    }

    #[must_use]
    pub fn delete<H, T>(self, path: &'static str, policy: Policy, handler: H) -> Self
    where
        H: Handler<T, S>,
        T: 'static,
    {
        self.add(Method::DELETE, path, policy, axum::routing::delete(handler))
    }

    fn add(
        mut self,
        method: Method,
        path: &'static str,
        policy: Policy,
        mr: MethodRouter<S>,
    ) -> Self {
        if !path.starts_with('/') || path.contains("//") {
            self.problems.push(RouterError::BadPath { path });
            return self;
        }
        if let Err(err) = policy.validate() {
            self.problems.push(RouterError::InvalidPolicy {
                method: method.to_string(),
                path,
                err,
            });
            return self;
        }
        if self
            .table
            .iter()
            .any(|r| r.path == path && r.method == method)
        {
            self.problems.push(RouterError::Duplicate {
                method: method.to_string(),
                path,
            });
            return self;
        }
        let p = Arc::new(policy.clone());
        let layered = mr.route_layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let p = Arc::clone(&p);
                async move { gate(p, req, next).await }
            },
        ));
        let merged = match self.routes.remove(path) {
            Some(existing) => existing.merge(layered),
            None => layered,
        };
        self.routes.insert(path, merged);
        self.table.push(RouteEntry {
            method,
            path,
            policy,
        });
        self
    }

    /// Registered routes so far.
    #[must_use]
    pub fn table(&self) -> &[RouteEntry] {
        &self.table
    }

    /// Build the axum router.
    ///
    /// # Errors
    /// Every problem found (invalid policy, duplicate, bad path).
    pub fn into_router(self) -> Result<(Router<S>, Vec<RouteEntry>), Vec<RouterError>> {
        if !self.problems.is_empty() {
            return Err(self.problems);
        }
        let mut r = Router::new();
        for (path, mr) in self.routes {
            // The one place routes enter axum: each MethodRouter already carries its policy gate.
            #[allow(clippy::disallowed_methods)]
            {
                r = r.route(path, mr);
            }
        }
        Ok((r, self.table))
    }
}

/// One line of the `xtask route-policies` report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RoutePolicyReport {
    pub method: String,
    pub path: &'static str,
    /// `Some(reason)` = anonymous route.
    pub public_reason: Option<&'static str>,
    pub permission: Option<&'static str>,
    pub idempotent: bool,
    pub high_risk: bool,
    /// Full policy (Debug) for review diffs.
    pub policy: String,
}

#[must_use]
pub fn report(table: &[RouteEntry]) -> Vec<RoutePolicyReport> {
    let mut out: Vec<RoutePolicyReport> = table
        .iter()
        .map(|r| RoutePolicyReport {
            method: r.method.to_string(),
            path: r.path,
            public_reason: public_reason(&r.policy),
            permission: r.policy.permission_of().map(domain::rbac::Perm::name),
            idempotent: r.policy.is_idempotent(),
            high_risk: r.policy.is_high_risk(),
            policy: format!("{:?}", r.policy),
        })
        .collect();
    out.sort_by(|a, b| (a.path, &a.method).cmp(&(b.path, &b.method)));
    out
}

/// Internal metrics router (served on the loopback-only `METRICS_ADDR` listener, never on the
/// public port; see `startup`). Not part of the policy table because it is not reachable from
/// outside the host.
pub fn metrics_router() -> Router {
    #[allow(clippy::disallowed_methods)]
    Router::new().route("/metrics", get(metrics_text))
}

async fn metrics_text() -> axum::response::Response {
    use axum::response::IntoResponse as _;
    telemetry::meters::update_process_gauges();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        telemetry::meters::render(),
    )
        .into_response()
}
