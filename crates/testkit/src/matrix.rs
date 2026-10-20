//! T-R2: authz matrix harness. Table driven over `api::route_policies(..)`: every route is called
//! with every fixture principal and the HTTP status is compared with the decision the policy gives
//! (`Policy::evaluate` -> `domain::decide*`), plus independent invariants that do NOT use the same
//! code path as the gate (so an error in both would still be caught):
//!
//! - never a 5xx, never a 2xx for a denied cell, never 401/403 for an allowed cell;
//! - anonymous / garbage / expired callers are never allowed on a non-public route;
//! - a principal kind the policy does not list (member on a staff route, device on a member route,
//!   staff on a member route, ...) is never allowed;
//! - suspended user, disabled member, suspended tenant and staff-without-MFA are never allowed;
//! - a 2xx body never contains another tenant's tenant id or owner membership id (data leak).
//!
//! New routes are covered automatically: an unknown route gets the default [`Probe`] (gate check
//! only). Add a [`Probe`] to [`ProbeTable`] to tighten a route to an exact 2xx.

use std::collections::{BTreeSet, HashMap};

use api::RoutePolicyReport;
use auth::{
    Audience, EvalContext, Freshness, Policy, Principal, PrincipalKind, PrincipalStateLoader as _,
    TokenVerifier as _,
};
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, header};
use tower::ServiceExt as _;

use crate::principals::{Persona, PersonaKind, names};
use crate::world::World;

/// What an ALLOWED call must look like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OkExpect {
    /// Exactly this status (valid request).
    Exact(u16),
    /// The gate let the call through: any status except 401/403/404/405/5xx (the probe has no
    /// valid body, so the handler may answer 400/415/422).
    Passes,
}

#[derive(Clone, Debug)]
pub struct Probe {
    pub body: Option<serde_json::Value>,
    pub ok: OkExpect,
    /// Changes state the matrix itself relies on (logout revokes the session): runs last.
    pub destructive: bool,
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            body: None,
            ok: OkExpect::Passes,
            destructive: false,
        }
    }
}

/// Per-route probes, keyed `"METHOD /path"`.
#[derive(Clone, Debug, Default)]
pub struct ProbeTable(HashMap<String, Probe>);

impl ProbeTable {
    /// Probes for the Phase 0 routes.
    #[must_use]
    pub fn phase0() -> Self {
        let mut t = Self::default();
        let exact = |s| Probe {
            ok: OkExpect::Exact(s),
            ..Probe::default()
        };
        t.0.insert("GET /health/live".into(), exact(200));
        t.0.insert("GET /health/ready".into(), exact(200));
        t.0.insert("GET /api/v1/me".into(), exact(200));
        t.0.insert("GET /api/v1/me/sessions".into(), exact(200));
        t.0.insert("GET /.well-known/jwks.json".into(), exact(200));
        t.0.insert("GET /api/v1/openapi.json".into(), exact(200));
        for p in ["/api/v1/auth/logout", "/api/v1/platform/auth/logout"] {
            t.0.insert(
                format!("POST {p}"),
                Probe {
                    ok: OkExpect::Exact(204),
                    destructive: true,
                    ..Probe::default()
                },
            );
        }
        t
    }

    /// Add / replace a probe.
    #[must_use]
    pub fn with(mut self, method: &str, path: &str, probe: Probe) -> Self {
        self.0.insert(format!("{method} {path}"), probe);
        self
    }

    fn get(&self, method: &str, path: &str) -> Probe {
        self.0
            .get(&format!("{method} {path}"))
            .cloned()
            .unwrap_or_else(|| Probe {
                // Any other logout route is destructive too (it revokes the caller's session).
                destructive: path.ends_with("/logout"),
                ..Probe::default()
            })
    }
}

/// Decision the harness expects for one (route, persona) cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expected {
    Allow,
    /// Deny with one of these statuses.
    Deny(Vec<u16>),
}

impl Expected {
    fn label(&self) -> String {
        match self {
            Self::Allow => "allow".to_owned(),
            Self::Deny(s) => format!("deny{s:?}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Cell {
    pub route: String,
    pub persona: &'static str,
    pub expected: Expected,
    pub status: u16,
}

#[derive(Debug, Default)]
pub struct MatrixReport {
    pub routes: usize,
    pub personas: usize,
    pub cells: Vec<Cell>,
    pub mismatches: Vec<String>,
    /// Non-public routes no persona got through the gate on (must all be step-up gated).
    pub never_allowed: Vec<String>,
    /// Routes whose path has `{param}` segments (tenant-addressed).
    pub templated_routes: usize,
}

impl MatrixReport {
    #[must_use]
    pub fn allowed_cells(&self) -> usize {
        self.cells
            .iter()
            .filter(|c| c.expected == Expected::Allow)
            .count()
    }

    /// One line per fact (stderr-friendly).
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "authz matrix: {} routes x {} personas = {} cells ({} allow, {} deny), {} mismatches, \
             {} templated routes, never allowed: {:?}",
            self.routes,
            self.personas,
            self.cells.len(),
            self.allowed_cells(),
            self.cells.len() - self.allowed_cells(),
            self.mismatches.len(),
            self.templated_routes,
            self.never_allowed
        )
    }

    /// Route x persona status grid (`A` = expected allow, `d` = expected deny), for humans.
    #[must_use]
    pub fn grid(&self) -> String {
        let mut rows: Vec<(String, Vec<String>)> = Vec::new();
        for c in &self.cells {
            let mark = if c.expected == Expected::Allow {
                'A'
            } else {
                'd'
            };
            let cell = format!("{}={}{}", c.persona, c.status, mark);
            match rows.last_mut() {
                Some((r, v)) if *r == c.route => v.push(cell),
                _ => rows.push((c.route.clone(), vec![cell])),
            }
        }
        rows.iter()
            .map(|(r, v)| {
                format!(
                    "{r}
    {}",
                    v.join(" ")
                )
            })
            .collect::<Vec<_>>()
            .join(
                "
",
            )
    }

    /// # Panics
    /// With every mismatch listed.
    pub fn assert_clean(&self) {
        assert!(
            self.mismatches.is_empty(),
            "{}\n{}",
            self.summary(),
            self.mismatches.join("\n")
        );
    }
}

fn is_templated(path: &str) -> bool {
    path.contains('{')
}

/// Fill `{param}` segments with tenant A's resources (so tenant B calls hit foreign ids).
fn fill_path(world: &World, path: &str) -> String {
    let a = world.tenant_a();
    let mut out = String::new();
    let mut rest = path;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        let (name, after) = tail.split_once('}').unwrap_or((tail, ""));
        let id = match name {
            "tenant_id" | "tenant" => a.id.0,
            "member_id" | "membership_id" => a.owner_membership.0,
            "group_id" => a.group.map_or_else(uuid::Uuid::now_v7, |g| g.0),
            _ => uuid::Uuid::now_v7(),
        };
        out.push_str(&id.to_string());
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Independent "must never be allowed" rules. `Some(reason)` = the cell has to be a deny.
fn must_deny(policy: &Policy, p: &Persona) -> Option<&'static str> {
    if policy.is_public() {
        return None;
    }
    match p.kind {
        PersonaKind::Anonymous | PersonaKind::Garbage | PersonaKind::Expired => {
            return Some("unauthenticated caller on a non-public route");
        }
        _ => {}
    }
    let kinds = policy.principal_kinds();
    let needed = match p.kind {
        PersonaKind::Member => PrincipalKind::Member,
        PersonaKind::Device => PrincipalKind::Device,
        _ => PrincipalKind::Staff,
    };
    if !kinds.contains(&needed) {
        return Some("principal kind not listed by the route policy");
    }
    match p.name {
        names::A_SUSPENDED_USER => Some("suspended user"),
        names::A_DISABLED_MEMBER => Some("disabled membership"),
        names::C_SUSPENDED_TENANT_OWNER => Some("suspended tenant"),
        names::STAFF_NO_MFA => Some("staff session without MFA"),
        _ => None,
    }
}

/// The decision the policy gives this persona (token -> verifier -> live loader -> `evaluate`).
pub async fn expected_decision(world: &World, policy: &Policy, p: &Persona) -> Expected {
    if policy.is_public() {
        return Expected::Allow;
    }
    let Some(token) = p.token.as_deref() else {
        return Expected::Deny(vec![401]);
    };
    let Ok(claims) = world.verifier.verify(token, &policy.audiences()) else {
        return Expected::Deny(vec![401]);
    };
    let principal = match world.loader.load(&claims, policy.freshness()).await {
        Ok(pr) => pr,
        Err(_) => return Expected::Deny(vec![401, 403]),
    };
    match policy.evaluate(&principal, &EvalContext::at(world.clock.now())) {
        Ok(_) => Expected::Allow,
        Err(d) => Expected::Deny(vec![d.status()]),
    }
}

fn foreign_ids(world: &World, p: &Persona) -> Vec<String> {
    let mut out = Vec::new();
    for fx in [world.a.as_ref(), world.b.as_ref()].into_iter().flatten() {
        if Some(fx.id) != p.tenant {
            out.push(fx.id.0.to_string());
            out.push(fx.owner_membership.0.to_string());
        }
    }
    out
}

fn request(method: &Method, path: &str, p: &Persona, probe: &Probe) -> Request<Body> {
    let mut b = Request::builder().method(method.clone()).uri(path);
    if let Some(t) = &p.token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let body = if *method == Method::GET || *method == Method::HEAD {
        Body::empty()
    } else {
        b = b.header(header::CONTENT_TYPE, "application/json");
        let v = probe.body.clone().unwrap_or_else(|| serde_json::json!({}));
        Body::from(v.to_string())
    };
    b.body(body).expect("request")
}

/// Run the whole matrix against `app` (built from [`World::app`]).
pub async fn run_matrix(world: &World, app: &Router, probes: &ProbeTable) -> MatrixReport {
    let opts = World::route_options();
    let reports: Vec<RoutePolicyReport> = api::route_policies(&opts).expect("route policies");
    let routes = api::build_routes(&opts);
    let table = routes.table();
    let mut rep = MatrixReport {
        routes: reports.len(),
        personas: world.personas.len(),
        ..MatrixReport::default()
    };
    if table.len() != reports.len() {
        rep.mismatches.push(format!(
            "route_policies reports {} routes but the table has {}",
            reports.len(),
            table.len()
        ));
    }

    // Destructive probes last.
    let mut order: Vec<&RoutePolicyReport> = reports.iter().collect();
    order.sort_by_key(|r| probes.get(&r.method, r.path).destructive);

    let mut allowed_routes: BTreeSet<String> = BTreeSet::new();
    for r in order {
        let key = format!("{} {}", r.method, r.path);
        let Some(entry) = table
            .iter()
            .find(|e| e.method.as_str() == r.method && e.path == r.path)
        else {
            rep.mismatches.push(format!(
                "{key}: in route_policies but not in the route table"
            ));
            continue;
        };
        let policy = &entry.policy;
        let probe = probes.get(&r.method, r.path);
        let templated = is_templated(r.path);
        if templated {
            rep.templated_routes += 1;
        }
        let method = Method::from_bytes(r.method.as_bytes()).expect("method");
        let path = fill_path(world, r.path);
        for p in &world.personas {
            let mut expected = expected_decision(world, policy, p).await;
            // Tenant-addressed route: another tenant's principal must never reach tenant A's row.
            if templated
                && !policy.is_public()
                && p.tenant.is_some()
                && p.tenant != Some(world.tenant_a().id)
                && matches!(p.kind, PersonaKind::Member | PersonaKind::Device)
            {
                expected = Expected::Deny(vec![401, 403, 404]);
            }
            if let Some(why) = must_deny(policy, p)
                && expected == Expected::Allow
            {
                rep.mismatches
                    .push(format!("{key} / {}: oracle allows ({why})", p.name));
                expected = Expected::Deny(vec![401, 403, 404]);
            }
            let resp = app
                .clone()
                .oneshot(request(&method, &path, p, &probe))
                .await
                .expect("response");
            let status = resp.status().as_u16();
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .expect("body");
            let text = String::from_utf8_lossy(&bytes);
            let mut bad: Vec<String> = Vec::new();
            if status >= 500 {
                bad.push(format!("server error {status}"));
            }
            match &expected {
                Expected::Allow => {
                    if matches!(status, 401 | 403) {
                        bad.push(format!("allowed but got {status}"));
                    }
                    match probe.ok {
                        OkExpect::Exact(s) if status != s => {
                            bad.push(format!("allowed, expected exactly {s}, got {status}"));
                        }
                        OkExpect::Passes if matches!(status, 404 | 405) => {
                            bad.push(format!("allowed but gate-level {status}"));
                        }
                        _ => {}
                    }
                    if !matches!(status, 401 | 403 | 404 | 405) && status < 500 {
                        allowed_routes.insert(key.clone());
                    }
                }
                Expected::Deny(set) => {
                    if (200..300).contains(&status) {
                        bad.push(format!("denied cell answered {status}"));
                    } else if !set.contains(&status) {
                        bad.push(format!("expected one of {set:?}, got {status}"));
                    }
                }
            }
            if (200..300).contains(&status) {
                for id in foreign_ids(world, p) {
                    if text.contains(&id) {
                        bad.push("2xx body contains another tenant's id (leak)".to_owned());
                        break;
                    }
                }
            }
            for b in bad {
                rep.mismatches.push(format!(
                    "{key} / {} ({}): expected {}, got {status}: {b}",
                    p.name,
                    p.note,
                    expected.label()
                ));
            }
            rep.cells.push(Cell {
                route: key.clone(),
                persona: p.name,
                expected,
                status,
            });
        }
    }
    for r in &reports {
        let key = format!("{} {}", r.method, r.path);
        let public = table
            .iter()
            .find(|e| e.method.as_str() == r.method && e.path == r.path)
            .is_none_or(|e| e.policy.is_public());
        if !public && !allowed_routes.contains(&key) {
            rep.never_allowed.push(key);
        }
    }
    rep
}

/// Persona principal as the loader sees it (member/device only), for oracle-style checks.
pub async fn load_principal(world: &World, p: &Persona, aud: &[Audience]) -> Option<Principal> {
    let token = p.token.as_deref()?;
    let claims = world.verifier.verify(token, aud).ok()?;
    world.loader.load(&claims, Freshness::Live).await.ok()
}
