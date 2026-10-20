//! Cross-tenant checks: tenant B principals against tenant A (HTTP and `domain::decide`).
//!
//! Phase 0 has no tenant-addressed route (the tenant always comes from the token), so the HTTP part
//! proves "own data only" on the self routes and the domain part proves, for EVERY permission in
//! the catalogue and every Phase 0 policy with a permission, that a foreign target is
//! `DenyReason::CrossTenant` (HTTP 404, never 403, never allowed). Routes with `{param}` segments
//! are covered by the matrix (`matrix::run_matrix` forces 401/403/404 for foreign tenants).

use auth::{Audience, EvalContext, Principal};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, header};
use domain::rbac::{Decision, DenyReason, Perm, Subject, Target, decide};
use tower::ServiceExt as _;

use crate::matrix::load_principal;
use crate::principals::{Persona, names};
use crate::world::World;

#[derive(Debug, Default)]
pub struct CrossTenantReport {
    pub checks: usize,
    pub failures: Vec<String>,
}

impl CrossTenantReport {
    /// # Panics
    /// With every failure listed.
    pub fn assert_clean(&self) {
        assert!(
            self.failures.is_empty(),
            "cross-tenant: {} checks, {} failures\n{}",
            self.checks,
            self.failures.len(),
            self.failures.join("\n")
        );
    }
}

async fn get_json(app: &Router, path: &str, p: &Persona) -> (u16, serde_json::Value) {
    let mut b = Request::get(path);
    if let Some(t) = &p.token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let r = app
        .clone()
        .oneshot(b.body(Body::empty()).expect("req"))
        .await
        .expect("resp");
    let status = r.status().as_u16();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20)
        .await
        .expect("body");
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

/// Self routes: every member answers with its OWN tenant/membership and only its own sessions.
pub async fn http_checks(world: &World, app: &Router) -> CrossTenantReport {
    let mut rep = CrossTenantReport::default();
    for p in world.personas.iter().filter(|p| p.is_member()) {
        let live = !matches!(
            p.name,
            names::A_SUSPENDED_USER | names::A_DISABLED_MEMBER | names::C_SUSPENDED_TENANT_OWNER
        );
        let (status, body) = get_json(app, "/api/v1/me", p).await;
        rep.checks += 1;
        if !live {
            if status != 401 && status != 403 {
                rep.failures.push(format!(
                    "{}: /me answered {status} for a dead account",
                    p.name
                ));
            }
            continue;
        }
        let want_t = p.tenant.map(|t| t.0.to_string());
        let want_m = p.membership.map(|m| m.0.to_string());
        let got_t = body
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let got_m = body
            .get("membership_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        if status != 200 || got_t != want_t || got_m != want_m {
            rep.failures.push(format!(
                "{}: /me status {status}, tenant/membership do not match the token owner",
                p.name
            ));
        }
        let (status, body) = get_json(app, "/api/v1/me/sessions", p).await;
        rep.checks += 1;
        let rows = body
            .get("data")
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default();
        // One login per persona => exactly one session, and it is the current one.
        let only_own = rows.len() == 1
            && rows[0].get("current").and_then(serde_json::Value::as_bool) == Some(true);
        if status != 200 || !only_own {
            rep.failures.push(format!(
                "{}: /me/sessions status {status}, {} rows (expected only the caller's own session)",
                p.name,
                rows.len()
            ));
        }
    }
    rep
}

/// Tenant B principals (members and A's device against B) vs tenant A resources, in the domain.
pub async fn domain_checks(world: &World) -> CrossTenantReport {
    let mut rep = CrossTenantReport::default();
    let a = world.tenant_a();
    let b = world.tenant_b();
    let aud = [Audience::Web, Audience::App];
    let a_owner = world.persona(names::A_OWNER);
    let Some(Principal::Member(a_owner_p)) = load_principal(world, a_owner, &aud).await else {
        rep.failures.push("a_owner did not load".to_owned());
        return rep;
    };
    let a_owner_state = a_owner_p.actor().state().as_member();
    let table = api::build_routes(&World::route_options());
    for (attacker, victim_tenant, victim_state, victim_group) in [
        (names::B_OWNER, a.id, a_owner_state.clone(), a.group),
        (names::B_MEMBER, a.id, a_owner_state, a.group),
    ] {
        let p = world.persona(attacker);
        let Some(Principal::Member(m)) = load_principal(world, p, &aud).await else {
            rep.failures.push(format!("{attacker} did not load"));
            continue;
        };
        if m.tenant() != b.id {
            rep.failures.push(format!("{attacker} is not in tenant B"));
            continue;
        }
        let mut targets = vec![
            Target::collection(victim_tenant),
            Target::of(victim_tenant, Subject::Unowned),
            Target::of(victim_tenant, Subject::Aggregate),
            Target::of(victim_tenant, Subject::Member(victim_state)),
        ];
        if let Some(g) = victim_group {
            targets.push(Target::of(victim_tenant, Subject::Group(g)));
        }
        for t in &targets {
            for perm in Perm::ALL {
                rep.checks += 1;
                let d = decide(m.actor().state(), *perm, m.features(), m.caps(), t);
                if d != Decision::Denied(DenyReason::CrossTenant) {
                    rep.failures.push(format!(
                        "{attacker}: decide({}) on a tenant A target = {d:?} (want CrossTenant)",
                        perm.name()
                    ));
                }
            }
        }
        // Every Phase 0 member policy with a permission, evaluated on tenant A's collection.
        for e in table.table() {
            let Some(perm) = e.policy.permission_of() else {
                continue;
            };
            if !e
                .policy
                .principal_kinds()
                .contains(&auth::PrincipalKind::Member)
            {
                continue;
            }
            rep.checks += 1;
            let r = e.policy.evaluate_on(
                &Principal::Member(m.clone()),
                Some(&Target::collection(victim_tenant)),
                &EvalContext::at(world.clock.now()),
            );
            match r {
                Err(d) if d.status() == 404 => {}
                other => rep.failures.push(format!(
                    "{attacker}: {} {} ({}) on tenant A = {other:?} (want 404 CrossTenant)",
                    e.method,
                    e.path,
                    perm.name()
                )),
            }
        }
    }
    rep
}
