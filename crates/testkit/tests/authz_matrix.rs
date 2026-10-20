//! T-R2: authz matrix over the Phase 0 routes + cross-tenant checks (local MySQL scratch DB).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use testkit::{ProbeTable, World, cross_tenant, run_matrix, with_scratch};

#[tokio::test]
async fn t_r2_authz_matrix_phase0_routes() {
    with_scratch("t_r2_matrix", |db, mig| async move {
        let world = World::standard(db, mig).await;
        let app = world.app().await;
        let rep = run_matrix(&world, &app, &ProbeTable::phase0()).await;
        eprintln!(
            "{}
{}",
            rep.grid(),
            rep.summary()
        );
        rep.assert_clean();
        assert!(rep.routes >= 12, "route table shrank: {}", rep.routes);
        assert!(rep.allowed_cells() > 0);
    })
    .await;
}

#[tokio::test]
async fn t_r2_cross_tenant_b_against_a() {
    with_scratch("t_r2_cross_tenant", |db, mig| async move {
        let world = World::standard(db, mig).await;
        let app = world.app().await;
        let http = cross_tenant::http_checks(&world, &app).await;
        let dom = cross_tenant::domain_checks(&world).await;
        eprintln!(
            "cross-tenant: {} http checks, {} domain checks",
            http.checks, dom.checks
        );
        http.assert_clean();
        dom.assert_clean();
        assert!(dom.checks > 1000, "domain checks ran: {}", dom.checks);
    })
    .await;
}

/// The harness must notice a wrong expectation: a persona that LOOKS like a disabled member but
/// really is an active one is allowed by the policy, which the independent invariant forbids.
#[tokio::test]
async fn t_r2_harness_detects_a_broken_expectation() {
    with_scratch("t_r2_negative", |db, mig| async move {
        let mut world = World::standard(db, mig).await;
        let app = world.app().await;
        for p in &mut world.personas {
            if p.name == testkit::principals::names::A_MEMBER {
                p.name = testkit::principals::names::A_DISABLED_MEMBER;
            }
        }
        let rep = run_matrix(&world, &app, &ProbeTable::phase0()).await;
        assert!(
            rep.mismatches
                .iter()
                .any(|m| m.contains("disabled membership")),
            "harness missed the wrong expectation: {}",
            rep.summary()
        );
    })
    .await;
}
