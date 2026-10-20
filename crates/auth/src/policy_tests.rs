//! Policy unit tests (no DB): public reason, no principal, feature-off for Owner, step-up, principal
//! kind separation, device binding, staff platform decisions.

use common::{DeviceId, SessionId, TenantId};
use domain::rbac::{
    DenyReason, DeviceScope, Feature, FeatureSet, Perm, PlatformDenyReason, PlatformPerm,
    StaffRole, Subject, Target, TenantRole, Visibility,
};
use time::OffsetDateTime;

use crate::loader::Freshness;
use crate::loader::test_support::{device, member, staff};
use crate::policy::{Authorized, DenyCode, EvalContext, Policy, PolicyError};
use crate::principal::Principal;
use crate::stepup::StepUpProof;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("ts")
}

fn ctx() -> EvalContext<'static> {
    EvalContext::at(now())
}

fn owner(features: FeatureSet) -> Principal {
    Principal::Member(member(TenantId::new(), TenantRole::Owner, features))
}

#[test]
fn public_route_needs_a_reason() {
    assert_eq!(
        Policy::public("").validate(),
        Err(PolicyError::PublicWithoutReason)
    );
    assert_eq!(
        Policy::public("   ").validate(),
        Err(PolicyError::PublicWithoutReason)
    );
    let d = Policy::public("")
        .evaluate(&Principal::Anonymous, &ctx())
        .expect_err("denied");
    assert_eq!(
        d.code,
        DenyCode::Misconfigured(PolicyError::PublicWithoutReason)
    );
    assert_eq!(
        Policy::public("liveness").evaluate(&Principal::Anonymous, &ctx()),
        Ok(Authorized::Public { reason: "liveness" })
    );
}

#[test]
fn no_principal_is_denied() {
    for p in [
        Policy::member().permission(Perm::ProfileReadSelf),
        Policy::member(),
        Policy::device().permission(Perm::ReportsDriveCreate),
        Policy::staff().platform(PlatformPerm::TenantsRead),
    ] {
        let d = p
            .evaluate(&Principal::Anonymous, &ctx())
            .expect_err("denied");
        assert_eq!(d.code, DenyCode::Unauthenticated);
        assert_eq!(d.status(), 401);
    }
}

#[test]
fn misconfigured_policies_are_denied() {
    assert_eq!(
        Policy::member()
            .platform(PlatformPerm::TenantsRead)
            .validate(),
        Err(PolicyError::PlatformPermWithoutStaff)
    );
    assert_eq!(
        Policy::device().validate(),
        Err(PolicyError::DeviceWithoutPermission)
    );
    assert_eq!(
        Policy::staff().validate(),
        Err(PolicyError::StaffWithoutPlatformPermission)
    );
    let d = Policy::device()
        .evaluate(&owner(FeatureSet::all()), &ctx())
        .expect_err("denied");
    assert!(matches!(d.code, DenyCode::Misconfigured(_)));
}

#[test]
fn feature_off_route_is_denied_for_owner() {
    // Matrix feature gate (groups.read needs `groups`).
    let d = Policy::member()
        .permission(Perm::GroupsRead)
        .evaluate(&owner(FeatureSet::none()), &ctx())
        .expect_err("denied");
    assert_eq!(
        d.code,
        DenyCode::Rbac(DenyReason::FeatureDisabled(Feature::Groups))
    );
    // Explicit route feature gate.
    let d = Policy::member()
        .permission(Perm::ProfileReadSelf)
        .feature(Feature::Subusers)
        .evaluate(&owner(FeatureSet::none()), &ctx())
        .expect_err("denied");
    assert_eq!(d.code, DenyCode::FeatureDisabled(Feature::Subusers));
    assert_eq!(d.status(), 403);
    // Same routes with the feature ON are allowed.
    let a = Policy::member()
        .permission(Perm::GroupsRead)
        .evaluate(&owner(FeatureSet::all()), &ctx())
        .expect("allowed");
    let Authorized::Tenant { scope, .. } = a else {
        panic!("tenant scope expected");
    };
    assert_eq!(scope.visibility(), &Visibility::Tenant);
}

#[test]
fn member_scope_comes_from_the_decision() {
    let p = Principal::Member(member(
        TenantId::new(),
        TenantRole::Viewer,
        FeatureSet::all(),
    ));
    let Ok(Authorized::Tenant { scope, .. }) = Policy::member()
        .permission(Perm::ProfileReadSelf)
        .evaluate(&p, &ctx())
    else {
        panic!("allowed expected");
    };
    assert_eq!(scope.visibility(), &Visibility::SelfOnly);
    // viewer cannot create members
    let d = Policy::member()
        .permission(Perm::MembersCreate)
        .evaluate(&p, &ctx())
        .expect_err("denied");
    assert!(matches!(d.code, DenyCode::Rbac(_)));
}

#[test]
fn cross_tenant_target_is_404() {
    let p = owner(FeatureSet::all());
    let other = Target::collection(TenantId::new());
    let d = Policy::member()
        .permission(Perm::ProfileReadSelf)
        .evaluate_on(&p, Some(&other), &ctx())
        .expect_err("denied");
    assert_eq!(d.code, DenyCode::Rbac(DenyReason::CrossTenant));
    assert_eq!(d.status(), 404);
}

#[test]
fn step_up_proof_must_match_session_action_and_target() {
    let t = TenantId::new();
    let policy = Policy::member().permission(Perm::DevicesRemoteWipe);
    assert!(policy.is_high_risk());
    assert_eq!(policy.freshness(), Freshness::Live);
    assert_eq!(
        policy.required_step_up(),
        Some(Perm::DevicesRemoteWipe.name())
    );
    let dev = DeviceId::new();
    let target = Target::of(t, Subject::Device(dev));
    let act = Perm::DevicesRemoteWipe.name();
    let m = member(t, TenantRole::Owner, FeatureSet::all());
    let session = m.session();
    let p = Principal::Member(m);

    // no proof
    let d = policy
        .evaluate_on(&p, Some(&target), &ctx())
        .expect_err("denied");
    assert_eq!(d.code, DenyCode::StepUpRequired);
    assert_eq!(d.status(), 403);
    // proof for another action / another target / another session
    for proof in [
        StepUpProof::new(session, "members.delete".to_owned(), Some(dev.0)),
        StepUpProof::new(session, act.to_owned(), Some(DeviceId::new().0)),
        StepUpProof::new(SessionId::new(), act.to_owned(), Some(dev.0)),
        StepUpProof::new(session, act.to_owned(), None),
    ] {
        let d = policy
            .evaluate_on(&p, Some(&target), &ctx().with_step_up(&proof))
            .expect_err("denied");
        assert_eq!(d.code, DenyCode::StepUpRequired, "{proof:?}");
    }
    // exact match
    let ok = StepUpProof::new(session, act.to_owned(), Some(dev.0));
    assert!(
        policy
            .evaluate_on(&p, Some(&target), &ctx().with_step_up(&ok))
            .is_ok()
    );

    // Explicit step_up() on a perm that does not need it by itself (collection target = None).
    let p2 = Policy::member()
        .permission(Perm::ProfileReadSelf)
        .step_up("export");
    assert!(p2.is_high_risk());
    assert_eq!(
        p2.evaluate(&p, &ctx()).expect_err("denied").code,
        DenyCode::StepUpRequired
    );
    let exp = StepUpProof::new(session, "export".to_owned(), None);
    assert!(p2.evaluate(&p, &ctx().with_step_up(&exp)).is_ok());
}

#[test]
fn principal_kinds_are_separated() {
    let staff_p = Principal::Staff(staff(StaffRole::Superadmin));
    let d = Policy::member()
        .permission(Perm::ProfileReadSelf)
        .evaluate(&staff_p, &ctx())
        .expect_err("denied");
    assert_eq!(d.code, DenyCode::WrongPrincipal);
    let d = Policy::staff()
        .platform(PlatformPerm::TenantsRead)
        .evaluate(&owner(FeatureSet::all()), &ctx())
        .expect_err("denied");
    assert_eq!(d.code, DenyCode::WrongPrincipal);
    let dev = Principal::Device(Box::new(device(
        TenantId::new(),
        &[DeviceScope::ReportsUpload],
    )));
    let d = Policy::member()
        .permission(Perm::ProfileReadSelf)
        .evaluate(&dev, &ctx())
        .expect_err("denied");
    assert_eq!(d.code, DenyCode::WrongPrincipal);
}

#[test]
fn staff_platform_decisions() {
    let sup = Principal::Staff(staff(StaffRole::Support));
    let d = Policy::staff()
        .platform(PlatformPerm::TenantsSuspend)
        .evaluate(&sup, &ctx())
        .expect_err("denied");
    assert_eq!(d.code, DenyCode::Platform(PlatformDenyReason::NoPermission));
    let sa = Principal::Staff(staff(StaffRole::Superadmin));
    assert!(matches!(
        Policy::staff()
            .platform(PlatformPerm::TenantsSuspend)
            .evaluate(&sa, &ctx()),
        Ok(Authorized::Platform { .. })
    ));
    // staff never get a tenant scope from Policy
    let d = Policy::staff()
        .platform(PlatformPerm::TenantsRead)
        .permission(Perm::ProfileReadSelf)
        .evaluate(&sa, &ctx())
        .expect_err("denied");
    assert_eq!(d.code, DenyCode::WrongPrincipal);
}

#[test]
fn device_is_bound_to_its_own_device_and_scopes() {
    let t = TenantId::new();
    let d = device(t, &[DeviceScope::ReportsUpload]);
    let own = Target::of(t, Subject::Device(d.device()));
    let other = Target::of(t, Subject::Device(DeviceId::new()));
    let p = Principal::Device(Box::new(d));
    let policy = Policy::device().permission(Perm::ReportsDriveCreate);
    let Ok(Authorized::Tenant { scope, .. }) = policy.evaluate_on(&p, Some(&own), &ctx()) else {
        panic!("own device allowed");
    };
    assert_eq!(scope.visibility(), &Visibility::SelfOnly);
    let e = policy
        .evaluate_on(&p, Some(&other), &ctx())
        .expect_err("denied");
    assert_eq!(e.code, DenyCode::Rbac(DenyReason::OutOfScope));
    // scope not granted
    let e = Policy::device()
        .permission(Perm::CreditsConsume)
        .evaluate_on(&p, Some(&own), &ctx())
        .expect_err("denied");
    assert_eq!(e.code, DenyCode::Rbac(DenyReason::NoPermission));
    // devices cannot satisfy step-up
    let e = Policy::device()
        .permission(Perm::ReportsDriveCreate)
        .step_up("x")
        .evaluate_on(&p, Some(&own), &ctx())
        .expect_err("denied");
    assert_eq!(e.code, DenyCode::StepUpRequired);
}
