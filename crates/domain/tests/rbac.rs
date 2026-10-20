//! T-D1 and the domain-level negative tests of RBAC.md §8.3 (E1..E30), §8.4 properties.
//!
//! E-cases covered here: E1 E2 E3 E4 E5(pure rule) E6 E7 E8 E9 E10 E11 E12(rule) E13(rule) E14 E15
//! E16(pure part) E19(step-up flag) E20(scope map + resource binding) E26(rule) E27(flag + rule)
//! E28(rule) E30. Deferred to api/db/auth tests: E5 and E12/E13 concurrency, E16/E17/E18 token+session
//! state, E19 token/replay/rate limit, E20/E21/E22 route + token audience, E23/E24 staff grants +
//! audit, E25 mass assignment, E26 cross-tenant lookup, E27 token, E28 lot/pool, E29 RLS.
//! The doc-vs-code cell diff lives in `tests/rbac_doc.rs`.

use std::collections::HashSet;

use common::{DeviceId, GroupId, MembershipId, TenantId};
use domain::rbac::matrix::ROWS;
use domain::rbac::*;
use proptest::prelude::*;
use smallvec::SmallVec;
use uuid::Uuid;

// ---------------------------------------------------------------- helpers

const T1: u128 = 1;
const T2: u128 = 2;

fn tenant(n: u128) -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(n))
}
fn mid(n: u128) -> MembershipId {
    MembershipId::from_uuid(Uuid::from_u128(n))
}
fn gid(n: u128) -> GroupId {
    GroupId::from_uuid(Uuid::from_u128(n))
}
fn did(n: u128) -> DeviceId {
    DeviceId::from_uuid(Uuid::from_u128(n))
}
fn groups(ns: &[u128]) -> GroupIds {
    ns.iter().map(|n| gid(*n)).collect::<SmallVec<_>>()
}
fn gref(t: u128, g: u128) -> GroupRef {
    GroupRef {
        tenant: tenant(t),
        id: gid(g),
    }
}

fn actor_in(t: u128, m: u128, role: TenantRole, member_of: &[u128], ga: &[u128]) -> ActorState {
    ActorState {
        tenant: tenant(t),
        membership: mid(m),
        role,
        status: MemberStatus::Active,
        groups: groups(member_of),
        ga_groups: groups(ga),
    }
}
fn actor(m: u128, role: TenantRole, member_of: &[u128], ga: &[u128]) -> ActorState {
    actor_in(T1, m, role, member_of, ga)
}
fn member_in(t: u128, m: u128, role: TenantRole, member_of: &[u128], ga: &[u128]) -> MemberState {
    actor_in(t, m, role, member_of, ga).as_member()
}

// Fixture world, tenant T1.
fn owner() -> ActorState {
    actor(1, TenantRole::Owner, &[], &[])
}
fn owner2() -> ActorState {
    actor(8, TenantRole::Owner, &[], &[])
}
fn admin() -> ActorState {
    actor(2, TenantRole::Admin, &[], &[])
}
fn admin2() -> ActorState {
    actor(7, TenantRole::Admin, &[], &[])
}
fn ga_g1() -> ActorState {
    actor(3, TenantRole::Member, &[1], &[1])
}
fn mem_g1() -> ActorState {
    actor(4, TenantRole::Member, &[1], &[])
}
fn mem_g2() -> ActorState {
    actor(5, TenantRole::Member, &[2], &[])
}
fn viewer_g1() -> ActorState {
    actor(6, TenantRole::Viewer, &[1], &[])
}

fn proof(role: StaffRole, t: u128) -> VerifiedStaffGrant {
    VerifiedStaffGrant::__from_verified_grant(role, tenant(t), common::GrantId::new())
}
fn agg() -> Target {
    Target::of(tenant(T1), Subject::Aggregate)
}

fn all_on() -> FeatureSet {
    FeatureSet::all()
}
fn full() -> Capabilities {
    Capabilities::full()
}
fn coll() -> Target {
    Target::collection(tenant(T1))
}
fn on(m: &ActorState) -> Target {
    Target::member(&m.as_member())
}
fn run(a: &ActorState, p: Perm, t: &Target) -> Decision {
    decide(a, p, &all_on(), &full(), t)
}

// ---------------------------------------------------------------- catalogue + matrix (T-D1)

#[test]
fn rows_align_with_catalogue() {
    assert_eq!(ROWS.len(), Perm::ALL.len(), "one matrix row per permission");
    for (i, (row, perm)) in ROWS.iter().zip(Perm::ALL).enumerate() {
        assert_eq!(row.perm, *perm, "row {i} out of order");
        assert_eq!(*perm as usize, i);
    }
}

#[test]
fn catalogue_names_are_unique_and_round_trip() {
    let mut seen = HashSet::new();
    for p in Perm::ALL {
        assert!(seen.insert(p.name()), "duplicate name {}", p.name());
        assert_eq!(Perm::from_name(p.name()), Some(*p));
        assert!(!p.name().starts_with("platform."));
    }
    let mut pseen = HashSet::new();
    for p in PlatformPerm::ALL {
        assert!(pseen.insert(p.name()));
        assert!(p.name().starts_with("platform."));
        assert_eq!(PlatformPerm::from_name(p.name()), Some(*p));
    }
    // 82 from §4.1-§4.9 + 50 from §4.12; 18 from §4.10 + 7 platform additions.
    assert_eq!(Perm::ALL.len(), 132);
    assert_eq!(PlatformPerm::ALL.len(), 25);
}

#[test]
fn platform_rows_align_with_catalogue() {
    // Superadmin has a cell on every platform perm, so every row resolved (alignment holds).
    for p in PlatformPerm::ALL {
        assert!(platform_grants(StaffRole::Superadmin, *p).is_some(), "{p}");
    }
}

#[test]
fn matrix_snapshot_matches_rbac_md_section_4() {
    insta::assert_snapshot!("tenant_matrix", render_matrix());
    insta::assert_snapshot!("platform_matrix", render_platform_matrix());
}

#[test]
fn owner_has_every_tenant_permission() {
    for p in Perm::ALL {
        assert!(grants(TenantRole::Owner, *p).is_some(), "owner lacks {p}");
    }
}

#[test]
fn lower_roles_never_exceed_higher_roles() {
    let breadth = |s: Option<Scope>| s.map_or(0, Scope::breadth);
    for p in Perm::ALL {
        let o = breadth(grants(TenantRole::Owner, *p));
        let a = breadth(grants(TenantRole::Admin, *p));
        let m = breadth(grants(TenantRole::Member, *p));
        let v = breadth(grants(TenantRole::Viewer, *p));
        assert!(o >= a && a >= m, "{p}: owner/admin/member not monotonic");
        assert!(m >= v, "{p}: viewer exceeds member");
        // GA never gets Tenant scope and never exceeds what admin has.
        let g = ga_grants(*p);
        assert!(
            g.is_none_or(|s| s != Scope::Tenant),
            "{p}: GA cell must not be T"
        );
        assert!(g.is_none() || a > 0, "{p}: GA has it but admin does not");
    }
}

#[test]
fn viewer_can_never_write() {
    for r in ROWS {
        if r.access == Access::Write {
            assert!(
                grants(TenantRole::Viewer, r.perm).is_none(),
                "viewer writes {}",
                r.perm
            );
        }
    }
    // And via decide(), with everything on, every subject kind, forged GA groups.
    let v = actor(6, TenantRole::Viewer, &[1], &[1]);
    let other = member_in(T1, 4, TenantRole::Member, &[1], &[]);
    let subjects = [
        Subject::Collection,
        Subject::Unowned,
        Subject::Group(gid(1)),
        Subject::Device(did(1)),
        Subject::Member(v.as_member()),
        Subject::Member(other),
    ];
    for p in Perm::ALL {
        for s in &subjects {
            let t = Target::of(tenant(T1), s.clone())
                .with_new_role(TenantRole::Viewer)
                .with_group(gref(T1, 1))
                .with_group_op(GroupMemberOp::Remove);
            if let Decision::Allowed(_) = run(&v, *p, &t) {
                assert_ne!(
                    matrix::access_of(*p),
                    Some(Access::Write),
                    "viewer wrote {p}"
                );
            }
        }
    }
}

#[test]
fn step_up_and_confirm_sets_are_exactly_the_destructive_lists() {
    let step: HashSet<Perm> = [
        Perm::DevicesRemoteWipe,
        Perm::MembersDelete,
        Perm::TenantOwnershipTransfer,
        Perm::TenantExportData,
        Perm::TenantClose,
        Perm::AutopilotConnectionManage,
        Perm::PrivateCloudManage,
    ]
    .into_iter()
    .collect();
    let actual: HashSet<Perm> = Perm::ALL
        .iter()
        .copied()
        .filter(|p| requires_step_up(*p))
        .collect();
    assert_eq!(actual, step);
    // Bulk licence transfer / revoke > 10 items.
    for p in [Perm::LicensesTransfer, Perm::LicensesRevoke] {
        assert!(!requires_step_up(p));
        assert!(!requires_step_up_bulk(p, BULK_STEP_UP_THRESHOLD));
        assert!(requires_step_up_bulk(p, BULK_STEP_UP_THRESHOLD + 1));
    }
    assert!(!requires_step_up_bulk(Perm::LicensesSync, 1_000));
    // Confirmation: remote wipe (also step-up) and Intune delete (confirm only).
    let confirm: HashSet<Perm> = Perm::ALL
        .iter()
        .copied()
        .filter(|p| requires_confirm(*p))
        .collect();
    assert_eq!(
        confirm,
        [Perm::DevicesRemoteWipe, Perm::AutopilotIntuneDeleteDevice]
            .into_iter()
            .collect()
    );
    assert!(!requires_step_up(Perm::AutopilotIntuneDeleteDevice));
}

#[test]
fn feature_gates_are_pinned() {
    use Feature::*;
    let gated = |p: Perm| {
        required_features(p)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
    };
    for r in ROWS {
        let name = r.perm.name();
        let want: Vec<Feature> = if matches!(
            r.perm,
            Perm::MembersReadRolesCatalogue | Perm::MembersPreferencesManageSelf
        ) {
            vec![]
        } else if r.perm == Perm::MembersBulkAssignDepartment {
            vec![Subusers, Groups]
        } else if name.starts_with("members.")
            || r.perm == Perm::DevicesAssign
            || r.perm == Perm::AutopilotDonorsCreate
        {
            vec![Subusers]
        } else if name.starts_with("groups.") || name.starts_with("departments.") {
            vec![Groups]
        } else if r.perm == Perm::ActivityReadMembers || r.perm == Perm::SessionsRevokeMembers {
            vec![UserActivity]
        } else if name.starts_with("private_cloud.") {
            vec![PrivateCloud]
        } else {
            vec![]
        };
        assert_eq!(gated(r.perm), want, "{name}");
    }
    // Soft gates (narrow to self): only per-member data; D-65: performance.read is NOT gated.
    assert_eq!(
        narrowing_feature(Perm::AuditReadActions),
        Some(UserActivity)
    );
    assert_eq!(narrowing_feature(Perm::PerformanceErasureMetricsRead), None);
    assert_eq!(narrowing_feature(Perm::PerformanceRead), None);
}

// ---------------------------------------------------------------- staff vs tenant

#[test]
fn staff_and_tenant_realms_are_disjoint() {
    let tenant_names: HashSet<&str> = Perm::ALL.iter().map(|p| p.name()).collect();
    for p in PlatformPerm::ALL {
        assert!(!tenant_names.contains(p.name()));
        assert_eq!(
            Perm::from_name(p.name()),
            None,
            "tenant parse accepted staff perm"
        );
    }
    for p in Perm::ALL {
        assert_eq!(PlatformPerm::from_name(p.name()), None);
    }
    for r in StaffRole::ALL {
        assert_eq!(TenantRole::parse(r.as_str()), None);
    }
    for r in TenantRole::ALL {
        assert_eq!(StaffRole::parse(r.as_str()), None);
    }
    assert_eq!(TenantRole::parse("superadmin"), None);
    assert_eq!(TenantRole::parse("groupadmin"), None);
}

#[test]
fn staff_matrix_special_cases() {
    let none = PlatformContext {
        ticket_ref_present: false,
        owner_approval_present: false,
    };
    let ticket = PlatformContext {
        ticket_ref_present: true,
        owner_approval_present: false,
    };
    let approved = PlatformContext {
        ticket_ref_present: true,
        owner_approval_present: true,
    };

    assert_eq!(
        decide_platform(StaffRole::Support, PlatformPerm::FeaturesToggle, none),
        PlatformDecision::Denied(PlatformDenyReason::TicketRequired)
    );
    assert_eq!(
        decide_platform(StaffRole::Support, PlatformPerm::FeaturesToggle, ticket),
        PlatformDecision::Allowed {
            restricted_view: false
        }
    );
    // Certificate revoke: support only with a ticket, superadmin without.
    assert_eq!(
        decide_platform(StaffRole::Support, PlatformPerm::ReportsRevoke, none),
        PlatformDecision::Denied(PlatformDenyReason::TicketRequired)
    );
    assert!(matches!(
        decide_platform(StaffRole::Support, PlatformPerm::ReportsRevoke, ticket),
        PlatformDecision::Allowed { .. }
    ));
    assert!(matches!(
        decide_platform(StaffRole::Superadmin, PlatformPerm::ReportsRevoke, none),
        PlatformDecision::Allowed { .. }
    ));
    for r in [StaffRole::Billing, StaffRole::Auditor] {
        assert!(platform_grants(r, PlatformPerm::ReportsRevoke).is_none());
    }
    // Cleaner codes: superadmin + billing only (customers can never mint).
    for (r, ok) in [
        (StaffRole::Superadmin, true),
        (StaffRole::Billing, true),
        (StaffRole::Support, false),
        (StaffRole::Auditor, false),
    ] {
        assert_eq!(
            platform_grants(r, PlatformPerm::CleanerCodesMint).is_some(),
            ok,
            "{r:?}"
        );
    }
    for p in [PlatformPerm::KeysRotate, PlatformPerm::TenantErase] {
        assert_eq!(
            decide_platform(StaffRole::Superadmin, p, ticket),
            PlatformDecision::Denied(PlatformDenyReason::OwnerApprovalRequired)
        );
        assert_eq!(
            decide_platform(StaffRole::Superadmin, p, approved),
            PlatformDecision::Allowed {
                restricted_view: false
            }
        );
        for r in [StaffRole::Support, StaffRole::Billing, StaffRole::Auditor] {
            assert_eq!(
                decide_platform(r, p, approved),
                PlatformDecision::Denied(PlatformDenyReason::NoPermission)
            );
        }
    }
    assert_eq!(
        decide_platform(StaffRole::Billing, PlatformPerm::TenantsRead, none),
        PlatformDecision::Allowed {
            restricted_view: true
        }
    );
    assert!(staff_tenant_data_access(StaffRole::Support, true));
    assert!(!staff_tenant_data_access(StaffRole::Support, false));
    assert!(!staff_tenant_data_access(StaffRole::Billing, true));
    assert!(!staff_tenant_data_access(StaffRole::Auditor, true));
    for p in [
        PlatformPerm::TenantsSuspend,
        PlatformPerm::Refunds,
        PlatformPerm::StaffManage,
        PlatformPerm::ReleasesManage,
    ] {
        assert!(platform_grants(StaffRole::Support, p).is_none());
    }
}

// ---------------------------------------------------------------- hierarchy (exhaustive + property)

#[test]
fn can_grant_is_strictly_below_actor() {
    for a in TenantRole::ALL {
        for t in TenantRole::ALL {
            if can_grant(a, t) {
                assert!(t.rank() < a.rank());
            }
        }
    }
    assert!(can_grant(TenantRole::Owner, TenantRole::Admin));
    assert!(can_grant(TenantRole::Admin, TenantRole::Member));
    assert!(!can_grant(TenantRole::Admin, TenantRole::Admin));
    assert!(!can_grant(TenantRole::Admin, TenantRole::Owner));
    assert!(!can_grant(TenantRole::Owner, TenantRole::Owner));
    assert!(!can_grant(TenantRole::Member, TenantRole::Viewer));
}

type St = (u128, u128, TenantRole, MemberStatus, Vec<u128>, Vec<u128>);

fn arb_role() -> impl Strategy<Value = TenantRole> {
    prop_oneof![
        Just(TenantRole::Owner),
        Just(TenantRole::Admin),
        Just(TenantRole::Member),
        Just(TenantRole::Viewer)
    ]
}
fn arb_status() -> impl Strategy<Value = MemberStatus> {
    prop_oneof![
        Just(MemberStatus::Active),
        Just(MemberStatus::Active),
        Just(MemberStatus::Active),
        Just(MemberStatus::Disabled),
        Just(MemberStatus::Suspended),
        Just(MemberStatus::PendingVerification),
        Just(MemberStatus::Deleted)
    ]
}
fn arb_groups() -> impl Strategy<Value = Vec<u128>> {
    prop::collection::vec(1u128..=3, 0..4)
}
fn arb_state() -> impl Strategy<Value = St> {
    (
        1u128..=2,
        1u128..=4,
        arb_role(),
        arb_status(),
        arb_groups(),
        arb_groups(),
    )
}
fn arb_features() -> impl Strategy<Value = FeatureSet> {
    (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|f| FeatureSet {
        subusers: f.0,
        groups: f.1,
        user_activity: f.2,
        private_cloud: f.3,
    })
}
fn mk_actor(s: &St) -> ActorState {
    let mut a = actor_in(s.0, s.1, s.2, &s.4, &s.5);
    a.status = s.3;
    a
}
fn mk_member(s: &St) -> MemberState {
    mk_actor(s).as_member()
}

proptest! {
    #[test]
    fn prop_can_grant_never_equal_or_higher(a in arb_role(), t in arb_role()) {
        if can_grant(a, t) {
            prop_assert!(t.rank() < a.rank());
        }
    }

    #[test]
    fn prop_can_manage_never_equal_or_higher(a in arb_state(), t in arb_state(), f in arb_features()) {
        let actor = mk_actor(&a);
        let target = mk_member(&t);
        if can_manage(&actor, &target, &f) {
            prop_assert!(actor.is_active());
            prop_assert_eq!(actor.tenant, target.tenant);
            prop_assert_ne!(actor.membership, target.membership);
            match actor.role {
                TenantRole::Owner | TenantRole::Admin => {
                    prop_assert!(target.role.rank() < actor.role.rank());
                }
                TenantRole::Member => {
                    // Group admin path: only with the groups toggle ON; effective rank 60 in a shared group.
                    prop_assert!(f.groups);
                    prop_assert!(!actor.ga_groups.is_empty());
                    prop_assert!(actor.ga_groups.iter().any(|g| target.groups.contains(g)));
                    prop_assert!(target.role.rank() < GROUP_ADMIN_RANK);
                    prop_assert!(!actor.ga_groups.iter().any(|g| target.ga_groups.contains(g)));
                }
                TenantRole::Viewer => prop_assert!(false, "viewer managed someone"),
            }
        }
    }

    #[test]
    fn prop_groups_toggle_off_voids_ga(a in arb_state(), t in arb_state()) {
        let mut actor = mk_actor(&a);
        actor.role = TenantRole::Member;
        let target = mk_member(&t);
        let off = all_on().with(Feature::Groups, false);
        prop_assert!(!can_manage(&actor, &target, &off));
        // Visible only if self (a plain member sees nobody else).
        prop_assert_eq!(
            can_view_member(&actor, &target, &off),
            actor.is_active() && actor.tenant == target.tenant && actor.membership == target.membership
        );
    }

    #[test]
    fn prop_decide_never_crosses_tenants(a in arb_state(), t in arb_state(), fi in 0..Perm::ALL.len()) {
        let actor = mk_actor(&a);
        let target_member = mk_member(&t);
        let tgt = Target::of(tenant(t.0), Subject::Member(target_member)).with_new_role(TenantRole::Viewer);
        let d = decide(&actor, Perm::ALL[fi], &all_on(), &full(), &tgt);
        if actor.tenant != tgt.tenant {
            prop_assert!(!d.is_allowed());
        }
    }

    #[test]
    fn prop_viewer_never_writes(
        s in arb_state(), t in arb_state(),
        subj in 0u8..5, fi in 0..Perm::ALL.len(),
        f in arb_features(),
        c in (any::<bool>(), any::<bool>(), any::<bool>()),
    ) {
        let mut v = mk_actor(&s);
        v.role = TenantRole::Viewer;
        v.tenant = tenant(T1);
        v.status = MemberStatus::Active;
        let subject = match subj {
            0 => Subject::Collection,
            1 => Subject::Unowned,
            2 => Subject::Group(gid(1)),
            3 => Subject::Device(did(1)),
            _ => Subject::Member(mk_member(&t)),
        };
        let tgt = Target::of(tenant(T1), subject).with_new_role(TenantRole::Viewer);
        let caps = Capabilities { can_view_reports: c.0, can_manage_machines: c.1, can_assign_licenses: c.2, max_machines: None, credit_allocation: None };
        let p = Perm::ALL[fi];
        if decide(&v, p, &f, &caps, &tgt).is_allowed() {
            prop_assert_ne!(matrix::access_of(p), Some(Access::Write));
        }
    }

    #[test]
    fn prop_group_admin_never_reaches_outside_own_groups(
        t in arb_state(), fi in 0..Perm::ALL.len(),
        ga in prop::collection::vec(1u128..=2, 1..3),
    ) {
        let g = actor(3, TenantRole::Member, &[1, 2], &ga);
        let mut tm = mk_member(&t);
        tm.tenant = tenant(T1);
        let tgt = Target::member(&tm);
        let p = Perm::ALL[fi];
        if let Decision::Allowed(Scope::Group) = decide(&g, p, &all_on(), &full(), &tgt) {
            let shares = g.ga_groups.iter().any(|x| tm.groups.contains(x));
            prop_assert!(tm.membership == g.membership || (shares && tm.role.rank() < GROUP_ADMIN_RANK));
        }
    }

    #[test]
    fn prop_allowed_scope_never_exceeds_matrix(a in arb_state(), fi in 0..Perm::ALL.len()) {
        let actor = mk_actor(&a);
        let p = Perm::ALL[fi];
        let tgt = Target::collection(actor.tenant);
        if let Decision::Allowed(s) = decide(&actor, p, &all_on(), &full(), &tgt) {
            let base = grants(actor.role, p).map_or(0, Scope::breadth);
            let ga = if actor.role == TenantRole::Member && !actor.ga_groups.is_empty() {
                ga_grants(p).map_or(0, Scope::breadth)
            } else { 0 };
            prop_assert!(s.breadth() <= base.max(ga));
        }
    }

    // Lifecycle goes through decide(): whatever validate_member_change allows, the matrix grants the
    // actor members.disable / members.delete (a GA never does) and the subusers toggle is on.
    #[test]
    fn prop_lifecycle_requires_matrix_grant(a in arb_state(), t in arb_state(), f in arb_features(), del in any::<bool>()) {
        let actor = mk_actor(&a);
        let target = mk_member(&t);
        let spare = member_in(T1, 99, TenantRole::Owner, &[], &[]);
        let change = if del { MemberChange::Delete { transfer_to: Some(&spare) } } else { MemberChange::Disable };
        if validate_member_change(&actor, &target, change, &f, 5).is_ok() {
            prop_assert!(matches!(actor.role, TenantRole::Owner | TenantRole::Admin));
            prop_assert!(f.subusers);
        }
    }
}

// ---------------------------------------------------------------- decide(): three checks

#[test]
fn feature_off_denies_even_owner() {
    for r in ROWS {
        for f in r.features.iter().flatten() {
            let feats = all_on().with(*f, false);
            let d = decide(&owner(), r.perm, &feats, &full(), &coll());
            assert_eq!(
                d,
                Decision::Denied(DenyReason::FeatureDisabled(*f)),
                "{}",
                r.perm
            );
        }
    }
    let off = FeatureSet::none();
    for p in [
        Perm::MembersRead,
        Perm::GroupsRead,
        Perm::ActivityReadMembers,
        Perm::PrivateCloudRead,
    ] {
        assert!(
            !decide(&owner(), p, &off, &full(), &coll()).is_allowed(),
            "{p}"
        );
    }
    assert_eq!(
        decide(&owner(), Perm::SessionsReadSelf, &off, &full(), &coll()),
        Decision::Allowed(Scope::SelfOnly)
    );
    assert!(decide(&owner(), Perm::ReportsDriveRead, &off, &full(), &coll()).is_allowed());
    // Two-feature perm: either toggle off denies.
    let t = on(&mem_g1());
    for f in [Feature::Subusers, Feature::Groups] {
        let d = decide(
            &owner(),
            Perm::MembersBulkAssignDepartment,
            &all_on().with(f, false),
            &full(),
            &t,
        );
        assert_eq!(d, Decision::Denied(DenyReason::FeatureDisabled(f)));
    }
    assert!(run(&owner(), Perm::MembersBulkAssignDepartment, &t).is_allowed());
}

#[test]
fn d65_performance_is_org_level_and_always_on() {
    let off = all_on().with(Feature::UserActivity, false);
    for a in [owner(), admin()] {
        assert_eq!(
            decide(&a, Perm::PerformanceRead, &off, &full(), &agg()),
            Decision::Allowed(Scope::Tenant)
        );
    }
    assert_eq!(
        decide(
            &owner(),
            Perm::PerformanceRead,
            &FeatureSet::none(),
            &full(),
            &agg()
        ),
        Decision::Allowed(Scope::Tenant)
    );
    // Per-member activity IS gated by the toggle.
    for p in [Perm::ActivityReadMembers, Perm::SessionsRevokeMembers] {
        assert_eq!(
            decide(&owner(), p, &off, &full(), &on(&mem_g1())),
            Decision::Denied(DenyReason::FeatureDisabled(Feature::UserActivity))
        );
    }
    // Per-member action log narrows to self when the toggle is off.
    assert_eq!(
        decide(&owner(), Perm::AuditReadActions, &off, &full(), &coll()),
        Decision::Allowed(Scope::SelfOnly)
    );
    assert_eq!(
        decide(
            &owner(),
            Perm::AuditReadActions,
            &off,
            &full(),
            &on(&mem_g1())
        ),
        Decision::Denied(DenyReason::OutOfScope)
    );
    assert_eq!(
        decide(
            &owner(),
            Perm::AuditReadActions,
            &all_on(),
            &full(),
            &on(&mem_g1())
        ),
        Decision::Allowed(Scope::Tenant)
    );
    assert!(!run(&viewer_g1(), Perm::AuditReadActions, &coll()).is_allowed());
    assert!(
        decide(
            &viewer_g1(),
            Perm::ActivityReadSelf,
            &FeatureSet::none(),
            &full(),
            &coll()
        )
        .is_allowed()
    );
}

#[test]
fn tenant_check_and_actor_state() {
    let other = Target::collection(tenant(T2));
    assert_eq!(
        run(&owner(), Perm::DevicesRead, &other),
        Decision::Denied(DenyReason::CrossTenant)
    );
    let foreign_member = member_in(T2, 9, TenantRole::Member, &[], &[]);
    assert_eq!(
        run(
            &owner(),
            Perm::DevicesRead,
            &Target::member(&foreign_member)
        ),
        Decision::Denied(DenyReason::CrossTenant)
    );
    let confused = Target::of(tenant(T1), Subject::Member(foreign_member));
    assert_eq!(
        run(&owner(), Perm::DevicesRead, &confused),
        Decision::Denied(DenyReason::CrossTenant)
    );
    for st in [
        MemberStatus::Disabled,
        MemberStatus::Suspended,
        MemberStatus::PendingVerification,
        MemberStatus::Deleted,
    ] {
        let mut o = owner();
        o.status = st;
        assert_eq!(
            run(&o, Perm::DevicesRead, &coll()),
            Decision::Denied(DenyReason::ActorInactive)
        );
    }
}

#[test]
fn denied_reason_codes_are_stable() {
    assert_eq!(DenyReason::Hierarchy.code(), "members.rank");
    assert_eq!(
        DenyReason::FeatureDisabled(Feature::Groups).code(),
        "feature.disabled"
    );
    assert_eq!(DenyReason::CrossTenant.code(), "authz.cross_tenant");
}

// ---------------------------------------------------------------- E-cases

#[test]
fn e1_admin_cannot_grant_admin_or_owner() {
    for r in [TenantRole::Admin, TenantRole::Owner] {
        let create = coll().with_new_role(r);
        assert_eq!(
            run(&admin(), Perm::MembersCreate, &create),
            Decision::Denied(DenyReason::Hierarchy)
        );
        let assign = on(&mem_g1()).with_new_role(r);
        assert_eq!(
            run(&admin(), Perm::MembersAssignRole, &assign),
            Decision::Denied(DenyReason::Hierarchy)
        );
    }
    assert_eq!(
        run(
            &owner(),
            Perm::MembersCreate,
            &coll().with_new_role(TenantRole::Owner)
        ),
        Decision::Denied(DenyReason::Hierarchy)
    );
    assert!(
        run(
            &admin(),
            Perm::MembersCreate,
            &coll().with_new_role(TenantRole::Member)
        )
        .is_allowed()
    );
    assert!(
        run(
            &owner(),
            Perm::MembersCreate,
            &coll().with_new_role(TenantRole::Admin)
        )
        .is_allowed()
    );
    assert_eq!(
        run(&admin(), Perm::MembersCreate, &coll()),
        Decision::Denied(DenyReason::InvalidTarget)
    );
    // Donor accounts are member creation too.
    assert_eq!(
        run(
            &admin(),
            Perm::AutopilotDonorsCreate,
            &coll().with_new_role(TenantRole::Admin)
        ),
        Decision::Denied(DenyReason::Hierarchy)
    );
}

const MEMBER_WRITES: [Perm; 9] = [
    Perm::MembersCreate,
    Perm::MembersUpdate,
    Perm::MembersAssignRole,
    Perm::MembersSetCapabilities,
    Perm::MembersDisable,
    Perm::MembersEnable,
    Perm::MembersDelete,
    Perm::MembersResetPassword,
    Perm::MembersTransferResources,
];

#[test]
fn e2_member_and_viewer_cannot_write_members() {
    for who in [mem_g1(), viewer_g1()] {
        for p in MEMBER_WRITES
            .into_iter()
            .chain([Perm::MembersBulkAssignDepartment])
        {
            for tgt in [
                coll().with_new_role(TenantRole::Viewer),
                on(&mem_g2()).with_new_role(TenantRole::Viewer),
                on(&who).with_new_role(TenantRole::Viewer),
            ] {
                assert!(!run(&who, p, &tgt).is_allowed(), "{:?} {p}", who.role);
            }
        }
    }
}

#[test]
fn e3_no_self_escalation() {
    for me in [owner(), admin(), ga_g1(), mem_g1()] {
        for p in [
            Perm::MembersAssignRole,
            Perm::MembersSetCapabilities,
            Perm::MembersEnable,
            Perm::MembersDisable,
            Perm::MembersDelete,
            Perm::MembersUpdate,
            Perm::MembersResetPassword,
            Perm::TenantOwnershipTransfer,
        ] {
            let tgt = on(&me).with_new_role(TenantRole::Owner);
            assert!(!run(&me, p, &tgt).is_allowed(), "{:?} self {p}", me.role);
        }
    }
    // An admin cannot make itself group admin either (grant target must be a member-role membership).
    let t = on(&admin()).with_group(gref(T1, 1));
    assert!(!run(&admin(), Perm::GroupsAssignAdmin, &t).is_allowed());
}

#[test]
fn e4_admin_cannot_touch_admin_or_owner() {
    for victim in [admin2(), owner(), owner2()] {
        // members.create has no victim (creating a plain member is legal); everything else targets one.
        for p in MEMBER_WRITES
            .into_iter()
            .filter(|p| *p != Perm::MembersCreate)
            .chain([
                Perm::SessionsRevokeMembers,
                Perm::TenantOwnershipTransfer,
                Perm::MembersBulkAssignDepartment,
            ])
        {
            let tgt = on(&victim).with_new_role(TenantRole::Member);
            assert!(
                !run(&admin(), p, &tgt).is_allowed(),
                "admin {p} on {:?}",
                victim.role
            );
        }
    }
    assert!(!run(&owner(), Perm::MembersDisable, &on(&owner2())).is_allowed());
    assert!(run(&owner(), Perm::MembersDisable, &on(&admin())).is_allowed());
}

#[test]
fn members_transfer_resources_is_stricter_than_the_spec_cell_for_admin() {
    // Spec cell: Admin T. We still apply rank < 80 (Rule::ManageMember): an admin cannot move a peer
    // admin's or the owner's resources; it can move a member's.
    assert_eq!(
        grants(TenantRole::Admin, Perm::MembersTransferResources),
        Some(Scope::Tenant)
    );
    assert!(!run(&admin(), Perm::MembersTransferResources, &on(&admin2())).is_allowed());
    assert!(!run(&admin(), Perm::MembersTransferResources, &on(&owner())).is_allowed());
    assert!(run(&admin(), Perm::MembersTransferResources, &on(&mem_g1())).is_allowed());
}

#[test]
fn e5_last_owner_rule() {
    let o = owner().as_member();
    assert_eq!(
        check_last_owner(&o, OwnerChange::Disable, 1),
        Err(LastOwner)
    );
    assert_eq!(check_last_owner(&o, OwnerChange::Delete, 1), Err(LastOwner));
    assert_eq!(
        check_last_owner(
            &o,
            OwnerChange::Demote {
                to: TenantRole::Admin
            },
            1
        ),
        Err(LastOwner)
    );
    assert_eq!(
        check_last_owner(&o, OwnerChange::Disable, 0),
        Err(LastOwner),
        "0 = broken, refuse"
    );
    assert_eq!(check_last_owner(&o, OwnerChange::Disable, 2), Ok(()));
    assert_eq!(
        check_last_owner(
            &o,
            OwnerChange::Demote {
                to: TenantRole::Owner
            },
            1
        ),
        Ok(())
    );
    assert_eq!(
        check_last_owner(&admin().as_member(), OwnerChange::Delete, 1),
        Ok(())
    );
    let mut dead = o.clone();
    dead.status = MemberStatus::Disabled;
    assert_eq!(check_last_owner(&dead, OwnerChange::Delete, 1), Ok(()));
}

#[test]
fn last_owner_is_reachable_through_the_lifecycle_validation() {
    let staff = StaffScope::new(&proof(StaffRole::Support, T1))
        .expect("support may use platform.members.support");
    // Staff flow (no tenant actor): disabling / deleting the only active owner is refused.
    let o = owner().as_member();
    let spare = admin().as_member();
    assert_eq!(
        validate_staff_member_change(&staff, &o, MemberChange::Disable, 1),
        Err(MemberChangeError::LastOwner)
    );
    assert_eq!(
        validate_staff_member_change(
            &staff,
            &o,
            MemberChange::Delete {
                transfer_to: Some(&spare)
            },
            1
        ),
        Err(MemberChangeError::LastOwner)
    );
    assert_eq!(
        validate_staff_member_change(&staff, &o, MemberChange::Disable, 2),
        Ok(())
    );
    // Delete still needs the explicit transfer target, before the last-owner check.
    assert_eq!(
        validate_staff_member_change(&staff, &o, MemberChange::Delete { transfer_to: None }, 1),
        Err(MemberChangeError::TransferTargetRequired)
    );
    // A tenant actor can never get that far against an owner: hierarchy refuses first.
    assert_eq!(
        validate_member_change(&owner2(), &o, MemberChange::Disable, &all_on(), 1),
        Err(MemberChangeError::Denied(DenyReason::Hierarchy))
    );
}

#[test]
fn lifecycle_goes_through_the_matrix_group_admin_cannot_disable_or_delete() {
    let victim = mem_g1().as_member();
    let spare = admin().as_member();
    // GA has "-" for members.disable and members.delete, whatever can_manage says.
    assert!(can_manage(&ga_g1(), &victim, &all_on()));
    assert_eq!(
        validate_member_change(&ga_g1(), &victim, MemberChange::Disable, &all_on(), 2),
        Err(MemberChangeError::Denied(DenyReason::NoPermission))
    );
    assert_eq!(
        validate_member_change(
            &ga_g1(),
            &victim,
            MemberChange::Delete {
                transfer_to: Some(&spare)
            },
            &all_on(),
            2
        ),
        Err(MemberChangeError::Denied(DenyReason::NoPermission))
    );
    for p in [
        Perm::MembersDisable,
        Perm::MembersDelete,
        Perm::MembersEnable,
        Perm::MembersAssignRole,
        Perm::MembersResetPassword,
    ] {
        assert_eq!(
            run(&ga_g1(), p, &on(&mem_g1())),
            Decision::Denied(DenyReason::NoPermission),
            "{p}"
        );
    }
    // Subusers toggle off: even the owner cannot run lifecycle changes.
    let off = all_on().with(Feature::Subusers, false);
    assert_eq!(
        validate_member_change(&owner(), &victim, MemberChange::Disable, &off, 2),
        Err(MemberChangeError::Denied(DenyReason::FeatureDisabled(
            Feature::Subusers
        )))
    );
    assert_eq!(
        validate_member_change(&owner(), &victim, MemberChange::Disable, &all_on(), 2),
        Ok(())
    );
}

#[test]
fn groups_toggle_off_gives_the_group_admin_no_extra_rights() {
    let off = all_on().with(Feature::Groups, false);
    let ga = ga_g1();
    let peer = mem_g1().as_member();
    assert!(can_manage(&ga, &peer, &all_on()));
    assert!(can_view_member(&ga, &peer, &all_on()));
    assert!(!can_manage(&ga, &peer, &off));
    assert!(!can_view_member(&ga, &peer, &off));
    assert!(
        can_view_member(&ga, &ga.as_member(), &off),
        "self stays visible"
    );
    // decide(): falls back to plain member rights (self only), group perms are feature-denied.
    for p in [
        Perm::MembersRead,
        Perm::DevicesRead,
        Perm::ReportsDriveRead,
        Perm::LicensesRead,
    ] {
        assert_eq!(
            decide(&ga, p, &off, &full(), &on(&mem_g1())),
            Decision::Denied(DenyReason::OutOfScope),
            "{p}"
        );
    }
    assert!(!decide(&ga, Perm::DevicesUpdate, &off, &full(), &on(&mem_g1())).is_allowed());
    assert_eq!(
        decide(&ga, Perm::GroupsRead, &off, &full(), &coll()),
        Decision::Denied(DenyReason::FeatureDisabled(Feature::Groups))
    );
    let t = on(&mem_g1())
        .with_group(gref(T1, 1))
        .with_group_op(GroupMemberOp::Remove);
    assert!(!decide(&ga, Perm::GroupsManageMembers, &off, &full(), &t).is_allowed());
}

#[test]
fn e6_group_admin_other_group_is_out_of_scope() {
    let ga = ga_g1();
    let other = mem_g2();
    for p in [
        Perm::MembersRead,
        Perm::MembersUpdate,
        Perm::DevicesRead,
        Perm::DevicesUpdate,
        Perm::ReportsDriveRead,
        Perm::LicensesAllocate,
        Perm::ActivityReadMembers,
    ] {
        assert_eq!(
            run(&ga, p, &on(&other)),
            Decision::Denied(DenyReason::OutOfScope),
            "{p}"
        );
    }
    assert_eq!(
        run(&ga, Perm::MembersRead, &on(&mem_g1())),
        Decision::Allowed(Scope::Group)
    );
    assert_eq!(
        run(&ga, Perm::DevicesUpdate, &on(&mem_g1())),
        Decision::Allowed(Scope::Group)
    );
    assert!(!run(&ga, Perm::MembersDisable, &on(&mem_g1())).is_allowed());
    let unowned = Target::of(tenant(T1), Subject::Unowned);
    assert!(!run(&ga, Perm::DevicesRead, &unowned).is_allowed());
    assert!(run(&admin(), Perm::DevicesRead, &unowned).is_allowed());
}

#[test]
fn e6_group_membership_add_is_owner_admin_only_remove_is_open_to_own_group_ga() {
    let ga = ga_g1();
    let add = |who: &ActorState, m: &ActorState, g: u128| {
        let t = on(m)
            .with_group(gref(T1, g))
            .with_group_op(GroupMemberOp::Add);
        run(who, Perm::GroupsManageMembers, &t)
    };
    let remove = |who: &ActorState, m: &ActorState, g: u128| {
        let t = on(m)
            .with_group(gref(T1, g))
            .with_group_op(GroupMemberOp::Remove);
        run(who, Perm::GroupsManageMembers, &t)
    };
    // A GA adding a member of G2 to G1: denied. Adding a G1 member into G1 again: denied too (never add).
    assert!(!add(&ga, &mem_g2(), 1).is_allowed());
    assert!(!add(&ga, &mem_g1(), 1).is_allowed());
    let outsider = actor(10, TenantRole::Member, &[], &[]);
    assert!(!add(&ga, &outsider, 1).is_allowed());
    // A GA removing a member of its own group: allowed (group scope).
    assert_eq!(remove(&ga, &mem_g1(), 1), Decision::Allowed(Scope::Group));
    // Removing from a group it does not administer / a member not in that group: denied.
    assert!(!remove(&ga, &mem_g2(), 2).is_allowed());
    assert!(!remove(&ga, &mem_g1(), 2).is_allowed());
    // Owner and admin may add (and remove), including a member of another group.
    for who in [owner(), admin()] {
        assert!(add(&who, &mem_g2(), 1).is_allowed(), "{:?} add", who.role);
        assert!(add(&who, &outsider, 1).is_allowed());
        assert!(remove(&who, &mem_g1(), 1).is_allowed());
    }
    // Admin cannot add the owner or a peer admin to a group (hierarchy).
    assert!(!add(&admin(), &owner(), 1).is_allowed());
    assert!(!add(&admin(), &admin2(), 1).is_allowed());
    // Missing group / op = invalid target (fail closed), foreign group record = cross tenant.
    assert_eq!(
        run(&owner(), Perm::GroupsManageMembers, &on(&mem_g1())),
        Decision::Denied(DenyReason::InvalidTarget)
    );
    let foreign = on(&mem_g1())
        .with_group(gref(T2, 1))
        .with_group_op(GroupMemberOp::Add);
    assert_eq!(
        run(&owner(), Perm::GroupsManageMembers, &foreign),
        Decision::Denied(DenyReason::CrossTenant)
    );
    // A viewer / plain member can do neither.
    assert!(!remove(&mem_g1(), &mem_g1(), 1).is_allowed());
    assert!(!remove(&viewer_g1(), &mem_g1(), 1).is_allowed());
}

#[test]
fn e7_group_admin_cannot_see_owner_or_admin() {
    let owner_in_g1 = actor(1, TenantRole::Owner, &[1], &[]);
    let admin_in_g1 = actor(2, TenantRole::Admin, &[1], &[]);
    for v in [owner_in_g1, admin_in_g1] {
        for p in [
            Perm::MembersRead,
            Perm::DevicesRead,
            Perm::ReportsDriveRead,
            Perm::CreditsRead,
        ] {
            assert_eq!(
                run(&ga_g1(), p, &on(&v)),
                Decision::Denied(DenyReason::OutOfScope),
                "{p}"
            );
        }
    }
    let peer = actor(9, TenantRole::Member, &[1], &[1]);
    assert!(!run(&ga_g1(), Perm::MembersUpdate, &on(&peer)).is_allowed());
}

#[test]
fn e8_group_admin_cannot_create_group_admin_or_assign_roles() {
    let ga = ga_g1();
    let target = on(&mem_g1())
        .with_new_role(TenantRole::Member)
        .with_group(gref(T1, 1));
    for p in [
        Perm::GroupsAssignAdmin,
        Perm::MembersAssignRole,
        Perm::MembersCreate,
        Perm::GroupsCreate,
        Perm::GroupsDelete,
    ] {
        assert_eq!(
            run(&ga, p, &target),
            Decision::Denied(DenyReason::NoPermission),
            "{p}"
        );
    }
    let grant = |who: &ActorState, m: &ActorState, g: GroupRef| {
        run(who, Perm::GroupsAssignAdmin, &on(m).with_group(g))
    };
    assert!(grant(&admin(), &mem_g1(), gref(T1, 1)).is_allowed());
    assert!(grant(&owner(), &mem_g2(), gref(T1, 2)).is_allowed());
    assert_eq!(
        grant(&admin(), &viewer_g1(), gref(T1, 1)),
        Decision::Denied(DenyReason::Hierarchy)
    );
    assert_eq!(
        grant(&admin(), &admin2(), gref(T1, 1)),
        Decision::Denied(DenyReason::Hierarchy)
    );
    // Group record of another tenant: refused (pure tenant check over the passed record).
    assert_eq!(
        grant(&owner(), &mem_g1(), gref(T2, 1)),
        Decision::Denied(DenyReason::CrossTenant)
    );
    assert_eq!(
        run(&admin(), Perm::GroupsAssignAdmin, &on(&mem_g1())),
        Decision::Denied(DenyReason::InvalidTarget)
    );
    let feats = all_on().with(Feature::Groups, false);
    assert!(!decide(&ga, Perm::DevicesUpdate, &feats, &full(), &on(&mem_g1())).is_allowed());
}

#[test]
fn can_grant_group_admin_checks_actor_and_group_tenant() {
    assert!(can_grant_group_admin(&owner(), &gref(T1, 1)));
    assert!(can_grant_group_admin(&admin(), &gref(T1, 1)));
    assert!(
        !can_grant_group_admin(&owner(), &gref(T2, 1)),
        "group of another tenant"
    );
    assert!(!can_grant_group_admin(&ga_g1(), &gref(T1, 1)));
    assert!(!can_grant_group_admin(&mem_g1(), &gref(T1, 1)));
    let mut off = owner();
    off.status = MemberStatus::Disabled;
    assert!(!can_grant_group_admin(&off, &gref(T1, 1)));
}

#[test]
fn e9_member_lists_members_sees_only_self() {
    assert_eq!(
        run(&mem_g1(), Perm::MembersRead, &coll()),
        Decision::Allowed(Scope::SelfOnly)
    );
    assert_eq!(
        run(&mem_g1(), Perm::MembersRead, &on(&mem_g1())),
        Decision::Allowed(Scope::SelfOnly)
    );
    assert_eq!(
        run(&mem_g1(), Perm::MembersRead, &on(&admin())),
        Decision::Denied(DenyReason::OutOfScope)
    );
    assert_eq!(
        run(&viewer_g1(), Perm::MembersRead, &coll()),
        Decision::Allowed(Scope::SelfOnly)
    );
    assert!(run(&admin(), Perm::MembersRead, &on(&mem_g1())).is_allowed());
    assert!(run(&admin(), Perm::MembersRead, &on(&admin())).is_allowed());
    assert!(!run(&admin(), Perm::MembersRead, &on(&admin2())).is_allowed());
    assert!(!run(&admin(), Perm::MembersRead, &on(&owner())).is_allowed());
}

#[test]
fn d64_owner_sees_every_member_including_co_owners() {
    for v in [owner2(), admin(), mem_g1(), viewer_g1()] {
        assert!(
            run(&owner(), Perm::MembersRead, &on(&v)).is_allowed(),
            "{:?}",
            v.role
        );
    }
    assert!(can_view_member(&owner(), &owner2().as_member(), &all_on()));
    assert!(!can_view_member(
        &owner(),
        &member_in(T2, 9, TenantRole::Member, &[], &[]),
        &all_on()
    ));
    // Owner can see but still cannot manage a co-owner.
    assert!(!can_manage(&owner(), &owner2().as_member(), &all_on()));
}

#[test]
fn e10_cannot_view_reports_sees_only_own() {
    let caps = Capabilities {
        can_view_reports: false,
        ..full()
    };
    let d = decide(&admin(), Perm::ReportsDriveRead, &all_on(), &caps, &coll());
    assert_eq!(d, Decision::Allowed(Scope::SelfOnly));
    let d = decide(
        &admin(),
        Perm::ReportsDriveRead,
        &all_on(),
        &caps,
        &on(&mem_g1()),
    );
    assert_eq!(d, Decision::Denied(DenyReason::OutOfScope));
    assert!(
        decide(
            &admin(),
            Perm::ReportsDriveRead,
            &all_on(),
            &caps,
            &on(&admin())
        )
        .is_allowed()
    );
    for p in [
        Perm::ReportsExport,
        Perm::ReportsExportBatch,
        Perm::ReportsDriveStatisticsRead,
        Perm::ReportsFileFacetsRead,
    ] {
        assert_eq!(
            decide(&admin(), p, &all_on(), &caps, &coll()),
            Decision::Allowed(Scope::SelfOnly),
            "{p}"
        );
    }
    assert_eq!(
        decide(&owner(), Perm::ReportsDriveRead, &all_on(), &caps, &coll()),
        Decision::Allowed(Scope::Tenant)
    );
    assert!(
        decide(
            &mem_g1(),
            Perm::ReportsDriveCreate,
            &all_on(),
            &caps,
            &coll()
        )
        .is_allowed()
    );
}

#[test]
fn e11_cannot_manage_machines_denies_device_changes_for_others() {
    let caps = Capabilities {
        can_manage_machines: false,
        ..full()
    };
    for p in [
        Perm::DevicesAssign,
        Perm::DevicesUpdate,
        Perm::DevicesRemoteCommand,
        Perm::DevicesTransfer,
    ] {
        assert_eq!(
            decide(&admin(), p, &all_on(), &caps, &coll()),
            Decision::Denied(DenyReason::CapabilityOff(CapabilityKind::ManageMachines)),
            "{p}"
        );
    }
    assert!(decide(&owner(), Perm::DevicesAssign, &all_on(), &caps, &coll()).is_allowed());
    assert!(decide(&admin(), Perm::DevicesRead, &all_on(), &caps, &coll()).is_allowed());
}

#[test]
fn d63_member_registers_own_device_without_capability() {
    let caps = Capabilities::default_for(TenantRole::Member); // can_manage_machines = false
    assert!(!caps.can_manage_machines);
    assert_eq!(
        decide(&mem_g1(), Perm::DevicesRegister, &all_on(), &caps, &coll()),
        Decision::Allowed(Scope::SelfOnly)
    );
    assert_eq!(
        decide(
            &mem_g1(),
            Perm::DevicesRegister,
            &all_on(),
            &caps,
            &on(&mem_g1())
        ),
        Decision::Allowed(Scope::SelfOnly)
    );
    // For somebody else: denied (out of self scope), also for a group admin and an admin.
    assert_eq!(
        decide(
            &mem_g1(),
            Perm::DevicesRegister,
            &all_on(),
            &caps,
            &on(&mem_g2())
        ),
        Decision::Denied(DenyReason::OutOfScope)
    );
    let no_cap = Capabilities {
        can_manage_machines: false,
        ..full()
    };
    assert_eq!(
        decide(
            &ga_g1(),
            Perm::DevicesRegister,
            &all_on(),
            &no_cap,
            &on(&mem_g1())
        ),
        Decision::Denied(DenyReason::OutOfScope)
    );
    assert_eq!(
        decide(
            &admin(),
            Perm::DevicesRegister,
            &all_on(),
            &no_cap,
            &on(&mem_g1())
        ),
        Decision::Denied(DenyReason::OutOfScope)
    );
    // With the capability the group admin / admin register for their members.
    assert_eq!(
        decide(
            &ga_g1(),
            Perm::DevicesRegister,
            &all_on(),
            &full(),
            &on(&mem_g1())
        ),
        Decision::Allowed(Scope::Group)
    );
    assert_eq!(
        decide(
            &admin(),
            Perm::DevicesRegister,
            &all_on(),
            &full(),
            &on(&mem_g1())
        ),
        Decision::Allowed(Scope::Tenant)
    );
    // Managing/assigning/updating even own devices still needs the capability.
    for p in [
        Perm::DevicesAssign,
        Perm::DevicesUpdate,
        Perm::DevicesTransfer,
    ] {
        assert!(
            !decide(&mem_g1(), p, &all_on(), &caps, &on(&mem_g1())).is_allowed(),
            "{p}"
        );
    }
    assert!(
        !decide(
            &viewer_g1(),
            Perm::DevicesRegister,
            &all_on(),
            &caps,
            &coll()
        )
        .is_allowed()
    );
    // max_machines still bounds own devices.
    let capped = Capabilities {
        max_machines: Some(1),
        ..caps
    };
    assert!(check_max_machines(&capped, 1, 1).is_err());
}

#[test]
fn can_assign_licenses_narrows_even_admins() {
    let caps = Capabilities {
        can_assign_licenses: false,
        ..full()
    };
    for p in [Perm::LicensesAllocate, Perm::LicensesTransfer] {
        assert!(!decide(&admin(), p, &all_on(), &caps, &coll()).is_allowed());
        assert!(decide(&owner(), p, &all_on(), &caps, &coll()).is_allowed());
    }
    assert!(decide(&admin(), Perm::LicensesRead, &all_on(), &caps, &coll()).is_allowed());
}

#[test]
fn e12_e13_quota_rules() {
    let caps = Capabilities {
        max_machines: Some(3),
        ..full()
    };
    assert_eq!(check_max_machines(&caps, 2, 1), Ok(()));
    let e = check_max_machines(&caps, 3, 1).expect_err("at limit");
    assert_eq!((e.quota, e.limit, e.current), ("max_machines", 3, 3));
    assert_eq!(
        check_max_machines(&full(), u32::MAX, 1),
        Ok(()),
        "unlimited"
    );

    let q = Quotas {
        max_members: Some(5),
        max_groups: Some(1),
        max_departments: None,
        max_licenses: Some(0),
    };
    assert_eq!(check_quota(&q, QuotaKind::Members, 4, 1), Ok(()));
    assert_eq!(
        check_quota(&q, QuotaKind::Members, 5, 1)
            .expect_err("x")
            .quota,
        "max_members"
    );
    assert_eq!(
        check_quota(&q, QuotaKind::Members, 4, 2)
            .expect_err("x")
            .limit,
        5
    );
    assert_eq!(
        check_quota(&q, QuotaKind::Groups, 1, 1)
            .expect_err("x")
            .quota,
        "max_groups"
    );
    assert_eq!(
        check_quota(&q, QuotaKind::Departments, 1_000, 1_000),
        Ok(()),
        "NULL = unlimited"
    );
    assert!(check_quota(&q, QuotaKind::Licenses, 0, 1).is_err());
    assert!(
        check_quota(&q, QuotaKind::Members, u32::MAX, 1).is_err(),
        "overflow = exceeded"
    );
    assert_eq!(quota_for(Perm::MembersCreate), Some(QuotaKind::Members));
    assert_eq!(quota_for(Perm::GroupsCreate), Some(QuotaKind::Groups));
    assert_eq!(quota_for(Perm::LicensesAllocate), Some(QuotaKind::Licenses));
    assert_eq!(quota_for(Perm::DevicesRead), None);
}

#[test]
fn e15_tenant_roles_have_no_platform_powers() {
    assert_eq!(Perm::from_name("platform.features.toggle"), None);
    assert_eq!(Perm::from_name("platform.quotas.update"), None);
    assert_eq!(Perm::from_name("platform.cleaner_codes.mint"), None);
    for p in Perm::ALL {
        assert!(!p.name().contains("features.toggle") && !p.name().contains("quotas"));
    }
    assert!(grants(TenantRole::Admin, Perm::TenantSettingsUpdate).is_none());
}

#[test]
fn e16_role_downgrade_changes_the_decision() {
    let mut a = admin();
    assert!(run(&a, Perm::MembersDisable, &on(&mem_g1())).is_allowed());
    a.role = TenantRole::Member;
    assert!(!run(&a, Perm::MembersDisable, &on(&mem_g1())).is_allowed());
}

#[test]
fn e19_e27_step_up_flags() {
    assert!(requires_step_up(Perm::DevicesRemoteWipe));
    assert!(requires_confirm(Perm::DevicesRemoteWipe));
    assert!(requires_step_up(Perm::TenantOwnershipTransfer));
    assert!(
        !requires_step_up(Perm::DevicesRemoteCommand),
        "remote_command: step-up nahi"
    );
    assert!(run(&admin(), Perm::DevicesRemoteWipe, &on(&mem_g1())).is_allowed());
    assert!(!run(&ga_g1(), Perm::DevicesRemoteWipe, &on(&mem_g1())).is_allowed());
    assert!(run(&owner(), Perm::TenantOwnershipTransfer, &on(&admin())).is_allowed());
    assert!(!run(&admin(), Perm::TenantOwnershipTransfer, &on(&mem_g1())).is_allowed());
    assert!(!run(&owner(), Perm::TenantOwnershipTransfer, &on(&owner2())).is_allowed());
}

#[test]
fn new_contract_permissions_have_the_documented_gates() {
    assert!(run(&admin(), Perm::LicensesRevoke, &coll()).is_allowed());
    assert!(!run(&ga_g1(), Perm::LicensesRevoke, &coll()).is_allowed());
    assert!(!run(&mem_g1(), Perm::LicensesRevoke, &coll()).is_allowed());
    assert!(requires_confirm(Perm::AutopilotIntuneDeleteDevice));
    assert!(run(&owner(), Perm::AutopilotIntuneDeleteDevice, &coll()).is_allowed());
    assert!(!run(&ga_g1(), Perm::AutopilotIntuneDeleteDevice, &coll()).is_allowed());
    assert_eq!(
        run(&mem_g1(), Perm::AuditReadActions, &coll()),
        Decision::Allowed(Scope::SelfOnly)
    );
    assert_eq!(
        run(&ga_g1(), Perm::AuditReadActions, &on(&mem_g1())),
        Decision::Allowed(Scope::Group)
    );
    assert_eq!(
        required_product(Perm::ReportsFileOfflineUpload),
        Some(Product::File)
    );
    assert_eq!(
        required_product(Perm::FreezeReportsRead),
        Some(Product::Freeze)
    );
    assert_eq!(
        required_product(Perm::CleanerTransactionsRead),
        Some(Product::Cleaner)
    );
    assert_eq!(
        required_product(Perm::AutopilotUemRecheckRun),
        Some(Product::Autopilot)
    );
    assert_eq!(required_product(Perm::ReportsExportBatch), None);
}

// ---------------------------------------------------------------- device principals

fn dev(operator: Option<ActorState>, scopes: &[DeviceScope]) -> DeviceActor {
    DeviceActor {
        tenant: tenant(T1),
        device: did(100),
        owner: operator.as_ref().map(|o| o.membership),
        scopes: SmallVec::from_slice(scopes),
        operator,
    }
}

#[test]
fn e20_device_scopes_reach_only_app_perms() {
    let all: Vec<DeviceScope> = DeviceScope::ALL.to_vec();
    let allowed: HashSet<Perm> = all.iter().flat_map(|s| s.perms().iter().copied()).collect();
    for p in Perm::ALL {
        assert_eq!(device_allows(&all, *p), allowed.contains(p));
    }
    for p in [
        Perm::MembersRead,
        Perm::DevicesRemoteWipe,
        Perm::TenantSettingsRead,
        Perm::LicensesAllocate,
        Perm::BillingManage,
        Perm::LicensesRevoke,
        Perm::AutopilotIntuneDeleteDevice,
    ] {
        assert!(!device_allows(&all, p), "device reaches {p}");
    }
    assert_eq!(
        DeviceScope::parse("device:heartbeat"),
        Some(DeviceScope::Heartbeat)
    );
    assert_eq!(DeviceScope::parse("members.read"), None);
    let names: HashSet<&str> = DeviceScope::ALL.iter().map(|s| s.name()).collect();
    assert_eq!(names.len(), DeviceScope::ALL.len());
    assert!(
        DeviceScope::ALL
            .iter()
            .all(|s| s.name().starts_with("device:"))
    );

    let d = dev(Some(mem_g1()), &[DeviceScope::ReportsReserve]);
    let caps = full();
    let go = |p, t: &Target| decide_device(&d, p, &all_on(), &caps, t);
    assert_eq!(
        go(Perm::ReportsDriveCreate, &coll()),
        Decision::Allowed(Scope::SelfOnly)
    );
    assert!(
        !go(Perm::CreditsConsume, &coll()).is_allowed(),
        "scope not granted"
    );
    assert!(!go(Perm::MembersRead, &coll()).is_allowed());
    assert_eq!(
        go(Perm::ReportsDriveCreate, &Target::collection(tenant(T2))),
        Decision::Denied(DenyReason::CrossTenant)
    );
    let mut dis = d.clone();
    if let Some(op) = dis.operator.as_mut() {
        op.status = MemberStatus::Disabled;
    }
    assert_eq!(
        decide_device(&dis, Perm::ReportsDriveCreate, &all_on(), &caps, &coll()),
        Decision::Denied(DenyReason::ActorInactive)
    );
    let vw = dev(Some(viewer_g1()), &[DeviceScope::ReportsReserve]);
    assert!(!decide_device(&vw, Perm::ReportsDriveCreate, &all_on(), &caps, &coll()).is_allowed());
}

#[test]
fn device_without_operator_is_bound_to_itself_and_its_owner() {
    let mut bound = dev(
        None,
        &[DeviceScope::ReportsUpload, DeviceScope::CreditsConsume],
    );
    bound.owner = Some(mid(4));
    let caps = full();
    let go = |dv: &DeviceActor, p, s: Subject| {
        decide_device(dv, p, &all_on(), &caps, &Target::of(tenant(T1), s))
    };
    // Collection (its own tenant-level call), itself, and its owning member: allowed.
    assert_eq!(
        go(&bound, Perm::ReportsDriveCreate, Subject::Collection),
        Decision::Allowed(Scope::SelfOnly)
    );
    assert_eq!(
        go(&bound, Perm::ReportsDriveCreate, Subject::Device(did(100))),
        Decision::Allowed(Scope::SelfOnly)
    );
    assert_eq!(
        go(
            &bound,
            Perm::CreditsConsume,
            Subject::Member(mem_g1().as_member())
        ),
        Decision::Allowed(Scope::SelfOnly)
    );
    // Anything else is denied: another device, another member, a group, the unowned pool.
    for s in [
        Subject::Device(did(101)),
        Subject::Member(mem_g2().as_member()),
        Subject::Member(admin().as_member()),
        Subject::Group(gid(1)),
        Subject::Unowned,
    ] {
        assert_eq!(
            go(&bound, Perm::ReportsDriveCreate, s.clone()),
            Decision::Denied(DenyReason::OutOfScope),
            "{s:?}"
        );
    }
    // No owner configured at all: only the collection and itself.
    let unowned_dev = dev(None, &[DeviceScope::ReportsUpload]);
    assert!(go(&unowned_dev, Perm::ReportsDriveCreate, Subject::Collection).is_allowed());
    assert!(
        !go(
            &unowned_dev,
            Perm::ReportsDriveCreate,
            Subject::Member(mem_g1().as_member())
        )
        .is_allowed()
    );
    // A member of another tenant can never be bound.
    let foreign = member_in(T2, 4, TenantRole::Member, &[], &[]);
    assert_eq!(
        go(&bound, Perm::ReportsDriveCreate, Subject::Member(foreign)),
        Decision::Denied(DenyReason::CrossTenant)
    );
    // With an operator, the device's own row is the operator's and other members are still refused.
    let with_op = dev(Some(mem_g1()), &[DeviceScope::ReportsUpload]);
    assert!(
        go(
            &with_op,
            Perm::ReportsDriveCreate,
            Subject::Device(did(100))
        )
        .is_allowed()
    );
    assert!(
        !go(
            &with_op,
            Perm::ReportsDriveCreate,
            Subject::Member(mem_g2().as_member())
        )
        .is_allowed()
    );
    assert!(!go(&with_op, Perm::ReportsDriveCreate, Subject::Device(did(7))).is_allowed());
}

#[test]
fn each_new_device_scope_maps_to_its_perms_and_nothing_else() {
    let caps = full();
    let cases: [(DeviceScope, &[Perm]); 4] = [
        (DeviceScope::LicensesOffline, &[Perm::LicensesActivate]),
        (DeviceScope::CreditsOfflineGrantRead, &[Perm::CreditsRead]),
        (
            DeviceScope::FreezeAgent,
            &[
                Perm::ReportsFreezeCreate,
                Perm::FreezeChatSend,
                Perm::FreezeChatRead,
            ],
        ),
        (
            DeviceScope::AutopilotCheck,
            &[Perm::AutopilotDevicesImport, Perm::AutopilotRecheck],
        ),
    ];
    for (scope, perms) in cases {
        assert_eq!(scope.perms(), perms, "{}", scope.name());
        let d = dev(Some(mem_g1()), &[scope]);
        for p in Perm::ALL {
            let r = decide_device(&d, *p, &all_on(), &caps, &coll());
            if perms.contains(p) {
                assert_eq!(
                    r,
                    Decision::Allowed(Scope::SelfOnly),
                    "{} -> {p}",
                    scope.name()
                );
            } else {
                assert!(!r.is_allowed(), "{} leaks {p}", scope.name());
            }
        }
        let no_scope = dev(Some(mem_g1()), &[DeviceScope::Heartbeat]);
        for p in perms {
            assert!(!decide_device(&no_scope, *p, &all_on(), &caps, &coll()).is_allowed());
        }
    }
    assert!(
        DeviceScope::ReportsUpload
            .perms()
            .contains(&Perm::ReportsDriveOfflineUpload)
    );
    assert!(
        !DeviceScope::ReportsUpload
            .perms()
            .contains(&Perm::ReportsFreezeOfflineUpload)
    );
    assert!(DeviceScope::Heartbeat.perms().is_empty());
}

// ---------------------------------------------------------------- lifecycle / misc

#[test]
fn e26_delete_needs_explicit_transfer_target() {
    let victim = mem_g1().as_member();
    let to = admin().as_member();
    let a = owner();
    let f = all_on();
    assert_eq!(
        validate_member_change(
            &a,
            &victim,
            MemberChange::Delete { transfer_to: None },
            &f,
            1
        ),
        Err(MemberChangeError::TransferTargetRequired)
    );
    let foreign = member_in(T2, 9, TenantRole::Admin, &[], &[]);
    assert_eq!(
        validate_member_change(
            &a,
            &victim,
            MemberChange::Delete {
                transfer_to: Some(&foreign)
            },
            &f,
            1
        ),
        Err(MemberChangeError::TransferTargetOtherTenant)
    );
    assert_eq!(
        validate_member_change(
            &a,
            &victim,
            MemberChange::Delete {
                transfer_to: Some(&victim)
            },
            &f,
            1
        ),
        Err(MemberChangeError::TransferTargetInvalid)
    );
    let mut dis = to.clone();
    dis.status = MemberStatus::Disabled;
    assert_eq!(
        validate_member_change(
            &a,
            &victim,
            MemberChange::Delete {
                transfer_to: Some(&dis)
            },
            &f,
            1
        ),
        Err(MemberChangeError::TransferTargetInvalid)
    );
    assert_eq!(
        validate_member_change(
            &a,
            &victim,
            MemberChange::Delete {
                transfer_to: Some(&to)
            },
            &f,
            1
        ),
        Ok(())
    );
    assert_eq!(
        validate_member_change(&a, &victim, MemberChange::Disable, &f, 1),
        Ok(())
    );
    assert_eq!(
        validate_member_change(
            &admin(),
            &admin2().as_member(),
            MemberChange::Disable,
            &f,
            1
        ),
        Err(MemberChangeError::Denied(DenyReason::Hierarchy))
    );
    assert_eq!(
        validate_member_change(
            &admin(),
            &victim,
            MemberChange::Delete {
                transfer_to: Some(&to)
            },
            &f,
            1
        ),
        Ok(())
    );
}

#[test]
fn e28_credit_allocation_rule() {
    let caps = Capabilities {
        credit_allocation: Some(10),
        ..full()
    };
    assert_eq!(check_credit_allocation(&caps, false, 9, 1), Ok(()));
    assert_eq!(
        check_credit_allocation(&caps, false, 10, 1),
        Err(AllocationError::Exceeded {
            limit: 10,
            used: 10
        })
    );
    assert_eq!(
        check_credit_allocation(&full(), false, 1_000, 1),
        Ok(()),
        "pool"
    );
    assert_eq!(
        check_credit_allocation(&full(), true, 0, 1),
        Err(AllocationError::Required)
    );
    assert!(check_credit_allocation(&caps, false, u32::MAX, 1).is_err());
}

#[test]
fn e30_unknown_is_never_allowed() {
    assert_eq!(Perm::from_name(""), None);
    assert_eq!(Perm::from_name("members.everything"), None);
    assert_eq!(Perm::from_name("MEMBERS.READ"), None, "case sensitive");
    assert_eq!(TenantRole::parse("Owner"), None);
    assert_eq!(StaffRole::parse("superadmin"), None);
    assert_eq!(PlatformPerm::from_name("platform.*"), None);
    assert_eq!(Product::parse("export"), None);
}

#[test]
fn group_admin_ignored_for_non_member_roles() {
    let admin_ga = actor(2, TenantRole::Admin, &[1], &[1]);
    assert_eq!(
        run(&admin_ga, Perm::DevicesRead, &coll()),
        Decision::Allowed(Scope::Tenant)
    );
    let viewer_ga = actor(6, TenantRole::Viewer, &[1], &[1]);
    assert!(!run(&viewer_ga, Perm::DevicesUpdate, &on(&mem_g1())).is_allowed());
    assert!(!can_manage(&viewer_ga, &mem_g1().as_member(), &all_on()));
}

#[test]
fn group_scope_visibility_and_tenant_scope_type() {
    let scope = |a: &ActorState, s: Scope| {
        let proof = AuthenticatedActor::__from_authenticated(a.clone());
        TenantScope::from_decision(&proof, Decision::Allowed(s), None).expect("allowed")
    };
    let ga = ga_g1();
    let ts = scope(&ga, Scope::Group);
    assert_eq!(ts.visibility(), &Visibility::Groups(groups(&[1])));
    assert_eq!(ts.tenant(), ga.tenant);
    assert_eq!(ts.actor(), ga.membership);
    assert_eq!(ts.staff_grant(), None);
    assert_eq!(
        scope(&owner(), Scope::Tenant).visibility(),
        &Visibility::Tenant
    );
    assert_eq!(
        scope(&mem_g1(), Scope::SelfOnly).visibility(),
        &Visibility::SelfOnly
    );
    assert_eq!(
        scope(&mem_g1(), Scope::Group).visibility(),
        &Visibility::Groups(SmallVec::new())
    );
    // A denied decision never yields a scope.
    let proof = AuthenticatedActor::__from_authenticated(owner());
    assert_eq!(
        TenantScope::from_decision(&proof, Decision::Denied(DenyReason::OutOfScope), None),
        Err(DenyReason::OutOfScope)
    );
}

#[test]
fn ga_members_update_is_field_limited() {
    assert!(ga_field_limited(Perm::MembersUpdate));
    assert!(!ga_field_limited(Perm::MembersRead));
}

#[test]
fn capability_defaults() {
    let m = Capabilities::default_for(TenantRole::Member);
    assert!(m.can_view_reports && !m.can_manage_machines && !m.can_assign_licenses);
    let a = Capabilities::default_for(TenantRole::Admin);
    assert!(a.can_view_reports && a.can_manage_machines && a.can_assign_licenses);
    assert_eq!(
        Capabilities::default_for(TenantRole::Owner),
        Capabilities::full()
    );
}

#[test]
fn required_products_cover_product_perms() {
    assert_eq!(
        required_product(Perm::ReportsDriveCreate),
        Some(Product::Drive)
    );
    assert_eq!(
        required_product(Perm::FreezeChatSend),
        Some(Product::Freeze)
    );
    assert_eq!(
        required_product(Perm::AutopilotRecheck),
        Some(Product::Autopilot)
    );
    assert_eq!(required_product(Perm::MembersRead), None);
    assert_eq!(
        required_capability(Perm::LicensesTransfer),
        Some(CapabilityKind::AssignLicenses)
    );
}

#[test]
fn d65_erasure_metrics_are_org_level_for_owner_and_admin() {
    let off = all_on().with(Feature::UserActivity, false);
    for a in [owner(), admin()] {
        assert_eq!(
            decide(
                &a,
                Perm::PerformanceErasureMetricsRead,
                &off,
                &full(),
                &agg()
            ),
            Decision::Allowed(Scope::Tenant)
        );
    }
    assert_eq!(
        decide(
            &owner(),
            Perm::PerformanceErasureMetricsRead,
            &FeatureSet::none(),
            &full(),
            &agg()
        ),
        Decision::Allowed(Scope::Tenant)
    );
}

#[test]
fn staff_scope_needs_the_support_permission_and_the_right_tenant() {
    for (r, ok) in [
        (StaffRole::Superadmin, true),
        (StaffRole::Support, true),
        (StaffRole::Billing, false),
        (StaffRole::Auditor, false),
    ] {
        assert_eq!(StaffScope::new(&proof(r, T1)).is_some(), ok, "{r:?}");
    }
    let scope = StaffScope::new(&proof(StaffRole::Support, T1)).expect("scope");
    let foreign = member_in(T2, 9, TenantRole::Member, &[], &[]);
    assert_eq!(
        validate_staff_member_change(&scope, &foreign, MemberChange::Disable, 5),
        Err(MemberChangeError::Denied(DenyReason::CrossTenant))
    );
    // validate_lifecycle (actor-free) is crate-private: tenant handlers cannot call it.
}

#[test]
fn d65_member_level_performance_needs_user_activity() {
    let off = all_on().with(Feature::UserActivity, false);
    let other = on(&mem_g1());
    for p in [Perm::PerformanceRead, Perm::PerformanceErasureMetricsRead] {
        let denied = Decision::Denied(DenyReason::FeatureDisabled(Feature::UserActivity));
        // Toggle OFF: another member's data is refused for owner, admin and group admin.
        for a in [owner(), admin(), ga_g1()] {
            assert_eq!(
                decide(&a, p, &off, &full(), &other),
                denied,
                "{p} {:?}",
                a.role
            );
        }
        // Aggregates (no member identity) and self stay allowed.
        for a in [owner(), admin()] {
            assert_eq!(
                decide(&a, p, &off, &full(), &agg()),
                Decision::Allowed(Scope::Tenant)
            );
        }
        assert!(decide(&mem_g1(), p, &off, &full(), &on(&mem_g1())).is_allowed());
        // Other subject kinds carry no aggregate guarantee: refused too.
        let g = Target::of(tenant(T1), Subject::Group(gid(1)));
        assert_eq!(decide(&owner(), p, &off, &full(), &g), denied);
        // Toggle ON: matrix behaviour.
        assert_eq!(
            decide(&owner(), p, &all_on(), &full(), &other),
            Decision::Allowed(Scope::Tenant)
        );
        assert_eq!(
            decide(&ga_g1(), p, &all_on(), &full(), &other),
            Decision::Allowed(Scope::Group)
        );
    }
}

#[test]
fn donor_accounts_are_member_role_only() {
    let donor = |a: &ActorState, r: TenantRole| {
        run(a, Perm::AutopilotDonorsCreate, &coll().with_new_role(r))
    };
    assert!(donor(&owner(), TenantRole::Member).is_allowed());
    assert!(donor(&admin(), TenantRole::Member).is_allowed());
    for r in [TenantRole::Admin, TenantRole::Owner, TenantRole::Viewer] {
        assert_eq!(
            donor(&owner(), r),
            Decision::Denied(DenyReason::Hierarchy),
            "{r:?}"
        );
    }
    assert_eq!(
        run(&owner(), Perm::AutopilotDonorsCreate, &coll()),
        Decision::Denied(DenyReason::InvalidTarget)
    );
    assert!(!donor(&ga_g1(), TenantRole::Member).is_allowed());
}

#[test]
fn d65_gate_off_list_calls_only_return_own_rows_and_aggregate_is_explicit() {
    let off = all_on().with(Feature::UserActivity, false);
    for p in [Perm::PerformanceRead, Perm::PerformanceErasureMetricsRead] {
        // A per-member list (Collection) is narrowed to the actor's own rows, whoever asks.
        for a in [owner(), admin(), ga_g1(), mem_g1()] {
            assert_eq!(
                decide(&a, p, &off, &full(), &coll()),
                Decision::Allowed(Scope::SelfOnly),
                "{p} {:?}",
                a.role
            );
        }
        // Org totals (Aggregate): owner and admin yes; GA / member refused (fail closed, a group
        // subset could single out one person).
        for a in [owner(), admin()] {
            assert_eq!(
                decide(&a, p, &off, &full(), &agg()),
                Decision::Allowed(Scope::Tenant)
            );
        }
        for a in [ga_g1(), mem_g1(), viewer_g1()] {
            assert_eq!(
                decide(&a, p, &off, &full(), &agg()),
                Decision::Denied(DenyReason::OutOfScope),
                "{:?}",
                a.role
            );
        }
        // Gate ON: Collection keeps the matrix scope and aggregate works as before.
        assert_eq!(
            decide(&owner(), p, &all_on(), &full(), &coll()),
            Decision::Allowed(Scope::Tenant)
        );
        assert_eq!(
            decide(&owner(), p, &all_on(), &full(), &agg()),
            Decision::Allowed(Scope::Tenant)
        );
        assert_eq!(
            decide(&ga_g1(), p, &all_on(), &full(), &coll()),
            Decision::Allowed(Scope::Group)
        );
    }
}

#[test]
fn aggregate_subject_is_refused_by_every_non_aggregate_permission() {
    let accepting: HashSet<Perm> = [Perm::PerformanceRead, Perm::PerformanceErasureMetricsRead]
        .into_iter()
        .collect();
    for r in ROWS {
        assert_eq!(r.aggregate_ok, accepting.contains(&r.perm), "{}", r.perm);
        if !r.aggregate_ok {
            for a in [owner(), admin(), ga_g1(), mem_g1(), viewer_g1()] {
                assert_eq!(
                    decide(&a, r.perm, &all_on(), &full(), &agg()),
                    Decision::Denied(DenyReason::InvalidTarget),
                    "{} {:?}",
                    r.perm,
                    a.role
                );
            }
        }
    }
    // Devices cannot use it either.
    let d = dev(Some(mem_g1()), &[DeviceScope::ReportsUpload]);
    assert!(!decide_device(&d, Perm::ReportsDriveCreate, &all_on(), &full(), &agg()).is_allowed());
}

#[test]
fn d65_gate_off_self_subject_gets_self_scope_only() {
    let off = all_on().with(Feature::UserActivity, false);
    for p in [Perm::PerformanceRead, Perm::PerformanceErasureMetricsRead] {
        for a in [owner(), admin(), ga_g1(), mem_g1()] {
            assert_eq!(
                decide(&a, p, &off, &full(), &on(&a)),
                Decision::Allowed(Scope::SelfOnly),
                "{p} {:?}",
                a.role
            );
        }
        // Gate ON keeps the matrix scope for self.
        assert_eq!(
            decide(&owner(), p, &all_on(), &full(), &on(&owner())),
            Decision::Allowed(Scope::Tenant)
        );
    }
}
