//! The single authorisation decision: tenant check, feature toggle, permission (+ capability
//! narrowing + hierarchy). Anything unknown or unspecified is `Denied` (fail closed).

use common::{DeviceId, GroupId, TenantId};

use super::caps::{Capabilities, CapabilityKind};
use super::hierarchy::{
    ActorState, GroupMemberOp, GroupRef, MemberState, can_grant, can_grant_group_admin, can_manage,
    can_view_member, effective,
};
use super::matrix::{Rule, row_of};
use super::perm::Perm;
use super::roles::{Feature, FeatureSet, GROUP_ADMIN_RANK, MemberStatus, Scope, TenantRole};

/// What the action is applied to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject {
    /// A list / "my own" call with no specific row. Allowed scope is returned; the repository's
    /// `Visibility` filter does the narrowing.
    Collection,
    /// A resource with no owner member (tenant-level pool). Only tenant scope reaches it.
    Unowned,
    /// Org-level totals with NO member identity (e.g. tenant KPIs). Accepted ONLY by permissions whose
    /// matrix row has `aggregate_ok` (today: `performance.read`, `performance.erasure_metrics.read`);
    /// every other permission answers `InvalidTarget` (fail closed). Unlike `Collection` it is never a
    /// per-member list, so the `user_activity` gate lets it through for Tenant scope.
    Aggregate,
    /// A group (groups.* actions).
    Group(GroupId),
    /// A device by id (device-principal binding). For tenant actors it is only reachable at tenant
    /// scope: resolve the device owner and pass `Subject::Member(owner)` for member-scoped checks.
    Device(DeviceId),
    /// A member, or the owning member of the resource (device, report, allocation...).
    Member(MemberState),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Tenant the data belongs to (from the loaded row/path, never from the body).
    pub tenant: TenantId,
    pub subject: Subject,
    /// Role being assigned/created (members.create, members.assign_role). Missing there = denied.
    pub new_role: Option<TenantRole>,
    /// Group record for `groups.assign_admin` and `groups.manage_members`.
    pub group: Option<GroupRef>,
    /// Add/remove for `groups.manage_members`.
    pub group_op: Option<GroupMemberOp>,
}

impl Target {
    #[must_use]
    pub const fn collection(tenant: TenantId) -> Self {
        Self {
            tenant,
            subject: Subject::Collection,
            new_role: None,
            group: None,
            group_op: None,
        }
    }

    #[must_use]
    pub fn of(tenant: TenantId, subject: Subject) -> Self {
        Self {
            subject,
            ..Self::collection(tenant)
        }
    }

    #[must_use]
    pub fn member(m: &MemberState) -> Self {
        Self::of(m.tenant, Subject::Member(m.clone()))
    }

    #[must_use]
    pub const fn with_new_role(mut self, role: TenantRole) -> Self {
        self.new_role = Some(role);
        self
    }

    #[must_use]
    pub const fn with_group(mut self, group: GroupRef) -> Self {
        self.group = Some(group);
        self
    }

    #[must_use]
    pub const fn with_group_op(mut self, op: GroupMemberOp) -> Self {
        self.group_op = Some(op);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// Target (or subject member / group record) belongs to another tenant. API maps to 404, never 403.
    CrossTenant,
    /// Actor not `Active`.
    ActorInactive,
    /// Row missing from the matrix (misaligned table).
    UnknownPermission,
    /// Check #2: feature toggle OFF (even for owner).
    FeatureDisabled(Feature),
    /// Role (and GA grant) has no cell for this permission.
    NoPermission,
    /// Narrowing capability is off.
    CapabilityOff(CapabilityKind),
    /// Subject outside the actor's scope (other group, other member, unowned). API maps to 404.
    OutOfScope,
    /// A rule needs a specific subject / `new_role` / group and none (or the wrong kind) was given.
    InvalidTarget,
    /// Hierarchy: equal/higher rank, self, or role not grantable. `members.rank`.
    Hierarchy,
}

impl DenyReason {
    /// Stable machine code for problem+json.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::CrossTenant => "authz.cross_tenant",
            Self::ActorInactive => "account.inactive",
            Self::UnknownPermission => "authz.unknown_permission",
            Self::FeatureDisabled(_) => "feature.disabled",
            Self::NoPermission => "authz.forbidden",
            Self::CapabilityOff(_) => "authz.capability_off",
            Self::OutOfScope => "authz.out_of_scope",
            Self::InvalidTarget => "authz.invalid_target",
            Self::Hierarchy => "members.rank",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed(Scope),
    Denied(DenyReason),
}

impl Decision {
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }

    #[must_use]
    pub const fn scope(&self) -> Option<Scope> {
        match self {
            Self::Allowed(s) => Some(*s),
            Self::Denied(_) => None,
        }
    }
}

fn is_self(actor: &ActorState, m: &MemberState) -> bool {
    actor.membership == m.membership
}

fn shares(a: &[GroupId], b: &[GroupId]) -> bool {
    a.iter().any(|g| b.contains(g))
}

/// Does `scope` reach `subject`? (Role-specific hierarchy comes after, in `Rule`.)
fn scope_reaches(actor: &ActorState, scope: Scope, subject: &Subject) -> bool {
    match subject {
        Subject::Collection | Subject::Aggregate => true,
        Subject::Unowned | Subject::Device(_) => scope == Scope::Tenant,
        Subject::Group(g) => match scope {
            Scope::Tenant => true,
            Scope::Group => actor.ga_groups.contains(g),
            Scope::SelfOnly => actor.groups.contains(g) || actor.ga_groups.contains(g),
        },
        Subject::Member(m) => match scope {
            Scope::Tenant => true,
            Scope::Group => {
                is_self(actor, m)
                    || (shares(&actor.ga_groups, &m.groups)
                        && m.role.rank() < GROUP_ADMIN_RANK
                        && !shares(&actor.ga_groups, &m.ga_groups))
            }
            Scope::SelfOnly => is_self(actor, m),
        },
    }
}

/// Authorise `actor` for `perm` on `target`.
///
/// Order: actor active, tenant, permission known, feature toggles (hard), role/GA grant, narrowing
/// (feature, capability), scope reaches the subject, hierarchy rule. Owner capabilities are always
/// full. GA grants count only for the `member` role and only while the `groups` feature is ON.
///
/// `groups.manage_members` as a plain scope answer would let a GA "add"; callers MUST pass the group
/// and `group_op` (rule `GroupMembership`): without them it is `InvalidTarget`.
#[must_use]
pub fn decide(
    actor: &ActorState,
    perm: Perm,
    features: &FeatureSet,
    caps: &Capabilities,
    target: &Target,
) -> Decision {
    use Decision::{Allowed, Denied};

    if !actor.is_active() {
        return Denied(DenyReason::ActorInactive);
    }
    if target.tenant != actor.tenant {
        return Denied(DenyReason::CrossTenant);
    }
    if let Subject::Member(m) = &target.subject
        && m.tenant != actor.tenant
    {
        return Denied(DenyReason::CrossTenant);
    }
    if let Some(g) = &target.group
        && g.tenant != actor.tenant
    {
        return Denied(DenyReason::CrossTenant);
    }
    let Some(row) = row_of(perm) else {
        return Denied(DenyReason::UnknownPermission);
    };
    if target.subject == Subject::Aggregate && !row.aggregate_ok {
        return Denied(DenyReason::InvalidTarget);
    }
    for f in row.features.iter().flatten() {
        if !features.has(*f) {
            return Denied(DenyReason::FeatureDisabled(*f));
        }
    }

    // Effective actor: GA grants are inert when `groups` is OFF or the base role is not `member`.
    let eff = effective(actor, features);

    let base = match eff.role {
        TenantRole::Owner => row.cells[0],
        TenantRole::Admin => row.cells[1],
        TenantRole::Member => row.cells[3],
        TenantRole::Viewer => row.cells[4],
    };
    let ga = if eff.is_group_admin() {
        row.cells[2]
    } else {
        None
    };
    let mut scope = match (base, ga) {
        (Some(b), Some(g)) => b.broader(g),
        (Some(s), None) | (None, Some(s)) => s,
        (None, None) => return Denied(DenyReason::NoPermission),
    };

    if let Some(f) = row.narrowed_by
        && !features.has(f)
    {
        scope = Scope::SelfOnly;
    }
    // D-65: org aggregates always; another member's data only with the toggle ON.
    if let Some(f) = row.member_gate
        && !features.has(f)
    {
        match &target.subject {
            // A list call is filtered by `Visibility`, so it could expose every member's row: with the
            // gate OFF it only ever returns the actor's own.
            Subject::Collection => scope = Scope::SelfOnly,
            // Org totals are fine, but only at tenant scope (a group subset could single out a person):
            // GA and members are refused, fail closed.
            Subject::Aggregate if scope == Scope::Tenant => {}
            Subject::Aggregate => return Denied(DenyReason::OutOfScope),
            // Own data only: never hand back a wider scope a handler could reuse for a list.
            Subject::Member(m) if is_self(&eff, m) => scope = Scope::SelfOnly,
            _ => return Denied(DenyReason::FeatureDisabled(f)),
        }
    }
    if let Some(cap) = row.cap
        && eff.role != TenantRole::Owner
        && !caps.has(cap)
    {
        match cap {
            // D-32: only own reports.
            CapabilityKind::ViewReports => scope = scope.narrower(Scope::SelfOnly),
            // D-63: registering one's OWN device needs no capability (scope self); others do.
            CapabilityKind::ManageMachines | CapabilityKind::AssignLicenses if row.cap_self_ok => {
                scope = scope.narrower(Scope::SelfOnly);
            }
            CapabilityKind::ManageMachines | CapabilityKind::AssignLicenses => {
                return Denied(DenyReason::CapabilityOff(cap));
            }
        }
    }

    if !scope_reaches(&eff, scope, &target.subject) {
        return Denied(DenyReason::OutOfScope);
    }

    match row.rule {
        Rule::Free => {}
        Rule::ReadMember => match &target.subject {
            Subject::Collection => {}
            Subject::Member(m) if can_view_member(&eff, m, features) => {}
            Subject::Member(_) => return Denied(DenyReason::OutOfScope),
            _ => return Denied(DenyReason::InvalidTarget),
        },
        Rule::ManageMember => match &target.subject {
            Subject::Member(m) if can_manage(&eff, m, features) => {}
            Subject::Member(_) => return Denied(DenyReason::Hierarchy),
            _ => return Denied(DenyReason::InvalidTarget),
        },
        Rule::NewMember => match target.new_role {
            Some(r) if can_grant(eff.role, r) => {}
            Some(_) => return Denied(DenyReason::Hierarchy),
            None => return Denied(DenyReason::InvalidTarget),
        },
        Rule::NewMemberOnly => match target.new_role {
            Some(TenantRole::Member) if can_grant(eff.role, TenantRole::Member) => {}
            Some(_) => return Denied(DenyReason::Hierarchy),
            None => return Denied(DenyReason::InvalidTarget),
        },
        Rule::AssignRole => match (&target.subject, target.new_role) {
            (Subject::Member(m), Some(r)) => {
                if !can_manage(&eff, m, features) || !can_grant(eff.role, r) {
                    return Denied(DenyReason::Hierarchy);
                }
            }
            _ => return Denied(DenyReason::InvalidTarget),
        },
        Rule::GrantGroupAdmin => match (&target.subject, &target.group) {
            (Subject::Member(m), Some(g)) => {
                if !can_grant_group_admin(&eff, g)
                    || m.role != TenantRole::Member
                    || m.status != MemberStatus::Active
                {
                    return Denied(DenyReason::Hierarchy);
                }
            }
            _ => return Denied(DenyReason::InvalidTarget),
        },
        Rule::GroupMembership => match (&target.subject, &target.group, target.group_op) {
            (Subject::Member(m), Some(g), Some(op)) => {
                if !can_manage(&eff, m, features) {
                    return Denied(DenyReason::Hierarchy);
                }
                match op {
                    // A GA can never add, not even into its own group.
                    GroupMemberOp::Add
                        if !matches!(eff.role, TenantRole::Owner | TenantRole::Admin) =>
                    {
                        return Denied(DenyReason::NoPermission);
                    }
                    GroupMemberOp::Add => {}
                    GroupMemberOp::Remove if scope == Scope::Group => {
                        // GA: own group only, and the member must actually be in it.
                        if !eff.ga_groups.contains(&g.id) || !m.groups.contains(&g.id) {
                            return Denied(DenyReason::OutOfScope);
                        }
                    }
                    GroupMemberOp::Remove => {}
                }
            }
            _ => return Denied(DenyReason::InvalidTarget),
        },
    }

    Allowed(scope)
}
