//! `TenantScope` / `Visibility` (PHASE0_SPEC §3.4). Domain mein rakhe taaki `db` aur `auth` dono
//! `domain` par depend karein (db ko auth nahi chahiye). Pure types, no IO.
//!
//! A `TenantScope` cannot be fabricated by other crates: its fields are private, it has no `Default`
//! and no `Deserialize`, and the only constructors are `TenantScope::from_decision` (needs an
//! `AuthenticatedActor` proof and an `Allowed` decision) and the `test-fixtures` helper.

use common::{GrantId, MembershipId, TenantId};
use smallvec::SmallVec;

use super::decide::{Decision, DenyReason};
use super::hierarchy::ActorState;
use super::roles::Scope;

pub use common::GroupId;

/// Which rows a repository may return/touch (RBAC.md §6.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// `tenant_id = $1` (owner/admin; admin's member lists additionally rank-filtered).
    Tenant,
    /// Rows owned by members of these groups, rank < 60. An EMPTY list matches nothing (fail closed).
    Groups(SmallVec<[GroupId; 4]>),
    /// `owner_membership_id = actor`.
    SelfOnly,
}

/// An actor whose token was verified and whose live state was loaded from the database.
///
/// Domain has no IO, so it cannot verify anything: this type only marks the hand-over (same pattern as
/// `VerifiedStaffGrant`). `__from_authenticated` MUST only be called by `auth::PrincipalStateLoader`,
/// after it has verified the token (audience, signature, expiry, session) and loaded the membership,
/// role, groups and tenant status live. Any other caller defeats tenant isolation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedActor {
    state: ActorState,
}

impl AuthenticatedActor {
    #[doc(hidden)]
    #[must_use]
    pub const fn __from_authenticated(state: ActorState) -> Self {
        Self { state }
    }

    #[must_use]
    pub const fn state(&self) -> &ActorState {
        &self.state
    }
}

/// Mandatory argument of every repository call. Built only from an `Allowed(scope)` decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantScope {
    tenant: TenantId,
    actor: MembershipId,
    visibility: Visibility,
    staff_grant: Option<GrantId>,
}

impl TenantScope {
    /// Visibility from a decision. `Allowed(Group)` takes the actor's GA groups (may be empty = sees
    /// nothing). The `AuthenticatedActor` proof is required, so a forged `Decision::Allowed` alone
    /// cannot produce a scope.
    ///
    /// # Errors
    /// The `DenyReason` of a `Denied` decision.
    pub fn from_decision(
        actor: &AuthenticatedActor,
        decision: Decision,
        staff_grant: Option<GrantId>,
    ) -> Result<Self, DenyReason> {
        let scope = match decision {
            Decision::Allowed(s) => s,
            Decision::Denied(reason) => return Err(reason),
        };
        let a = &actor.state;
        let visibility = match scope {
            Scope::Tenant => Visibility::Tenant,
            Scope::Group => Visibility::Groups(a.ga_groups.clone()),
            Scope::SelfOnly => Visibility::SelfOnly,
        };
        Ok(Self {
            tenant: a.tenant,
            actor: a.membership,
            visibility,
            staff_grant,
        })
    }

    /// Test helper for other crates' tests (enable the `test-fixtures` feature as a dev-dependency).
    /// Never available in normal builds.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[must_use]
    pub const fn for_tests(
        tenant: TenantId,
        actor: MembershipId,
        visibility: Visibility,
        staff_grant: Option<GrantId>,
    ) -> Self {
        Self {
            tenant,
            actor,
            visibility,
            staff_grant,
        }
    }

    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub const fn actor(&self) -> MembershipId {
        self.actor
    }

    #[must_use]
    pub const fn visibility(&self) -> &Visibility {
        &self.visibility
    }

    #[must_use]
    pub const fn staff_grant(&self) -> Option<GrantId> {
        self.staff_grant
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_constructor_round_trips_through_accessors() {
        let t = TenantId::new();
        let m = MembershipId::new();
        let s = TenantScope::for_tests(t, m, Visibility::SelfOnly, None);
        assert_eq!((s.tenant(), s.actor(), s.staff_grant()), (t, m, None));
        assert_eq!(s.visibility(), &Visibility::SelfOnly);
    }
}
