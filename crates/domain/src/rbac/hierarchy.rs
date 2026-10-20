//! Hierarchy rules (RBAC.md §3.3, §6.5): can_grant, can_manage, last-owner, disable vs delete.
//! Pure functions over states the caller loaded live from the DB.

use common::{GroupId, MembershipId, TenantId};
use smallvec::SmallVec;

use super::caps::Capabilities;
use super::decide::{Decision, DenyReason, Target, decide};
use super::matrix::grants;
use super::perm::Perm;
use super::roles::{FeatureSet, GROUP_ADMIN_RANK, MemberStatus, TenantRole};

pub type GroupIds = SmallVec<[GroupId; 4]>;

/// A group record as loaded by the caller (pure check over the passed record: its tenant must be the
/// actor's tenant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupRef {
    pub tenant: TenantId,
    pub id: GroupId,
}

/// `groups.manage_members` is two different acts: ADD is owner/admin only, REMOVE is also open to a
/// group admin for its own groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupMemberOp {
    Add,
    Remove,
}

/// The caller, from live state (never from token claims alone).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorState {
    pub tenant: TenantId,
    pub membership: MembershipId,
    pub role: TenantRole,
    pub status: MemberStatus,
    /// Groups the actor belongs to.
    pub groups: GroupIds,
    /// Groups the actor is group admin of (`group_admin_grants`). Only a `member` role can use them.
    pub ga_groups: GroupIds,
}

/// A member being acted on (or the owner of a resource being acted on).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberState {
    pub tenant: TenantId,
    pub membership: MembershipId,
    pub role: TenantRole,
    pub status: MemberStatus,
    pub groups: GroupIds,
    pub ga_groups: GroupIds,
}

impl ActorState {
    #[must_use]
    pub fn as_member(&self) -> MemberState {
        MemberState {
            tenant: self.tenant,
            membership: self.membership,
            role: self.role,
            status: self.status,
            groups: self.groups.clone(),
            ga_groups: self.ga_groups.clone(),
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == MemberStatus::Active
    }

    /// Group-admin power is real only for the `member` role (owner/admin have tenant scope,
    /// viewer is read-only) and only while the `groups` feature is on (caller clears it otherwise).
    #[must_use]
    pub fn is_group_admin(&self) -> bool {
        self.role == TenantRole::Member && !self.ga_groups.is_empty()
    }
}

impl MemberState {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == MemberStatus::Active
    }
}

fn shares_group(a: &[GroupId], b: &[GroupId]) -> bool {
    a.iter().any(|g| b.contains(g))
}

/// Target is itself a group admin in a group the actor also administers: effective rank there is 60,
/// so an equal-rank GA cannot manage it.
fn is_peer_ga(actor: &ActorState, target: &MemberState) -> bool {
    shares_group(&actor.ga_groups, &target.ga_groups)
}

/// Role-level grant rule: actor needs `members.assign_role` and the target role must be strictly
/// below the actor's rank (nobody grants an equal or higher role; owner only via ownership transfer).
#[must_use]
pub fn can_grant(actor: TenantRole, target: TenantRole) -> bool {
    grants(actor, Perm::MembersAssignRole).is_some() && target.rank() < actor.rank()
}

/// The actor as seen with the `groups` toggle applied: GA grants are void when it is OFF, and only the
/// `member` role can carry them.
pub(crate) fn effective(actor: &ActorState, features: &FeatureSet) -> ActorState {
    let mut e = actor.clone();
    if !features.groups || e.role != TenantRole::Member {
        e.ga_groups.clear();
    }
    e
}

/// Can `actor` act on member `target` (edit, disable, delete, reset password, revoke sessions...)?
/// Owner/admin: target rank strictly lower (so nobody manages an equal or higher rank). Group admin
/// (only while the `groups` toggle is ON): target must share one of the actor's GA groups, have base
/// rank < 60 and not be a peer GA. Never self, never cross-tenant, never when the actor is not active.
/// This is only the *hierarchy* half: whether the actor's role may do the specific action at all is
/// the matrix (`decide`); lifecycle callers must go through `decide` (see `validate_member_change`).
#[must_use]
pub fn can_manage(actor: &ActorState, target: &MemberState, features: &FeatureSet) -> bool {
    let actor = &effective(actor, features);
    if !actor.is_active() || actor.tenant != target.tenant || actor.membership == target.membership
    {
        return false;
    }
    match actor.role {
        TenantRole::Owner | TenantRole::Admin => target.role.rank() < actor.role.rank(),
        TenantRole::Member => {
            actor.is_group_admin()
                && shares_group(&actor.ga_groups, &target.groups)
                && target.role.rank() < GROUP_ADMIN_RANK
                && !is_peer_ga(actor, target)
        }
        TenantRole::Viewer => false,
    }
}

/// D-64: can `actor` *see* member `target`? Self always; owner EVERY member of the tenant including
/// co-owners; admin strictly lower rank plus self; GA (toggle ON) own-group members below rank 60;
/// member/viewer only self ("upar wale neeche ko dekhein, neeche wale upar ko kabhi nahi", RBAC.md §2).
#[must_use]
pub fn can_view_member(actor: &ActorState, target: &MemberState, features: &FeatureSet) -> bool {
    let actor = &effective(actor, features);
    if !actor.is_active() || actor.tenant != target.tenant {
        return false;
    }
    if actor.membership == target.membership {
        return true;
    }
    match actor.role {
        TenantRole::Owner => true,
        TenantRole::Admin => target.role.rank() < actor.role.rank(),
        TenantRole::Member => {
            actor.is_group_admin()
                && shares_group(&actor.ga_groups, &target.groups)
                && target.role.rank() < GROUP_ADMIN_RANK
                && !is_peer_ga(actor, target)
        }
        TenantRole::Viewer => false,
    }
}

/// `groups.assign_admin`: only owner/admin create group admins (group admins cannot), and only inside
/// their own tenant (pure check over the passed group record). The target must additionally be an
/// active `member`-role membership (checked in `decide`).
#[must_use]
pub fn can_grant_group_admin(actor: &ActorState, group: &GroupRef) -> bool {
    actor.is_active()
        && matches!(actor.role, TenantRole::Owner | TenantRole::Admin)
        && group.tenant == actor.tenant
}

/// A change that may remove an active owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerChange {
    Demote { to: TenantRole },
    Disable,
    Delete,
}

/// `409 members.last_owner`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LastOwner;

/// Last-owner rule: the change would leave the tenant without an active owner.
/// `active_owner_count` is read under `SELECT ... FOR UPDATE` on the tenant row (0 = broken state, also refused).
///
/// # Errors
/// `LastOwner` if `target` is an active owner, the change removes owner status, and it is the last one.
pub fn check_last_owner(
    target: &MemberState,
    change: OwnerChange,
    active_owner_count: u32,
) -> Result<(), LastOwner> {
    let removes_owner = match change {
        OwnerChange::Demote { to } => to != TenantRole::Owner,
        OwnerChange::Disable | OwnerChange::Delete => true,
    };
    if target.role == TenantRole::Owner
        && target.is_active()
        && removes_owner
        && active_owner_count <= 1
    {
        return Err(LastOwner);
    }
    Ok(())
}

/// A member lifecycle change. Disable and delete differ: disable = reversible, no transfer;
/// delete = soft delete with an explicit `transfer_to` (RBAC.md §6.5; missing = 400, no silent default).
#[derive(Clone, Copy, Debug)]
pub enum MemberChange<'a> {
    Disable,
    Delete {
        transfer_to: Option<&'a MemberState>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberChangeError {
    /// 400: delete without `transfer_to`.
    TransferTargetRequired,
    /// 404: `transfer_to` is in another tenant.
    TransferTargetOtherTenant,
    /// 409/400: `transfer_to` is not active, or is the member being deleted.
    TransferTargetInvalid,
    /// The actor may not do this (role/matrix, hierarchy, feature, tenant): the `decide` reason.
    Denied(DenyReason),
    /// 409 `members.last_owner`.
    LastOwner,
}

/// Actor-independent lifecycle rules: transfer target (required for delete, same tenant, active, not the
/// member itself) and the last-owner rule. Used by `validate_member_change` after authorisation and
/// directly by staff flows (platform support disabling a customer owner), where `LastOwner` is
/// reachable. A tenant actor can never outrank an owner, so for tenant actors `LastOwner` cannot fire.
///
/// # Errors
/// See `MemberChangeError`.
pub(crate) fn validate_lifecycle(
    target: &MemberState,
    change: MemberChange<'_>,
    active_owner_count: u32,
) -> Result<(), MemberChangeError> {
    if let MemberChange::Delete { transfer_to } = change {
        let Some(to) = transfer_to else {
            return Err(MemberChangeError::TransferTargetRequired);
        };
        if to.tenant != target.tenant {
            return Err(MemberChangeError::TransferTargetOtherTenant);
        }
        if to.membership == target.membership || !to.is_active() {
            return Err(MemberChangeError::TransferTargetInvalid);
        }
    }
    let owner_change = match change {
        MemberChange::Disable => OwnerChange::Disable,
        MemberChange::Delete { .. } => OwnerChange::Delete,
    };
    check_last_owner(target, owner_change, active_owner_count)
        .map_err(|LastOwner| MemberChangeError::LastOwner)
}

/// Full validation for a tenant actor disabling/deleting a member. The actor part goes through
/// `decide()` for the exact permission (`members.disable` / `members.delete`), so the matrix applies
/// (a group admin has "-" for both, whatever `can_manage` says), the `subusers` toggle applies, tenant
/// and hierarchy apply. A missing `transfer_to` is reported first (400 beats 403 so the UI learns
/// what is missing).
///
/// # Errors
/// See `MemberChangeError`.
pub fn validate_member_change(
    actor: &ActorState,
    target: &MemberState,
    change: MemberChange<'_>,
    features: &FeatureSet,
    active_owner_count: u32,
) -> Result<(), MemberChangeError> {
    if let MemberChange::Delete { transfer_to: None } = change {
        return Err(MemberChangeError::TransferTargetRequired);
    }
    let perm = match change {
        MemberChange::Disable => Perm::MembersDisable,
        MemberChange::Delete { .. } => Perm::MembersDelete,
    };
    // No capability is attached to these perms, so `full()` only satisfies the signature.
    match decide(
        actor,
        perm,
        features,
        &Capabilities::full(),
        &Target::member(target),
    ) {
        Decision::Allowed(_) => {}
        Decision::Denied(reason) => return Err(MemberChangeError::Denied(reason)),
    }
    validate_lifecycle(target, change, active_owner_count)
}
