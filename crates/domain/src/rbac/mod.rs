//! `domain::rbac`: permission catalogue, role x permission matrix, hierarchy, capabilities,
//! quotas and the single `decide()`. Source of truth: `docs/RBAC.md`. Pure, no IO.

pub mod caps;
pub mod decide;
pub mod device;
pub mod hierarchy;
pub mod matrix;
pub mod perm;
pub mod platform;
pub mod roles;
pub mod scope;

pub use caps::{
    AllocationError, Capabilities, CapabilityKind, QuotaExceeded, QuotaKind, Quotas,
    check_credit_allocation, check_max_machines, check_quota, quota_for,
};
pub use decide::{Decision, DenyReason, Subject, Target, decide};
pub use device::{DeviceActor, DeviceScope, decide_device, device_allows};
pub use hierarchy::{
    ActorState, GroupIds, GroupMemberOp, GroupRef, LastOwner, MemberChange, MemberChangeError,
    MemberState, OwnerChange, can_grant, can_grant_group_admin, can_manage, can_view_member,
    check_last_owner, validate_member_change,
};
pub use matrix::{
    Access, BULK_STEP_UP_THRESHOLD, Rule, ga_field_limited, ga_grants, grants, narrowing_feature,
    render_matrix, required_capability, required_feature, required_features, required_product,
    requires_confirm, requires_step_up, requires_step_up_bulk,
};
pub use perm::{Perm, PlatformPerm};
pub use platform::{
    PlatformContext, PlatformDecision, PlatformDenyReason, PlatformGrant, StaffScope,
    VerifiedStaffGrant, decide_platform, platform_grants, render_platform_matrix,
    staff_tenant_data_access, validate_staff_member_change,
};
pub use roles::{
    Feature, FeatureSet, GROUP_ADMIN_RANK, MemberStatus, Product, Scope, StaffRole, TenantRole,
};
pub use scope::{AuthenticatedActor, GroupId, TenantScope, Visibility};
