//! Fixture principals: one [`Persona`] per row of the authz matrix. A persona carries the bearer
//! token (minted by the REAL issuer) and the identity facts the oracle needs; it never carries a
//! password, and `Debug` never prints the token.

use common::{MembershipId, TenantId, UserId};
use domain::rbac::TenantRole;

/// What kind of caller a persona is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersonaKind {
    /// No `Authorization` header.
    Anonymous,
    /// A bearer value that is not a JWT.
    Garbage,
    /// A correctly signed member token whose `exp` is in the past.
    Expired,
    /// Tenant member (web audience, password login through `AuthService`).
    Member,
    /// Enrolled device principal (device audience).
    Device,
    /// Platform staff (platform audience).
    Staff,
}

#[derive(Clone)]
pub struct Persona {
    pub name: &'static str,
    pub kind: PersonaKind,
    pub tenant: Option<TenantId>,
    pub membership: Option<MembershipId>,
    pub user: Option<UserId>,
    pub role: Option<TenantRole>,
    /// Bearer token (`None` = anonymous).
    pub token: Option<String>,
    /// Why this persona exists / what it must never do (shown in mismatch reports).
    pub note: &'static str,
}

impl std::fmt::Debug for Persona {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Persona")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("tenant", &self.tenant)
            .field("role", &self.role)
            .field("has_token", &self.token.is_some())
            .finish()
    }
}

impl Persona {
    #[must_use]
    pub const fn is_member(&self) -> bool {
        matches!(self.kind, PersonaKind::Member)
    }
}

/// Persona names (stable: tests and mismatch reports use them).
pub mod names {
    pub const ANONYMOUS: &str = "anonymous";
    pub const GARBAGE: &str = "garbage_token";
    pub const EXPIRED: &str = "a_owner_expired_token";
    pub const A_OWNER: &str = "a_owner";
    pub const A_ADMIN: &str = "a_admin";
    pub const A_MEMBER: &str = "a_member";
    pub const A_VIEWER: &str = "a_viewer";
    pub const A_GROUP_ADMIN: &str = "a_group_admin";
    pub const A_SUSPENDED_USER: &str = "a_suspended_user";
    pub const A_DISABLED_MEMBER: &str = "a_disabled_member";
    pub const B_OWNER: &str = "b_owner";
    pub const B_MEMBER: &str = "b_member";
    pub const C_SUSPENDED_TENANT_OWNER: &str = "c_suspended_tenant_owner";
    pub const A_DEVICE: &str = "a_device";
    pub const STAFF_MFA: &str = "staff_support_mfa";
    pub const STAFF_NO_MFA: &str = "staff_support_no_mfa";
}
