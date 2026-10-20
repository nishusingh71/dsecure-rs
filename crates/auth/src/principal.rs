//! Principals (PHASE0_SPEC §3.4). Fields are private and constructors crate-private: a principal can
//! only come out of [`crate::loader::DbPrincipalLoader`] (live state) — the only code that calls
//! `AuthenticatedActor::__from_authenticated`.

use common::{DeviceId, MembershipId, SessionId, TenantId, UserId};
use db::VerifiedGrant;
use domain::rbac::{
    AuthenticatedActor, Capabilities, DeviceActor, FeatureSet, GroupId, StaffRole, TenantRole,
};
use time::OffsetDateTime;

use crate::claims::Audience;

#[derive(Clone, Debug)]
pub enum Principal {
    Member(MemberPrincipal),
    /// Boxed: the device actor carries the operator state (keeps `Principal` small).
    Device(Box<DevicePrincipal>),
    Staff(StaffPrincipal),
    Cleaner(CleanerPrincipal),
    Anonymous,
}

#[derive(Clone, Debug)]
pub struct MemberPrincipal {
    pub(crate) actor: AuthenticatedActor,
    pub(crate) user: UserId,
    pub(crate) session: SessionId,
    pub(crate) caps: Capabilities,
    pub(crate) features: FeatureSet,
    pub(crate) authz_version: u64,
    pub(crate) mfa_at: Option<OffsetDateTime>,
    pub(crate) audience: Audience,
}

impl MemberPrincipal {
    #[must_use]
    pub const fn user(&self) -> UserId {
        self.user
    }
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.actor.state().tenant
    }
    #[must_use]
    pub const fn membership(&self) -> MembershipId {
        self.actor.state().membership
    }
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }
    #[must_use]
    pub const fn role(&self) -> TenantRole {
        self.actor.state().role
    }
    #[must_use]
    pub fn groups(&self) -> &[GroupId] {
        &self.actor.state().groups
    }
    #[must_use]
    pub fn ga_groups(&self) -> &[GroupId] {
        &self.actor.state().ga_groups
    }
    #[must_use]
    pub const fn caps(&self) -> &Capabilities {
        &self.caps
    }
    #[must_use]
    pub const fn features(&self) -> &FeatureSet {
        &self.features
    }
    /// Live membership `authz_version`.
    #[must_use]
    pub const fn authz_version(&self) -> u64 {
        self.authz_version
    }
    #[must_use]
    pub const fn mfa_at(&self) -> Option<OffsetDateTime> {
        self.mfa_at
    }
    #[must_use]
    pub const fn audience(&self) -> Audience {
        self.audience
    }
    #[must_use]
    pub const fn actor(&self) -> &AuthenticatedActor {
        &self.actor
    }
}

/// Enrolled device. Its operator membership is loaded live; device scopes are a subset of the
/// operator's permissions (`domain::decide_device`).
#[derive(Clone, Debug)]
pub struct DevicePrincipal {
    pub(crate) device: DeviceId,
    pub(crate) credential: uuid::Uuid,
    pub(crate) device_actor: DeviceActor,
    pub(crate) operator: AuthenticatedActor,
    pub(crate) caps: Capabilities,
    pub(crate) features: FeatureSet,
    pub(crate) product_code: String,
}

impl DevicePrincipal {
    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.device
    }
    #[must_use]
    pub const fn credential(&self) -> uuid::Uuid {
        self.credential
    }
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.device_actor.tenant
    }
    /// Owning operator membership (resources the device creates are owned by it).
    #[must_use]
    pub const fn owner(&self) -> MembershipId {
        self.operator.state().membership
    }
    #[must_use]
    pub const fn device_actor(&self) -> &DeviceActor {
        &self.device_actor
    }
    #[must_use]
    pub fn product_code(&self) -> &str {
        &self.product_code
    }
}

#[derive(Clone, Debug)]
pub struct StaffPrincipal {
    pub(crate) user: UserId,
    pub(crate) role: StaffRole,
    pub(crate) session: SessionId,
    pub(crate) mfa_at: Option<OffsetDateTime>,
    /// Only from `db::staff_grant::verify` via [`crate::staff::StaffGrantVerifier`].
    pub(crate) grant: Option<VerifiedGrant>,
}

impl StaffPrincipal {
    #[must_use]
    pub const fn user(&self) -> UserId {
        self.user
    }
    #[must_use]
    pub const fn role(&self) -> StaffRole {
        self.role
    }
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }
    #[must_use]
    pub const fn mfa_at(&self) -> Option<OffsetDateTime> {
        self.mfa_at
    }
    #[must_use]
    pub const fn grant(&self) -> Option<&VerifiedGrant> {
        self.grant.as_ref()
    }

    /// Attach a grant that the db verifier produced (must belong to this staff user).
    ///
    /// # Errors
    /// `Forbidden` if the grant is for another staff user.
    pub fn with_grant(mut self, grant: VerifiedGrant) -> Result<Self, crate::error::AuthError> {
        if grant.staff_user() != self.user {
            return Err(crate::error::AuthError::Forbidden("staff_grant_owner"));
        }
        self.grant = Some(grant);
        Ok(self)
    }
}

/// System Cleaner account (separate realm). Loader for it lands with the cleaner identity model
/// (D-11); until then no cleaner token is ever accepted by a loader.
#[derive(Clone, Debug)]
pub struct CleanerPrincipal {
    pub(crate) user: UserId,
    pub(crate) session: SessionId,
}

impl CleanerPrincipal {
    #[must_use]
    pub const fn user(&self) -> UserId {
        self.user
    }
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }
}
