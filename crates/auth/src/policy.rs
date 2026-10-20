//! Route `Policy` (PHASE0_SPEC §3.4, RBAC.md §6.1): who may call, which permission, which feature,
//! step-up, idempotency. `evaluate` delegates the decision to `domain::decide*` and returns a sealed
//! `TenantScope`. Anything missing, unknown or failing = `Denied` (fail closed).

use common::{SessionId, TenantId, UserId};
use domain::rbac::{
    Decision, DenyReason, Feature, Perm, PlatformContext, PlatformDecision, PlatformDenyReason,
    PlatformPerm, Scope, StaffRole, Target, TenantScope, decide, decide_device, decide_platform,
    requires_step_up,
};
use time::OffsetDateTime;

use crate::claims::{Audience, PrincipalKind};
use crate::loader::Freshness;
use crate::principal::Principal;
use crate::stepup::{StepUpProof, target_id};

/// Permissions that always read live state (DATABASE.md §4.4 / RBAC.md §6.4 high-risk list).
const HIGH_RISK: &[Perm] = &[
    Perm::DevicesRemoteWipe,
    Perm::MembersDelete,
    Perm::MembersAssignRole,
    Perm::TenantOwnershipTransfer,
    Perm::CreditsConsume,
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Kinds {
    member: bool,
    device: bool,
    staff: bool,
    cleaner: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    kinds: Kinds,
    public_reason: Option<&'static str>,
    perm: Option<Perm>,
    platform: Option<PlatformPerm>,
    features: Vec<Feature>,
    step_up: Option<&'static str>,
    idempotent: bool,
    high_risk: bool,
}

/// Build-time policy problems (router refuses to start).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("public route without a reason")]
    PublicWithoutReason,
    #[error("public route with principal requirements")]
    PublicWithRequirements,
    #[error("route without any principal kind")]
    NoPrincipal,
    #[error("platform permission on a non-staff policy")]
    PlatformPermWithoutStaff,
    #[error("device policy without a permission")]
    DeviceWithoutPermission,
    #[error("staff policy without a platform permission")]
    StaffWithoutPlatformPermission,
}

/// What a policy evaluation hands to the handler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authorized {
    Public {
        reason: &'static str,
    },
    /// Member or device: tenant data access through `Db::tenant_tx(&scope)`.
    Tenant {
        scope: TenantScope,
        kind: PrincipalKind,
    },
    Platform {
        staff: UserId,
        role: StaffRole,
        restricted_view: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyCode {
    /// No / wrong principal for this route (401).
    Unauthenticated,
    WrongPrincipal,
    Rbac(DenyReason),
    Platform(PlatformDenyReason),
    FeatureDisabled(Feature),
    StepUpRequired,
    Misconfigured(PolicyError),
    /// Authenticated but refused outside RBAC (e.g. read-only staff grant): 403.
    Forbidden,
    /// Live state could not be read (DB down / pool exhausted): 503, never an allow.
    Unavailable,
    /// Internal error while loading state: 500, never an allow.
    Internal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("denied")]
pub struct Denied {
    pub code: DenyCode,
}

impl Denied {
    pub(crate) const fn new(code: DenyCode) -> Self {
        Self { code }
    }

    /// HTTP status for problem+json (cross-tenant and out-of-scope look like 404).
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self.code {
            DenyCode::Unauthenticated | DenyCode::WrongPrincipal => 401,
            DenyCode::Rbac(DenyReason::CrossTenant | DenyReason::OutOfScope) => 404,
            DenyCode::Misconfigured(_) | DenyCode::Internal => 500,
            DenyCode::Unavailable => 503,
            _ => 403,
        }
    }

    /// Stable machine code.
    #[must_use]
    pub const fn code_str(&self) -> &'static str {
        match self.code {
            DenyCode::Unauthenticated | DenyCode::WrongPrincipal => "auth.unauthenticated",
            DenyCode::Rbac(r) => r.code(),
            DenyCode::Platform(_) => "authz.forbidden",
            DenyCode::FeatureDisabled(_) => "feature.disabled",
            DenyCode::StepUpRequired => "auth.step_up_required",
            DenyCode::Misconfigured(_) | DenyCode::Internal => "internal",
            DenyCode::Forbidden => "authz.forbidden",
            DenyCode::Unavailable => "service.unavailable",
        }
    }
}

/// Per-request inputs that are not part of the principal.
#[derive(Clone, Copy, Debug)]
pub struct EvalContext<'a> {
    pub now: OffsetDateTime,
    pub platform: PlatformContext,
    /// Step-up proof consumed for THIS request (`AuthService::consume_step_up`).
    pub step_up: Option<&'a StepUpProof>,
}

impl<'a> EvalContext<'a> {
    #[must_use]
    pub const fn at(now: OffsetDateTime) -> Self {
        Self {
            now,
            platform: PlatformContext {
                ticket_ref_present: false,
                owner_approval_present: false,
            },
            step_up: None,
        }
    }

    #[must_use]
    pub const fn with_step_up(mut self, proof: &'a StepUpProof) -> Self {
        self.step_up = Some(proof);
        self
    }
}

impl Policy {
    const fn empty() -> Self {
        Self {
            kinds: Kinds {
                member: false,
                device: false,
                staff: false,
                cleaner: false,
            },
            public_reason: None,
            perm: None,
            platform: None,
            features: Vec::new(),
            step_up: None,
            idempotent: false,
            high_risk: false,
        }
    }

    /// Anonymous route. The reason is mandatory (empty = `PublicWithoutReason`).
    #[must_use]
    pub const fn public(reason: &'static str) -> Self {
        let mut p = Self::empty();
        p.public_reason = Some(reason);
        p
    }

    #[must_use]
    pub const fn member() -> Self {
        let mut p = Self::empty();
        p.kinds.member = true;
        p
    }

    #[must_use]
    pub const fn device() -> Self {
        let mut p = Self::empty();
        p.kinds.device = true;
        p
    }

    #[must_use]
    pub const fn member_or_device() -> Self {
        let mut p = Self::empty();
        p.kinds.member = true;
        p.kinds.device = true;
        p
    }

    #[must_use]
    pub const fn staff() -> Self {
        let mut p = Self::empty();
        p.kinds.staff = true;
        p
    }

    #[must_use]
    pub const fn permission(mut self, perm: Perm) -> Self {
        self.perm = Some(perm);
        self
    }

    #[must_use]
    pub const fn platform(mut self, perm: PlatformPerm) -> Self {
        self.platform = Some(perm);
        self
    }

    /// Extra explicit feature gate (on top of the matrix's own feature columns).
    #[must_use]
    pub fn feature(mut self, f: Feature) -> Self {
        if !self.features.contains(&f) {
            self.features.push(f);
        }
        self
    }

    /// Require a step-up proof for `action` (password re-entry, 5 min).
    #[must_use]
    pub const fn step_up(mut self, action: &'static str) -> Self {
        self.step_up = Some(action);
        self.high_risk = true;
        self
    }

    #[must_use]
    pub const fn idempotent(mut self) -> Self {
        self.idempotent = true;
        self
    }

    /// Always read live principal state for this route (cache bypass).
    #[must_use]
    pub const fn high_risk(mut self) -> Self {
        self.high_risk = true;
        self
    }

    /// Token audiences this policy accepts (api gap 4): the verifier is called with exactly this
    /// list, so a token of another audience / principal kind is refused BEFORE any live DB load.
    /// Member = web + app, device = device, staff = platform. Public = none.
    #[must_use]
    pub fn audiences(&self) -> Vec<Audience> {
        let mut out = Vec::with_capacity(4);
        if self.public_reason.is_some() {
            return out;
        }
        if self.kinds.member {
            out.extend([Audience::Web, Audience::App]);
        }
        if self.kinds.device {
            out.push(Audience::Device);
        }
        if self.kinds.staff {
            out.push(Audience::Platform);
        }
        if self.kinds.cleaner {
            out.push(Audience::Cleaner);
        }
        out
    }

    /// Principal kinds this policy accepts.
    #[must_use]
    pub fn principal_kinds(&self) -> Vec<PrincipalKind> {
        let mut out: Vec<PrincipalKind> = self.audiences().iter().map(|a| a.kind()).collect();
        out.dedup();
        out
    }

    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.public_reason.is_some()
    }

    #[must_use]
    pub const fn is_idempotent(&self) -> bool {
        self.idempotent
    }

    #[must_use]
    pub const fn permission_of(&self) -> Option<Perm> {
        self.perm
    }

    /// Explicit high-risk, a high-risk permission, or any step-up requirement.
    #[must_use]
    pub fn is_high_risk(&self) -> bool {
        self.high_risk
            || self.step_up.is_some()
            || self
                .perm
                .is_some_and(|p| HIGH_RISK.contains(&p) || requires_step_up(p))
    }

    /// Cache mode the loader must use for this route.
    #[must_use]
    pub fn freshness(&self) -> Freshness {
        if self.is_high_risk() {
            Freshness::Live
        } else {
            Freshness::Cached
        }
    }

    /// Step-up action required by this policy (explicit, or implied by the permission).
    fn step_up_action(&self) -> Option<&'static str> {
        self.step_up
            .or_else(|| self.perm.filter(|p| requires_step_up(*p)).map(Perm::name))
    }

    /// Router build-time validation.
    ///
    /// # Errors
    /// The first problem found.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let k = self.kinds;
        let any_kind = k.member || k.device || k.staff || k.cleaner;
        if let Some(reason) = self.public_reason {
            if reason.trim().is_empty() {
                return Err(PolicyError::PublicWithoutReason);
            }
            if any_kind || self.perm.is_some() || self.platform.is_some() || self.step_up.is_some()
            {
                return Err(PolicyError::PublicWithRequirements);
            }
            return Ok(());
        }
        if !any_kind {
            return Err(PolicyError::NoPrincipal);
        }
        if self.platform.is_some() && !k.staff {
            return Err(PolicyError::PlatformPermWithoutStaff);
        }
        if k.device && self.perm.is_none() {
            return Err(PolicyError::DeviceWithoutPermission);
        }
        if k.staff && self.platform.is_none() {
            return Err(PolicyError::StaffWithoutPlatformPermission);
        }
        Ok(())
    }

    /// Evaluate against the principal's own tenant (list / "my" routes).
    ///
    /// # Errors
    /// `Denied` (fail closed).
    pub fn evaluate(&self, p: &Principal, ctx: &EvalContext<'_>) -> Result<Authorized, Denied> {
        let tenant = match p {
            Principal::Member(m) => Some(m.tenant()),
            Principal::Device(d) => Some(d.tenant()),
            _ => None,
        };
        self.evaluate_on(p, tenant.map(Target::collection).as_ref(), ctx)
    }

    /// Evaluate on a specific target (row loaded by the handler; tenant from the row, never the body).
    ///
    /// # Errors
    /// `Denied` (fail closed).
    pub fn evaluate_on(
        &self,
        p: &Principal,
        target: Option<&Target>,
        ctx: &EvalContext<'_>,
    ) -> Result<Authorized, Denied> {
        if let Err(e) = self.validate() {
            return Err(Denied::new(DenyCode::Misconfigured(e)));
        }
        if let Some(reason) = self.public_reason {
            return Ok(Authorized::Public { reason });
        }
        match p {
            Principal::Anonymous => Err(Denied::new(DenyCode::Unauthenticated)),
            Principal::Member(m) if self.kinds.member => {
                for f in &self.features {
                    if !m.features().has(*f) {
                        return Err(Denied::new(DenyCode::FeatureDisabled(*f)));
                    }
                }
                self.check_step_up(m.session(), target, ctx)?;
                let decision = match (self.perm, target) {
                    (Some(perm), Some(t)) => {
                        decide(m.actor().state(), perm, m.features(), m.caps(), t)
                    }
                    (Some(_), None) => Decision::Denied(DenyReason::InvalidTarget),
                    // Authenticated-only route (logout, me): own data only.
                    (None, _) => Decision::Allowed(Scope::SelfOnly),
                };
                let scope = TenantScope::from_decision(m.actor(), decision, None)
                    .map_err(|r| Denied::new(DenyCode::Rbac(r)))?;
                Ok(Authorized::Tenant {
                    scope,
                    kind: PrincipalKind::Member,
                })
            }
            Principal::Device(d) if self.kinds.device => {
                for f in &self.features {
                    if !d.features.has(*f) {
                        return Err(Denied::new(DenyCode::FeatureDisabled(*f)));
                    }
                }
                // Devices cannot step up.
                if self.step_up_action().is_some() {
                    return Err(Denied::new(DenyCode::StepUpRequired));
                }
                let (Some(perm), Some(t)) = (self.perm, target) else {
                    return Err(Denied::new(DenyCode::Rbac(DenyReason::InvalidTarget)));
                };
                let decision = decide_device(&d.device_actor, perm, &d.features, &d.caps, t);
                let scope = TenantScope::from_decision(&d.operator, decision, None)
                    .map_err(|r| Denied::new(DenyCode::Rbac(r)))?;
                Ok(Authorized::Tenant {
                    scope,
                    kind: PrincipalKind::Device,
                })
            }
            Principal::Staff(s) if self.kinds.staff => {
                self.check_step_up(s.session(), target, ctx)?;
                // Staff never get a tenant scope here: tenant data goes through
                // `Db::tenant_tx_for_staff(&VerifiedGrant)` (db re-verifies the grant).
                if self.perm.is_some() {
                    return Err(Denied::new(DenyCode::WrongPrincipal));
                }
                let Some(pp) = self.platform else {
                    return Err(Denied::new(DenyCode::Platform(
                        PlatformDenyReason::NoPermission,
                    )));
                };
                match decide_platform(s.role(), pp, ctx.platform) {
                    PlatformDecision::Allowed { restricted_view } => Ok(Authorized::Platform {
                        staff: s.user(),
                        role: s.role(),
                        restricted_view,
                    }),
                    PlatformDecision::Denied(r) => Err(Denied::new(DenyCode::Platform(r))),
                }
            }
            _ => Err(Denied::new(DenyCode::WrongPrincipal)),
        }
    }

    /// The proof must have been consumed for this session, this action and this target.
    fn check_step_up(
        &self,
        session: SessionId,
        target: Option<&Target>,
        ctx: &EvalContext<'_>,
    ) -> Result<(), Denied> {
        let Some(action) = self.step_up_action() else {
            return Ok(());
        };
        match ctx.step_up {
            Some(p)
                if p.session() == session
                    && p.action() == action
                    && p.target() == target_id(target) =>
            {
                Ok(())
            }
            _ => Err(Denied::new(DenyCode::StepUpRequired)),
        }
    }

    /// Step-up action this policy requires (explicit, or implied by the permission). The handler
    /// passes it to `AuthService::consume_step_up`.
    #[must_use]
    pub fn required_step_up(&self) -> Option<&'static str> {
        self.step_up_action()
    }
}

/// Handler extractor (`P` = route policy id). Built only from an `Authorized::Tenant`.
#[derive(Clone, Debug)]
pub struct Authz<const P: u16>(TenantScope);

impl<const P: u16> Authz<P> {
    /// `None` for non-tenant authorisations.
    #[must_use]
    pub fn from_authorized(a: Authorized) -> Option<Self> {
        match a {
            Authorized::Tenant { scope, .. } => Some(Self(scope)),
            _ => None,
        }
    }

    #[must_use]
    pub const fn scope(&self) -> &TenantScope {
        &self.0
    }

    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.0.tenant()
    }
}
