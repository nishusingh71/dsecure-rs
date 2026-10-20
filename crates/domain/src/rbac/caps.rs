//! Per-member capabilities (narrowing masks) and tenant quotas (RBAC.md §5.2, §5.3).

use serde::{Deserialize, Serialize};

use super::roles::TenantRole;

/// Which capability a permission needs (matrix "Cap" column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CapabilityKind {
    /// false = only own reports (D-32): narrows read/export scope to `SelfOnly`.
    ViewReports,
    /// false = devices register/update/assign/remote_command denied.
    ManageMachines,
    /// false = licences allocate/transfer denied (admins bhi).
    AssignLicenses,
}

/// Masks never give more than the role; effective = role perms ∩ capabilities. Owner is always full.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub can_view_reports: bool,
    pub can_manage_machines: bool,
    pub can_assign_licenses: bool,
    /// Active devices limit of this member; `None` = unlimited.
    pub max_machines: Option<u32>,
    /// Credit allocation cap of this member; `None` = no allocation (tenant pool, unless the
    /// tenant has `require_allocation`).
    pub credit_allocation: Option<u32>,
}

impl Capabilities {
    /// Owner (and tests): everything on, no limits.
    #[must_use]
    pub const fn full() -> Self {
        Self {
            can_view_reports: true,
            can_manage_machines: true,
            can_assign_licenses: true,
            max_machines: None,
            credit_allocation: None,
        }
    }

    /// Defaults from RBAC.md §5.3: can_view_reports true; can_manage_machines true for
    /// admin; can_assign_licenses true for owner/admin. No `Default` impl on purpose.
    #[must_use]
    pub const fn default_for(role: TenantRole) -> Self {
        match role {
            TenantRole::Owner => Self::full(),
            TenantRole::Admin => Self::full(),
            TenantRole::Member | TenantRole::Viewer => Self {
                can_view_reports: true,
                can_manage_machines: false,
                can_assign_licenses: false,
                max_machines: None,
                credit_allocation: None,
            },
        }
    }

    #[must_use]
    pub const fn has(&self, k: CapabilityKind) -> bool {
        match k {
            CapabilityKind::ViewReports => self.can_view_reports,
            CapabilityKind::ManageMachines => self.can_manage_machines,
            CapabilityKind::AssignLicenses => self.can_assign_licenses,
        }
    }
}

/// Tenant quotas, set by staff only. `None` = unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quotas {
    pub max_members: Option<u32>,
    pub max_groups: Option<u32>,
    pub max_departments: Option<u32>,
    pub max_licenses: Option<u32>,
}

impl Quotas {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_members: None,
            max_groups: None,
            max_departments: None,
            max_licenses: None,
        }
    }

    #[must_use]
    pub const fn limit(&self, k: QuotaKind) -> Option<u32> {
        match k {
            QuotaKind::Members => self.max_members,
            QuotaKind::Groups => self.max_groups,
            QuotaKind::Departments => self.max_departments,
            QuotaKind::Licenses => self.max_licenses,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QuotaKind {
    Members,
    Groups,
    Departments,
    Licenses,
}

impl QuotaKind {
    /// Name used in `409 quota.exceeded` (`quota` field).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Members => "max_members",
            Self::Groups => "max_groups",
            Self::Departments => "max_departments",
            Self::Licenses => "max_licenses",
        }
    }
}

/// Quota that guards a permission when it *creates* something (RBAC.md §4 Feature column).
/// `members.enable` also counts (enable = a member becomes active again).
#[must_use]
pub const fn quota_for(perm: super::perm::Perm) -> Option<QuotaKind> {
    use super::perm::Perm;
    match perm {
        Perm::MembersCreate | Perm::MembersEnable => Some(QuotaKind::Members),
        Perm::GroupsCreate => Some(QuotaKind::Groups),
        Perm::DepartmentsManage => Some(QuotaKind::Departments),
        Perm::LicensesAllocate => Some(QuotaKind::Licenses),
        _ => None,
    }
}

/// `409 quota.exceeded`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaExceeded {
    pub quota: &'static str,
    pub limit: u32,
    pub current: u32,
}

fn check_limit(
    quota: &'static str,
    limit: Option<u32>,
    current: u32,
    adding: u32,
) -> Result<(), QuotaExceeded> {
    let Some(limit) = limit else {
        return Ok(());
    };
    match current.checked_add(adding) {
        Some(total) if total <= limit => Ok(()),
        // Overflow bhi exceed maana jata hai (fail closed).
        _ => Err(QuotaExceeded {
            quota,
            limit,
            current,
        }),
    }
}

/// Caller holds the `FOR UPDATE` lock and passes the live `current` count; domain sirf compare karta hai.
///
/// # Errors
/// `QuotaExceeded` when `current + adding > limit`.
pub fn check_quota(
    quotas: &Quotas,
    kind: QuotaKind,
    current: u32,
    adding: u32,
) -> Result<(), QuotaExceeded> {
    check_limit(kind.name(), quotas.limit(kind), current, adding)
}

/// Member's `max_machines` (register/assign tx).
///
/// # Errors
/// `QuotaExceeded` (quota = "max_machines") when `active + adding > max_machines`.
pub fn check_max_machines(
    caps: &Capabilities,
    active_devices: u32,
    adding: u32,
) -> Result<(), QuotaExceeded> {
    check_limit("max_machines", caps.max_machines, active_devices, adding)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationError {
    /// Tenant has `require_allocation` but the member has none.
    Required,
    Exceeded {
        limit: u32,
        used: u32,
    },
}

/// `credits.consume` inside the member's allocation (D-33). No allocation + `require_allocation=false` = pool.
///
/// # Errors
/// `Required` / `Exceeded` as above.
pub fn check_credit_allocation(
    caps: &Capabilities,
    require_allocation: bool,
    used: u32,
    requesting: u32,
) -> Result<(), AllocationError> {
    match caps.credit_allocation {
        None if require_allocation => Err(AllocationError::Required),
        None => Ok(()),
        Some(limit) => match used.checked_add(requesting) {
            Some(total) if total <= limit => Ok(()),
            _ => Err(AllocationError::Exceeded { limit, used }),
        },
    }
}
