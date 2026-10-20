//! Roles, features, scopes, products (RBAC.md §3, §5.1).

use serde::{Deserialize, Serialize};

/// Effective rank of a group admin *inside its own group* (RBAC.md §3.1).
pub const GROUP_ADMIN_RANK: u8 = 60;

/// Tenant roles. "superadmin" tenant role exist hi nahi karta (customers are never staff).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl TenantRole {
    pub const ALL: [Self; 4] = [Self::Owner, Self::Admin, Self::Member, Self::Viewer];

    /// 100 / 80 / 40 / 20.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Owner => 100,
            Self::Admin => 80,
            Self::Member => 40,
            Self::Viewer => 20,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }

    /// Exact lowercase match; anything else (incl. "superadmin", "groupadmin") = `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// Platform staff roles (alag realm, RBAC.md §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaffRole {
    Superadmin,
    Support,
    Billing,
    Auditor,
}

impl StaffRole {
    pub const ALL: [Self; 4] = [
        Self::Superadmin,
        Self::Support,
        Self::Billing,
        Self::Auditor,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Superadmin => "platform_superadmin",
            Self::Support => "platform_support",
            Self::Billing => "platform_billing",
            Self::Auditor => "platform_auditor",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// Per-tenant feature toggles (default OFF, only staff change them; RBAC.md §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    Subusers,
    Groups,
    UserActivity,
    PrivateCloud,
}

impl Feature {
    pub const ALL: [Self; 4] = [
        Self::Subusers,
        Self::Groups,
        Self::UserActivity,
        Self::PrivateCloud,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subusers => "subusers",
            Self::Groups => "groups",
            Self::UserActivity => "user_activity",
            Self::PrivateCloud => "private_cloud",
        }
    }
}

/// Live toggle state of one tenant. No `Default` impl on purpose: use `none()` (all OFF) explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureSet {
    pub subusers: bool,
    pub groups: bool,
    pub user_activity: bool,
    pub private_cloud: bool,
}

impl FeatureSet {
    /// Single-buyer default: everything OFF.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            subusers: false,
            groups: false,
            user_activity: false,
            private_cloud: false,
        }
    }

    #[must_use]
    pub const fn all() -> Self {
        Self {
            subusers: true,
            groups: true,
            user_activity: true,
            private_cloud: true,
        }
    }

    #[must_use]
    pub const fn has(&self, f: Feature) -> bool {
        match f {
            Feature::Subusers => self.subusers,
            Feature::Groups => self.groups,
            Feature::UserActivity => self.user_activity,
            Feature::PrivateCloud => self.private_cloud,
        }
    }

    #[must_use]
    pub const fn with(mut self, f: Feature, on: bool) -> Self {
        match f {
            Feature::Subusers => self.subusers = on,
            Feature::Groups => self.groups = on,
            Feature::UserActivity => self.user_activity = on,
            Feature::PrivateCloud => self.private_cloud = on,
        }
        self
    }
}

/// How much of the tenant a grant reaches (RBAC.md §4 legend: T / G / S).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// T: whole tenant.
    Tenant,
    /// G: only the actor's own group(s).
    Group,
    /// S: only self (or resources assigned to self).
    SelfOnly,
}

impl Scope {
    /// Breadth: Tenant 3 > Group 2 > `SelfOnly` 1.
    #[must_use]
    pub const fn breadth(self) -> u8 {
        match self {
            Self::Tenant => 3,
            Self::Group => 2,
            Self::SelfOnly => 1,
        }
    }

    #[must_use]
    pub const fn narrower(self, other: Self) -> Self {
        if self.breadth() <= other.breadth() {
            self
        } else {
            other
        }
    }

    #[must_use]
    pub const fn broader(self, other: Self) -> Self {
        if self.breadth() >= other.breadth() {
            self
        } else {
            other
        }
    }

    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::Tenant => 'T',
            Self::Group => 'G',
            Self::SelfOnly => 'S',
        }
    }
}

/// Membership / account status. Only `Active` can act.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Active,
    PendingVerification,
    Suspended,
    Disabled,
    Deleted,
}

/// Products (RBAC.md §4.7). Entitlement is checked by the caller (licence/credit pool), not toggles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Product {
    Drive,
    Diag,
    File,
    Cleaner,
    Freeze,
    Autopilot,
}

impl Product {
    pub const ALL: [Self; 6] = [
        Self::Drive,
        Self::Diag,
        Self::File,
        Self::Cleaner,
        Self::Freeze,
        Self::Autopilot,
    ];

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Drive => "drive",
            Self::Diag => "diag",
            Self::File => "file",
            Self::Cleaner => "cleaner",
            Self::Freeze => "freeze",
            Self::Autopilot => "autopilot",
        }
    }
}
