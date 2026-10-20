//! `TABLE_CLASSES` registry (DATABASE.md §2.6) for `xtask schema-check` (P0-20) and the local
//! schema test. Every migrated table must be listed; unknown table = fail.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableClass {
    /// PK `(tenant_id, ...)`, every index tenant-leading, access only via `TenantTx`.
    Tenant,
    /// Global human identity (users, sessions, ...), `IdentityTx` named queries.
    Identity,
    /// Global lookup -> `(tenant_id, id)` pointer.
    Directory,
    /// Staff/catalogue/config (`PlatformTx` / `SystemTx`).
    Platform,
    /// Global append/churn; nullable `tenant_id` + tenant-leading index where read per tenant.
    Infra,
}

/// Phase 0 tables (sets 0100, 0150, 0200, 0800).
pub const TABLE_CLASSES: &[(&str, TableClass)] = &[
    ("tenants", TableClass::Platform),
    ("tenant_settings", TableClass::Tenant),
    ("tenant_features", TableClass::Tenant),
    ("tenant_feature_changes", TableClass::Tenant),
    ("tenant_quotas", TableClass::Tenant),
    ("authz_epochs", TableClass::Infra),
    ("users", TableClass::Identity),
    ("user_credentials", TableClass::Identity),
    ("mfa_factors", TableClass::Identity),
    ("mfa_recovery_codes", TableClass::Identity),
    ("platform_staff", TableClass::Platform),
    ("staff_access_grants", TableClass::Platform),
    ("departments", TableClass::Tenant),
    ("groups", TableClass::Tenant),
    ("memberships", TableClass::Tenant),
    ("membership_directory", TableClass::Directory),
    ("membership_capabilities", TableClass::Tenant),
    ("group_memberships", TableClass::Tenant),
    ("group_admin_grants", TableClass::Tenant),
    ("member_preferences", TableClass::Tenant),
    ("data_keys", TableClass::Platform),
    ("signing_keys", TableClass::Platform),
    ("sessions", TableClass::Identity),
    ("refresh_tokens", TableClass::Identity),
    ("step_up_tokens", TableClass::Identity),
    ("auth_challenges", TableClass::Identity),
    ("device_credentials", TableClass::Tenant),
    ("audit_events", TableClass::Infra),
    ("audit_chain_blocks", TableClass::Infra),
    ("outbox_events", TableClass::Infra),
    ("jobs", TableClass::Infra),
    ("idempotency_keys", TableClass::Infra),
    ("tenant_counters", TableClass::Tenant),
    ("member_counters", TableClass::Tenant),
];

/// Tables owned by tooling, ignored by the schema check.
pub const TOOLING_TABLES: &[&str] = &[
    "_sqlx_migrations",
    "_sqlx_migrations_shadow",
    "_migration_lock",
];

#[must_use]
pub fn class_of(table: &str) -> Option<TableClass> {
    TABLE_CLASSES
        .iter()
        .find(|(t, _)| *t == table)
        .map(|(_, c)| *c)
}
