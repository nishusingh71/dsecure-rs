//! All SQL of the db crate (L2): one file per query under `crates/db/queries/<table>/<name>.sql`.
//! Each file starts with `-- class:` and the ordered `params:` list (input for `xtask sql-lint`).
//! Sirf `crate::sql` in strings ko execute karta hai; Rust code mein inline SQL nahi.

pub(crate) const TENANTS_INSERT: &str = include_str!("../queries/tenants/insert.sql");
pub(crate) const TENANTS_GET: &str = include_str!("../queries/tenants/get.sql");
pub(crate) const TENANTS_LOCK_FOR_UPDATE: &str =
    include_str!("../queries/tenants/lock_for_update.sql");
pub(crate) const TENANT_SETTINGS_INSERT: &str =
    include_str!("../queries/tenant_settings/insert.sql");
pub(crate) const TENANT_QUOTAS_INSERT: &str = include_str!("../queries/tenant_quotas/insert.sql");
pub(crate) const TENANT_QUOTAS_LOCK_FOR_UPDATE: &str =
    include_str!("../queries/tenant_quotas/lock_for_update.sql");
pub(crate) const TENANT_QUOTAS_SET_MAX_MEMBERS: &str =
    include_str!("../queries/tenant_quotas/set_max_members.sql");
pub(crate) const AUTHZ_EPOCHS_INSERT: &str = include_str!("../queries/authz_epochs/insert.sql");
pub(crate) const AUTHZ_EPOCHS_BUMP: &str = include_str!("../queries/authz_epochs/bump.sql");
pub(crate) const AUTHZ_EPOCHS_GET: &str = include_str!("../queries/authz_epochs/get.sql");
pub(crate) const AUTHZ_EPOCHS_CHANGED_TIES: &str =
    include_str!("../queries/authz_epochs/changed_ties.sql");
pub(crate) const AUTHZ_EPOCHS_CHANGED_AFTER: &str =
    include_str!("../queries/authz_epochs/changed_after.sql");
pub(crate) const TENANT_COUNTERS_INSERT: &str =
    include_str!("../queries/tenant_counters/insert.sql");
pub(crate) const TENANT_COUNTERS_GET: &str = include_str!("../queries/tenant_counters/get.sql");
pub(crate) const TENANT_COUNTERS_LOCK_FOR_UPDATE: &str =
    include_str!("../queries/tenant_counters/lock_for_update.sql");
pub(crate) const TENANT_COUNTERS_ADD_MEMBERS: &str =
    include_str!("../queries/tenant_counters/add_members.sql");
pub(crate) const TENANT_COUNTERS_ADD_GROUPS: &str =
    include_str!("../queries/tenant_counters/add_groups.sql");
pub(crate) const TENANT_COUNTERS_ADD_DEPARTMENTS: &str =
    include_str!("../queries/tenant_counters/add_departments.sql");
pub(crate) const MEMBER_COUNTERS_INSERT: &str =
    include_str!("../queries/member_counters/insert.sql");
pub(crate) const USERS_INSERT: &str = include_str!("../queries/users/insert.sql");
pub(crate) const USERS_GET: &str = include_str!("../queries/users/get.sql");
pub(crate) const USERS_FIND_BY_EMAIL_BIDX: &str =
    include_str!("../queries/users/find_by_email_bidx.sql");
pub(crate) const USERS_EXISTS: &str = include_str!("../queries/users/exists.sql");
pub(crate) const USER_CREDENTIALS_UPSERT: &str =
    include_str!("../queries/user_credentials/upsert.sql");
pub(crate) const USER_CREDENTIALS_GET: &str = include_str!("../queries/user_credentials/get.sql");
pub(crate) const MEMBERSHIPS_INSERT: &str = include_str!("../queries/memberships/insert.sql");
pub(crate) const MEMBERSHIPS_GET: &str = include_str!("../queries/memberships/get.sql");
pub(crate) const MEMBERSHIPS_GET_FOR_UPDATE: &str =
    include_str!("../queries/memberships/get_for_update.sql");
pub(crate) const MEMBERSHIPS_EXISTS: &str = include_str!("../queries/memberships/exists.sql");
pub(crate) const MEMBERSHIPS_BELONGS_TO_USER: &str =
    include_str!("../queries/memberships/belongs_to_user.sql");
pub(crate) const MEMBERSHIPS_LIST_TENANT: &str =
    include_str!("../queries/memberships/list_tenant.sql");
pub(crate) const MEMBERSHIPS_LIST_SELF: &str = include_str!("../queries/memberships/list_self.sql");
pub(crate) const MEMBERSHIPS_LIST_GROUPS: &str =
    include_str!("../queries/memberships/list_groups.sql");
pub(crate) const MEMBERSHIPS_VISIBLE_IN_GROUPS: &str =
    include_str!("../queries/memberships/visible_in_groups.sql");
pub(crate) const MEMBERSHIPS_ACTIVE_OWNERS_FOR_UPDATE: &str =
    include_str!("../queries/memberships/active_owners_for_update.sql");
pub(crate) const MEMBERSHIPS_SET_ROLE: &str = include_str!("../queries/memberships/set_role.sql");
pub(crate) const MEMBERSHIPS_SET_STATUS: &str =
    include_str!("../queries/memberships/set_status.sql");
pub(crate) const MEMBERSHIP_DIRECTORY_INSERT: &str =
    include_str!("../queries/membership_directory/insert.sql");
pub(crate) const MEMBERSHIP_DIRECTORY_UPDATE: &str =
    include_str!("../queries/membership_directory/update.sql");
pub(crate) const MEMBERSHIP_DIRECTORY_BY_USER: &str =
    include_str!("../queries/membership_directory/by_user.sql");
pub(crate) const DEPARTMENTS_EXISTS: &str = include_str!("../queries/departments/exists.sql");
pub(crate) const GROUPS_INSERT: &str = include_str!("../queries/groups/insert.sql");
pub(crate) const GROUPS_EXISTS: &str = include_str!("../queries/groups/exists.sql");
pub(crate) const GROUP_MEMBERSHIPS_INSERT: &str =
    include_str!("../queries/group_memberships/insert.sql");
pub(crate) const SESSIONS_INSERT: &str = include_str!("../queries/sessions/insert.sql");
pub(crate) const SESSIONS_GET: &str = include_str!("../queries/sessions/get.sql");
pub(crate) const SESSIONS_REVOKE: &str = include_str!("../queries/sessions/revoke.sql");
pub(crate) const SESSIONS_LIST_MEMBER: &str = include_str!("../queries/sessions/list_member.sql");
pub(crate) const REFRESH_TOKENS_INSERT: &str = include_str!("../queries/refresh_tokens/insert.sql");
pub(crate) const REFRESH_TOKENS_FIND_BY_HASH: &str =
    include_str!("../queries/refresh_tokens/find_by_hash.sql");
pub(crate) const REFRESH_TOKENS_MARK_USED: &str =
    include_str!("../queries/refresh_tokens/mark_used.sql");
pub(crate) const REFRESH_TOKENS_REVOKE_FAMILY: &str =
    include_str!("../queries/refresh_tokens/revoke_family.sql");
pub(crate) const DATA_KEYS_ACTIVE: &str = include_str!("../queries/data_keys/active.sql");
pub(crate) const DATA_KEYS_BY_KID: &str = include_str!("../queries/data_keys/by_kid.sql");
pub(crate) const DATA_KEYS_INSERT: &str = include_str!("../queries/data_keys/insert.sql");
pub(crate) const DATA_KEYS_DEACTIVATE: &str = include_str!("../queries/data_keys/deactivate.sql");
pub(crate) const OUTBOX_EVENTS_INSERT: &str = include_str!("../queries/outbox_events/insert.sql");
pub(crate) const JOBS_INSERT: &str = include_str!("../queries/jobs/insert.sql");
pub(crate) const JOBS_COUNT_PENDING_TENANT: &str =
    include_str!("../queries/jobs/count_pending_tenant.sql");
pub(crate) const JOBS_CANDIDATES: &str = include_str!("../queries/jobs/candidates.sql");
pub(crate) const JOBS_CLAIM: &str = include_str!("../queries/jobs/claim.sql");
pub(crate) const JOBS_GET_CLAIMED: &str = include_str!("../queries/jobs/get_claimed.sql");
pub(crate) const JOBS_HEARTBEAT: &str = include_str!("../queries/jobs/heartbeat.sql");
pub(crate) const JOBS_COMPLETE: &str = include_str!("../queries/jobs/complete.sql");
pub(crate) const JOBS_RETRY: &str = include_str!("../queries/jobs/retry.sql");
pub(crate) const JOBS_DEAD: &str = include_str!("../queries/jobs/dead.sql");
pub(crate) const JOBS_GET_STATUS: &str = include_str!("../queries/jobs/get_status.sql");
pub(crate) const IDEMPOTENCY_KEYS_GET_FOR_UPDATE: &str =
    include_str!("../queries/idempotency_keys/get_for_update.sql");
pub(crate) const IDEMPOTENCY_KEYS_INSERT: &str =
    include_str!("../queries/idempotency_keys/insert.sql");
pub(crate) const IDEMPOTENCY_KEYS_RESET_EXPIRED: &str =
    include_str!("../queries/idempotency_keys/reset_expired.sql");
pub(crate) const IDEMPOTENCY_KEYS_COMPLETE: &str =
    include_str!("../queries/idempotency_keys/complete.sql");
pub(crate) const JOBS_LOCK_CLAIMED: &str = include_str!("../queries/jobs/lock_claimed.sql");
pub(crate) const OUTBOX_EVENTS_COUNT_PENDING_TENANT: &str =
    include_str!("../queries/outbox_events/count_pending_tenant.sql");
pub(crate) const PLATFORM_STAFF_INSERT: &str = include_str!("../queries/platform_staff/insert.sql");
pub(crate) const STAFF_ACCESS_GRANTS_INSERT: &str =
    include_str!("../queries/staff_access_grants/insert.sql");
pub(crate) const JOBS_REAP_CANDIDATES: &str = include_str!("../queries/jobs/reap_candidates.sql");
pub(crate) const JOBS_REAP_CANDIDATES_KIND: &str =
    include_str!("../queries/jobs/reap_candidates_kind.sql");
pub(crate) const JOBS_REAP_REQUEUE_ONE: &str = include_str!("../queries/jobs/reap_requeue_one.sql");
pub(crate) const JOBS_REAP_DEAD_ONE: &str = include_str!("../queries/jobs/reap_dead_one.sql");
pub(crate) const JOBS_RELEASE: &str = include_str!("../queries/jobs/release.sql");
pub(crate) const OUTBOX_EVENTS_CLAIM_CANDIDATES: &str =
    include_str!("../queries/outbox_events/claim_candidates.sql");
pub(crate) const OUTBOX_EVENTS_CLAIM_ONE: &str =
    include_str!("../queries/outbox_events/claim_one.sql");
pub(crate) const OUTBOX_EVENTS_GET_CLAIMED: &str =
    include_str!("../queries/outbox_events/get_claimed.sql");
pub(crate) const OUTBOX_EVENTS_MARK_PUBLISHED: &str =
    include_str!("../queries/outbox_events/mark_published.sql");
pub(crate) const OUTBOX_EVENTS_RELEASE: &str = include_str!("../queries/outbox_events/release.sql");
pub(crate) const IDEMPOTENCY_KEYS_EXPIRED_CANDIDATES: &str =
    include_str!("../queries/idempotency_keys/expired_candidates.sql");
pub(crate) const IDEMPOTENCY_KEYS_TOMBSTONE: &str =
    include_str!("../queries/idempotency_keys/tombstone.sql");
pub(crate) const PLATFORM_STAFF_GET_FOR_UPDATE: &str =
    include_str!("../queries/platform_staff/get_for_update.sql");
pub(crate) const PLATFORM_STAFF_COUNT_FOR_UPDATE: &str =
    include_str!("../queries/platform_staff/count_for_update.sql");
pub(crate) const STAFF_ACCESS_GRANTS_CLOSE: &str =
    include_str!("../queries/staff_access_grants/close.sql");
pub(crate) const TENANTS_EXISTS_ACTIVE: &str = include_str!("../queries/tenants/exists_active.sql");
pub(crate) const STAFF_ACCESS_GRANTS_GET_CURRENT: &str =
    include_str!("../queries/staff_access_grants/get_current.sql");
pub(crate) const SIGNING_KEYS_INSERT: &str = include_str!("../queries/signing_keys/insert.sql");
pub(crate) const SIGNING_KEYS_ACTIVE_FOR: &str =
    include_str!("../queries/signing_keys/active_for.sql");
pub(crate) const SIGNING_KEYS_BY_KID: &str = include_str!("../queries/signing_keys/by_kid.sql");
pub(crate) const SIGNING_KEYS_LIST_PUBLIC: &str =
    include_str!("../queries/signing_keys/list_public.sql");
pub(crate) const SIGNING_KEYS_SET_STATUS: &str =
    include_str!("../queries/signing_keys/set_status.sql");
pub(crate) const OUTBOX_EVENTS_CLAIM_CANDIDATES_TENANT: &str =
    include_str!("../queries/outbox_events/claim_candidates_tenant.sql");
pub(crate) const MEMBERSHIPS_EXISTS_USER: &str =
    include_str!("../queries/memberships/exists_user.sql");
pub(crate) const IDEMPOTENCY_KEYS_RELEASE: &str =
    include_str!("../queries/idempotency_keys/release.sql");
pub(crate) const IDEMPOTENCY_KEYS_RESET_TAKEOVER: &str =
    include_str!("../queries/idempotency_keys/reset_takeover.sql");

/// (name, sql) of every query file, for tests (lint-like checks).
#[cfg(test)]
pub(crate) const ALL: &[(&str, &str)] = &[
    ("tenants/insert", TENANTS_INSERT),
    ("tenants/get", TENANTS_GET),
    ("tenants/lock_for_update", TENANTS_LOCK_FOR_UPDATE),
    ("tenant_settings/insert", TENANT_SETTINGS_INSERT),
    ("tenant_quotas/insert", TENANT_QUOTAS_INSERT),
    (
        "tenant_quotas/lock_for_update",
        TENANT_QUOTAS_LOCK_FOR_UPDATE,
    ),
    (
        "tenant_quotas/set_max_members",
        TENANT_QUOTAS_SET_MAX_MEMBERS,
    ),
    ("authz_epochs/insert", AUTHZ_EPOCHS_INSERT),
    ("authz_epochs/bump", AUTHZ_EPOCHS_BUMP),
    ("authz_epochs/get", AUTHZ_EPOCHS_GET),
    ("authz_epochs/changed_ties", AUTHZ_EPOCHS_CHANGED_TIES),
    ("authz_epochs/changed_after", AUTHZ_EPOCHS_CHANGED_AFTER),
    ("tenant_counters/insert", TENANT_COUNTERS_INSERT),
    ("tenant_counters/get", TENANT_COUNTERS_GET),
    (
        "tenant_counters/lock_for_update",
        TENANT_COUNTERS_LOCK_FOR_UPDATE,
    ),
    ("tenant_counters/add_members", TENANT_COUNTERS_ADD_MEMBERS),
    ("tenant_counters/add_groups", TENANT_COUNTERS_ADD_GROUPS),
    (
        "tenant_counters/add_departments",
        TENANT_COUNTERS_ADD_DEPARTMENTS,
    ),
    ("member_counters/insert", MEMBER_COUNTERS_INSERT),
    ("users/insert", USERS_INSERT),
    ("users/get", USERS_GET),
    ("users/find_by_email_bidx", USERS_FIND_BY_EMAIL_BIDX),
    ("users/exists", USERS_EXISTS),
    ("user_credentials/upsert", USER_CREDENTIALS_UPSERT),
    ("user_credentials/get", USER_CREDENTIALS_GET),
    ("memberships/insert", MEMBERSHIPS_INSERT),
    ("memberships/get", MEMBERSHIPS_GET),
    ("memberships/get_for_update", MEMBERSHIPS_GET_FOR_UPDATE),
    ("memberships/exists", MEMBERSHIPS_EXISTS),
    ("memberships/belongs_to_user", MEMBERSHIPS_BELONGS_TO_USER),
    ("memberships/list_tenant", MEMBERSHIPS_LIST_TENANT),
    ("memberships/list_self", MEMBERSHIPS_LIST_SELF),
    ("memberships/list_groups", MEMBERSHIPS_LIST_GROUPS),
    (
        "memberships/visible_in_groups",
        MEMBERSHIPS_VISIBLE_IN_GROUPS,
    ),
    (
        "memberships/active_owners_for_update",
        MEMBERSHIPS_ACTIVE_OWNERS_FOR_UPDATE,
    ),
    ("memberships/set_role", MEMBERSHIPS_SET_ROLE),
    ("memberships/set_status", MEMBERSHIPS_SET_STATUS),
    ("membership_directory/insert", MEMBERSHIP_DIRECTORY_INSERT),
    ("membership_directory/update", MEMBERSHIP_DIRECTORY_UPDATE),
    ("membership_directory/by_user", MEMBERSHIP_DIRECTORY_BY_USER),
    ("departments/exists", DEPARTMENTS_EXISTS),
    ("groups/insert", GROUPS_INSERT),
    ("groups/exists", GROUPS_EXISTS),
    ("group_memberships/insert", GROUP_MEMBERSHIPS_INSERT),
    ("sessions/insert", SESSIONS_INSERT),
    ("sessions/get", SESSIONS_GET),
    ("sessions/revoke", SESSIONS_REVOKE),
    ("sessions/list_member", SESSIONS_LIST_MEMBER),
    ("refresh_tokens/insert", REFRESH_TOKENS_INSERT),
    ("refresh_tokens/find_by_hash", REFRESH_TOKENS_FIND_BY_HASH),
    ("refresh_tokens/mark_used", REFRESH_TOKENS_MARK_USED),
    ("refresh_tokens/revoke_family", REFRESH_TOKENS_REVOKE_FAMILY),
    ("data_keys/active", DATA_KEYS_ACTIVE),
    ("data_keys/by_kid", DATA_KEYS_BY_KID),
    ("data_keys/insert", DATA_KEYS_INSERT),
    ("data_keys/deactivate", DATA_KEYS_DEACTIVATE),
    ("outbox_events/insert", OUTBOX_EVENTS_INSERT),
    ("jobs/insert", JOBS_INSERT),
    ("jobs/count_pending_tenant", JOBS_COUNT_PENDING_TENANT),
    ("jobs/candidates", JOBS_CANDIDATES),
    ("jobs/claim", JOBS_CLAIM),
    ("jobs/get_claimed", JOBS_GET_CLAIMED),
    ("jobs/heartbeat", JOBS_HEARTBEAT),
    ("jobs/complete", JOBS_COMPLETE),
    ("jobs/retry", JOBS_RETRY),
    ("jobs/dead", JOBS_DEAD),
    ("jobs/get_status", JOBS_GET_STATUS),
    (
        "idempotency_keys/get_for_update",
        IDEMPOTENCY_KEYS_GET_FOR_UPDATE,
    ),
    ("idempotency_keys/insert", IDEMPOTENCY_KEYS_INSERT),
    (
        "idempotency_keys/reset_expired",
        IDEMPOTENCY_KEYS_RESET_EXPIRED,
    ),
    ("idempotency_keys/complete", IDEMPOTENCY_KEYS_COMPLETE),
    ("jobs/lock_claimed", JOBS_LOCK_CLAIMED),
    (
        "outbox_events/count_pending_tenant",
        OUTBOX_EVENTS_COUNT_PENDING_TENANT,
    ),
    ("platform_staff/insert", PLATFORM_STAFF_INSERT),
    ("staff_access_grants/insert", STAFF_ACCESS_GRANTS_INSERT),
    ("jobs/reap_candidates", JOBS_REAP_CANDIDATES),
    ("jobs/reap_candidates_kind", JOBS_REAP_CANDIDATES_KIND),
    ("jobs/reap_requeue_one", JOBS_REAP_REQUEUE_ONE),
    ("jobs/reap_dead_one", JOBS_REAP_DEAD_ONE),
    ("jobs/release", JOBS_RELEASE),
    (
        "outbox_events/claim_candidates",
        OUTBOX_EVENTS_CLAIM_CANDIDATES,
    ),
    ("outbox_events/claim_one", OUTBOX_EVENTS_CLAIM_ONE),
    ("outbox_events/get_claimed", OUTBOX_EVENTS_GET_CLAIMED),
    ("outbox_events/mark_published", OUTBOX_EVENTS_MARK_PUBLISHED),
    ("outbox_events/release", OUTBOX_EVENTS_RELEASE),
    (
        "idempotency_keys/expired_candidates",
        IDEMPOTENCY_KEYS_EXPIRED_CANDIDATES,
    ),
    ("idempotency_keys/tombstone", IDEMPOTENCY_KEYS_TOMBSTONE),
    (
        "platform_staff/get_for_update",
        PLATFORM_STAFF_GET_FOR_UPDATE,
    ),
    (
        "platform_staff/count_for_update",
        PLATFORM_STAFF_COUNT_FOR_UPDATE,
    ),
    ("staff_access_grants/close", STAFF_ACCESS_GRANTS_CLOSE),
    ("tenants/exists_active", TENANTS_EXISTS_ACTIVE),
    (
        "staff_access_grants/get_current",
        STAFF_ACCESS_GRANTS_GET_CURRENT,
    ),
    ("signing_keys/insert", SIGNING_KEYS_INSERT),
    ("signing_keys/active_for", SIGNING_KEYS_ACTIVE_FOR),
    ("signing_keys/by_kid", SIGNING_KEYS_BY_KID),
    ("signing_keys/list_public", SIGNING_KEYS_LIST_PUBLIC),
    ("signing_keys/set_status", SIGNING_KEYS_SET_STATUS),
    (
        "outbox_events/claim_candidates_tenant",
        OUTBOX_EVENTS_CLAIM_CANDIDATES_TENANT,
    ),
    ("memberships/exists_user", MEMBERSHIPS_EXISTS_USER),
    ("idempotency_keys/release", IDEMPOTENCY_KEYS_RELEASE),
    (
        "idempotency_keys/reset_takeover",
        IDEMPOTENCY_KEYS_RESET_TAKEOVER,
    ),
];
