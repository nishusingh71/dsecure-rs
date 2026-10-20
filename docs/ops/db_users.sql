-- docs/ops/db_users.sql  (P0-23) -- DRAFT for the owner / main session. NOT EXECUTED by any agent.
-- Source: docs/DATABASE.md §2.5 (DB users), §2.2 L8 (no DELETE/DDL for the app), D-17/D-56 (retention).
--
-- Rules
--   * No passwords in this file. Replace every <...> placeholder at apply time; store secrets in the
--     secret manager only. Never commit filled-in values.
--   * One database per environment: dsecure_dev (local), dsecure_staging, dsecure_prod (names nv).
--     NEVER the legacy database `Cloud_Erase__App` (the db crate refuses it at connect time).
--   * TiDB Cloud Serverless prefixes user names with the cluster prefix (e.g. '<prefix>.dsecure_app');
--     exact naming and the host part ('%') are NOT verified. TLS is enforced by the server endpoint
--     on Serverless; on self-managed MySQL/TiDB use REQUIRE SSL as shown.
--   * Schema changes: apply migrations with the migrator user BEFORE deploying code.
--   * Grants are PER TABLE (least privilege, review F5), generated from the db crate's table registry.
--     Retention gets table-level DELETE only on listed infra tables, and stays disabled (ACCOUNT LOCK)
--     until the owner approves each data class.
--
-- Replace the database name below per environment.
-- SET @db = 'dsecure_prod';   -- (documentation only; GRANT needs a literal name)

-- ---------------------------------------------------------------------------------------------
-- 1) Migrator: DDL on the app database only. Used only by the release step `dsecure-api migrate`.
--    Needs REFERENCES only in MySQL CI (shadow FKs); keep it out of staging/prod.
-- ---------------------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'dsecure_migrator'@'%' IDENTIFIED BY '<MIGRATOR_PASSWORD>' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, CREATE, ALTER, INDEX, DROP
  ON `dsecure_prod`.* TO 'dsecure_migrator'@'%';
-- The migrator also owns the tooling tables `_sqlx_migrations`, `_sqlx_migrations_shadow` and
-- `_migration_lock` (lock row: UPDATE-based acquire/release, no DELETE needed).
-- DROP is needed only for expand/contract cleanup migrations; the owner may revoke it between releases:
-- REVOKE DROP ON `dsecure_prod`.* FROM 'dsecure_migrator'@'%';
-- sqlx migration bookkeeping table lives in the same database (covered by the grant above).

-- ---------------------------------------------------------------------------------------------
-- 2) App (API + in-process workers). PER-TABLE grants generated from db::table_classes::TABLE_CLASSES by
--    db::grants::grant_statements (test `grants::tests::ops_doc_matches_generator` keeps this in sync).
--    S/I/U on tenant/identity/directory/infra tables; audit tables S/I only (append-only);
--    data_keys S/I; signing_keys, platform_staff, staff_access_grants SELECT only (keys, staff and
--    grants = platform-admin path with a verified approver, review R1). No DELETE, no DDL.
--    New tables need a new grant (CI: regenerate with `cargo test -p db print_grants -- --ignored --nocapture`).
-- ---------------------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'dsecure_app'@'%' IDENTIFIED BY '<APP_PASSWORD>' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenants` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_settings` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_features` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_feature_changes` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_quotas` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`authz_epochs` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`users` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`user_credentials` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`mfa_factors` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`mfa_recovery_codes` TO 'dsecure_app'@'%';
GRANT SELECT ON `dsecure_prod`.`platform_staff` TO 'dsecure_app'@'%';
GRANT SELECT ON `dsecure_prod`.`staff_access_grants` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`departments` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`groups` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`memberships` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`membership_directory` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`membership_capabilities` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`group_memberships` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`group_admin_grants` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`member_preferences` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`data_keys` TO 'dsecure_app'@'%';
GRANT SELECT ON `dsecure_prod`.`signing_keys` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`sessions` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`refresh_tokens` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`step_up_tokens` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`auth_challenges` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`device_credentials` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`audit_events` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`audit_chain_blocks` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`outbox_events` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`jobs` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`idempotency_keys` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_counters` TO 'dsecure_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`member_counters` TO 'dsecure_app'@'%';
GRANT SELECT ON `dsecure_prod`.`_sqlx_migrations` TO 'dsecure_app'@'%';

-- ---------------------------------------------------------------------------------------------
-- 3) Worker (separate worker service, D-02): least privilege for jobs: tenant tables S/I/U,
--    identity/directory S, jobs/outbox S/I/U, audit S/I, data_keys S/I (lazy tenant DEK), authz_epochs S/U,
--    no staff tables, no idempotency keys.
-- ---------------------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'dsecure_worker'@'%' IDENTIFIED BY '<WORKER_PASSWORD>' REQUIRE SSL;
GRANT SELECT ON `dsecure_prod`.`tenants` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_settings` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_features` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_feature_changes` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_quotas` TO 'dsecure_worker'@'%';
GRANT SELECT, UPDATE ON `dsecure_prod`.`authz_epochs` TO 'dsecure_worker'@'%';
GRANT SELECT ON `dsecure_prod`.`users` TO 'dsecure_worker'@'%';
GRANT SELECT ON `dsecure_prod`.`user_credentials` TO 'dsecure_worker'@'%';
GRANT SELECT ON `dsecure_prod`.`mfa_factors` TO 'dsecure_worker'@'%';
GRANT SELECT ON `dsecure_prod`.`mfa_recovery_codes` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`departments` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`groups` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`memberships` TO 'dsecure_worker'@'%';
GRANT SELECT ON `dsecure_prod`.`membership_directory` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`membership_capabilities` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`group_memberships` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`group_admin_grants` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`member_preferences` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`data_keys` TO 'dsecure_worker'@'%';
GRANT SELECT ON `dsecure_prod`.`signing_keys` TO 'dsecure_worker'@'%';
GRANT SELECT ON `dsecure_prod`.`sessions` TO 'dsecure_worker'@'%';
GRANT SELECT ON `dsecure_prod`.`refresh_tokens` TO 'dsecure_worker'@'%';
GRANT SELECT ON `dsecure_prod`.`step_up_tokens` TO 'dsecure_worker'@'%';
GRANT SELECT ON `dsecure_prod`.`auth_challenges` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`device_credentials` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`audit_events` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`audit_chain_blocks` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`outbox_events` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`jobs` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_counters` TO 'dsecure_worker'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`member_counters` TO 'dsecure_worker'@'%';
GRANT SELECT ON `dsecure_prod`.`_sqlx_migrations` TO 'dsecure_worker'@'%';

-- ---------------------------------------------------------------------------------------------
-- 4) Read-only: reconciliation, support SELECTs (main session), RU reports.
-- ---------------------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'dsecure_readonly'@'%' IDENTIFIED BY '<READONLY_PASSWORD>' REQUIRE SSL;
GRANT SELECT ON `dsecure_prod`.`tenants` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`tenant_settings` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`tenant_features` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`tenant_feature_changes` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`tenant_quotas` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`authz_epochs` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`users` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`user_credentials` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`mfa_factors` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`mfa_recovery_codes` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`platform_staff` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`staff_access_grants` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`departments` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`groups` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`memberships` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`membership_directory` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`membership_capabilities` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`group_memberships` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`group_admin_grants` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`member_preferences` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`data_keys` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`signing_keys` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`sessions` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`refresh_tokens` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`step_up_tokens` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`auth_challenges` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`device_credentials` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`audit_events` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`audit_chain_blocks` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`outbox_events` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`jobs` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`idempotency_keys` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`tenant_counters` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`member_counters` TO 'dsecure_readonly'@'%';
GRANT SELECT ON `dsecure_prod`.`_sqlx_migrations` TO 'dsecure_readonly'@'%';

-- ---------------------------------------------------------------------------------------------
-- 4b) Platform admin (db::platform_admin::PlatformAdminDb): the ONLY user that creates staff and access
--     grants (INSERT) and does the narrow UPDATEs, COLUMN-level only (review R5): platform_staff(role,
--     revoked_at), staff_access_grants(closed_at), data_keys(status, active_marker, rotated_at,
--     destroyed_at, destroyed_by_approval), signing_keys(status, not_after). Never wrapped_dek, kek_ref,
--     staff_user_id or tenant_id. Audit rows S/I; tenants S. Platform console / ops tooling only.
-- ---------------------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'dsecure_platform_admin'@'%' IDENTIFIED BY '<PLATFORM_ADMIN_PASSWORD>' REQUIRE SSL;
GRANT SELECT ON `dsecure_prod`.`tenants` TO 'dsecure_platform_admin'@'%';
GRANT SELECT, INSERT, UPDATE (role, revoked_at) ON `dsecure_prod`.`platform_staff` TO 'dsecure_platform_admin'@'%';
GRANT SELECT, INSERT, UPDATE (closed_at) ON `dsecure_prod`.`staff_access_grants` TO 'dsecure_platform_admin'@'%';
GRANT SELECT, INSERT, UPDATE (status, active_marker, rotated_at, destroyed_at, destroyed_by_approval) ON `dsecure_prod`.`data_keys` TO 'dsecure_platform_admin'@'%';
GRANT SELECT, INSERT, UPDATE (status, not_after) ON `dsecure_prod`.`signing_keys` TO 'dsecure_platform_admin'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`audit_events` TO 'dsecure_platform_admin'@'%';

-- ---------------------------------------------------------------------------------------------
-- 5) Retention (D-17, D-56): DELETE only on listed infra tables. DISABLED until the owner approves
--    each data class: created locked, no grants applied until approval.
-- ---------------------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'dsecure_retention'@'%' IDENTIFIED BY '<RETENTION_PASSWORD>' REQUIRE SSL ACCOUNT LOCK;
-- After owner approval, per table (Phase 0 tables only; add later tables when they exist):
-- GRANT SELECT, DELETE ON `dsecure_prod`.`idempotency_keys` TO 'dsecure_retention'@'%';
-- GRANT SELECT, DELETE ON `dsecure_prod`.`step_up_tokens`   TO 'dsecure_retention'@'%';
-- GRANT SELECT, DELETE ON `dsecure_prod`.`auth_challenges`  TO 'dsecure_retention'@'%';
-- GRANT SELECT, DELETE ON `dsecure_prod`.`outbox_events`    TO 'dsecure_retention'@'%';
-- GRANT SELECT, DELETE ON `dsecure_prod`.`jobs`             TO 'dsecure_retention'@'%';
-- GRANT SELECT, DELETE ON `dsecure_prod`.`refresh_tokens`   TO 'dsecure_retention'@'%';  -- > 90 days
-- GRANT SELECT, DELETE ON `dsecure_prod`.`sessions`         TO 'dsecure_retention'@'%';  -- > 90 days
-- ALTER USER 'dsecure_retention'@'%' ACCOUNT UNLOCK;

-- ---------------------------------------------------------------------------------------------
-- 6) Local dev / CI (MySQL 8.4 on 127.0.0.1 only). Mirrors the split above, plus scratch databases for
--    per-test isolation (`dsecure_t_<random>`, created and dropped by the test harness).
-- ---------------------------------------------------------------------------------------------
-- CREATE USER IF NOT EXISTS 'dsecure_migrator'@'localhost' IDENTIFIED BY '<LOCAL_MIGRATOR_PASSWORD>';
-- GRANT ALL PRIVILEGES ON `dsecure_dev`.*  TO 'dsecure_migrator'@'localhost';
-- GRANT ALL PRIVILEGES ON `dsecure_test`.* TO 'dsecure_migrator'@'localhost';
-- GRANT ALL PRIVILEGES ON `dsecure\_t\_%`.* TO 'dsecure_migrator'@'localhost';   -- scratch DBs only
-- CREATE USER IF NOT EXISTS 'dsecure_app'@'localhost' IDENTIFIED BY '<LOCAL_APP_PASSWORD>';
-- Local app user: same per-table statements as section 2 with `dsecure_dev` / `dsecure_test`.
-- The test `tests::t_grants::least_privilege_grants_refuse_audit_update_and_delete` applies the generated
-- App grants to a scratch DB for a scratch user `dsecure_t_grants` (local root) and checks 1142 refusals.

-- ---------------------------------------------------------------------------------------------
-- Verification (read-only, any env): the app user must hold no DELETE and no DDL.
-- ---------------------------------------------------------------------------------------------
-- SHOW GRANTS FOR 'dsecure_app'@'%';
-- SHOW GRANTS FOR 'dsecure_worker'@'%';
-- The db crate test `tests::t_grants::app_user_cannot_delete_or_ddl` checks this on the local MySQL
-- (SHOW GRANTS + a DELETE that must fail with error 1142).
