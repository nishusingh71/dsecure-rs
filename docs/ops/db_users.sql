-- docs/ops/db_users.sql  (P0-23) -- DRAFT for the owner / main session. NOT EXECUTED by any agent.
-- Source: docs/DATABASE.md §2.5 (DB users), §2.2 L8 (no DELETE/DDL for the app), D-17/D-56 (retention).
--
-- Rules
--   * No passwords in this file. Replace every <...> placeholder at apply time; store secrets in the
--     secret manager only. Never commit filled-in values.
--   * One database per environment: dsecure_dev (local), dsecure_staging, dsecure_prod (names nv).
--     NEVER the legacy database `Cloud_Erase__App` (the db crate refuses it at connect time).
--   * User names (B3, db::grants::DB_USER_*): rs_mig, rs_app, rs_wrk, rs_ro, rs_padm, rs_ret. TiDB Cloud
--     Serverless prefixes user names with the cluster prefix ('<prefix>.rs_app'@'%') and limits a user
--     name to 32 characters; the prefix is about 16 characters with the dot, so names stay <= 15
--     (test grants::tests::user_names_fit_tidb_serverless_limit). On Serverless write every name below
--     as '<prefix>.<name>'. Outside dev/test the code checks ONE name: the platform-admin pool refuses
--     to start unless CURRENT_USER() is exactly 'rs_padm' or '<prefix without dots>.rs_padm' (any host).
--     The other names are a convention; local dev / CI may use any names (CI still creates
--     dsecure_migrator / dsecure_app, which is fine). The host part ('%') is NOT verified on TiDB.
--     TLS is enforced by the server endpoint on Serverless; on self-managed MySQL/TiDB use REQUIRE SSL
--     as shown.
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
CREATE USER IF NOT EXISTS 'rs_mig'@'%' IDENTIFIED BY '<MIGRATOR_PASSWORD>' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, CREATE, ALTER, INDEX, DROP
  ON `dsecure_prod`.* TO 'rs_mig'@'%';
-- The migrator also owns the tooling tables `_sqlx_migrations`, `_sqlx_migrations_shadow` and
-- `_migration_lock` (lock row: UPDATE-based acquire/release, no DELETE needed).
-- DROP is needed only for expand/contract cleanup migrations; the owner may revoke it between releases:
-- REVOKE DROP ON `dsecure_prod`.* FROM 'rs_mig'@'%';
-- sqlx migration bookkeeping table lives in the same database (covered by the grant above).

-- ---------------------------------------------------------------------------------------------
-- 2) App (API + in-process workers). PER-TABLE grants generated from db::table_classes::TABLE_CLASSES by
--    db::grants::grant_statements (test `grants::tests::ops_doc_matches_generator` keeps this in sync).
--    S/I/U on tenant/identity/directory/infra tables; audit tables S/I only (append-only);
--    data_keys S/I; signing_keys, platform_staff, staff_access_grants, platform_bootstrap SELECT only (keys, staff and
--    grants = platform-admin path with a verified approver, review R1). No DELETE, no DDL.
--    New tables need a new grant (CI: regenerate with `cargo test -p db print_grants -- --ignored --nocapture`).
-- ---------------------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'rs_app'@'%' IDENTIFIED BY '<APP_PASSWORD>' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenants` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_settings` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_features` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_feature_changes` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_quotas` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`authz_epochs` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`users` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`user_credentials` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`mfa_factors` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`mfa_recovery_codes` TO 'rs_app'@'%';
GRANT SELECT ON `dsecure_prod`.`platform_staff` TO 'rs_app'@'%';
GRANT SELECT ON `dsecure_prod`.`staff_access_grants` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`departments` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`groups` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`memberships` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`membership_directory` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`membership_capabilities` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`group_memberships` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`group_admin_grants` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`member_preferences` TO 'rs_app'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`data_keys` TO 'rs_app'@'%';
GRANT SELECT ON `dsecure_prod`.`signing_keys` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`sessions` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`refresh_tokens` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`step_up_tokens` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`auth_challenges` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`device_credentials` TO 'rs_app'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`audit_events` TO 'rs_app'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`audit_chain_blocks` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`outbox_events` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`jobs` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`idempotency_keys` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_counters` TO 'rs_app'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`member_counters` TO 'rs_app'@'%';
GRANT SELECT ON `dsecure_prod`.`platform_bootstrap` TO 'rs_app'@'%';
GRANT SELECT ON `dsecure_prod`.`_sqlx_migrations` TO 'rs_app'@'%';

-- ---------------------------------------------------------------------------------------------
-- 3) Worker (separate worker service, D-02): least privilege for jobs: tenant tables S/I/U,
--    identity/directory S, jobs/outbox S/I/U, audit S/I, data_keys S/I (lazy tenant DEK), authz_epochs S/U,
--    no staff tables, no idempotency keys.
-- ---------------------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'rs_wrk'@'%' IDENTIFIED BY '<WORKER_PASSWORD>' REQUIRE SSL;
GRANT SELECT ON `dsecure_prod`.`tenants` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_settings` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_features` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_feature_changes` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_quotas` TO 'rs_wrk'@'%';
GRANT SELECT, UPDATE ON `dsecure_prod`.`authz_epochs` TO 'rs_wrk'@'%';
GRANT SELECT ON `dsecure_prod`.`users` TO 'rs_wrk'@'%';
GRANT SELECT ON `dsecure_prod`.`user_credentials` TO 'rs_wrk'@'%';
GRANT SELECT ON `dsecure_prod`.`mfa_factors` TO 'rs_wrk'@'%';
GRANT SELECT ON `dsecure_prod`.`mfa_recovery_codes` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`departments` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`groups` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`memberships` TO 'rs_wrk'@'%';
GRANT SELECT ON `dsecure_prod`.`membership_directory` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`membership_capabilities` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`group_memberships` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`group_admin_grants` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`member_preferences` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`data_keys` TO 'rs_wrk'@'%';
GRANT SELECT ON `dsecure_prod`.`signing_keys` TO 'rs_wrk'@'%';
GRANT SELECT ON `dsecure_prod`.`sessions` TO 'rs_wrk'@'%';
GRANT SELECT ON `dsecure_prod`.`refresh_tokens` TO 'rs_wrk'@'%';
GRANT SELECT ON `dsecure_prod`.`step_up_tokens` TO 'rs_wrk'@'%';
GRANT SELECT ON `dsecure_prod`.`auth_challenges` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`device_credentials` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`audit_events` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`audit_chain_blocks` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`outbox_events` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`jobs` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`tenant_counters` TO 'rs_wrk'@'%';
GRANT SELECT, INSERT, UPDATE ON `dsecure_prod`.`member_counters` TO 'rs_wrk'@'%';
GRANT SELECT ON `dsecure_prod`.`_sqlx_migrations` TO 'rs_wrk'@'%';

-- ---------------------------------------------------------------------------------------------
-- 4) Read-only: reconciliation, support SELECTs (main session), RU reports.
-- ---------------------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'rs_ro'@'%' IDENTIFIED BY '<READONLY_PASSWORD>' REQUIRE SSL;
GRANT SELECT ON `dsecure_prod`.`tenants` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`tenant_settings` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`tenant_features` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`tenant_feature_changes` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`tenant_quotas` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`authz_epochs` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`users` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`user_credentials` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`mfa_factors` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`mfa_recovery_codes` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`platform_staff` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`staff_access_grants` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`departments` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`groups` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`memberships` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`membership_directory` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`membership_capabilities` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`group_memberships` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`group_admin_grants` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`member_preferences` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`data_keys` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`signing_keys` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`sessions` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`refresh_tokens` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`step_up_tokens` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`auth_challenges` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`device_credentials` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`audit_events` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`audit_chain_blocks` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`outbox_events` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`jobs` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`idempotency_keys` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`tenant_counters` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`member_counters` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`platform_bootstrap` TO 'rs_ro'@'%';
GRANT SELECT ON `dsecure_prod`.`_sqlx_migrations` TO 'rs_ro'@'%';

-- ---------------------------------------------------------------------------------------------
-- 4b) Platform admin (db::platform_admin::PlatformAdminDb): the ONLY user that creates staff and access
--     grants (INSERT) and does the narrow UPDATEs, COLUMN-level only (review R5): platform_staff(role,
--     revoked_at), staff_access_grants(closed_at), data_keys(status, active_marker, rotated_at,
--     destroyed_at, destroyed_by_approval), signing_keys(status, not_after). Never wrapped_dek, kek_ref,
--     staff_user_id or tenant_id. Audit rows S/I; platform_bootstrap S/I (first-run singleton marker,
--     migration 0880_0001); tenants S. Platform console / ops tooling only:
--     `dsecure-api staff-bootstrap` (first superadmin; the users / credentials / MFA rows go through
--     the app user, so rs_padm needs no grant on users) and `cargo xtask provision-keys seed-db`.
-- ---------------------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'rs_padm'@'%' IDENTIFIED BY '<PLATFORM_ADMIN_PASSWORD>' REQUIRE SSL;
GRANT SELECT ON `dsecure_prod`.`tenants` TO 'rs_padm'@'%';
GRANT SELECT, INSERT, UPDATE (role, revoked_at) ON `dsecure_prod`.`platform_staff` TO 'rs_padm'@'%';
GRANT SELECT, INSERT, UPDATE (closed_at) ON `dsecure_prod`.`staff_access_grants` TO 'rs_padm'@'%';
GRANT SELECT, INSERT, UPDATE (status, active_marker, rotated_at, destroyed_at, destroyed_by_approval) ON `dsecure_prod`.`data_keys` TO 'rs_padm'@'%';
GRANT SELECT, INSERT, UPDATE (status, not_after) ON `dsecure_prod`.`signing_keys` TO 'rs_padm'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`audit_events` TO 'rs_padm'@'%';
GRANT SELECT, INSERT ON `dsecure_prod`.`platform_bootstrap` TO 'rs_padm'@'%';

-- ---------------------------------------------------------------------------------------------
-- 5) Retention (D-17, D-56): DELETE only on listed infra tables. DISABLED until the owner approves
--    each data class: created locked, no grants applied until approval.
-- ---------------------------------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'rs_ret'@'%' IDENTIFIED BY '<RETENTION_PASSWORD>' REQUIRE SSL ACCOUNT LOCK;
-- After owner approval, per table (Phase 0 tables only; add later tables when they exist):
-- GRANT SELECT, DELETE ON `dsecure_prod`.`idempotency_keys` TO 'rs_ret'@'%';
-- GRANT SELECT, DELETE ON `dsecure_prod`.`step_up_tokens`   TO 'rs_ret'@'%';
-- GRANT SELECT, DELETE ON `dsecure_prod`.`auth_challenges`  TO 'rs_ret'@'%';
-- GRANT SELECT, DELETE ON `dsecure_prod`.`outbox_events`    TO 'rs_ret'@'%';
-- GRANT SELECT, DELETE ON `dsecure_prod`.`jobs`             TO 'rs_ret'@'%';
-- GRANT SELECT, DELETE ON `dsecure_prod`.`refresh_tokens`   TO 'rs_ret'@'%';  -- > 90 days
-- GRANT SELECT, DELETE ON `dsecure_prod`.`sessions`         TO 'rs_ret'@'%';  -- > 90 days
-- ALTER USER 'rs_ret'@'%' ACCOUNT UNLOCK;

-- ---------------------------------------------------------------------------------------------
-- 6) Local dev / CI (MySQL 8.4 on 127.0.0.1 only). Mirrors the split above, plus scratch databases for
--    per-test isolation (`dsecure_t_<random>`, created and dropped by the test harness).
-- ---------------------------------------------------------------------------------------------
-- CREATE USER IF NOT EXISTS 'rs_mig'@'localhost' IDENTIFIED BY '<LOCAL_MIGRATOR_PASSWORD>';
-- GRANT ALL PRIVILEGES ON `dsecure_dev`.*  TO 'rs_mig'@'localhost';
-- GRANT ALL PRIVILEGES ON `dsecure_test`.* TO 'rs_mig'@'localhost';
-- GRANT ALL PRIVILEGES ON `dsecure\_t\_%`.* TO 'rs_mig'@'localhost';   -- scratch DBs only
-- CREATE USER IF NOT EXISTS 'rs_app'@'localhost' IDENTIFIED BY '<LOCAL_APP_PASSWORD>';
-- Local app user: same per-table statements as section 2 with `dsecure_dev` / `dsecure_test`.
-- The test `tests::t_grants::least_privilege_grants_refuse_audit_update_and_delete` applies the generated
-- App grants to a scratch DB for a scratch user `dsecure_t_grants` (local root) and checks 1142 refusals.
-- Per scratch DB the harness (db::testing::ScratchDb) creates its own app user `dsecure_ta_<hex>` and, on
-- demand, a platform-admin user `dsecure_tp_<hex>` with the generated grants (api test t_ops runs
-- staff-bootstrap with exactly these narrow grants); both are dropped with the scratch DB.

-- ---------------------------------------------------------------------------------------------
-- Verification (read-only, any env): the app user must hold no DELETE and no DDL.
-- ---------------------------------------------------------------------------------------------
-- SHOW GRANTS FOR 'rs_app'@'%';
-- SHOW GRANTS FOR 'rs_wrk'@'%';
-- The db crate test `tests::t_grants::app_user_cannot_delete_or_ddl` checks this on the local MySQL
-- (SHOW GRANTS + a DELETE that must fail with error 1142).
