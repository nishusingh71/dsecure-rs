-- set 0100_tenancy_identity. Reserved PLATFORM pseudo-tenant (db::PLATFORM_TENANT_ID), data row, one
-- statement. Owner of platform-scope rows that need a tenant id (platform DEKs in data_keys, audit
-- anchor blobs). status 'platform': never loginable (no memberships/directory rows; the db crate
-- refuses TenantTx for it) and excluded from tenant lists. No quotas/counters/epoch rows on purpose.
-- display_name_enc is a 1-byte marker, not ciphertext (nothing to decrypt).
INSERT INTO tenants (id, kind, display_name_enc, status, data_region, created_at, updated_at, version)
VALUES (0x00000000000070008000000000000001, 'organization', 0x00, 'platform', 'default',
        '2026-01-01 00:00:00.000000', '2026-01-01 00:00:00.000000', 1);
