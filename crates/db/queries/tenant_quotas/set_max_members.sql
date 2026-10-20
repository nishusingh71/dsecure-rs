-- class: tenant (platform staff write). params: max_members, updated_by_staff, updated_at, tenant_id
UPDATE tenant_quotas SET max_members = ?, updated_by_staff = ?, updated_at = ?, version = version + 1
WHERE tenant_id = ?
