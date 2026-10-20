-- class: tenant. params: tenant_id
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT tenant_id, members_active, groups_active, departments_active, devices_active, licenses_active,
       licenses_in_use, updated_at
FROM tenant_counters WHERE tenant_id = ?
