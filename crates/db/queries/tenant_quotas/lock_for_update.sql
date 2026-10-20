-- class: tenant. Quota MUTEX row. params: tenant_id
SELECT tenant_id, max_members, max_groups, max_departments, max_licenses
FROM tenant_quotas WHERE tenant_id = ? FOR UPDATE
