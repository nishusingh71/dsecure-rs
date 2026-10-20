-- class: platform. Tenant MUTEX row (DATABASE.md 4.3). params: tenant_id
SELECT id, status FROM tenants WHERE id = ? FOR UPDATE
