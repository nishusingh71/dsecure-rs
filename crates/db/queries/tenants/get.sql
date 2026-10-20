-- class: platform (own row only, id = tx tenant). params: tenant_id
SELECT id, kind, status, version, created_at FROM tenants WHERE id = ?
