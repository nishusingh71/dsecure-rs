-- class: tenant. params: revoked_at, tenant_id, id
UPDATE device_credentials SET revoked_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL
