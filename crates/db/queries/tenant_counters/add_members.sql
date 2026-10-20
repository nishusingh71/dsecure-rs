-- class: tenant. Never below 0 (0 rows = NotPersisted). params: delta, updated_at, tenant_id, delta
UPDATE tenant_counters SET members_active = members_active + ?, updated_at = ?
WHERE tenant_id = ? AND members_active + ? >= 0
