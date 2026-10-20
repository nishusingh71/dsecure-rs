-- class: tenant. params: delta, updated_at, tenant_id, delta
UPDATE tenant_counters SET groups_active = groups_active + ?, updated_at = ?
WHERE tenant_id = ? AND groups_active + ? >= 0
