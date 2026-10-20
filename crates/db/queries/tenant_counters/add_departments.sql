-- class: tenant. params: delta, updated_at, tenant_id, delta
UPDATE tenant_counters SET departments_active = departments_active + ?, updated_at = ?
WHERE tenant_id = ? AND departments_active + ? >= 0
