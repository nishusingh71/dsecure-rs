-- class: infra (ix_outbox_tenant_pending; per-tenant relay / tests on a shared DB). params: tenant_id, now,
--   limit
SELECT id FROM outbox_events
WHERE tenant_id = ? AND published_at IS NULL AND (lease_until IS NULL OR lease_until < ?)
ORDER BY created_at, id LIMIT ?
