-- class: infra (ix_outbox_tenant_pending; bounded by the cap). params: tenant_id, cap
SELECT COUNT(*) AS n FROM (SELECT 1 FROM outbox_events WHERE tenant_id = ? AND published_at IS NULL LIMIT ?) x
