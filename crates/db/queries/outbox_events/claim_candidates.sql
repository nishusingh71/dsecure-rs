-- class: infra (ix_outbox_pending; snapshot read). params: now, limit
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT id FROM outbox_events WHERE published_at IS NULL AND (lease_until IS NULL OR lease_until < ?)
ORDER BY created_at, id LIMIT ?
