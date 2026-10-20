-- class: infra (poller page 2: strictly newer rows; range scan on ix_authz_epochs_poll, index order).
-- params: since, limit
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT tenant_id, epoch, updated_at FROM authz_epochs USE INDEX (ix_authz_epochs_poll)
WHERE updated_at > ?
ORDER BY updated_at, tenant_id LIMIT ?
