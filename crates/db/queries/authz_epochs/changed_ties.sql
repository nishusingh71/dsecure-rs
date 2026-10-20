-- class: infra (poller page 1: rows with exactly the cursor timestamp after the cursor tenant; range
-- scan on ix_authz_epochs_poll). params: since, after_tenant_id, limit
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT tenant_id, epoch, updated_at FROM authz_epochs USE INDEX (ix_authz_epochs_poll)
WHERE updated_at = ? AND tenant_id > ?
ORDER BY tenant_id LIMIT ?
