-- class: infra (ix_jobs_lease, kind filtered). params: now, kind, limit
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT id FROM jobs WHERE status = 'running' AND lease_until < ? AND kind = ? ORDER BY lease_until LIMIT ?
