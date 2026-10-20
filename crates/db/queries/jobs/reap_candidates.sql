-- class: infra (ix_jobs_lease; snapshot read, no range locks). params: now, limit
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT id FROM jobs WHERE status = 'running' AND lease_until < ? ORDER BY lease_until LIMIT ?
