-- class: infra (ix_jobs_due; snapshot read, no lock). params: kind, now, limit
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT id FROM jobs WHERE status = 'queued' AND kind = ? AND run_after <= ? ORDER BY run_after LIMIT ?
