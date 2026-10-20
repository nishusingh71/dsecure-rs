-- class: infra. params: id, kind, job_key, tenant_id, payload, run_after, max_attempts, created_at
INSERT INTO jobs (id, kind, job_key, tenant_id, payload, status, run_after, max_attempts, created_at)
VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?)
