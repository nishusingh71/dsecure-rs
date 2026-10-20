-- class: infra. Lease re-check inside the job's business tx (latest row, locked; reaper waits).
-- params: id, claim_token, now
SELECT id, kind, tenant_id, payload, attempts, max_attempts, lease_until
FROM jobs WHERE id = ? AND claim_token = ? AND status = 'running' AND lease_until > ? FOR UPDATE
