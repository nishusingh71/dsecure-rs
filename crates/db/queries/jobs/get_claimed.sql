-- class: infra. params: id, claim_token
SELECT id, kind, tenant_id, payload, attempts, max_attempts, lease_until
FROM jobs WHERE id = ? AND claim_token = ? AND status = 'running'
