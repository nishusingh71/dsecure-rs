-- class: infra. params: finished_at, id, claim_token
UPDATE jobs SET status = 'succeeded', finished_at = ?, lease_until = NULL
WHERE id = ? AND claim_token = ? AND status = 'running'
