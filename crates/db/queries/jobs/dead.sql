-- class: infra. params: finished_at, last_error_code, id, claim_token
UPDATE jobs SET status = 'dead', finished_at = ?, lease_until = NULL, last_error_code = ?
WHERE id = ? AND claim_token = ? AND status = 'running'
