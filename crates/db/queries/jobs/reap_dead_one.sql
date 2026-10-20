-- class: infra. params: finished_at, id, now
UPDATE jobs SET status = 'dead', finished_at = ?, lease_until = NULL, last_error_code = 'lease_expired'
WHERE id = ? AND status = 'running' AND lease_until < ? AND attempts >= max_attempts
