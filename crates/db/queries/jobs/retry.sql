-- class: infra. params: run_after, last_error_code, id, claim_token
UPDATE jobs SET status = 'queued', claimed_by = NULL, claim_token = NULL, lease_until = NULL, run_after = ?,
  last_error_code = ?
WHERE id = ? AND claim_token = ? AND status = 'running'
