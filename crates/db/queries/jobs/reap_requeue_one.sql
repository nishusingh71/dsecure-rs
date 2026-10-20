-- class: infra (PK point update; waits for an open job tx, then re-checks). params: run_after, id, now
UPDATE jobs SET status = 'queued', claimed_by = NULL, claim_token = NULL, lease_until = NULL, run_after = ?,
  last_error_code = 'lease_expired'
WHERE id = ? AND status = 'running' AND lease_until < ? AND attempts < max_attempts
