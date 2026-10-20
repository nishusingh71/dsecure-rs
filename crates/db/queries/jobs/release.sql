-- class: infra (graceful shutdown: back to queued, attempt not consumed, no backoff). params: id, claim_token
UPDATE jobs SET status = 'queued', claimed_by = NULL, claim_token = NULL, lease_until = NULL,
  attempts = attempts - 1
WHERE id = ? AND claim_token = ? AND status = 'running' AND attempts > 0
