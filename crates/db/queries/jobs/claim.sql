-- class: infra. Lease claim (DATABASE.md 8.4): rows_affected = 1 means owned.
-- params: claimed_by, claim_token, lease_until, id, now
UPDATE jobs SET status = 'running', claimed_by = ?, claim_token = ?, lease_until = ?, attempts = attempts + 1
WHERE id = ? AND status = 'queued' AND run_after <= ?
