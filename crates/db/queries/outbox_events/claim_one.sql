-- class: infra (PK point update; 1 row = claimed; fresh claim_token per claim). params: claimed_by,
--   claim_token, lease_until, id, now
UPDATE outbox_events SET claimed_by = ?, claim_token = ?, lease_until = ?, attempts = attempts + 1
WHERE id = ? AND published_at IS NULL AND (lease_until IS NULL OR lease_until < ?)
