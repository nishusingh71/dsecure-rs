-- class: infra. params: id, claim_token
UPDATE outbox_events SET claimed_by = NULL, claim_token = NULL, lease_until = NULL
WHERE id = ? AND claim_token = ? AND published_at IS NULL
