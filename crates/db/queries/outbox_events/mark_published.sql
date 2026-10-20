-- class: infra (only the current lease holder, only while the lease is valid). params: published_at, id,
--   claim_token, now
UPDATE outbox_events SET published_at = ?, lease_until = NULL
WHERE id = ? AND claim_token = ? AND lease_until > ? AND published_at IS NULL
