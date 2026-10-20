-- class: infra (drops the stored response of an expired key; row stays until TTL). params: scope_key,
--   principal_id, idem_key, now
UPDATE idempotency_keys SET response_body = NULL, resource_id = NULL
WHERE scope_key = ? AND principal_id = ? AND idem_key = ? AND expires_at <= ?
