-- class: infra. params: request_hash, created_at, expires_at, scope_key, principal_id, idem_key, now
UPDATE idempotency_keys SET request_hash = ?, status_code = NULL, response_body = NULL, resource_id = NULL,
  created_at = ?, expires_at = ?
WHERE scope_key = ? AND principal_id = ? AND idem_key = ? AND expires_at <= ?
