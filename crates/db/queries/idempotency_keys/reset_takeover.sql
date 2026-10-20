-- class: infra (reuse an expired key, or take over an in-progress one older than the stale timeout).
-- params: request_hash, created_at, expires_at, scope_key, principal_id, idem_key, now, stale_before
UPDATE idempotency_keys SET request_hash = ?, status_code = NULL, response_body = NULL, resource_id = NULL,
  created_at = ?, expires_at = ?
WHERE scope_key = ? AND principal_id = ? AND idem_key = ?
  AND (expires_at <= ? OR (status_code IS NULL AND created_at < ?))
