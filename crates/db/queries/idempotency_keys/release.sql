-- class: infra (request died/timed out: its in-progress reservation becomes expired; never DELETE).
-- Ownership = same principal, key and request hash, still uncompleted. params: expires_at, scope_key,
--   principal_id, idem_key, request_hash
UPDATE idempotency_keys SET expires_at = ?
WHERE scope_key = ? AND principal_id = ? AND idem_key = ? AND request_hash = ? AND status_code IS NULL
