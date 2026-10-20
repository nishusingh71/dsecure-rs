-- class: infra. params: status_code, response_body, resource_id, scope_key, principal_id, idem_key
UPDATE idempotency_keys SET status_code = ?, response_body = ?, resource_id = ?
WHERE scope_key = ? AND principal_id = ? AND idem_key = ? AND status_code IS NULL
