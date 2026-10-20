-- class: infra (scope_key = tenant_id). params: scope_key, principal_id, idem_key
SELECT request_hash, status_code, response_body, resource_id, expires_at
FROM idempotency_keys WHERE scope_key = ? AND principal_id = ? AND idem_key = ? FOR UPDATE
