-- class: infra. params: scope_key, principal_id, idem_key, request_hash, created_at, expires_at
INSERT INTO idempotency_keys (scope_key, principal_id, idem_key, request_hash, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?)
