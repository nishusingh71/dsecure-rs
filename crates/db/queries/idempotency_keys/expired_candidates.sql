-- class: infra (ix_idem_expiry; snapshot read). params: now, limit
SELECT scope_key, principal_id, idem_key FROM idempotency_keys
WHERE expires_at <= ? AND response_body IS NOT NULL ORDER BY expires_at LIMIT ?
