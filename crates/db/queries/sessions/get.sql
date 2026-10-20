-- class: identity (sid from token = PK point get). params: id
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT id, user_id, tenant_id, membership_id, principal_kind, client_kind, product_code, device_label, mfa_at,
       created_at, last_seen_at, expires_at, revoked_at, revoke_reason
FROM sessions WHERE id = ?
