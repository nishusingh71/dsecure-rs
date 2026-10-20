-- class: identity, read through TenantTx (ix_sessions_tenant_member). params: tenant_id, membership_id,
--   after_id, limit
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT s.id, s.user_id, s.tenant_id, s.membership_id, s.principal_kind, s.client_kind, s.product_code,
       s.device_label, s.mfa_at, s.created_at, s.last_seen_at, s.expires_at, s.revoked_at, s.revoke_reason
FROM sessions s WHERE s.tenant_id = ? AND s.membership_id = ? AND s.id < ? ORDER BY s.id DESC LIMIT ?
