-- class: identity (reuse detection). params: revoked_at, family_id
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL
