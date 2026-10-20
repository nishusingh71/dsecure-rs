-- class: identity. params: token_hash
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT id, session_id, family_id, issued_at, expires_at, used_at, replaced_by, revoked_at
FROM refresh_tokens WHERE token_hash = ?
