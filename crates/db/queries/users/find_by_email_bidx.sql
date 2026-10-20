-- class: identity (ux_users_email_bidx point get). params: email_bidx
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT id, email_bidx, email_enc, name_enc, status, email_verified_at, authz_version, tokens_valid_after,
       version, created_at
FROM users WHERE email_bidx = ?
