-- class: identity. params: id
SELECT id, email_bidx, email_enc, name_enc, status, email_verified_at, authz_version, tokens_valid_after,
       version, created_at
FROM users WHERE id = ?
