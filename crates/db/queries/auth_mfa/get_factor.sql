-- class: identity (PK point get). params: user_id, id
SELECT user_id, id, secret_enc, last_used_at, disabled_at
FROM mfa_factors WHERE user_id = ? AND id = ? AND kind = 'totp'
