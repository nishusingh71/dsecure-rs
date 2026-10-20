-- class: identity (confirmed = last_used_at set by the confirming code; PK prefix user_id, few rows).
-- params: user_id
SELECT user_id, id, secret_enc, last_used_at, disabled_at
FROM mfa_factors
WHERE user_id = ? AND kind = 'totp' AND disabled_at IS NULL AND last_used_at IS NOT NULL
ORDER BY created_at DESC LIMIT 1
