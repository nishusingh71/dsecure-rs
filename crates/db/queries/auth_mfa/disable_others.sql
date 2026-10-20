-- class: identity (one active TOTP factor per user). params: disabled_at, user_id, keep_id
UPDATE mfa_factors SET disabled_at = ?
WHERE user_id = ? AND kind = 'totp' AND id <> ? AND disabled_at IS NULL
