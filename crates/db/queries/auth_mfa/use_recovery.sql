-- class: identity (single use, atomic; PK prefix user_id, at most 10 live rows). params: used_at, user_id,
--   code_hmac
UPDATE mfa_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hmac = ? AND used_at IS NULL
