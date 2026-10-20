-- class: identity (new recovery set replaces the old one; no DELETE). params: used_at, user_id
UPDATE mfa_recovery_codes SET used_at = ? WHERE user_id = ? AND used_at IS NULL
