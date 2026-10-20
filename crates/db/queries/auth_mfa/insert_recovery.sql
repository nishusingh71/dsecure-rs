-- class: identity (only the HMAC of a recovery code is stored). params: user_id, id, code_hmac
INSERT INTO mfa_recovery_codes (user_id, id, code_hmac) VALUES (?, ?, ?)
