-- class: identity (TOTP enrolment, pending until confirmed: last_used_at IS NULL). params: user_id, id,
--   secret_enc, label, created_at
INSERT INTO mfa_factors (user_id, id, kind, secret_enc, label, created_at)
VALUES (?, ?, 'totp', ?, ?, ?)
