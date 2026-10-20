-- class: identity (second factor completed for this session). params: mfa_at, id
UPDATE sessions SET mfa_at = ? WHERE id = ? AND revoked_at IS NULL
