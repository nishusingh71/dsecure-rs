-- class: identity. params: revoked_at, revoke_reason, id
UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL
