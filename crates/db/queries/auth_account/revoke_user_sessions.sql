-- class: identity (suspend / disable: every live session of the user; ix_sessions_user).
-- params: revoked_at, revoke_reason, user_id
UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE user_id = ? AND revoked_at IS NULL
