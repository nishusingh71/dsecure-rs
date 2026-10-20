-- class: identity (suspend / disable: every live refresh token of every session of the user; ix_rt_session).
-- params: revoked_at, user_id
UPDATE refresh_tokens SET revoked_at = ?
WHERE session_id IN (SELECT s.id FROM sessions s WHERE s.user_id = ?) AND revoked_at IS NULL
