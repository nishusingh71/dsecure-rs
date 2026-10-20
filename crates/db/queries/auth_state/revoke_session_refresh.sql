-- class: identity (logout and reuse detection: every live refresh token of the session; ix_rt_session).
-- params: revoked_at, session_id
UPDATE refresh_tokens SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL
