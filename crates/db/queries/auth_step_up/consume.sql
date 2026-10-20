-- class: identity (atomic single-use consume under the unique token hash; 0 rows = replay, wrong session,
--   wrong action, wrong target or expired). params: used_at, token_hash, session_id, action, target_id, now
UPDATE step_up_tokens SET used_at = ?
WHERE token_hash = ? AND session_id = ? AND action = ? AND target_id <=> ? AND used_at IS NULL AND expires_at > ?
