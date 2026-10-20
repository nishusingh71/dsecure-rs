-- class: identity (TOTP replay guard: last_used_at = start of the last accepted time step; a code is
--   accepted only for a strictly later step, atomically). params: step_at, user_id, id, step_at
UPDATE mfa_factors SET last_used_at = ?
WHERE user_id = ? AND id = ? AND disabled_at IS NULL AND (last_used_at IS NULL OR last_used_at < ?)
