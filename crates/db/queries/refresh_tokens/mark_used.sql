-- class: identity (rotation; 0 rows = reuse/race). params: used_at, replaced_by, id
UPDATE refresh_tokens SET used_at = ?, replaced_by = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL
