-- class: identity (idle tracking, written at most once per throttle window). params: last_seen_at, id, older_than
UPDATE sessions SET last_seen_at = ? WHERE id = ? AND revoked_at IS NULL AND last_seen_at < ?
