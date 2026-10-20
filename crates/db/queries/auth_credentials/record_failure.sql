-- class: identity. params: failed_attempts, last_failed_at, locked_until, user_id
UPDATE user_credentials SET failed_attempts = ?, last_failed_at = ?, locked_until = ?, version = version + 1
WHERE user_id = ?
