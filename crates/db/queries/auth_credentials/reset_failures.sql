-- class: identity (successful login). params: user_id
UPDATE user_credentials SET failed_attempts = 0, last_failed_at = NULL, locked_until = NULL, version = version + 1
WHERE user_id = ?
