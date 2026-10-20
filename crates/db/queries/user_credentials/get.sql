-- class: identity. params: user_id
SELECT user_id, password_hash, hash_scheme, failed_attempts, locked_until, version
FROM user_credentials WHERE user_id = ?
