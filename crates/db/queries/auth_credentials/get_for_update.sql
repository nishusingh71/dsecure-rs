-- class: identity (lockout counter update, row lock on the credential row of the user). params: user_id
SELECT user_id, password_hash, hash_scheme, failed_attempts, last_failed_at, locked_until
FROM user_credentials WHERE user_id = ? FOR UPDATE
