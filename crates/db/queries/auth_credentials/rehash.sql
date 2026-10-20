-- class: identity (legacy bcrypt or old Argon2 params to current Argon2id; compare-and-swap on the old hash,
--   password_changed_at untouched). params: password_hash, hash_scheme, user_id, old_password_hash
UPDATE user_credentials SET password_hash = ?, hash_scheme = ?, version = version + 1
WHERE user_id = ? AND password_hash = ?
