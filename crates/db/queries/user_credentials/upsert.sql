-- class: identity. params: user_id, password_hash, hash_scheme, password_changed_at
INSERT INTO user_credentials (user_id, password_hash, hash_scheme, password_changed_at)
VALUES (?, ?, ?, ?)
ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), hash_scheme = VALUES(hash_scheme),
  password_changed_at = VALUES(password_changed_at), failed_attempts = 0, locked_until = NULL,
  version = version + 1
