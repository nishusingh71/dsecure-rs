-- class: platform (platform-admin path only; private key = FieldEncryptor ciphertext, never PEM).
-- params: kid, purpose, alg, public_key, wrapped_private_key, not_before, not_after, created_at
INSERT INTO signing_keys (kid, purpose, alg, public_key, private_key_ref, wrapped_private_key, status,
  not_before, not_after, created_at)
VALUES (?, ?, ?, ?, NULL, ?, 'active', ?, ?, ?)
