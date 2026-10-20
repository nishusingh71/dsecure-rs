-- class: identity. params: id, session_id, family_id, token_hash, issued_at, expires_at
INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, issued_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?)
