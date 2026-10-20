-- set 0200_sessions (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE auth_challenges (                       -- password reset (link and/or OTP), email verify, invites
  id BINARY(16) NOT NULL, user_id BINARY(16) NOT NULL,
  kind VARCHAR(24) NOT NULL,                         -- password_reset|email_verify|invite
  code_hmac BINARY(32) NULL,                         -- OTP (apps / dashboard OTP flow, D-46)
  token_hmac BINARY(32) NOT NULL,                    -- link token
  attempts INT NOT NULL DEFAULT 0, max_attempts INT NOT NULL DEFAULT 5,
  created_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL, used_at DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_ac_token (token_hmac),
  KEY ix_ac_user_kind (user_id, kind, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
