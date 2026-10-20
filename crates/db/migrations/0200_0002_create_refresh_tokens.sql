-- set 0200_sessions (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE refresh_tokens (
  id BINARY(16) NOT NULL, session_id BINARY(16) NOT NULL,
  family_id BINARY(16) NOT NULL, token_hash BINARY(32) NOT NULL,
  issued_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL,
  used_at DATETIME(6) NULL, replaced_by BINARY(16) NULL, revoked_at DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_rt_hash (token_hash),
  KEY ix_rt_family (family_id),
  KEY ix_rt_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
