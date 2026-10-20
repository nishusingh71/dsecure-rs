-- set 0200_sessions (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE step_up_tokens (
  id BINARY(16) NOT NULL, session_id BINARY(16) NOT NULL,
  action VARCHAR(48) NOT NULL, target_id BINARY(16) NULL, token_hash BINARY(32) NOT NULL,
  expires_at DATETIME(6) NOT NULL, used_at DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_sut_hash (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
