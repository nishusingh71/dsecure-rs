-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE mfa_recovery_codes (
  user_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  code_hmac BINARY(32) NOT NULL, used_at DATETIME(6) NULL,
  PRIMARY KEY (user_id, id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
