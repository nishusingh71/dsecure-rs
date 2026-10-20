-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE user_credentials (
  user_id BINARY(16) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,               -- PHC string
  hash_scheme   VARCHAR(16) NOT NULL,                -- argon2id|bcrypt_legacy
  password_changed_at DATETIME(6) NOT NULL,
  failed_attempts INT NOT NULL DEFAULT 0, last_failed_at DATETIME(6) NULL, locked_until DATETIME(6) NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (user_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
