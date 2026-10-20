-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE mfa_factors (
  user_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  kind VARCHAR(16) NOT NULL,                         -- totp|webauthn
  secret_enc VARBINARY(256) NULL, credential_public_key VARBINARY(1024) NULL, label VARCHAR(64) NULL,
  created_at DATETIME(6) NOT NULL, last_used_at DATETIME(6) NULL, disabled_at DATETIME(6) NULL,
  PRIMARY KEY (user_id, id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
