-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE users (                                 -- class: identity (global human identity)
  id                 BINARY(16) NOT NULL,
  email_bidx         BINARY(32) NOT NULL,            -- HMAC(global email key, normalised email); on erase overwritten with random
  email_enc          VARBINARY(512) NOT NULL,
  name_enc           VARBINARY(512) NULL,
  phone_enc          VARBINARY(256) NULL,
  status             VARCHAR(24) NOT NULL DEFAULT 'pending_verification', -- pending_verification|active|suspended|disabled|erased
  email_verified_at  DATETIME(6) NULL,
  verification_source VARCHAR(16) NULL,              -- email_link|legacy_import|payment_link|staff
  locale VARCHAR(16) NULL, timezone VARCHAR(64) NULL,
  authz_version      BIGINT UNSIGNED NOT NULL DEFAULT 1,
  tokens_valid_after DATETIME(6) NULL,
  last_tenant_id     BINARY(16) NULL,
  legacy_user_id     BIGINT NULL,
  created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, erased_at DATETIME(6) NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_users_email_bidx (email_bidx),       -- erase = bidx random (no partial index needed)
  UNIQUE KEY ux_users_legacy (legacy_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
