-- set 0200_sessions (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE device_credentials (                    -- enrolled app installations (Device principal)
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL, device_id BINARY(16) NOT NULL,
  operator_membership_id BINARY(16) NOT NULL,
  product_code VARCHAR(16) NOT NULL,
  scopes VARCHAR(255) NOT NULL,                      -- space-separated scope codes (no array type)
  secret_hash BINARY(32) NULL, public_key VARBINARY(128) NULL,  -- secret or Ed25519 device key (D-24 signed offline uploads)
  created_at DATETIME(6) NOT NULL, last_used_at DATETIME(6) NULL, revoked_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_dc_device (tenant_id, device_id, revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
