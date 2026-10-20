-- set 0800_audit_infra (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE idempotency_keys (
  scope_key BINARY(16) NOT NULL,                     -- tenant_id, or user_id for tenant-less principals
  principal_id BINARY(16) NOT NULL, idem_key VARCHAR(128) NOT NULL,
  request_hash BINARY(32) NOT NULL, status_code SMALLINT NULL, response_body VARBINARY(16384) NULL,
  resource_id BINARY(16) NULL, created_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (scope_key, principal_id, idem_key) /*T![clustered_index] CLUSTERED */,
  KEY ix_idem_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
