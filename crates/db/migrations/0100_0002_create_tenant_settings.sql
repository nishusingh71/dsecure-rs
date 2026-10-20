-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE tenant_settings (                       -- class: tenant (natural key)
  tenant_id BINARY(16) NOT NULL,
  timezone  VARCHAR(64) NOT NULL DEFAULT 'UTC',
  require_credit_allocation BOOLEAN NOT NULL DEFAULT FALSE,
  autopilot_auto_check BOOLEAN NOT NULL DEFAULT FALSE,     -- legacy Users.mdm_auto_check_enabled
  updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
