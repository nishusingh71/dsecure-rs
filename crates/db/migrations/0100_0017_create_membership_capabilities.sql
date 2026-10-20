-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE membership_capabilities (
  tenant_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
  can_view_reports BOOLEAN NOT NULL DEFAULT TRUE,
  can_manage_machines BOOLEAN NOT NULL DEFAULT FALSE,
  can_assign_licenses BOOLEAN NOT NULL DEFAULT FALSE,
  max_machines INT NULL,
  updated_by BINARY(16) NULL, updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, membership_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
