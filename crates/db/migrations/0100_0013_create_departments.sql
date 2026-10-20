-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE departments (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  name VARCHAR(128) NOT NULL, name_norm VARCHAR(128) NOT NULL,
  name_active VARCHAR(128) NULL,                     -- = name_norm while not archived (unique-when-active)
  created_at DATETIME(6) NOT NULL, archived_at DATETIME(6) NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_departments_name (tenant_id, name_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
