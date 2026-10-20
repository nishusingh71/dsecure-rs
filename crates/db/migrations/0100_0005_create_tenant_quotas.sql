-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE tenant_quotas (                         -- NULL = unlimited; only platform staff writes; also quota MUTEX row
  tenant_id BINARY(16) NOT NULL,
  max_members INT NULL, max_groups INT NULL, max_departments INT NULL, max_licenses INT NULL,
  updated_by_staff BINARY(16) NULL, updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
