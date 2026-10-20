-- set 0800_audit_infra (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE tenant_counters (                       -- O(1) dashboard summary; also used inside quota tx
  tenant_id BINARY(16) NOT NULL,
  members_active INT NOT NULL DEFAULT 0, groups_active INT NOT NULL DEFAULT 0, departments_active INT NOT NULL DEFAULT 0,
  devices_active INT NOT NULL DEFAULT 0, licenses_active INT NOT NULL DEFAULT 0, licenses_in_use INT NOT NULL DEFAULT 0,
  autopilot_devices INT NOT NULL DEFAULT 0, freeze_endpoints INT NOT NULL DEFAULT 0,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
