-- set 0800_audit_infra (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE member_counters (                       -- per-member devices/reports (Group with-users counts, max_machines)
  tenant_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
  devices_active INT NOT NULL DEFAULT 0, reports_total BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, membership_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
