-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE tenant_feature_changes (                -- append-only history
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  feature VARCHAR(24) NOT NULL, enabled BOOLEAN NOT NULL,
  changed_by_staff BINARY(16) NOT NULL, reason VARCHAR(500) NOT NULL, ticket_ref VARCHAR(64) NULL,
  changed_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
