-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE tenant_features (                       -- toggles; only platform staff writes
  tenant_id BINARY(16) NOT NULL,
  feature   VARCHAR(24) NOT NULL,                    -- subusers|groups|user_activity|private_cloud
  enabled   BOOLEAN NOT NULL DEFAULT FALSE,
  changed_by_staff BINARY(16) NOT NULL,
  changed_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, feature) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
