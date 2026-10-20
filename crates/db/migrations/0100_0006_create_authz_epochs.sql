-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE authz_epochs (                          -- class: infra; replaces LISTEN/NOTIFY (§4.4)
  tenant_id  BINARY(16) NOT NULL,                    -- 0x00.. row = platform/staff epoch
  epoch      BIGINT UNSIGNED NOT NULL DEFAULT 1,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id) /*T![clustered_index] CLUSTERED */,
  KEY ix_authz_epochs_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
