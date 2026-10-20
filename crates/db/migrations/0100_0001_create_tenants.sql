-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE tenants (                               -- class: platform
  id                   BINARY(16)   NOT NULL,
  kind                 VARCHAR(16)  NOT NULL,        -- organization | individual
  display_name_enc     VARBINARY(512) NOT NULL,
  status               VARCHAR(16)  NOT NULL DEFAULT 'active',   -- active|suspended|closed|erased|platform
  data_region          VARCHAR(16)  NOT NULL DEFAULT 'default',
  legacy_owner_user_id BIGINT       NULL,
  created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
  closed_at DATETIME(6) NULL, erased_at DATETIME(6) NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_tenants_legacy (legacy_owner_user_id),
  KEY ix_tenants_status (status, id),
  CONSTRAINT ck_tenants_kind CHECK (kind IN ('organization','individual')),
  -- 'platform' = reserved pseudo-tenant (0100_0021), never loginable, excluded from tenant lists
  CONSTRAINT ck_tenants_status CHECK (status IN ('active','suspended','closed','erased','platform'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
