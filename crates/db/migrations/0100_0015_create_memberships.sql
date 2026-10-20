-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE memberships (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  user_id   BINARY(16) NOT NULL,
  role      VARCHAR(16) NOT NULL,                    -- owner|admin|member|viewer
  role_rank TINYINT UNSIGNED NOT NULL,               -- 100/80/40/20 (denormalised for visibility filters)
  kind      VARCHAR(16) NOT NULL DEFAULT 'primary',  -- primary|subuser (reporting only)
  status    VARCHAR(16) NOT NULL DEFAULT 'active',   -- invited|active|disabled|deleted
  parent_membership_id BINARY(16) NULL,
  department_id BINARY(16) NULL,
  authz_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  display_name_enc VARBINARY(512) NULL,
  display_name_norm_hash BINARY(32) NULL,            -- tenant bidx for exact-name search (optional)
  created_by BINARY(16) NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
  disabled_at DATETIME(6) NULL, deleted_at DATETIME(6) NULL,
  last_login_at DATETIME(6) NULL,
  legacy_subuser_id BIGINT NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_memberships_user (tenant_id, user_id),
  KEY ix_memberships_role (tenant_id, status, role_rank, id),
  KEY ix_memberships_dept (tenant_id, department_id, id),
  KEY ix_memberships_parent (tenant_id, parent_membership_id, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
