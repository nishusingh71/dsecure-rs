-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE `groups` (                              -- `groups` is a reserved word in MySQL 8: always quote
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  parent_group_id BINARY(16) NULL,
  name VARCHAR(128) NOT NULL, name_norm VARCHAR(128) NOT NULL, name_active VARCHAR(128) NULL,
  description VARCHAR(500) NULL,
  created_by_membership BINARY(16) NOT NULL,
  created_at DATETIME(6) NOT NULL, archived_at DATETIME(6) NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  legacy_group_id BIGINT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_groups_name (tenant_id, name_active),
  KEY ix_groups_name_search (tenant_id, name_norm)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
