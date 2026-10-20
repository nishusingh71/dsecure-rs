-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE group_memberships (
  tenant_id BINARY(16) NOT NULL, group_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
  added_by BINARY(16) NOT NULL, added_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, group_id, membership_id) /*T![clustered_index] CLUSTERED */,
  KEY ix_gm_member (tenant_id, membership_id, group_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
