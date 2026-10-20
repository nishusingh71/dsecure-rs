-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE staff_access_grants (                   -- class: platform; staff → tenant data, time boxed
  id BINARY(16) NOT NULL, staff_user_id BINARY(16) NOT NULL, tenant_id BINARY(16) NOT NULL,
  reason VARCHAR(500) NOT NULL, ticket_ref VARCHAR(64) NULL, scope VARCHAR(16) NOT NULL,   -- read|support_write
  opened_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL, closed_at DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  KEY ix_sag_staff (staff_user_id, tenant_id, expires_at),
  KEY ix_sag_tenant (tenant_id, opened_at)           -- tenant owner sees staff access in own audit view
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
