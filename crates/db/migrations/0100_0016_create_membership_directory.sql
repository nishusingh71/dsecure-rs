-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE membership_directory (                  -- class: directory; login: user → tenants (no tenant known yet)
  user_id BINARY(16) NOT NULL, tenant_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
  status VARCHAR(16) NOT NULL, role VARCHAR(16) NOT NULL, updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (user_id, tenant_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
