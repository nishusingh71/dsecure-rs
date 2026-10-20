-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE platform_staff (                        -- class: platform
  user_id BINARY(16) NOT NULL,
  role VARCHAR(32) NOT NULL,                         -- platform_superadmin|platform_support|platform_billing|platform_auditor
  granted_by BINARY(16) NULL, granted_at DATETIME(6) NOT NULL, revoked_at DATETIME(6) NULL,
  PRIMARY KEY (user_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
