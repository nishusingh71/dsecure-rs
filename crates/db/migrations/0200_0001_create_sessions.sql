-- set 0200_sessions (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE sessions (                              -- class: identity (sid from token = PK point get)
  id BINARY(16) NOT NULL,
  user_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NULL,                         -- NULL for staff sessions
  membership_id BINARY(16) NULL,
  principal_kind VARCHAR(16) NOT NULL,               -- member|staff|cleaner
  client_kind VARCHAR(24) NOT NULL,                  -- web|desktop_app|platform_console
  product_code VARCHAR(16) NULL,
  ip_enc VARBINARY(128) NULL, ua_family VARCHAR(64) NULL, ua_hash BINARY(32) NULL,
  device_label VARCHAR(128) NULL,                    -- "Windows 11 / Chrome" (non-PII summary)
  mfa_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL, last_seen_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL,
  revoked_at DATETIME(6) NULL, revoke_reason VARCHAR(24) NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  KEY ix_sessions_user (user_id, expires_at),
  KEY ix_sessions_tenant_member (tenant_id, membership_id, id),   -- activity list / timeline (keyset by id = time)
  KEY ix_sessions_tenant (tenant_id, id)                          -- tenant-wide login activity (user_activity ON)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
