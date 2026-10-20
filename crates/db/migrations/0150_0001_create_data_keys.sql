-- set 0150_keys (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE data_keys (                             -- class: platform; wrapped DEKs
  kid VARCHAR(48) NOT NULL,
  purpose VARCHAR(16) NOT NULL,                      -- identity|pii|reports|secrets|bidx_email|bidx_license|bidx_tenant|audit
  tenant_id BINARY(16) NULL,                         -- NULL = platform-wide
  scope_key BINARY(16) NOT NULL,                     -- tenant_id or 0x00..00 (no COALESCE index)
  kek_ref VARCHAR(255) NOT NULL, wrapped_dek VARBINARY(512) NOT NULL,
  status VARCHAR(16) NOT NULL,                       -- active|decrypt_only|retired|destroyed
  active_marker VARCHAR(1) NULL,                     -- 'Y' while active, else NULL (unique-when-active)
  created_at DATETIME(6) NOT NULL, rotated_at DATETIME(6) NULL, destroyed_at DATETIME(6) NULL, destroyed_by_approval BINARY(16) NULL,
  PRIMARY KEY (kid),
  UNIQUE KEY ux_dk_active (purpose, scope_key, active_marker)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
