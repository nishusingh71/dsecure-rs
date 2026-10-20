-- set 0100_tenancy_identity (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE member_preferences (                    -- UI prefs (legacy pdf_export_settings.column_view_config etc.)
  tenant_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL, pref_key VARCHAR(48) NOT NULL,
  value_json JSON NOT NULL,                          -- app cap 8 KB; e.g. 'autopilot.device_table.columns'
  updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, membership_id, pref_key) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
