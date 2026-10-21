-- set 0880_platform_bootstrap (review N2). Singleton marker of the first-run staff bootstrap: the
-- bootstrap tx inserts row id = 1 FIRST, so a second (concurrent) bootstrap fails on the PRIMARY KEY.
-- `SELECT COUNT(*) ... FOR UPDATE` on an empty platform_staff does not serialise on TiDB (no gap
-- locks). New forward file; existing migrations untouched. One DDL per file.
CREATE TABLE platform_bootstrap (                    -- class: platform
  id TINYINT UNSIGNED NOT NULL,                      -- always 1 (singleton)
  user_id BINARY(16) NOT NULL,                       -- the first platform_superadmin
  created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
