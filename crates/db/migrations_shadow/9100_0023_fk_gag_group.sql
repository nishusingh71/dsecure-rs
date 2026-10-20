-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE group_admin_grants ADD CONSTRAINT fk_gag_group FOREIGN KEY (tenant_id, group_id) REFERENCES `groups` (tenant_id, id);
