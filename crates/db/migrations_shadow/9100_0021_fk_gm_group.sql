-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE group_memberships ADD CONSTRAINT fk_gm_group FOREIGN KEY (tenant_id, group_id) REFERENCES `groups` (tenant_id, id);
