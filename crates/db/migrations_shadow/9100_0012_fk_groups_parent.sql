-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE `groups` ADD CONSTRAINT fk_groups_parent FOREIGN KEY (tenant_id, parent_group_id) REFERENCES `groups` (tenant_id, id);
