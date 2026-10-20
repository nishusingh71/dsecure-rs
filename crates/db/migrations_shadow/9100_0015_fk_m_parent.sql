-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE memberships ADD CONSTRAINT fk_m_parent FOREIGN KEY (tenant_id, parent_membership_id) REFERENCES memberships (tenant_id, id);
