-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE member_counters ADD CONSTRAINT fk_mcnt_membership FOREIGN KEY (tenant_id, membership_id) REFERENCES memberships (tenant_id, id);
