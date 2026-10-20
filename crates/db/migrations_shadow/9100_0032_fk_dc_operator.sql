-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE device_credentials ADD CONSTRAINT fk_dc_operator FOREIGN KEY (tenant_id, operator_membership_id) REFERENCES memberships (tenant_id, id);
