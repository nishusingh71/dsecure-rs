-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE staff_access_grants ADD CONSTRAINT fk_sag_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id);
