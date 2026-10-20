-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE data_keys ADD CONSTRAINT fk_dk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id);
