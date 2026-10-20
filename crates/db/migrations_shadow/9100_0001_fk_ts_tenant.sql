-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE tenant_settings ADD CONSTRAINT fk_ts_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id);
