-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE tenant_quotas ADD CONSTRAINT fk_tq_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id);
