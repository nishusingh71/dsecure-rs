-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE departments ADD CONSTRAINT fk_dept_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id);
