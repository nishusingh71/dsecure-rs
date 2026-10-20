-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE tenant_feature_changes ADD CONSTRAINT fk_tfc_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id);
