-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE memberships ADD CONSTRAINT fk_m_dept FOREIGN KEY (tenant_id, department_id) REFERENCES departments (tenant_id, id);
