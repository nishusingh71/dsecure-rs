-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE platform_staff ADD CONSTRAINT fk_ps_user FOREIGN KEY (user_id) REFERENCES users (id);
