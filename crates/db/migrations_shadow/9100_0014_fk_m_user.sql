-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE memberships ADD CONSTRAINT fk_m_user FOREIGN KEY (user_id) REFERENCES users (id);
