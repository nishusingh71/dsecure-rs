-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE sessions ADD CONSTRAINT fk_s_user FOREIGN KEY (user_id) REFERENCES users (id);
