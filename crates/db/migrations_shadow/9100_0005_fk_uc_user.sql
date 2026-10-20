-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE user_credentials ADD CONSTRAINT fk_uc_user FOREIGN KEY (user_id) REFERENCES users (id);
