-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE auth_challenges ADD CONSTRAINT fk_ac_user FOREIGN KEY (user_id) REFERENCES users (id);
