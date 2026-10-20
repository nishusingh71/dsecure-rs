-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE mfa_recovery_codes ADD CONSTRAINT fk_mrc_user FOREIGN KEY (user_id) REFERENCES users (id);
