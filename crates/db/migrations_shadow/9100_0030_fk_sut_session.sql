-- MySQL CI only (D-55, DATABASE.md §2.4): shadow FK, never applied on TiDB. One DDL per file.
ALTER TABLE step_up_tokens ADD CONSTRAINT fk_sut_session FOREIGN KEY (session_id) REFERENCES sessions (id);
