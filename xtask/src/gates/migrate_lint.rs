//! `cargo xtask migrate-lint` (DATABASE.md §11.1): migration files par rules.
//!
//! - ek file = ek statement (DDL implicit commit; multi-statement file beech mein fail = half-applied),
//! - `DROP` / `TRUNCATE` kahin bhi, `DELETE` statement-start par = fail (forward-only, expand/contract),
//! - TiDB-only syntax (`CLUSTERED`, `SHARD_ROW_ID_BITS`, `TTL`, ...) sirf `/*T! ... */` ke andar; comment
//!   ke bahar dikhe to MySQL par fail hoga, isliye gate fail.
//!
//! Tokenizer comments ko whitespace banata hai, isliye `/*T! */` aur `-- ...` ke andar ke words ignore hote hain.

use super::Violation;
use anyhow::Result;
use sqlparser::dialect::MySqlDialect;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

pub const GATE: &str = "migrate-lint";

/// Words that exist only on TiDB (must live inside `/*T! ... */`).
const TIDB_ONLY: &[&str] = &[
    "CLUSTERED",
    "NONCLUSTERED",
    "SHARD_ROW_ID_BITS",
    "PRE_SPLIT_REGIONS",
    "AUTO_RANDOM",
    "AUTO_ID_CACHE",
    "TTL",
    "TTL_ENABLE",
    "TTL_JOB_INTERVAL",
    "PLACEMENT",
    "TIFLASH",
];

pub fn lint_migration(file: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    let tokens = match Tokenizer::new(&MySqlDialect {}, text).tokenize() {
        Ok(t) => t,
        Err(e) => {
            out.push(Violation::new(GATE, file, format!("tokenizer error: {e}")));
            return out;
        }
    };
    // TiDB Serverless rejects `TTL_JOB_INTERVAL` (error 20001, v8.5.3: TTL runs on the service's own
    // schedule), so it is banned everywhere, including inside `/*T! ... */` (`--` notes are fine).
    for t in &tokens {
        let hit = match t {
            Token::Whitespace(Whitespace::MultiLineComment(c)) => {
                c.to_ascii_uppercase().contains("TTL_JOB_INTERVAL")
            }
            Token::Word(w) => w.value.eq_ignore_ascii_case("TTL_JOB_INTERVAL"),
            _ => false,
        };
        if hit {
            out.push(Violation::new(
                GATE,
                file,
                "`TTL_JOB_INTERVAL` is rejected by TiDB Serverless (error 20001); omit it",
            ));
        }
    }
    let mut statements = 0usize;
    let mut in_stmt = false;
    let mut first_word_seen = false;
    for t in &tokens {
        match t {
            Token::Whitespace(_) | Token::EOF => {}
            Token::SemiColon => {
                if in_stmt {
                    statements += 1;
                }
                in_stmt = false;
                first_word_seen = false;
            }
            other => {
                in_stmt = true;
                if let Token::Word(w) = other
                    && w.quote_style.is_none()
                {
                    let up = w.value.to_ascii_uppercase();
                    if !first_word_seen {
                        first_word_seen = true;
                        if up == "DELETE" {
                            out.push(Violation::new(
                                GATE,
                                file,
                                "DELETE statement is not allowed in a migration",
                            ));
                        }
                    }
                    if up == "DROP" || up == "TRUNCATE" {
                        out.push(Violation::new(
                            GATE,
                            file,
                            format!(
                                "`{up}` is not allowed in a migration (forward-only, additive)"
                            ),
                        ));
                    }
                    if TIDB_ONLY.contains(&up.as_str()) {
                        out.push(Violation::new(
                            GATE,
                            file,
                            format!("TiDB-only syntax `{up}` outside a `/*T! ... */` comment"),
                        ));
                    }
                }
            }
        }
    }
    if in_stmt {
        statements += 1;
    }
    match statements {
        1 => {}
        0 => out.push(Violation::new(
            GATE,
            file,
            "migration file has no statement",
        )),
        n => out.push(Violation::new(
            GATE,
            file,
            format!("{n} statements in one migration file (one DDL/DML statement per file)"),
        )),
    }
    out
}

/// `crates/db/migrations` and `migrations_shadow`. Returns (violations, files checked).
pub fn run_on_repo(root: &std::path::Path) -> Result<(Vec<Violation>, usize)> {
    let mut out = Vec::new();
    let mut n = 0;
    for dir in ["crates/db/migrations", "crates/db/migrations_shadow"] {
        let d = root.join(dir);
        if !d.is_dir() {
            continue;
        }
        for f in super::walk(&d, "sql")? {
            n += 1;
            let text = std::fs::read_to_string(&f)?;
            out.extend(lint_migration(&super::rel(root, &f), &text));
        }
    }
    Ok((out, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msgs(sql: &str) -> Vec<String> {
        lint_migration("m.sql", sql)
            .into_iter()
            .map(|v| v.message)
            .collect()
    }

    #[test]
    fn good_single_statement_with_wrapped_tidb_syntax_passes() {
        let v = msgs(
            "-- set x\nCREATE TABLE t (id BINARY(16) NOT NULL, PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */) ENGINE=InnoDB;\n",
        );
        assert!(v.is_empty(), "{v:?}");
        let v = msgs(
            "-- ttl\nALTER TABLE jobs COMMENT = 'x' /*T! TTL = `finished_at` + INTERVAL 14 DAY TTL_ENABLE = 'OFF' */;",
        );
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn two_statements_are_caught() {
        let v = msgs("CREATE TABLE a (id INT); CREATE TABLE b (id INT);");
        assert!(v.iter().any(|m| m.contains("2 statements")), "{v:?}");
    }

    #[test]
    fn drop_truncate_delete_are_caught() {
        assert!(msgs("DROP TABLE a").iter().any(|m| m.contains("DROP")));
        assert!(
            msgs("ALTER TABLE a DROP COLUMN b")
                .iter()
                .any(|m| m.contains("DROP"))
        );
        assert!(
            msgs("TRUNCATE TABLE a")
                .iter()
                .any(|m| m.contains("TRUNCATE"))
        );
        assert!(
            msgs("DELETE FROM a WHERE id = 1")
                .iter()
                .any(|m| m.contains("DELETE"))
        );
    }

    #[test]
    fn on_delete_in_a_fk_is_not_a_delete_statement() {
        let v = msgs(
            "ALTER TABLE a ADD CONSTRAINT fk FOREIGN KEY (x) REFERENCES b (id) ON DELETE RESTRICT",
        );
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn unwrapped_tidb_syntax_is_caught() {
        let v = msgs("CREATE TABLE t (id INT) SHARD_ROW_ID_BITS=4");
        assert!(v.iter().any(|m| m.contains("SHARD_ROW_ID_BITS")), "{v:?}");
        let v = msgs("CREATE TABLE t (id INT, PRIMARY KEY (id) CLUSTERED)");
        assert!(v.iter().any(|m| m.contains("CLUSTERED")), "{v:?}");
    }

    #[test]
    fn words_inside_comments_and_strings_are_ignored() {
        let v = msgs("-- DROP TABLE x\nINSERT INTO t (c) VALUES ('DROP; DELETE TTL');");
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn empty_file_is_caught() {
        let v = msgs("-- only a comment\n");
        assert!(v.iter().any(|m| m.contains("no statement")), "{v:?}");
    }

    #[test]
    fn ttl_job_interval_is_rejected_even_inside_tidb_comment() {
        let bad = "ALTER TABLE jobs COMMENT = 'x'
  /*T! TTL = `finished_at` + INTERVAL 14 DAY TTL_ENABLE = 'OFF' TTL_JOB_INTERVAL = '1h' */;";
        assert!(
            msgs(bad).iter().any(|m| m.contains("TTL_JOB_INTERVAL")),
            "{:?}",
            msgs(bad)
        );
        let ok = "-- no TTL_JOB_INTERVAL here (note)
ALTER TABLE jobs COMMENT = 'x'
  /*T! TTL = `finished_at` + INTERVAL 14 DAY TTL_ENABLE = 'OFF' */;";
        assert!(msgs(ok).is_empty(), "{:?}", msgs(ok));
    }
}
