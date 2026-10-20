//! Source-text gates over `crates/**/*.rs`: `no-raw-sql` (L4) aur `sealed-ctor-gate` (carry-forward 13).
//!
//! Text scan hai (parser nahi): comment-only lines skip hoti hain; `#[cfg(test)]` region brace-count se
//! pehchani jaati hai (braces ke andar string literals mein `{`/`}` ho to approximate). Gate sirf report
//! karta hai, source nahi badalta.
//!
//! # sealed-ctor-gate: limits (jaan-bujh kar documented)
//! - Substring match: `__from_verified_grant`, `__from_authenticated`, `for_tests(` line mein kahin bhi.
//!   Gate type-aware nahi: macro-generated call, string-concatenated name, ya ek line ko do mein todna
//!   (name ke beech line-break) isse bach nikal sakta hai; alias (`use ... as f`) se call `f(..)` bhi nahi pakdi jaati.
//! - Allowed files: `__from_verified_grant` sirf `crates/db/src/staff_grant.rs`, `__from_authenticated` sirf
//!   `crates/auth/src/loader.rs`. `fn <name>` definition lines aur `//` comment lines skip hoti hain.
//! - Domain exemption: `crates/domain/` (jo crate inhe define karta hai) apne tests mein inhe call kar sakta hai;
//!   exemption poore `crates/domain/**` par hai, sirf test code par nahi (domain ki production code mein galat
//!   call gate se nahi pakdi jaayegi; review/clippy par chhodi hai). Baaki har crate strict.
//! - `for_tests(`: test code = `tests/`, `benches/`, `crates/testkit/`, `tests.rs`/`*_tests.rs`/`testing.rs`,
//!   aur `#[cfg(test)]` region (brace-count approximate). `#[cfg(feature = "test-fixtures")]` code test nahi gina jaata.
//! - Gate sirf `crates/**/*.rs` dekhta hai (xtask, build scripts, docs nahi).

use super::Violation;
use anyhow::Result;
use regex::Regex;
use std::path::Path;

pub const GATE_RAW: &str = "no-raw-sql";
pub const GATE_SEALED: &str = "sealed-ctor-gate";

/// The ONLY file allowed to call `sqlx::query*` (db crate's `sql.rs`).
pub const SQL_RS: &str = "crates/db/src/sql.rs";
pub const GRANT_RS: &str = "crates/db/src/staff_grant.rs";
pub const LOADER_RS: &str = "crates/auth/src/loader.rs";
/// Crate that defines both sealed constructors; it may call them in its own tests.
pub const DEFINING_CRATE: &str = "crates/domain/";

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

fn line_of(text: &str, byte: usize) -> usize {
    text[..byte].bytes().filter(|b| *b == b'\n').count() + 1
}

/// `no-raw-sql`: `sqlx::query*` / `raw_sql` outside `crates/db/src/sql.rs`, and
/// `#[allow(clippy::disallowed_methods)]` outside `crates/db` (DATABASE.md §2.2 L4).
pub fn scan_raw_sql(file: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    let (Ok(call), Ok(import), Ok(allow)) = (
        Regex::new(r"\bsqlx::(query\w*|raw_sql)\b"),
        Regex::new(
            r"use\s+sqlx::(?:\{[^}]*\b(?:query\w*|raw_sql)\b[^}]*\}|(?:query\w*|raw_sql)\b)",
        ),
        Regex::new(r"#\[allow\([^\]]*clippy::disallowed_methods"),
    ) else {
        return out;
    };
    if file != SQL_RS {
        for (i, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            if let Some(m) = call.find(line) {
                out.push(Violation::new(
                    GATE_RAW,
                    format!("{file}:{}", i + 1),
                    format!(
                        "raw `{}` outside {SQL_RS} (use a query file through db)",
                        m.as_str()
                    ),
                ));
            }
        }
        for m in import.find_iter(text) {
            let line = line_of(text, m.start());
            if text.lines().nth(line - 1).is_some_and(is_comment) {
                continue;
            }
            out.push(Violation::new(
                GATE_RAW,
                format!("{file}:{line}"),
                "`use sqlx::query...` import outside crates/db/src/sql.rs",
            ));
        }
    }
    if !file.starts_with("crates/db/") {
        // `allow(disallowed_methods)` legit hai spawn/route/env ke liye (clippy.toml); sirf tab flag jab
        // allow ke agle 8 lines mein `sqlx::` aaye (SQL ban ko suppress karna).
        for m in allow.find_iter(text) {
            let line = line_of(text, m.start());
            let near_sqlx = text
                .lines()
                .skip(line)
                .take(8)
                .any(|l| l.contains("sqlx::"));
            if near_sqlx {
                out.push(Violation::new(
                    GATE_RAW,
                    format!("{file}:{line}"),
                    "`#[allow(clippy::disallowed_methods)]` suppressing a sqlx call outside crates/db",
                ));
            }
        }
    }
    out
}

/// Files that count as test code for the `for_tests(` rule.
pub fn is_test_path(file: &str) -> bool {
    file.contains("/tests/")
        || file.contains("/benches/")
        || file.starts_with("crates/testkit/")
        || file.ends_with("/tests.rs")
        || file.ends_with("_tests.rs")
        || file.ends_with("/testing.rs")
}

/// Per line: inside a `#[cfg(test)]` (or `cfg(any(test, ...))`) item?
pub fn test_regions(text: &str) -> Vec<bool> {
    let attr = Regex::new(r"#\[cfg\(([^\]]*)\)\]").ok();
    let test_word = Regex::new(r"\btest\b").ok();
    let mut flags = Vec::new();
    let mut pending = false;
    let mut depth: i32 = 0;
    let mut in_region = false;
    for line in text.lines() {
        let mut flag = in_region;
        if !in_region {
            if let Some(re) = &attr
                && let Some(c) = re.captures(line)
            {
                let inner = &c[1];
                let mentions_test = test_word.as_ref().is_some_and(|r| r.is_match(inner));
                if mentions_test && !inner.contains("not(test") {
                    pending = true;
                    flag = true;
                }
            }
            if pending {
                flag = true;
                if let Some(pos) = line.find('{') {
                    in_region = true;
                    pending = false;
                    depth = 0;
                    for ch in line[pos..].chars() {
                        match ch {
                            '{' => depth += 1,
                            '}' => depth -= 1,
                            _ => {}
                        }
                    }
                    if depth <= 0 {
                        in_region = false;
                    }
                } else if line.trim_end().ends_with(';') {
                    pending = false;
                }
            }
        } else {
            for ch in line.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if depth <= 0 {
                in_region = false;
            }
        }
        flags.push(flag);
    }
    flags
}

/// `sealed-ctor-gate` for one file.
pub fn scan_sealed(file: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    let regions = test_regions(text);
    let test_file = is_test_path(file);
    let def = |name: &str| format!("fn {name}");
    for (i, line) in text.lines().enumerate() {
        if is_comment(line) {
            continue;
        }
        let loc = || format!("{file}:{}", i + 1);
        if line.contains("__from_verified_grant")
            && file != GRANT_RS
            && !file.starts_with(DEFINING_CRATE)
            && !line.contains(&def("__from_verified_grant"))
        {
            out.push(Violation::new(
                GATE_SEALED,
                loc(),
                format!("`__from_verified_grant` used outside {GRANT_RS}"),
            ));
        }
        if line.contains("__from_authenticated")
            && file != LOADER_RS
            && !file.starts_with(DEFINING_CRATE)
            && !line.contains(&def("__from_authenticated"))
        {
            out.push(Violation::new(
                GATE_SEALED,
                loc(),
                format!("`__from_authenticated` used outside {LOADER_RS}"),
            ));
        }
        if line.contains("for_tests(")
            && !test_file
            && !regions.get(i).copied().unwrap_or(false)
            && !line.contains("fn for_tests(")
        {
            out.push(Violation::new(
                GATE_SEALED,
                loc(),
                "`for_tests(` used in non-test code",
            ));
        }
    }
    out
}

/// Scan all `crates/**/*.rs`. Returns (no-raw-sql violations, sealed violations, files scanned).
pub fn run_on_repo(root: &Path) -> Result<(Vec<Violation>, Vec<Violation>, usize)> {
    let files = super::walk(&root.join("crates"), "rs")?;
    let mut raw = Vec::new();
    let mut sealed = Vec::new();
    for f in &files {
        let rel = super::rel(root, f);
        let text = std::fs::read_to_string(f)?;
        raw.extend(scan_raw_sql(&rel, &text));
        sealed.extend(scan_sealed(&rel, &text));
    }
    Ok((raw, sealed, files.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_sqlx_query_in_a_non_db_crate_is_caught() {
        let v = scan_raw_sql(
            "crates/api/src/handler.rs",
            "fn f() {\n    let q = sqlx::query(\"SELECT 1\");\n}\n",
        );
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].location.ends_with(":2"));
        let v = scan_raw_sql(
            "crates/api/src/h.rs",
            "let x = sqlx::query_as::<_, T>(\"..\");",
        );
        assert_eq!(v.len(), 1);
        let v = scan_raw_sql("crates/api/src/h.rs", "use sqlx::{MySqlPool, query};\n");
        assert_eq!(v.len(), 1, "{v:?}");
        let v = scan_raw_sql("crates/db/src/other.rs", "sqlx::query(\"x\")");
        assert_eq!(v.len(), 1, "other db files are not exempt");
    }

    #[test]
    fn sql_rs_and_comments_are_fine() {
        assert!(scan_raw_sql(SQL_RS, "pub fn q() { sqlx::query(sql) }").is_empty());
        assert!(
            scan_raw_sql(
                "crates/api/src/a.rs",
                "// sqlx::query is banned\n/// sqlx::query docs\n"
            )
            .is_empty()
        );
        assert!(scan_raw_sql("crates/api/src/a.rs", "let p: sqlx::MySqlPool;").is_empty());
    }

    #[test]
    fn allow_disallowed_methods_outside_db_is_caught() {
        let v = scan_raw_sql(
            "crates/api/src/a.rs",
            "#[allow(clippy::disallowed_methods)]\nfn x() { sqlx::query(\"x\"); }",
        );
        // the call itself + the suppressing attribute
        assert_eq!(v.len(), 2, "{v:?}");
        let spawn = scan_raw_sql(
            "crates/api/src/a.rs",
            "#[allow(clippy::disallowed_methods)]\nlet w = tokio::spawn(f());",
        );
        assert!(
            spawn.is_empty(),
            "spawn/route/env allows are legit: {spawn:?}"
        );
        assert!(
            scan_raw_sql(
                "crates/db/src/sql.rs",
                "#[allow(clippy::disallowed_methods)]\nfn x() {}"
            )
            .is_empty()
        );
    }

    #[test]
    fn sealed_constructor_in_the_wrong_file_is_caught() {
        let v = scan_sealed(
            "crates/api/src/evil.rs",
            "let g = VerifiedStaffGrant::__from_verified_grant(a, b);\nlet p = Principal::__from_authenticated(x);\n",
        );
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v.iter().all(|x| x.gate == GATE_SEALED));
    }

    #[test]
    fn sealed_constructor_in_the_right_file_or_definition_passes() {
        assert!(scan_sealed(GRANT_RS, "VerifiedStaffGrant::__from_verified_grant(a)").is_empty());
        assert!(scan_sealed(LOADER_RS, "Principal::__from_authenticated(x)").is_empty());
        assert!(
            scan_sealed(
                "crates/domain/src/rbac/platform.rs",
                "pub fn __from_verified_grant(a: A) -> Self {"
            )
            .is_empty()
        );
        assert!(
            scan_sealed(
                "crates/api/src/a.rs",
                "// calls __from_authenticated only in loader\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn defining_crate_may_call_sealed_ctors_others_may_not() {
        let src = "let g = X::__from_verified_grant(a);
let p = X::__from_authenticated(b);
";
        assert!(scan_sealed("crates/domain/tests/rbac.rs", src).is_empty());
        assert_eq!(scan_sealed("crates/auth/tests/x.rs", src).len(), 2);
        assert_eq!(scan_sealed("crates/db/src/other.rs", src).len(), 2);
    }

    #[test]
    fn for_tests_in_non_test_code_is_caught() {
        let v = scan_sealed(
            "crates/workers/src/runner.rs",
            "let j = ClaimedJob::for_tests(1);\n",
        );
        assert_eq!(v.len(), 1, "{v:?}");
    }

    #[test]
    fn for_tests_in_test_code_passes() {
        assert!(scan_sealed("crates/db/tests/x.rs", "ClaimedJob::for_tests(1);").is_empty());
        assert!(
            scan_sealed(
                "crates/db/src/tests/fixtures.rs",
                "ClaimedJob::for_tests(1);"
            )
            .is_empty()
        );
        assert!(
            scan_sealed("crates/db/src/jobs.rs", "pub fn for_tests(x: u8) -> Self {").is_empty()
        );
        let src = "fn real() {}\n#[cfg(test)]\nmod tests {\n    fn t() {\n        ClaimedJob::for_tests(1);\n    }\n}\nfn after() {\n    ClaimedJob::for_tests(2);\n}\n";
        let v = scan_sealed("crates/workers/src/runner.rs", src);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].location.ends_with(":9"), "{v:?}");
    }

    #[test]
    fn test_regions_marks_cfg_test_mod_only() {
        let r = test_regions("fn a() {}\n#[cfg(test)]\nmod t {\n  fn x() {}\n}\nfn b() {}\n");
        assert_eq!(r, vec![false, true, true, true, true, false]);
    }
}
