//! `cargo xtask sql-lint` (DATABASE.md §2.2 L3, T-DB8): har `crates/db/queries/**/*.sql` ko `sqlparser`
//! (MySQL dialect) se parse karta hai.
//!
//! Fail hota hai jab:
//! - header `-- class: <tenant|identity|directory|platform|infra>` nahi hai,
//! - file mein ek statement nahi hai ya parse nahi hota,
//! - `DELETE` (ya SELECT/INSERT/UPDATE ke alawa koi statement),
//! - `SELECT *` / `t.*` projection,
//! - tenant-class table par SELECT/UPDATE mein `tenant_id = ?` top-level AND conjunct nahi
//!   (JOIN: `a.tenant_id = b.tenant_id` + ek bind; subquery: apna ya bahar ka bound conjunct),
//! - tenant-class table mein INSERT jisme `tenant_id` column nahi (ya column list hi nahi),
//! - tenant query ke header `params:` mein `tenant_id` nahi,
//! - multi-row SELECT bina LIMIT (point get = unique key poori equality se bound, aggregate-only
//!   projection, ya header `-- bounded: <reason>` se exempt).
//!
//! Tenant-class = `TABLE_CLASSES` ya (table registry mein nahi + header class `tenant`).
//! Unregistered table (aur header tenant nahi) = violation.

use super::Violation;
use super::classes::Class;
use anyhow::Result;
use regex::Regex;
use sqlparser::ast::{
    BinaryOperator, Expr, GroupByExpr, Insert, Join, JoinConstraint, JoinOperator, Query, Select,
    SelectItem, SetExpr, Statement, TableFactor, TableObject, TableWithJoins, Value, Visit,
    Visitor,
};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

pub const GATE: &str = "sql-lint";

/// Registry + unique-key map (migrations se) jo lint ko chahiye.
#[derive(Default, Clone)]
pub struct LintCtx {
    pub classes: HashMap<String, Class>,
    /// table -> unique column sets (PRIMARY KEY + UNIQUE KEY), lowercase.
    pub unique_keys: HashMap<String, Vec<Vec<String>>>,
}

/// Header facts of a query file.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub class: Option<String>,
    pub params: Option<Vec<String>>,
    pub hot: bool,
    pub bounded_reason: Option<String>,
}

/// Leading `--` comment lines.
pub fn parse_header(text: &str) -> Header {
    let mut lines = Vec::new();
    let mut raw = Vec::new();
    for line in text.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("--") {
            raw.push(rest.to_owned());
            lines.push(rest.trim().to_owned());
        } else if t.is_empty() {
            continue;
        } else {
            break;
        }
    }
    let joined = lines.join(" ");
    let mut h = Header::default();
    if let Ok(re) = Regex::new(r"class:\s*([A-Za-z]+)") {
        h.class = re.captures(&joined).map(|c| c[1].to_ascii_lowercase());
    }
    // params: pehli line ka baaki hissa + continuation lines (do ya zyada spaces se shuru).
    if let Some(pos) = raw.iter().position(|l| l.contains("params:")) {
        let mut rest = raw[pos]
            .split_once("params:")
            .map_or(String::new(), |(_, r)| r.to_owned());
        for l in raw.iter().skip(pos + 1) {
            if l.starts_with("  ") {
                rest.push(' ');
                rest.push_str(l);
            } else {
                break;
            }
        }
        let rest = rest.as_str();
        if let Ok(re) = Regex::new(r"[a-z_][a-z0-9_]*") {
            h.params = Some(re.find_iter(rest).map(|m| m.as_str().to_owned()).collect());
        }
    }
    h.hot = lines.iter().any(|l| l == "hot" || l.starts_with("hot:"));
    h.bounded_reason = lines.iter().find_map(|l| {
        l.strip_prefix("bounded:")
            .map(|r| r.trim().to_owned())
            .filter(|r| !r.is_empty())
    });
    h
}

/// `PRIMARY KEY (...)` / `UNIQUE KEY x (...)` from CREATE TABLE migration text.
pub fn parse_unique_keys(migrations: &[&str]) -> HashMap<String, Vec<Vec<String>>> {
    let mut out: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    let (Ok(t_re), Ok(pk_re), Ok(uq_re)) = (
        Regex::new(r"(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-z0-9_]+)`?"),
        Regex::new(r"(?i)PRIMARY\s+KEY\s*\(([^)]*)\)"),
        Regex::new(r"(?i)UNIQUE\s+(?:KEY|INDEX)\s+`?[a-z0-9_]*`?\s*\(([^)]*)\)"),
    ) else {
        return out;
    };
    for sql in migrations {
        let Some(t) = t_re.captures(sql) else {
            continue;
        };
        let table = t[1].to_ascii_lowercase();
        let cols = |s: &str| -> Vec<String> {
            s.split(',')
                .filter_map(|c| {
                    c.split_whitespace()
                        .next()
                        .map(|w| w.trim_matches('`').to_ascii_lowercase())
                })
                .collect()
        };
        for re in [&pk_re, &uq_re] {
            for c in re.captures_iter(sql) {
                out.entry(table.clone()).or_default().push(cols(&c[1]));
            }
        }
    }
    out
}

fn obj_last(name: &sqlparser::ast::ObjectName) -> String {
    let s = name.to_string();
    s.rsplit('.')
        .next()
        .unwrap_or("")
        .trim_matches('`')
        .to_ascii_lowercase()
}

/// A table occurrence in a FROM/UPDATE scope.
#[derive(Clone, Debug)]
pub struct Occ {
    pub table: String,
    pub alias: String,
}

type Col = (String, String); // (alias or "*", column)

#[derive(Default, Clone)]
struct Bound {
    cols: HashSet<Col>,
}

impl Bound {
    fn is(&self, alias: &str, col: &str) -> bool {
        self.cols.contains(&(alias.to_owned(), col.to_owned()))
            || self.cols.contains(&("*".to_owned(), col.to_owned()))
    }
}

fn flatten_and<'a>(e: &'a Expr, out: &mut Vec<&'a Expr>) {
    match e {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            flatten_and(left, out);
            flatten_and(right, out);
        }
        Expr::Nested(inner) => flatten_and(inner, out),
        other => out.push(other),
    }
}

fn as_col(e: &Expr) -> Option<Col> {
    match e {
        Expr::Identifier(i) => Some(("*".into(), i.value.to_ascii_lowercase())),
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
            let n = parts.len();
            Some((
                parts[n - 2].value.to_ascii_lowercase(),
                parts[n - 1].value.to_ascii_lowercase(),
            ))
        }
        Expr::Nested(inner) => as_col(inner),
        _ => None,
    }
}

fn is_const(e: &Expr) -> bool {
    match e {
        Expr::Value(v) => !matches!(v.value, Value::Null),
        Expr::Nested(inner) => is_const(inner),
        _ => false,
    }
}

/// Bound columns: `col = ?` / `col = literal` conjuncts plus `a.c = b.d` propagation to a fixpoint.
fn compute_bound(
    conjuncts: &[&Expr],
    inherited: &Bound,
    using_pairs: &[(String, String)],
) -> (Bound, Vec<(Col, Col)>) {
    let mut bound = inherited.clone();
    let mut edges: Vec<(Col, Col)> = Vec::new();
    for c in conjuncts {
        if let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = c
        {
            match (as_col(left), as_col(right)) {
                (Some(a), None) if is_const(right) => {
                    bound.cols.insert(a);
                }
                (None, Some(b)) if is_const(left) => {
                    bound.cols.insert(b);
                }
                (Some(a), Some(b)) => edges.push((a, b)),
                _ => {}
            }
        }
    }
    for (l, r) in using_pairs {
        edges.push((
            (l.clone(), "tenant_id".into()),
            (r.clone(), "tenant_id".into()),
        ));
    }
    loop {
        let mut changed = false;
        for (a, b) in &edges {
            let a_b = bound.is(&a.0, &a.1);
            let b_b = bound.is(&b.0, &b.1);
            if a_b && !b_b {
                changed |= bound.cols.insert(b.clone());
            } else if b_b && !a_b {
                changed |= bound.cols.insert(a.clone());
            }
        }
        if !changed {
            break;
        }
    }
    (bound, edges)
}

struct Scope {
    occs: Vec<Occ>,
    conjuncts_owned: Vec<Expr>,
    using_pairs: Vec<(String, String)>,
}

fn factor_occ(f: &TableFactor) -> Option<Occ> {
    if let TableFactor::Table { name, alias, .. } = f {
        let table = obj_last(name);
        let a = alias
            .as_ref()
            .map_or_else(|| table.clone(), |a| a.name.value.to_ascii_lowercase());
        Some(Occ { table, alias: a })
    } else {
        None
    }
}

fn join_constraint(op: &JoinOperator) -> Option<&JoinConstraint> {
    match op {
        JoinOperator::Join(c)
        | JoinOperator::Inner(c)
        | JoinOperator::Left(c)
        | JoinOperator::LeftOuter(c)
        | JoinOperator::Right(c)
        | JoinOperator::RightOuter(c)
        | JoinOperator::FullOuter(c)
        | JoinOperator::CrossJoin(c)
        | JoinOperator::Semi(c)
        | JoinOperator::LeftSemi(c)
        | JoinOperator::Anti(c)
        | JoinOperator::LeftAnti(c) => Some(c),
        _ => None,
    }
}

fn scope_of(from: &[TableWithJoins], selection: Option<&Expr>) -> Scope {
    let mut occs = Vec::new();
    let mut conj = Vec::new();
    let mut using_pairs = Vec::new();
    if let Some(s) = selection {
        conj.push(s.clone());
    }
    for twj in from {
        let first = factor_occ(&twj.relation);
        if let Some(o) = &first {
            occs.push(o.clone());
        }
        for Join {
            relation,
            join_operator,
            ..
        } in &twj.joins
        {
            let o = factor_occ(relation);
            if let Some(o) = &o {
                occs.push(o.clone());
            }
            match join_constraint(join_operator) {
                Some(JoinConstraint::On(e)) => conj.push(e.clone()),
                Some(JoinConstraint::Using(cols)) => {
                    let uses_tenant = cols.iter().any(|c| obj_last(c) == "tenant_id");
                    if let (true, Some(l), Some(r)) = (uses_tenant, &first, &o) {
                        using_pairs.push((l.alias.clone(), r.alias.clone()));
                    }
                }
                _ => {}
            }
        }
    }
    Scope {
        occs,
        conjuncts_owned: conj,
        using_pairs,
    }
}

fn bound_of(scope: &Scope, inherited: &Bound) -> Bound {
    bound_and_edges(scope, inherited).0
}

fn bound_and_edges(scope: &Scope, inherited: &Bound) -> (Bound, Vec<(Col, Col)>) {
    let mut refs: Vec<&Expr> = Vec::new();
    for e in &scope.conjuncts_owned {
        flatten_and(e, &mut refs);
    }
    compute_bound(&refs, inherited, &scope.using_pairs)
}

fn is_aggregate_only(sel: &Select) -> bool {
    let no_group = matches!(&sel.group_by, GroupByExpr::Expressions(v, _) if v.is_empty());
    if !no_group || sel.projection.is_empty() {
        return false;
    }
    sel.projection.iter().all(|item| {
        let e = match item {
            SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => e,
            _ => return false,
        };
        if let Expr::Function(f) = e {
            matches!(
                obj_last(&f.name).as_str(),
                "count" | "max" | "min" | "sum" | "avg"
            )
        } else {
            false
        }
    })
}

/// Single-row select: aggregate-only, or every table in scope has a unique key fully bound.
fn select_is_bounded(sel: &Select, ctx: &LintCtx, inherited: &Bound) -> bool {
    if is_aggregate_only(sel) || sel.from.is_empty() {
        return true;
    }
    let scope = scope_of(&sel.from, sel.selection.as_ref());
    let all_plain = sel.from.iter().all(|t| {
        matches!(t.relation, TableFactor::Table { .. })
            && t.joins
                .iter()
                .all(|j| matches!(j.relation, TableFactor::Table { .. }))
    });
    if !all_plain || scope.occs.is_empty() {
        return false;
    }
    // Single-row analysis: a table is single-row when a unique key is fully determined; all columns of a
    // single-row table then determine the columns equal to them (many-to-one FK joins stay single-row).
    let (mut det, edges) = bound_and_edges(&scope, inherited);
    let mut single: HashSet<String> = HashSet::new();
    loop {
        let mut changed = false;
        for o in &scope.occs {
            if single.contains(&o.alias) {
                continue;
            }
            let ok = ctx.unique_keys.get(&o.table).is_some_and(|keys| {
                keys.iter()
                    .any(|k| !k.is_empty() && k.iter().all(|c| det.is(&o.alias, c)))
            });
            if ok {
                single.insert(o.alias.clone());
                changed = true;
            }
        }
        for (a, b) in &edges {
            if single.contains(&a.0) {
                changed |= det.cols.insert(b.clone());
            }
            if single.contains(&b.0) {
                changed |= det.cols.insert(a.clone());
            }
        }
        if !changed {
            break;
        }
    }
    scope.occs.iter().all(|o| single.contains(&o.alias))
}

fn body_is_bounded(body: &SetExpr, ctx: &LintCtx) -> bool {
    match body {
        SetExpr::Select(s) => select_is_bounded(s, ctx, &Bound::default()),
        SetExpr::SetOperation { left, right, .. } => {
            body_is_bounded(left, ctx) && body_is_bounded(right, ctx)
        }
        SetExpr::Query(q) => q.limit_clause.is_some() || body_is_bounded(&q.body, ctx),
        SetExpr::Values(_) => true,
        _ => false,
    }
}

struct Linter<'a> {
    ctx: &'a LintCtx,
    header_class: Option<Class>,
    file: &'a str,
    out: Vec<Violation>,
    stack: Vec<Bound>,
    cte_names: HashSet<String>,
    query_depth: usize,
    bounded_exempt: bool,
    needs_tenant_param: bool,
}

impl Linter<'_> {
    fn v(&mut self, msg: impl Into<String>) {
        self.out.push(Violation::new(GATE, self.file, msg));
    }

    fn is_tenant_table(&self, table: &str) -> bool {
        match self.ctx.classes.get(table) {
            Some(c) => *c == Class::Tenant,
            None => !self.cte_names.contains(table) && self.header_class == Some(Class::Tenant),
        }
    }

    fn check_scope_tables(&mut self, occs: &[Occ], bound: &Bound, what: &str) {
        for o in occs {
            let registered = self.ctx.classes.contains_key(&o.table);
            if !registered
                && !self.cte_names.contains(&o.table)
                && self.header_class != Some(Class::Tenant)
            {
                self.v(format!(
                    "{what}: table `{}` is not in TABLE_CLASSES (register it or fix the name)",
                    o.table
                ));
                continue;
            }
            if self.is_tenant_table(&o.table) {
                self.needs_tenant_param = true;
                if !bound.is(&o.alias, "tenant_id") {
                    self.v(format!(
                        "{what}: tenant table `{}` (alias `{}`) has no top-level `tenant_id = ?` predicate",
                        o.table, o.alias
                    ));
                }
            }
        }
    }

    fn check_insert(&mut self, ins: &Insert) {
        let TableObject::TableName(name) = &ins.table else {
            self.v("INSERT: unsupported table form");
            return;
        };
        let table = obj_last(name);
        if !self.ctx.classes.contains_key(&table) && self.header_class != Some(Class::Tenant) {
            self.v(format!("INSERT: table `{table}` is not in TABLE_CLASSES"));
            return;
        }
        if self.is_tenant_table(&table) {
            self.needs_tenant_param = true;
            if ins.columns.is_empty() {
                self.v(format!(
                    "INSERT into tenant table `{table}` has no column list (cannot verify tenant_id)"
                ));
            } else if !ins.columns.iter().any(|c| obj_last(c) == "tenant_id") {
                self.v(format!(
                    "INSERT into tenant table `{table}` lacks the `tenant_id` column"
                ));
            }
        }
    }
}

impl Visitor for Linter<'_> {
    type Break = ();

    fn pre_visit_query(&mut self, q: &Query) -> ControlFlow<()> {
        if let Some(with) = &q.with {
            for c in &with.cte_tables {
                self.cte_names
                    .insert(c.alias.name.value.to_ascii_lowercase());
            }
        }
        if self.query_depth == 0
            && q.limit_clause.is_none()
            && !self.bounded_exempt
            && !body_is_bounded(&q.body, self.ctx)
        {
            self.v(
                "SELECT without LIMIT is an unbounded list (add LIMIT, bind a unique key, or header `-- bounded: <reason>`)",
            );
        }
        self.query_depth += 1;
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _q: &Query) -> ControlFlow<()> {
        self.query_depth = self.query_depth.saturating_sub(1);
        ControlFlow::Continue(())
    }

    fn pre_visit_select(&mut self, sel: &Select) -> ControlFlow<()> {
        for item in &sel.projection {
            if matches!(
                item,
                SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..)
            ) {
                self.v("SELECT * is not allowed (list the columns)");
            }
        }
        let inherited = self.stack.last().cloned().unwrap_or_default();
        let scope = scope_of(&sel.from, sel.selection.as_ref());
        let bound = bound_of(&scope, &inherited);
        self.check_scope_tables(&scope.occs, &bound, "SELECT");
        self.stack.push(bound);
        ControlFlow::Continue(())
    }

    fn post_visit_select(&mut self, _s: &Select) -> ControlFlow<()> {
        self.stack.pop();
        ControlFlow::Continue(())
    }
}

/// Lint one query file. Pure: no disk access.
pub fn lint_query(file: &str, text: &str, ctx: &LintCtx) -> Vec<Violation> {
    let header = parse_header(text);
    let mut out = Vec::new();
    let header_class = match header.class.as_deref().map(Class::parse) {
        Some(Some(c)) => Some(c),
        Some(None) => {
            out.push(Violation::new(
                GATE,
                file,
                "header `-- class:` has an unknown class",
            ));
            None
        }
        None => {
            out.push(Violation::new(
                GATE,
                file,
                "missing header `-- class: <class>`",
            ));
            None
        }
    };
    let sql = text.replace("/*GROUP_IDS*/", "?");
    let stmts = match Parser::parse_sql(&MySqlDialect {}, &sql) {
        Ok(s) => s,
        Err(e) => {
            out.push(Violation::new(GATE, file, format!("parse error: {e}")));
            return out;
        }
    };
    if stmts.len() != 1 {
        out.push(Violation::new(
            GATE,
            file,
            format!("expected exactly 1 statement, found {}", stmts.len()),
        ));
        return out;
    }
    let mut l = Linter {
        ctx,
        header_class,
        file,
        out,
        stack: Vec::new(),
        cte_names: HashSet::new(),
        query_depth: 0,
        bounded_exempt: header.bounded_reason.is_some(),
        needs_tenant_param: false,
    };
    match &stmts[0] {
        Statement::Query(q) => {
            let _ = q.visit(&mut l);
        }
        Statement::Insert(ins) => {
            l.check_insert(ins);
            if let Some(src) = &ins.source {
                let _ = src.visit(&mut l);
            }
        }
        Statement::Update(u) => {
            let scope = scope_of(std::slice::from_ref(&u.table), u.selection.as_ref());
            let bound = bound_of(&scope, &Bound::default());
            l.check_scope_tables(&scope.occs, &bound, "UPDATE");
            l.stack.push(bound);
            // UPDATE ke andar ki subqueries top-level SELECT nahi hain (LIMIT rule laagu nahi).
            l.query_depth = 1;
            if let Some(sel) = &u.selection {
                let _ = sel.visit(&mut l);
            }
            for a in &u.assignments {
                let _ = a.value.visit(&mut l);
            }
        }
        Statement::Delete(_) => l.v("DELETE is not allowed (soft delete / status columns only)"),
        other => l.v(format!(
            "statement kind not allowed in a query file: {}",
            first_words(&other.to_string())
        )),
    }
    if l.needs_tenant_param {
        match &header.params {
            Some(p) if p.iter().any(|x| x == "tenant_id") => {}
            Some(_) => l.v("tenant query header `params:` does not list `tenant_id`"),
            None => l.v("tenant query has no header `params:` list"),
        }
    }
    l.out
}

fn first_words(s: &str) -> String {
    s.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

/// Table occurrences (with aliases) of the top-level FROM of a query text; used by explain-check.
pub fn top_level_occurrences(text: &str) -> Vec<Occ> {
    let sql = text.replace("/*GROUP_IDS*/", "?");
    let Ok(stmts) = Parser::parse_sql(&MySqlDialect {}, &sql) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for s in &stmts {
        match s {
            Statement::Query(q) => collect_occ(&q.body, &mut out),
            Statement::Update(u) => {
                out.extend(scope_of(std::slice::from_ref(&u.table), None).occs);
            }
            _ => {}
        }
    }
    out
}

fn collect_occ(body: &SetExpr, out: &mut Vec<Occ>) {
    match body {
        SetExpr::Select(s) => out.extend(scope_of(&s.from, None).occs),
        SetExpr::SetOperation { left, right, .. } => {
            collect_occ(left, out);
            collect_occ(right, out);
        }
        SetExpr::Query(q) => collect_occ(&q.body, out),
        _ => {}
    }
}

/// Lint all `crates/db/queries/**/*.sql`. Returns (violations, files checked).
pub fn run_on_repo(root: &std::path::Path) -> Result<(Vec<Violation>, usize)> {
    let ctx = load_ctx(root)?;
    let files = super::walk(&root.join("crates/db/queries"), "sql")?;
    let mut out = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f)?;
        out.extend(lint_query(&super::rel(root, f), &text, &ctx));
    }
    Ok((out, files.len()))
}

/// Registry + unique keys from the repo.
pub fn load_ctx(root: &std::path::Path) -> Result<LintCtx> {
    let src = std::fs::read_to_string(root.join("crates/db/src/table_classes.rs"))?;
    let classes = super::classes::parse_table_classes(&src)?;
    let mut texts = Vec::new();
    for f in super::walk(&root.join("crates/db/migrations"), "sql")? {
        texts.push(std::fs::read_to_string(f)?);
    }
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    Ok(LintCtx {
        classes,
        unique_keys: parse_unique_keys(&refs),
    })
}

/// Hot-marked query files (`-- hot` header line) or all of them: (repo-relative path, text).
pub fn hot_files(root: &std::path::Path, all: bool) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for f in super::walk(&root.join("crates/db/queries"), "sql")? {
        let text = std::fs::read_to_string(&f)?;
        if all || parse_header(&text).hot {
            out.push((super::rel(root, &f), text));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> LintCtx {
        let mut classes = HashMap::new();
        for (t, c) in [
            ("groups", Class::Tenant),
            ("memberships", Class::Tenant),
            ("users", Class::Identity),
            ("jobs", Class::Infra),
        ] {
            classes.insert(t.to_owned(), c);
        }
        let migs = [
            "CREATE TABLE groups (tenant_id BINARY(16), id BINARY(16), PRIMARY KEY (tenant_id, id), UNIQUE KEY ux_g_name (tenant_id, name_norm))",
            "CREATE TABLE users (id BINARY(16), email_bidx BINARY(32), PRIMARY KEY (id), UNIQUE KEY ux_e (email_bidx))",
            "CREATE TABLE memberships (tenant_id BINARY(16), id BINARY(16), PRIMARY KEY (tenant_id, id))",
        ];
        LintCtx {
            classes,
            unique_keys: parse_unique_keys(&migs),
        }
    }

    fn lint(sql: &str) -> Vec<String> {
        lint_query("t.sql", sql, &ctx())
            .into_iter()
            .map(|v| v.message)
            .collect()
    }

    fn has(v: &[String], needle: &str) -> bool {
        v.iter().any(|m| m.contains(needle))
    }

    #[test]
    fn good_tenant_select_passes() {
        let v = lint(
            "-- class: tenant. params: tenant_id, after_id, limit\nSELECT id, name FROM groups WHERE tenant_id = ? AND id < ? ORDER BY id DESC LIMIT ?",
        );
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn good_point_get_without_limit_passes() {
        let v = lint(
            "-- class: tenant. params: tenant_id, id\nSELECT id FROM groups WHERE tenant_id = ? AND id = ? FOR UPDATE",
        );
        assert!(v.is_empty(), "{v:?}");
        let v = lint("-- class: identity. params: id\nSELECT id FROM users WHERE id = ?");
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn good_insert_update_and_aggregate_pass() {
        let v = lint(
            "-- class: tenant. params: tenant_id, id, name\nINSERT INTO groups (tenant_id, id, name) VALUES (?, ?, ?)",
        );
        assert!(v.is_empty(), "{v:?}");
        let v = lint(
            "-- class: tenant. params: name, tenant_id, id\nUPDATE groups SET name = ? WHERE tenant_id = ? AND id = ?",
        );
        assert!(v.is_empty(), "{v:?}");
        let v = lint(
            "-- class: tenant. params: tenant_id\nSELECT COUNT(*) FROM memberships WHERE tenant_id = ?",
        );
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn plain_select_missing_tenant_id_is_caught() {
        let v = lint(
            "-- class: tenant. params: tenant_id, limit\nSELECT id FROM groups WHERE id = ? LIMIT ?",
        );
        assert!(has(&v, "no top-level `tenant_id = ?`"), "{v:?}");
    }

    #[test]
    fn tenant_id_inside_or_does_not_count() {
        let v = lint(
            "-- class: tenant. params: tenant_id, id, limit\nSELECT id FROM groups WHERE (tenant_id = ? OR id = ?) LIMIT ?",
        );
        assert!(has(&v, "no top-level `tenant_id = ?`"), "{v:?}");
    }

    #[test]
    fn join_without_second_tenant_bind_is_caught() {
        let bad = lint(
            "-- class: tenant. params: tenant_id, limit\nSELECT g.id FROM groups g JOIN memberships m ON m.id = g.id WHERE g.tenant_id = ? LIMIT ?",
        );
        assert!(has(&bad, "alias `m`"), "{bad:?}");
        let good = lint(
            "-- class: tenant. params: tenant_id, limit\nSELECT g.id FROM groups g JOIN memberships m ON m.tenant_id = g.tenant_id AND m.id = g.id WHERE g.tenant_id = ? LIMIT ?",
        );
        assert!(good.is_empty(), "{good:?}");
    }

    #[test]
    fn update_missing_tenant_id_is_caught() {
        let v = lint(
            "-- class: tenant. params: name, id, tenant_id\nUPDATE groups SET name = ? WHERE id = ?",
        );
        assert!(has(&v, "UPDATE: tenant table"), "{v:?}");
    }

    #[test]
    fn subquery_missing_tenant_id_is_caught() {
        let bad = lint(
            "-- class: tenant. params: tenant_id, limit\nSELECT g.id FROM groups g WHERE g.tenant_id = ? AND g.id IN (SELECT m.id FROM memberships m WHERE m.status = 'x') LIMIT ?",
        );
        assert!(has(&bad, "alias `m`"), "{bad:?}");
        let correlated = lint(
            "-- class: tenant. params: tenant_id, limit\nSELECT g.id FROM groups g WHERE g.tenant_id = ? AND EXISTS (SELECT 1 FROM memberships m WHERE m.tenant_id = g.tenant_id AND m.id = g.id) LIMIT ?",
        );
        assert!(correlated.is_empty(), "{correlated:?}");
    }

    #[test]
    fn insert_without_tenant_column_is_caught() {
        let v = lint(
            "-- class: tenant. params: tenant_id, id\nINSERT INTO groups (id, name) VALUES (?, ?)",
        );
        assert!(has(&v, "lacks the `tenant_id` column"), "{v:?}");
        let v = lint("-- class: tenant. params: tenant_id\nINSERT INTO groups VALUES (?, ?)");
        assert!(has(&v, "no column list"), "{v:?}");
    }

    #[test]
    fn select_star_is_caught() {
        let v = lint(
            "-- class: tenant. params: tenant_id, limit\nSELECT * FROM groups WHERE tenant_id = ? LIMIT ?",
        );
        assert!(has(&v, "SELECT *"), "{v:?}");
        let v = lint(
            "-- class: tenant. params: tenant_id, limit\nSELECT g.* FROM groups g WHERE g.tenant_id = ? LIMIT ?",
        );
        assert!(has(&v, "SELECT *"), "{v:?}");
    }

    #[test]
    fn delete_is_caught() {
        let v = lint(
            "-- class: tenant. params: tenant_id, id\nDELETE FROM groups WHERE tenant_id = ? AND id = ?",
        );
        assert!(has(&v, "DELETE is not allowed"), "{v:?}");
    }

    #[test]
    fn unbounded_list_is_caught_and_bounded_header_exempts() {
        let v = lint(
            "-- class: tenant. params: tenant_id\nSELECT id FROM groups WHERE tenant_id = ? ORDER BY id",
        );
        assert!(has(&v, "unbounded list"), "{v:?}");
        let ok = lint(
            "-- class: tenant. params: tenant_id\n-- bounded: at most 20 groups per tenant quota\nSELECT id FROM groups WHERE tenant_id = ? ORDER BY id",
        );
        assert!(ok.is_empty(), "{ok:?}");
    }

    #[test]
    fn missing_class_header_and_unknown_table_are_caught() {
        let v = lint("SELECT id FROM users WHERE id = ?");
        assert!(has(&v, "missing header"), "{v:?}");
        let v = lint("-- class: identity. params: id\nSELECT id FROM mystery WHERE id = ?");
        assert!(has(&v, "not in TABLE_CLASSES"), "{v:?}");
    }

    #[test]
    fn tenant_query_needs_tenant_id_param_in_header() {
        let v = lint(
            "-- class: tenant. params: id, limit\nSELECT id FROM groups WHERE tenant_id = ? LIMIT ?",
        );
        assert!(has(&v, "does not list `tenant_id`"), "{v:?}");
    }

    #[test]
    fn group_ids_marker_and_infra_pass() {
        let v = lint(
            "-- class: tenant. params: tenant_id, ids\nSELECT id FROM groups WHERE tenant_id = ? AND id IN (/*GROUP_IDS*/) LIMIT 200",
        );
        assert!(v.is_empty(), "{v:?}");
        let v = lint(
            "-- class: infra. params: now, limit\nSELECT id FROM jobs WHERE run_after <= ? ORDER BY run_after LIMIT ?",
        );
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn update_with_subquery_and_many_to_one_join_pass() {
        let v = lint(
            "-- class: infra. params: now, user_id
UPDATE jobs SET run_after = ? WHERE id IN (SELECT s.id FROM groups s WHERE s.tenant_id = ?)",
        );
        assert!(v.iter().all(|m| !m.contains("unbounded")), "{v:?}");
        let v = lint(
            "-- class: tenant. params: tenant_id, id
SELECT g.id, m.id FROM groups g JOIN memberships m ON m.tenant_id = g.tenant_id AND m.id = g.parent WHERE g.tenant_id = ? AND g.id = ?",
        );
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn header_parsing() {
        let h = parse_header("-- class: infra (x). params: a, b,\n--   c\n-- hot\nSELECT 1");
        assert_eq!(h.class.as_deref(), Some("infra"));
        assert_eq!(
            h.params.as_deref(),
            Some(&["a".to_owned(), "b".into(), "c".into()][..])
        );
        assert!(h.hot);
    }
}
