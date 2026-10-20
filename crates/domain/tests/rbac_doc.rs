//! Doc-vs-code diff: parses the role x permission tables of `docs/RBAC.md` §4 at test time and
//! compares EVERY cell with the const matrix (`ROWS`), the staff matrix and the device scope list.
//! The insta snapshot only proves the code equals itself; this proves the code equals the document.
//!
//! Parse format assumptions (the test fails loudly when they break, it never skips a row silently):
//! - Scanned region: from the `## 4.` heading to the `## 5.` heading. `### 4.11` is the device-scope
//!   table (only the first-column `device:*` names are read).
//! - A table row is a line starting with `|`. The header row (first cell `Permission`) selects the mode:
//!   `superadmin` in cell 2 = staff table (cells: superadmin, support, billing, auditor);
//!   `Others` in cell 4 = tenant table with 3 role cells (GA, Member, Viewer share the "Others" cell);
//!   otherwise tenant table: Owner, Admin, GA, Member, Viewer in cells 2..6.
//! - Permission names = backtick tokens of the first cell, after removing parenthesised text (nesting
//!   allowed) and everything from the first `=`. A token starting with `.` is a suffix replacing the last
//!   segment of the previous name (`a.b.read` + `.import` = `a.b.import`). `<p>` expands to the six
//!   products. Names are listed with `,` or `/` between them.
//! - A role cell is read after removing parenthesised text. With several names in the row and a cell
//!   containing `/`, the cell is split and must have exactly one part per name; a single part applies to
//!   all names. The first character decides: `T`/`G`/`S` scope, `—`/`-` none (staff tables: `✓` yes).
//!   The words `step-up` and `confirm` anywhere in an Owner/Admin cell set those flags. Staff flags come
//!   from the raw cell: `ticket`, `owner approval`, `commerce fields` / `metadata` (restricted view).
//! - The feature column (index 6, or 4 in the "Others" table) is scanned for the toggle names
//!   `subusers`, `groups`, `user_activity`, `private_cloud` (parenthesised text removed).
//! - A name that appears twice (e.g. `platform.leads.manage`) must have identical cells.

use std::collections::{BTreeMap, BTreeSet};

use domain::rbac::matrix::row_of;
use domain::rbac::*;

fn doc_text() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/RBAC.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| format!("READ ERROR {}: {e}", path.display()))
}

// ---------------------------------------------------------------- parsing

fn strip_parens(s: &str) -> String {
    let mut depth = 0u32;
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Backtick tokens of the first cell, expanded (suffixes, `<p>`).
fn names(first: &str) -> Result<Vec<String>, String> {
    let mut s = strip_parens(first);
    if let Some(i) = s.find('=') {
        s.truncate(i);
    }
    let mut out: Vec<String> = Vec::new();
    for (i, tok) in s.split('`').enumerate() {
        if i % 2 == 0 {
            continue;
        }
        let tok = tok.trim();
        if let Some(suffix) = tok.strip_prefix('.') {
            let prev = out
                .last()
                .ok_or_else(|| format!("suffix {tok} without previous name"))?;
            let (head, _) = prev
                .rsplit_once('.')
                .ok_or_else(|| format!("bad base {prev}"))?;
            let full = format!("{head}.{suffix}");
            out.push(full);
        } else {
            out.push(tok.to_owned());
        }
    }
    let mut expanded = Vec::new();
    for n in out {
        if n.contains("<p>") {
            for p in Product::ALL {
                expanded.push(n.replace("<p>", p.as_str()));
            }
        } else {
            expanded.push(n);
        }
    }
    if expanded.is_empty() {
        return Err(format!("no permission names in cell {first:?}"));
    }
    Ok(expanded)
}

/// One cell split per name (see module docs).
fn split_cell(raw: &str, n: usize) -> Result<Vec<String>, String> {
    let stripped = strip_parens(raw);
    if n == 1 {
        return Ok(vec![stripped.trim().to_owned()]);
    }
    let parts: Vec<String> = stripped.split('/').map(|p| p.trim().to_owned()).collect();
    if parts.len() == n {
        Ok(parts)
    } else if parts.len() == 1 {
        Ok(vec![parts[0].clone(); n])
    } else {
        Err(format!(
            "cell {raw:?} has {} parts for {n} names",
            parts.len()
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DocCell {
    scope: Option<Scope>,
    step_up: bool,
    confirm: bool,
}

fn parse_tenant_cell(part: &str) -> Result<DocCell, String> {
    let scope = match part.trim().chars().next() {
        Some('T') => Some(Scope::Tenant),
        Some('G') => Some(Scope::Group),
        Some('S') => Some(Scope::SelfOnly),
        Some('—' | '-' | '–') => None,
        other => return Err(format!("unparseable scope cell {part:?} ({other:?})")),
    };
    Ok(DocCell {
        scope,
        step_up: part.contains("step-up"),
        confirm: part.contains("confirm"),
    })
}

#[derive(Debug, PartialEq, Eq)]
struct DocRow {
    cells: [DocCell; 5],
    features: BTreeSet<&'static str>,
    caps: BTreeSet<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StaffCell {
    allowed: bool,
    ticket: bool,
    owner_approval: bool,
    restricted: bool,
}

fn parse_staff_cell(raw: &str) -> Result<StaffCell, String> {
    let first = raw.trim().chars().next();
    let allowed = match first {
        Some('✓') => true,
        Some('—' | '-' | '–') => false,
        other => return Err(format!("unparseable staff cell {raw:?} ({other:?})")),
    };
    Ok(StaffCell {
        allowed,
        ticket: allowed && raw.contains("ticket"),
        owner_approval: allowed && raw.contains("owner approval"),
        restricted: allowed && (raw.contains("commerce fields") || raw.contains("metadata")),
    })
}

fn feature_words(cell: &str) -> BTreeSet<&'static str> {
    let s = strip_parens(cell);
    Feature::ALL
        .iter()
        .map(|f| f.as_str())
        .filter(|w| s.contains(w))
        .collect()
}

const CAP_WORDS: [&str; 3] = [
    "can_view_reports",
    "can_manage_machines",
    "can_assign_licenses",
];

/// Capability names mentioned in the feature/cap column (parenthesised text removed).
fn cap_words(cell: &str) -> BTreeSet<&'static str> {
    let s = strip_parens(cell);
    CAP_WORDS
        .iter()
        .copied()
        .filter(|w| s.contains(w))
        .collect()
}

struct Parsed {
    tenant: BTreeMap<String, DocRow>,
    staff: BTreeMap<String, [StaffCell; 4]>,
    device_scopes: BTreeSet<String>,
}

fn parse(text: &str) -> Result<Parsed, String> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        None,
        Tenant,
        TenantOthers,
        Staff,
    }
    let mut p = Parsed {
        tenant: BTreeMap::new(),
        staff: BTreeMap::new(),
        device_scopes: BTreeSet::new(),
    };
    let (mut in_section, mut in_411, mut mode) = (false, false, Mode::None);
    for (ln, line) in text.lines().enumerate() {
        let at = |m: &str| format!("RBAC.md line {}: {m}", ln + 1);
        if line.starts_with("## 4.") {
            in_section = true;
            continue;
        }
        if line.starts_with("## 5.") {
            break;
        }
        if !in_section {
            continue;
        }
        if line.starts_with("### ") {
            in_411 = line.contains("4.11");
            mode = Mode::None;
            continue;
        }
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if in_411 {
            for (i, tok) in cells[0].split('`').enumerate() {
                if i % 2 == 1 && tok.starts_with("device:") {
                    p.device_scopes.insert(tok.to_owned());
                }
            }
            continue;
        }
        if cells[0] == "Permission" {
            mode = if cells.get(1) == Some(&"superadmin") {
                Mode::Staff
            } else if cells.get(3) == Some(&"Others") {
                Mode::TenantOthers
            } else {
                Mode::Tenant
            };
            continue;
        }
        if cells[0].starts_with("---") || mode == Mode::None {
            continue;
        }
        let ns = names(cells[0]).map_err(|e| at(&e))?;
        match mode {
            Mode::Staff => {
                if cells.len() < 5 {
                    return Err(at("staff row needs 4 role cells"));
                }
                for (i, name) in ns.iter().enumerate() {
                    let mut row: Vec<StaffCell> = Vec::new();
                    for c in &cells[1..5] {
                        let raw = &split_cell(c, ns.len()).map_err(|e| at(&e))?[i];
                        // Staff flags need the parenthesised words, so parse the unsplit raw cell.
                        row.push(
                            parse_staff_cell(if ns.len() == 1 { c } else { raw })
                                .map_err(|e| at(&e))?,
                        );
                    }
                    let row: [StaffCell; 4] = row.try_into().map_err(|_| at("staff cells"))?;
                    if let Some(old) = p.staff.insert(name.clone(), row.clone())
                        && old != row
                    {
                        return Err(at(&format!("{name} listed twice with different cells")));
                    }
                }
            }
            Mode::Tenant | Mode::TenantOthers => {
                let (role_cells, feat_idx): (Vec<&str>, usize) = if mode == Mode::TenantOthers {
                    if cells.len() < 5 {
                        return Err(at("others row needs 4 cells"));
                    }
                    (vec![cells[1], cells[2], cells[3], cells[3], cells[3]], 4)
                } else {
                    if cells.len() < 7 {
                        return Err(at("tenant row needs >= 7 cells"));
                    }
                    (cells[1..6].to_vec(), 6)
                };
                let split: Vec<Vec<String>> = role_cells
                    .iter()
                    .map(|c| split_cell(c, ns.len()))
                    .collect::<Result<_, _>>()
                    .map_err(|e| at(&e))?;
                for (i, name) in ns.iter().enumerate() {
                    let mut cs: Vec<DocCell> = Vec::new();
                    for col in &split {
                        cs.push(parse_tenant_cell(&col[i]).map_err(|e| at(&e))?);
                    }
                    let row = DocRow {
                        cells: cs.try_into().map_err(|_| at("cells"))?,
                        features: feature_words(cells[feat_idx]),
                        caps: cap_words(cells[feat_idx]),
                    };
                    if let Some(old) = p.tenant.insert(name.clone(), row)
                        && Some(&old) != p.tenant.get(name)
                    {
                        return Err(at(&format!("{name} listed twice with different cells")));
                    }
                }
            }
            Mode::None => {}
        }
    }
    Ok(p)
}

// ---------------------------------------------------------------- explicit override lists

/// (permission, column 0=Owner 1=Admin 2=GA 3=Member 4=Viewer, what the CODE has, reason).
/// Every entry is a deliberate, cited difference between RBAC.md's cell text and the code.
const CELL_OVERRIDES: &[(&str, usize, Option<Scope>, &str)] = &[
    // Doc row `cleaner.run, cleaner.redeem, cleaner.reports.read` has Viewer "S (read)": S only for the
    // read permission. Parsing applies the row's cell to all three names, so run/redeem differ here.
    (
        "cleaner.run",
        4,
        None,
        "Viewer cell 'S (read)' = read-only; applies to cleaner.reports.read only",
    ),
    (
        "cleaner.redeem",
        4,
        None,
        "Viewer cell 'S (read)' = read-only; applies to cleaner.reports.read only",
    ),
];

/// Feature differences: (permission, code feature words, reason).
const FEATURE_OVERRIDES: &[(&str, &[&str], &str)] = &[
    // (D-65 needs no entry: performance.read / erasure metrics keep the `user_activity` word through
    // `member_gate` = other members' data only; aggregates stay open. See decide tests.)
    // §5.1 lists `PUT /devices/{id}/assignment` as gated by `subusers`; the §4.5 Feature/Cap column
    // names only the capability.
    ("devices.assign", &["subusers"], "RBAC.md §5.1 gating table"),
];

/// Capability differences: (permission, capability words the CODE has, reason).
const CAP_OVERRIDES: &[(&str, &[&str], &str)] = &[
    // Doc: "Cap `can_assign_licenses` nahi chahiye" = the capability is NOT needed for activation.
    (
        "licenses.activate",
        &[],
        "doc says the capability is not needed",
    ),
    // Doc: bare "Cap; step-up nahi" without naming it: it is the machines capability.
    (
        "devices.remote_command",
        &["can_manage_machines"],
        "doc names no capability, bare 'Cap'",
    ),
    // §4.6 shows no capability for transfer; §5.3 says can_assign_licenses=false denies
    // licenses.allocate/transfer.
    (
        "licenses.transfer",
        &["can_assign_licenses"],
        "RBAC.md §5.3",
    ),
];

/// Rows where the capability is skipped for the actor's OWN scope (`cap_self_ok`).
const CAP_SELF_OK: &[&str] = &[
    // D-63: a member may register their own device without can_manage_machines.
    "devices.register",
];

/// Code requires step-up although the §4 table cell does not say so (it is in §6.6 only).
const STEP_UP_EXTRAS: &[&str] = &["members.delete"];

fn code_cell(perm: Perm, col: usize) -> Option<Scope> {
    row_of(perm).and_then(|r| r.cells[col])
}

fn code_feature_words(perm: Perm) -> BTreeSet<&'static str> {
    let Some(r) = row_of(perm) else {
        return BTreeSet::new();
    };
    r.features
        .iter()
        .flatten()
        .chain(r.narrowed_by.iter())
        .chain(r.member_gate.iter())
        .map(|f| f.as_str())
        .collect()
}

fn code_cap_words(perm: Perm) -> BTreeSet<&'static str> {
    use domain::rbac::CapabilityKind::*;
    row_of(perm)
        .and_then(|r| r.cap)
        .map(|c| match c {
            ViewReports => "can_view_reports",
            ManageMachines => "can_manage_machines",
            AssignLicenses => "can_assign_licenses",
        })
        .into_iter()
        .collect()
}

// ---------------------------------------------------------------- the tests

#[test]
fn doc_parses_and_has_the_expected_shape() {
    let text = doc_text();
    assert!(
        !text.starts_with("READ ERROR"),
        "{}",
        &text[..text.len().min(200)]
    );
    let parsed = parse(&text).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        parsed.tenant.len() >= 130,
        "only {} tenant permissions parsed",
        parsed.tenant.len()
    );
    assert!(
        parsed.staff.len() >= 25,
        "only {} staff permissions parsed",
        parsed.staff.len()
    );
}

#[test]
fn every_tenant_cell_in_the_doc_equals_the_matrix() {
    let parsed = parse(&doc_text()).unwrap_or_else(|e| panic!("{e}"));
    let mut problems: Vec<String> = Vec::new();

    // 1. Same permission set in both directions.
    let doc_names: BTreeSet<&str> = parsed.tenant.keys().map(String::as_str).collect();
    let code_names: BTreeSet<&str> = Perm::ALL.iter().map(|p| p.name()).collect();
    for n in doc_names.difference(&code_names) {
        problems.push(format!("MISSING IN CODE: {n}"));
    }
    for n in code_names.difference(&doc_names) {
        problems.push(format!("NOT IN DOC: {n}"));
    }

    // 2. Cell by cell.
    let cols = ["Owner", "Admin", "GA", "Member", "Viewer"];
    let mut overridden = 0usize;
    for (name, row) in &parsed.tenant {
        let Some(perm) = Perm::from_name(name) else {
            continue;
        };
        for (col, doc_cell) in row.cells.iter().enumerate() {
            let code = code_cell(perm, col);
            if let Some((_, _, want, _why)) = CELL_OVERRIDES
                .iter()
                .find(|(n, c, _, _)| n == name && *c == col)
            {
                overridden += 1;
                if code != *want {
                    problems.push(format!(
                        "{name} {}: override says code {want:?}, code has {code:?}",
                        cols[col]
                    ));
                }
                continue;
            }
            if code != doc_cell.scope {
                problems.push(format!(
                    "{name} {}: doc {:?} != code {code:?}",
                    cols[col], doc_cell.scope
                ));
            }
        }

        // 3. Step-up / confirm flags (Owner/Admin cells).
        let doc_step = row.cells[0].step_up || row.cells[1].step_up;
        let doc_confirm = row.cells[0].confirm || row.cells[1].confirm;
        let code_step = requires_step_up(perm);
        let extra = STEP_UP_EXTRAS.contains(&name.as_str());
        if doc_step && !code_step {
            problems.push(format!("{name}: doc says step-up, code does not"));
        }
        if code_step && !doc_step && !extra {
            problems.push(format!(
                "{name}: code requires step-up, doc cell does not (add to STEP_UP_EXTRAS?)"
            ));
        }
        if doc_confirm != requires_confirm(perm) {
            problems.push(format!(
                "{name}: confirm doc={doc_confirm} code={}",
                requires_confirm(perm)
            ));
        }

        // 4b. Capability column, both directions, plus the D-63 self exemption.
        let code_caps = code_cap_words(perm);
        let want_caps: BTreeSet<&str> = match CAP_OVERRIDES.iter().find(|(n, _, _)| n == name) {
            Some((_, words, _)) => words.iter().copied().collect(),
            None => row.caps.iter().copied().collect(),
        };
        if code_caps != want_caps {
            problems.push(format!(
                "{name}: capability doc {:?} (after overrides {want_caps:?}) != code {code_caps:?}",
                row.caps
            ));
        }
        let self_ok = row_of(perm).is_some_and(|r| r.cap_self_ok);
        if self_ok != CAP_SELF_OK.contains(&name.as_str()) {
            problems.push(format!(
                "{name}: cap_self_ok={self_ok} not matching CAP_SELF_OK list"
            ));
        }

        // 4. Feature toggles.
        let code_words = code_feature_words(perm);
        let want_words: BTreeSet<&str> = match FEATURE_OVERRIDES.iter().find(|(n, _, _)| n == name)
        {
            Some((_, words, _)) => words.iter().copied().collect(),
            None => row.features.iter().copied().collect(),
        };
        if code_words != want_words {
            problems.push(format!(
                "{name}: feature doc {:?} (after overrides {want_words:?}) != code {code_words:?}",
                row.features
            ));
        }
    }
    assert_eq!(
        overridden,
        CELL_OVERRIDES.len(),
        "an override entry matched no doc row"
    );
    assert!(
        problems.is_empty(),
        "RBAC.md and domain::rbac differ:\n{}",
        problems.join("\n")
    );
}

#[test]
fn licenses_revoke_bulk_step_up_matches_the_doc_note() {
    // §4.12 note: "step-up if bulk > 10".
    assert!(!requires_step_up(Perm::LicensesRevoke));
    assert!(!requires_step_up_bulk(Perm::LicensesRevoke, 10));
    assert!(requires_step_up_bulk(Perm::LicensesRevoke, 11));
}

#[test]
fn every_staff_cell_in_the_doc_equals_the_platform_matrix() {
    let parsed = parse(&doc_text()).unwrap_or_else(|e| panic!("{e}"));
    let mut problems: Vec<String> = Vec::new();
    let doc_names: BTreeSet<&str> = parsed.staff.keys().map(String::as_str).collect();
    let code_names: BTreeSet<&str> = PlatformPerm::ALL.iter().map(|p| p.name()).collect();
    for n in doc_names.difference(&code_names) {
        problems.push(format!("MISSING IN CODE: {n}"));
    }
    for n in code_names.difference(&doc_names) {
        problems.push(format!("NOT IN DOC: {n}"));
    }
    for (name, cells) in &parsed.staff {
        let Some(perm) = PlatformPerm::from_name(name) else {
            continue;
        };
        for (i, role) in StaffRole::ALL.iter().enumerate() {
            let doc = &cells[i];
            let code = platform_grants(*role, perm);
            let code_cell = StaffCell {
                allowed: code.is_some(),
                ticket: code.is_some_and(|g| g.ticket_required),
                owner_approval: code.is_some_and(|g| g.owner_approval),
                restricted: code.is_some_and(|g| g.restricted_view),
            };
            if *doc != code_cell {
                problems.push(format!(
                    "{name} {role:?}: doc {doc:?} != code {code_cell:?}"
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "RBAC.md and domain::rbac differ:\n{}",
        problems.join("\n")
    );
}

#[test]
fn device_scopes_in_the_doc_equal_the_code() {
    let parsed = parse(&doc_text()).unwrap_or_else(|e| panic!("{e}"));
    let code: BTreeSet<String> = DeviceScope::ALL
        .iter()
        .map(|s| s.name().to_owned())
        .collect();
    assert_eq!(parsed.device_scopes, code);
    assert!(parsed.device_scopes.len() >= 9);
}

#[test]
fn parser_unit_checks() {
    assert_eq!(
        names("`autopilot.devices.read` / `.import` / `.delete`").unwrap_or_default(),
        [
            "autopilot.devices.read",
            "autopilot.devices.import",
            "autopilot.devices.delete"
        ]
    );
    assert_eq!(
        names("`a.b` (x `c.d`) = `e.f` tail").unwrap_or_default(),
        ["a.b"]
    );
    assert_eq!(names("`reports.<p>.read`").unwrap_or_default().len(), 6);
    assert_eq!(
        split_cell("T/T + step-up", 2).unwrap_or_default(),
        ["T", "T + step-up"]
    );
    assert_eq!(split_cell("G (a/b)", 1).unwrap_or_default(), ["G"]);
    assert!(split_cell("T/T/T", 2).is_err());
    assert!(parse_tenant_cell("X").is_err());
    assert_eq!(
        parse_tenant_cell("T + step-up + confirm"),
        Ok(DocCell {
            scope: Some(Scope::Tenant),
            step_up: true,
            confirm: true
        })
    );
    assert!(parse_staff_cell("✓ (+ owner approval)").is_ok_and(|c| c.owner_approval));
    assert!(parse_staff_cell("?").is_err());
    // Duplicated names must agree.
    let bad = "## 4. x\n### 4.1\n| Permission | Owner | Admin | GA | Member | Viewer | Feature |\n|---|\n| `a.b` | T | T | — | — | — | — |\n| `a.b` | T | — | — | — | — | — |\n## 5.\n";
    assert!(parse(bad).is_err());
}
