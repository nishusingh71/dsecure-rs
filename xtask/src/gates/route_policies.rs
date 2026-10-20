//! `cargo xtask route-policies [--check|--write]` (RBAC.md, T-R1): api route table vs reviewed file.
//!
//! Report = `api::app::route_policies(&RouteOptions { environment: Production, openapi_public: false })`,
//! ek line per route: `METHOD path | kinds=member,device | public=<reason|->`. Production + openapi off =
//! sabse tight (public) surface. Reviewed file: `docs/public-routes.txt`.
//!
//! - (no flag): report stderr par print.
//! - `--check`: report ko reviewed file se diff; koi bhi farq (naya/hata/badla route) = fail.
//! - `--write`: reviewed file regenerate (owner review ke baad hi commit).
//!
//! Principal kinds `Policy` ke Debug text se aate hain (`Kinds` private hai): agar auth crate Debug format
//! badle to yeh gate `kinds=?` dikhayega aur check fail hoga (fail closed).

use super::{Violation, finish, repo_root, say};
use anyhow::{Context, Result, bail};
use api::app::{RouteOptions, route_policies};
use api::router::RoutePolicyReport;
use config::Environment;
use std::collections::BTreeSet;

pub const GATE: &str = "route-policies";
pub const REVIEWED_FILE: &str = "docs/public-routes.txt";

const HEADER: &str = "# Reviewed route policy list (xtask route-policies). One line per route:\n\
# METHOD path | kinds=<principal kinds> | public=<reason, or - when authenticated>\n\
# Report options: environment=Production, openapi_public=false.\n\
# Regenerate with `cargo run -p xtask -- route-policies --write`; any diff must be reviewed by the owner.\n";

fn kinds_of(policy_debug: &str) -> String {
    let Some(i) = policy_debug.find("Kinds {") else {
        return "?".to_owned();
    };
    let block = &policy_debug[i..];
    let block = block.split('}').next().unwrap_or(block);
    let mut k = Vec::new();
    for name in ["member", "device", "staff", "cleaner"] {
        if block.contains(&format!("{name}: true")) {
            k.push(name);
        }
    }
    if k.is_empty() {
        "-".to_owned()
    } else {
        k.join(",")
    }
}

/// One report line.
pub fn render_line(r: &RoutePolicyReport) -> String {
    format!(
        "{} {} | kinds={} | public={}",
        r.method,
        r.path,
        kinds_of(&r.policy),
        r.public_reason.unwrap_or("-")
    )
}

/// Sorted, deduplicated report lines.
pub fn render(reports: &[RoutePolicyReport]) -> Vec<String> {
    let set: BTreeSet<String> = reports.iter().map(render_line).collect();
    set.into_iter().collect()
}

/// Lines of a report: whitespace normalised, blank and `#` comment lines dropped.
fn lines(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Human-readable differences: `+ line` = in the actual report only, `- line` = in the reviewed file only.
pub fn diff_reports(reviewed: &str, actual: &str) -> Vec<String> {
    let (r, a) = (lines(reviewed), lines(actual));
    let mut out: Vec<String> = a.difference(&r).map(|l| format!("+ {l}")).collect();
    out.extend(r.difference(&a).map(|l| format!("- {l}")));
    out
}

/// Violations for `--check`.
pub fn check(reviewed: &str, actual_lines: &[String]) -> Vec<Violation> {
    diff_reports(reviewed, &actual_lines.join("\n"))
        .into_iter()
        .map(|d| {
            Violation::new(
                GATE,
                REVIEWED_FILE,
                format!("{d} (review the route, then regenerate with --write)"),
            )
        })
        .collect()
}

fn actual_report() -> Result<Vec<String>> {
    let reports = route_policies(&RouteOptions {
        environment: Environment::Production,
        openapi_public: false,
    })
    .map_err(|e| anyhow::anyhow!("api route table does not build: {e:?}"))?;
    Ok(render(&reports))
}

pub fn run(args: impl Iterator<Item = String>) -> Result<()> {
    let mut mode = "print";
    for a in args {
        match a.as_str() {
            "--check" => mode = "check",
            "--write" => mode = "write",
            other => bail!("unknown argument `{other}`; usage: route-policies [--check|--write]"),
        }
    }
    let lines = actual_report()?;
    let path = repo_root()?.join(REVIEWED_FILE);
    match mode {
        "write" => {
            let body = format!("{HEADER}{}\n", lines.join("\n"));
            std::fs::write(&path, body).with_context(|| format!("cannot write {REVIEWED_FILE}"))?;
            say!(
                "route-policies: wrote {} routes to {REVIEWED_FILE}",
                lines.len()
            );
            Ok(())
        }
        "check" => {
            let reviewed = std::fs::read_to_string(&path).with_context(|| {
                format!("{REVIEWED_FILE} missing (generate with --write, then review)")
            })?;
            finish(GATE, &check(&reviewed, &lines), lines.len())
        }
        _ => {
            for l in &lines {
                say!("{l}");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: &str = "member: false, device: false, staff: false, cleaner: false";
    const MD: &str = "member: true, device: true, staff: false, cleaner: false";

    fn rep(
        method: &str,
        path: &'static str,
        public: Option<&'static str>,
        kinds: &str,
    ) -> RoutePolicyReport {
        RoutePolicyReport {
            method: method.to_owned(),
            path,
            public_reason: public,
            permission: None,
            idempotent: false,
            high_risk: false,
            policy: format!("Policy {{ kinds: Kinds {{ {kinds} }}, public_reason: None }}"),
        }
    }

    fn base() -> Vec<RoutePolicyReport> {
        vec![
            rep("GET", "/health", Some("liveness"), NONE),
            rep("GET", "/v1/me", None, MD),
        ]
    }

    #[test]
    fn render_shows_kinds_and_public_reason() {
        let l = render(&base());
        assert_eq!(l[0], "GET /health | kinds=- | public=liveness");
        assert_eq!(l[1], "GET /v1/me | kinds=member,device | public=-");
    }

    #[test]
    fn reviewed_list_passes() {
        let lines = render(&base());
        let reviewed = format!("{HEADER}{}\n", lines.join("\n"));
        assert!(check(&reviewed, &lines).is_empty());
    }

    #[test]
    fn adding_a_public_route_fails_the_gate() {
        let reviewed = format!("{HEADER}{}\n", render(&base()).join("\n"));
        let mut now = base();
        now.push(rep("POST", "/v1/secret", Some("oops"), NONE));
        let v = check(&reviewed, &render(&now));
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].message.starts_with("+ POST /v1/secret"), "{v:?}");
        // a policy change on an existing route is a diff too (+ and -)
        now.pop();
        now[1] = rep("GET", "/v1/me", Some("now public"), MD);
        assert_eq!(check(&reviewed, &render(&now)).len(), 2);
    }

    #[test]
    fn removed_route_and_comments_and_spacing() {
        let reviewed = "# c\nGET  /a | kinds=- | public=x\nGET /b | kinds=- | public=y\n";
        let d = diff_reports(reviewed, "GET /a | kinds=- | public=x");
        assert_eq!(d, vec!["- GET /b | kinds=- | public=y"]);
    }

    #[test]
    fn real_api_table_builds_in_the_reviewed_format() {
        let lines = actual_report().unwrap();
        assert!(!lines.is_empty());
        assert!(
            lines
                .iter()
                .all(|l| l.contains(" | kinds=") && l.contains(" | public="))
        );
    }
}
