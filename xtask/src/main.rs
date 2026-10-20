//! xtask: dev helper commands + P0-20 data-layer gates. `dev-keys` aur gates implemented; baaki stubs
//! har ek task ke saath aayenge.
//!
//! Gates (`cargo xtask <gate>`): sql-lint, migrate-lint, no-raw-sql, sealed-ctor-gate, schema-check,
//! explain-check, route-policies [--check]; `gates [--db]` sab static gates ek saath chalata hai.

mod dev_keys;
mod gates;

use anyhow::{Result, bail};

const STUBS: &[&str] = &["sqlx-prepare", "loadtest"];

const GATES: &[&str] = &[
    "sql-lint",
    "migrate-lint",
    "no-raw-sql",
    "sealed-ctor-gate",
    "schema-check",
    "explain-check",
    "ru-report",
    "route-policies",
    "db-reset",
    "gates",
];

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        bail!(
            "usage: cargo xtask <dev-keys|{}|{}>",
            GATES.join("|"),
            STUBS.join("|")
        );
    };
    if cmd == "dev-keys" {
        return dev_keys::run(args);
    }
    if let Some(r) = gates::dispatch(&cmd, args) {
        return r;
    }
    if STUBS.contains(&cmd.as_str()) {
        bail!("xtask `{cmd}`: not implemented yet");
    }
    bail!(
        "unknown xtask command `{cmd}`; expected one of: dev-keys, {}, {}",
        GATES.join(", "),
        STUBS.join(", ")
    )
}
